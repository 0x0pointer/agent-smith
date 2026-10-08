"""Tests for the /ai-redteam engine hardening (issues #246–#261).

Transport-aware oracles, status histograms, probabilistic filter probing,
fixed-payload k/N replay, matched-sample comparison, the structured/integrity
oracle, the agent-in-the-loop probe_turn protocol, and the LLM-cell closure gate.
Local in-process HTTP servers only — no external network, no LLM.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import core.coverage
from core import ai_redteam
from mcp_server import redteam_tools as rtt
from mcp_server.redteam import attack_loop, calibration, filter_probe, oracles, structured, transport
from mcp_server.scan_engine import artifacts as art


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def server():
    """Start a local HTTP server whose behaviour is a per-test `handle(body, headers)`
    returning (status, json_body, extra_headers)."""
    servers = []

    def start(handle):
        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                status, body, extra = handle(raw, self.headers)
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_port}/chat"

    yield start
    for s in servers:
        s.shutdown()


@pytest.fixture
def stores(tmp_path, monkeypatch):
    """Isolate the artifact dir (both views of it) and the AI red-team store."""
    adir = tmp_path / "artifacts"
    adir.mkdir()
    monkeypatch.setattr(art, "_ARTIFACTS_DIR", adir)
    monkeypatch.setattr(core.coverage, "_ARTIFACTS_DIR", adir)
    monkeypatch.setattr(ai_redteam, "_FILE", tmp_path / "ai_redteam.json")
    monkeypatch.setattr(core.coverage, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
    return adir


# ── oracles (#261 #1–#3) ──────────────────────────────────────────────────────

def test_marker_supplied_but_absent_is_never_success():
    v = oracles.heuristic_judge('{"name": "[redacted]"}', "leak", ["SECRET"])
    assert not v.complied
    assert v.score <= 0.59


def test_non_marker_compliance_capped_at_progress():
    v = oracles.heuristic_judge("Sure, here is a long helpful answer " * 10, "leak", ["SECRET"])
    assert not v.complied and v.score <= 0.59 and v.label == "progress"


@pytest.mark.parametrize("text", ["Het spijt me, dat kan ik niet doen.",
                                  "Es tut mir leid, ich kann nicht helfen.",
                                  "Lo siento, no puedo ayudar con eso.",
                                  "[REDACTED]"])
def test_non_english_refusals_and_redactions(text):
    assert oracles.classify(text) == "refused"


@pytest.mark.parametrize("text,kind", [("[send error: HTTP 500 gateway]", "blocked"),
                                       ("[send error: HTTP 401]", "auth_failure"),
                                       ("[send error: HTTP 429 slow down]", "rate_limited"),
                                       ("[send error: URLError: refused]", "unreachable")])
def test_transport_errors_never_score_as_progress(text, kind):
    v = oracles.heuristic_judge(text, "goal")
    assert not v.complied and v.score == 0.0
    assert v.evidence["transport"] == kind
    assert oracles.llm_judge(text, "goal", model=lambda p: '{"complied": true}').score == 0.0


# ── transport (#261 #3, #250, #247) ───────────────────────────────────────────

def test_sender_reports_http_status_and_body(server):
    url = server(lambda b, h: (500, {"error": "blocked by gateway"}, None))
    send = transport.HttpSender(url, max_retries=0)
    out = send("hi")
    assert out.startswith("[send error: HTTP 500") and "blocked by gateway" in out
    assert send.codes[500] == 1


def test_sender_dumps_non_string_reply_key(server):
    url = server(lambda b, h: (200, {"reply": [{"a": 1}]}, None))
    assert json.loads(transport.HttpSender(url)("x")) == [{"a": 1}]


def test_sender_retries_429_with_retry_after(server):
    calls = {"n": 0}

    def handle(b, h):
        calls["n"] += 1
        if calls["n"] == 1:
            return 429, {"error": "slow"}, {"Retry-After": "0"}
        return 200, {"reply": "ok"}, None
    send = transport.HttpSender(server(handle))
    assert send("x") == "ok"
    assert send.retries == 1 and send.codes[200] == 1 and 429 not in send.codes


def test_sender_follows_set_cookie_rotation(server):
    seen = []

    def handle(b, h):
        seen.append(h.get("Cookie"))
        return 200, {"reply": "ok"}, {"Set-Cookie": f"sid=v{len(seen)}; Path=/"}
    send = transport.HttpSender(server(handle), headers={"Cookie": "sid=v0"})
    send("a")
    send("b")
    assert seen == ["sid=v0", "sid=v1"]


def test_headers_from_known_assets(monkeypatch):
    from core import session as scan_session
    monkeypatch.setattr(scan_session, "get", lambda: {"known_assets": {
        "auth_tokens": [{"value": "old"}, {"value": "jwt-new"}],
        "session_cookies": [{"name": "sid", "value": "abc"}]}})
    h = transport.resolve_headers({"headers_from": "known_assets", "headers": {"X-A": "1"}})
    assert h == {"Authorization": "Bearer jwt-new", "Cookie": "sid=abc", "X-A": "1"}


def test_session_cookie_upsert_replaces_rotated_value():
    from core.session import assets as asset_mod
    store = {"session_cookies": [{"name": "sid", "value": "v1"}]}
    asset_mod._upsert_session_cookies(store, [{"name": "sid", "value": "v2"}, {"name": "x", "value": "1"}])
    assert store["session_cookies"] == [{"name": "sid", "value": "v2"}, {"name": "x", "value": "1"}]


# ── attack loop stats (#261 #17, #257) ────────────────────────────────────────

def test_feedback_attack_splits_reached_vs_blocked():
    i = {"n": 0}

    def send(msg, cid=None):
        i["n"] += 1
        return "[send error: HTTP 500 blocked]" if i["n"] % 2 else "I'm sorry, I can't."
    r = attack_loop.feedback_attack("leak", send, success_markers=["SECRET"], max_attempts=10)
    assert r["attempts"] == 10
    assert r["reached_model"] + r["blocked"] == 10
    assert r["codes"]["500"] == r["blocked"] and r["codes"]["200"] == r["reached_model"]
    assert r["success_rate_over_reached"] == 0.0
    assert sum(p["attempts"] for p in r["phase_counts"].values()) == 10


def test_reproduce_retries_blocked_and_flags_insufficient():
    from mcp_server.redteam.oracles import Verdict
    seq = iter([Verdict(False, 0, "refused", evidence={"transport": "blocked"}), True, False] * 10)
    r = attack_loop.reproduce(lambda: next(seq), n=4)
    assert r["n"] == 4 and r["not_reached"]["blocked"] >= 1 and "insufficient_samples" not in r
    always_blocked = attack_loop.reproduce(
        lambda: Verdict(False, 0, "refused", evidence={"transport": "blocked"}), n=3)
    assert always_blocked["n"] == 0 and always_blocked["insufficient_samples"]


# ── filter probe (#255, #261 #4) ──────────────────────────────────────────────

def test_filter_probe_counts_http_block_and_reports_rates():
    def send(msg, cid=None):
        return "[send error: HTTP 500 guard]" if "Ignore all previous" in msg else "ok"
    r = filter_probe.probe_filter(send, candidates=["base64", "rot13"], n=3)
    assert r["plaintext_blocked"] is True
    assert r["rates"]["direct"]["rate"] == 0.0
    assert r["rates"]["base64"]["rate"] == 1.0 and "base64" in r["bypass"]
    assert r["control"]["rate"] == 1.0


def test_filter_probe_probabilistic_guard_and_notes():
    i = {"n": 0}

    def send(msg, cid=None):
        i["n"] += 1
        return "[send error: HTTP 500]" if i["n"] % 3 == 0 else "ok"
    r = filter_probe.probe_filter(send, candidates=["base64"], n=6)
    assert 0 < r["rates"]["base64"]["rate"] < 1
    assert any("plaintext canary NOT blocked" in n for n in r["notes"])
    assert any("benign control" in n for n in r["notes"])


def test_pick_transforms_ranks_by_rate():
    pr = {"bypass": ["base64", "hex"], "rates": {"base64": {"rate": 0.6}, "hex": {"rate": 1.0}}}
    assert filter_probe.pick_transforms(pr) == ["hex", "base64"]


# ── calibrate (#261 #5) ───────────────────────────────────────────────────────

def test_calibrate_reports_unreachable_labs():
    r = calibration.calibrate("http://127.0.0.1:9", max_attempts=2)
    assert r["unreachable"] is True and r["calibrated"] is False and "unreachable" in r["summary"]


# ── structured oracle (#246, #258) ────────────────────────────────────────────

_BASE = {"records": [{"name": "ACME", "amount": 10}, {"name": "Globex", "amount": 20}]}


def test_jsonpath_subset():
    assert structured.jsonpath(_BASE, "$.records[*].name") == ["ACME", "Globex"]
    assert structured.jsonpath(_BASE, "$.records[?(@.name=='ACME')].amount") == [10]
    assert structured.jsonpath(_BASE, "$..amount") == [10, 20]
    assert structured.jsonpath(_BASE, "$.records[-1]['name']") == ["Globex"]


def test_structured_verdict_dropped_record_with_200_json():
    observed = {"records": [{"name": "Globex", "amount": 20}]}
    pred = [{"path": "$.records[?(@.name=='ACME')]", "op": "absent"}]
    v = structured.structured_verdict(json.dumps(observed), _BASE, pred)
    assert v.complied and v.score == 1.0
    v2 = structured.structured_verdict(json.dumps(_BASE), _BASE, pred)
    assert not v2.complied


def test_structured_verdict_without_predicates_is_a_lead_not_success():
    observed = {"records": [{"name": "ACME", "amount": 99}, {"name": "Globex", "amount": 20}]}
    v = structured.structured_verdict(json.dumps(observed), _BASE)
    assert not v.complied and v.label == "deviated" and v.score >= 0.5
    assert v.evidence["diff"]["changed"][0]["path"] == "$.records[0].amount"


def test_unstable_baseline_paths_ignored():
    a = {"id": "1", "x": 1}
    b = {"id": "2", "x": 1}
    ign = structured.unstable_paths([a, b])
    assert ign == {"$.id"}
    assert not structured.diff(a, {"id": "3", "x": 1}, ign)["deviates"]


# ── tool layer: preflight, artifacts, reproduce, compare, probe_turn ──────────

def test_feedback_attack_preflight_aborts_on_401(server, stores):
    url = server(lambda b, h: (401, {"error": "session expired"}, None))
    r = json.loads(rtt._dispatch("feedback_attack", url, {"goal": "x", "max_retries": 0}))
    assert r["aborted"] and r["preflight"]["transport"] == "auth_failure"


def test_feedback_attack_persists_full_transcript(server, stores):
    url = server(lambda b, h: (200, {"reply": "I'm sorry, I can't help."}, None))
    r = json.loads(rtt._dispatch("feedback_attack", url,
                                 {"goal": "leak", "success_markers": ["SECRET"], "max_attempts": 20}))
    assert len(r["transcript"]) == 12 and r["transcript_trimmed"] == 8
    full = json.loads(art.read_artifact_raw(r["artifact_id"]))
    assert len(full["transcript"]) == 20 and full["smith_evidence"]["reached_model"] == 20
    stored = ai_redteam.get()["attacks"][-1]
    assert stored["codes"] == {"200": 20} and stored["artifact_id"] == r["artifact_id"]


def test_reproduce_action_per_variant_kn(server, stores):
    def handle(b, h):
        msg = json.loads(b)["message"]
        return 200, {"reply": "SECRET-42" if "plain" in msg else "no"}, None
    r = json.loads(rtt._dispatch("reproduce", server(handle), {
        "payloads": {"a": "plain ask", "b": "other"}, "n": 4, "success_markers": ["SECRET"]}))
    assert r["variants"]["a"]["k"] == 4 and r["variants"]["b"]["k"] == 0
    assert ai_redteam.get()["reproductions"][-1]["variants"]["a"]["n"] == 4


def test_compare_flags_insufficient_matched_samples(server, stores):
    def handle(b, h):
        msg = json.loads(b)["message"]
        return (500, {}, None) if "B" in msg else (200, {"reply": "fine"}, None)
    r = json.loads(rtt._dispatch("compare", server(handle), {
        "variants": {"a": "variant A", "b": "variant B"}, "n": 10, "max_retries": 0}))
    assert r["verdict"] == "insufficient matched samples" and r["insufficient_samples"] == ["b"]


def test_probe_turn_requires_assessment_and_concludes(server, stores):
    def handle(b, h):
        msg = json.loads(b)["message"]
        recs = [{"name": "ACME"}] if "drop" in msg else [{"name": "ACME"}, {"name": "Globex"}]
        return 200, {"reply": {"records": recs}}, None
    url = server(handle)
    t0 = json.loads(rtt._dispatch("probe_turn", url, {"objective": "drop Globex",
                                                      "payload": "clean doc", "baseline": True}))
    sid = t0["session_id"]
    assert t0["baseline_set"]
    t1 = json.loads(rtt._dispatch("probe_turn", "", {"session_id": sid, "payload": "attempt 1"}))
    assert t1["diff"]["deviates"] is False and "raw_output" in t1
    rej = json.loads(rtt._dispatch("probe_turn", "", {"session_id": sid, "payload": "attempt 2"}))
    assert "assessment is required" in rej["error"]
    t2 = json.loads(rtt._dispatch("probe_turn", "", {"session_id": sid, "payload": "drop it",
                                                     "assessment": "no change; try a direct ask"}))
    assert t2["diff"]["removed"] == ["$.records[1].name"]
    done = json.loads(rtt._dispatch("probe_turn", "", {"session_id": sid, "conclude": {
        "verdict": "met", "rationale": "record silently dropped"}}))
    assert done["smith_evidence"]["turns"] == 2 and done["smith_evidence"]["assessed_turns"] == 1
    assert art.artifact_exists(done["artifact_id"])


# ── coverage gate (#248, #249) ────────────────────────────────────────────────

async def _llm_cell(itype="jailbreak"):
    await core.coverage.add_endpoint(path="/v1/chat/completions", method="POST",
                                     params=[{"name": "message", "type": "llm_prompt", "value_hint": ""}])
    m = core.coverage._load()["matrix"]
    return next(c["id"] for c in m if c["injection_type"] == itype)


def _store(stores, name, doc):
    (stores / f"{name}.txt").write_text(json.dumps(doc) if isinstance(doc, dict) else doc)
    return name


@pytest.mark.asyncio
async def test_llm_cell_rejects_single_http_artifact(stores):
    cid = await _llm_cell()
    aid = _store(stores, "http_request_120000_aaaaaaaa", {"status": 200})
    r = await core.coverage.update_cell(cid, "tested_clean", artifact_id=aid)
    assert isinstance(r, str) and "REJECTED" in r and "redteam" in r


@pytest.mark.asyncio
async def test_llm_cell_budget_enforced_on_redteam_evidence(stores):
    cid = await _llm_cell()
    await core.coverage.update_cell(cid, "in_progress")
    thin = _store(stores, "redteam_feedback_attack_120000_bbbbbbbb", {"smith_evidence": {
        "kind": "feedback_attack", "reached_model": 3, "families": ["direct", "roleplay"]}})
    r = await core.coverage.update_cell(cid, "tested_clean", artifact_id=thin)
    assert isinstance(r, str) and "reached the model" in r
    ok = _store(stores, "redteam_feedback_attack_120000_cccccccc", {"smith_evidence": {
        "kind": "feedback_attack", "reached_model": 12, "families": ["direct", "roleplay"]}})
    assert await core.coverage.update_cell(cid, "tested_clean", artifact_id=ok) is True


@pytest.mark.asyncio
async def test_llm_vulnerable_without_kn_tagged_needs_reproduction(stores, monkeypatch):
    from core.coverage import operations
    monkeypatch.setattr(operations, "_validate_finding_link", lambda s, f: "")
    cid = await _llm_cell("system_prompt_leak")
    aid = _store(stores, "http_request_120000_dddddddd", {"status": 200})
    r = await core.coverage.update_cell(cid, "vulnerable", artifact_id=aid, finding_id="f1")
    assert isinstance(r, str) and "needs_reproduction" in r
    cell = next(c for c in core.coverage._load()["matrix"] if c["id"] == cid)
    assert cell["needs_reproduction"] is True


@pytest.mark.asyncio
async def test_skip_reason_agent_policy_block(stores):
    cid = await _llm_cell("prompt_injection")
    r = await core.coverage.update_cell(cid, "skipped", skip_reason="agent_policy_block")
    assert isinstance(r, str) and "needs notes" in r
    r = await core.coverage.update_cell(cid, "skipped", skip_reason="agent_policy_block",
                                        notes="integrity-injection attempt stopped client-side")
    assert r is True
    cell = next(c for c in core.coverage._load()["matrix"] if c["id"] == cid)
    assert cell["skip_reason"] == "agent_policy_block"
    bad = await core.coverage.update_cell(cid, "skipped", skip_reason="nope")
    assert "unknown skip_reason" in bad
