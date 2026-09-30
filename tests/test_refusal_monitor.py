"""Usage-Policy refusal monitor (core/api_server/smith/refusal.py): detects a
Claude Code content-safety refusal in the driving transcript, notifies the operator,
and queues a NON-BLOCKING skip directive — without ever spawning a process. Negative
controls: ordinary prose is not a refusal, a recovered scan is not wedged, and a dev
conversation that merely quotes the policy is not mistaken for the scan driver."""
import asyncio
import json

import pytest

import core.api_server.smith as smith
import core.api_server.smith.refusal as rf

REFUSAL = ("API Error: Claude Code is unable to respond to this request, which appears to "
           "violate our Usage Policy (https://www.anthropic.com/legal/aup). This request "
           "triggered cyber-related safeguards.")


# ── transcript builders ──────────────────────────────────────────────────────

def _assistant(text):
    return {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": text}]}}


def _assistant_str(text):
    return {"type": "assistant", "message": {"role": "assistant", "content": text}}


def _user(text):
    return {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": text}]}}


def _pentest_call(name="mcp__pentest-agent__http"):
    return {"type": "assistant", "message": {"role": "assistant",
            "content": [{"type": "tool_use", "name": name, "input": {}}]}}


def _write(path, events):
    path.write_text("".join(json.dumps(e) + "\n" for e in events))


# ── marker classifier (with negative control) ────────────────────────────────

@pytest.mark.parametrize("text", [
    REFUSAL,
    "Output blocked by content filtering policy.",
    "This request triggered cyber-related safeguards.",
    "I'm unable to respond to this request.",
])
def test_looks_like_refusal_positive(text):
    assert rf._looks_like_refusal(text)


@pytest.mark.parametrize("text", [
    "Running an nmap scan against the target now.",
    "I found a SQL injection on the login endpoint; filing a finding.",
    "",
    "The security policy of the app allows weak passwords — that's a finding.",  # 'policy' but not the marker
])
def test_looks_like_refusal_negative(text):
    assert not rf._looks_like_refusal(text)


# ── terminal-assistant-text extraction ───────────────────────────────────────

def test_terminal_assistant_text_picks_last_assistant_ignoring_trailing_user():
    events = [_assistant("earlier turn"), _pentest_call(), _assistant(REFUSAL), _user("")]
    assert rf._looks_like_refusal(rf._terminal_assistant_text(events))


def test_terminal_assistant_text_handles_string_content():
    assert rf._terminal_assistant_text([_assistant_str(REFUSAL)]) == REFUSAL


def test_terminal_assistant_text_recovered_scan_reads_not_refusal():
    # last assistant turn is a normal tool call -> scan recovered, not wedged
    events = [_assistant(REFUSAL), _pentest_call(), _assistant("Continuing with the next cell.")]
    assert not rf._looks_like_refusal(rf._terminal_assistant_text(events))


def test_terminal_assistant_text_raw_fallback_when_no_text_block():
    # an API-error entry stored without a text block still gets scanned via raw JSON
    ev = {"type": "assistant", "message": {"role": "assistant", "isApiErrorMessage": True,
          "content": [], "error": REFUSAL}}
    assert rf._looks_like_refusal(rf._terminal_assistant_text([ev]))


# ── scan-relevance discriminator ─────────────────────────────────────────────

def test_tail_has_pentest_tooluse():
    assert rf._tail_has_pentest_tooluse([_pentest_call("mcp__pentest-agent__scan")])
    assert rf._tail_has_pentest_tooluse([_pentest_call("pentest-agent_kali")])   # opencode/codex form
    assert not rf._tail_has_pentest_tooluse([_assistant("just text"), _user("hi")])


# ── _evaluate_transcript ─────────────────────────────────────────────────────

def test_evaluate_wedged_scan_transcript_hits(tmp_path):
    p = tmp_path / "scan.jsonl"
    _write(p, [_pentest_call(), _assistant(REFUSAL)])
    hit = rf._evaluate_transcript(p, require_scan_relevance=True)
    assert hit and hit[0] == p and rf._looks_like_refusal(hit[1])


def test_evaluate_healthy_transcript_returns_none(tmp_path):
    p = tmp_path / "scan.jsonl"
    _write(p, [_pentest_call(), _assistant("all cells tested clean")])
    assert rf._evaluate_transcript(p, require_scan_relevance=True) is None


def test_evaluate_refusal_without_pentest_tooluse_gated_by_relevance(tmp_path):
    # a dev/chat transcript that merely QUOTES the refusal, no pentest tool calls
    p = tmp_path / "dev.jsonl"
    _write(p, [_user("why did it stop?"), _assistant(f"It said: {REFUSAL}")])
    assert rf._evaluate_transcript(p, require_scan_relevance=True) is None   # ignored as non-scan
    assert rf._evaluate_transcript(p, require_scan_relevance=False) is not None  # trusted when it's the recorded sid


# ── _find_wedged_transcript ──────────────────────────────────────────────────

def test_find_uses_recorded_sid_directly(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "_project_transcript_dir", lambda: tmp_path)
    monkeypatch.setattr(rf, "_recorded_smith_sid", lambda: "sess-abc")
    p = tmp_path / "sess-abc.jsonl"
    _write(p, [_assistant(REFUSAL)])   # no pentest tool_use needed — it's the scan's own session
    hit = rf._find_wedged_transcript(now=1e12)
    assert hit and hit[0].name == "sess-abc.jsonl"


def test_find_interactive_ignores_dev_transcript_picks_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "_project_transcript_dir", lambda: tmp_path)
    monkeypatch.setattr(rf, "_recorded_smith_sid", lambda: None)   # interactive: no minted id
    dev = tmp_path / "dev.jsonl"
    _write(dev, [_user("q"), _assistant(f"It refused: {REFUSAL}")])       # quotes policy, no pentest calls
    scan = tmp_path / "scan.jsonl"
    _write(scan, [_pentest_call(), _assistant(REFUSAL)])                  # the real wedged driver
    import os
    now = os.path.getmtime(scan) + 1
    hit = rf._find_wedged_transcript(now=now)
    assert hit and hit[0].name == "scan.jsonl"


def test_find_recovered_when_newer_healthy_session_exists(tmp_path, monkeypatch):
    # after recovery the abandoned transcript is still terminal-on-refusal, but a NEWER
    # healthy session is the real driver -> newest-wins rule reads the scan as recovered
    import os
    import time
    monkeypatch.setattr(rf, "_project_transcript_dir", lambda: tmp_path)
    monkeypatch.setattr(rf, "_recorded_smith_sid", lambda: None)
    old = tmp_path / "old.jsonl"
    _write(old, [_pentest_call(), _assistant(REFUSAL)])
    new = tmp_path / "new.jsonl"
    _write(new, [_pentest_call(), _assistant("resumed — testing the next cell")])
    os.utime(old, (time.time() - 100, time.time() - 100))
    os.utime(new, (time.time(), time.time()))
    assert rf._find_wedged_transcript(now=time.time() + 1) is None
    # ...but if the newest IS the wedged one, it still fires
    os.utime(new, (time.time() - 200, time.time() - 200))
    assert rf._find_wedged_transcript(now=time.time() + 1)[0].name == "old.jsonl"


def test_find_missing_project_dir_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "_project_transcript_dir", lambda: tmp_path / "does-not-exist")
    monkeypatch.setattr(rf, "_recorded_smith_sid", lambda: None)
    assert rf._find_wedged_transcript(now=1e12) is None


# ── _handle_refusal: notify + skip directive + mode-aware escalation ──────────

@pytest.fixture
def captured(monkeypatch):
    calls = {"directives": [], "notifies": [], "interventions": []}
    import core.steering as cs
    monkeypatch.setattr(cs.steering_queue, "add_directive",
                        lambda **kw: calls["directives"].append(kw) or "steer-1")
    monkeypatch.setattr(smith, "_watchdog_notify",
                        lambda title, body, code: calls["notifies"].append((title, body, code)))
    import core.session.intervention as iv
    monkeypatch.setattr(iv, "get_intervention", lambda: None)
    monkeypatch.setattr(iv, "trigger_intervention",
                        lambda **kw: calls["interventions"].append(kw) or {})
    monkeypatch.setattr(smith, "_refusal_consecutive", 0)
    return calls


def test_handle_refusal_notifies_and_queues_skip_directive(captured, monkeypatch):
    monkeypatch.setenv("SMITH_WATCHDOG_DISABLED", "1")  # interactive
    smith._refusal_consecutive = 1
    rf._handle_refusal({"skill": "reverse-shell"}, REFUSAL)
    assert len(captured["directives"]) == 1
    d = captured["directives"][0]
    assert d["code"] == "POLICY_REFUSAL_SKIP" and d["force"] is True
    assert "reword" in d["message"].lower()          # anti-evasion guarantee
    assert "reverse-shell" in d["message"]
    assert captured["notifies"] and captured["notifies"][0][2] == "POLICY_REFUSAL"
    assert "type 'continue'" in captured["notifies"][0][1]   # interactive guidance
    assert not captured["interventions"]             # 1 refusal — no HIR yet


def test_handle_refusal_headless_body_and_no_hir(captured, monkeypatch):
    monkeypatch.delenv("SMITH_WATCHDOG_DISABLED", raising=False)  # headless
    smith._refusal_consecutive = 5   # even past threshold, headless never fires the HIR
    rf._handle_refusal({"skill": "web-exploit"}, REFUSAL)
    body = captured["notifies"][0][1]
    assert "watchdog will respawn" in body
    assert not captured["interventions"]             # headless leans on watchdog caps


def test_handle_refusal_interactive_escalates_after_threshold(captured, monkeypatch):
    monkeypatch.setenv("SMITH_WATCHDOG_DISABLED", "1")  # interactive
    smith._refusal_consecutive = rf._REFUSAL_ESCALATE_AFTER
    rf._handle_refusal({"skill": "reverse-shell"}, REFUSAL)
    assert captured["interventions"] and captured["interventions"][0]["code"] == "HIR_POLICY_REFUSAL"


# ── tick: dedup by size + streak reset ────────────────────────────────────────

@pytest.mark.asyncio
async def test_tick_dedups_persistent_wedge_and_resets_on_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "_project_transcript_dir", lambda: tmp_path)
    monkeypatch.setattr(rf, "_recorded_smith_sid", lambda: "s")
    monkeypatch.setattr(smith, "_refusal_last_alert", {})
    monkeypatch.setattr(smith, "_refusal_consecutive", 0)
    monkeypatch.setattr(rf._api, "_read_json", lambda _p: {"status": "running", "skill": "x"})
    handled = []
    monkeypatch.setattr(rf, "_handle_refusal", lambda sd, txt: handled.append(txt))

    p = tmp_path / "s.jsonl"
    _write(p, [_assistant(REFUSAL)])
    await rf._refusal_monitor_tick(now=1e12)
    await rf._refusal_monitor_tick(now=1e12)   # unchanged transcript -> deduped
    assert len(handled) == 1                    # alerted exactly once for the same wedge

    _write(p, [_assistant("recovered — continuing"), _pentest_call()])  # scan resumed
    await rf._refusal_monitor_tick(now=1e12)
    assert len(handled) == 1                    # not re-alerted
    assert smith._refusal_consecutive == 0      # streak reset on recovery


@pytest.mark.asyncio
async def test_tick_idle_when_no_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(rf._api, "_read_json", lambda _p: {"status": "complete"})
    monkeypatch.setattr(smith, "_refusal_consecutive", 3)
    called = []
    monkeypatch.setattr(rf, "_find_wedged_transcript", lambda now: called.append(now))
    await rf._refusal_monitor_tick(now=1e12)
    assert not called                            # no transcript scan when idle
    assert smith._refusal_consecutive == 0       # streak cleared


# ── edge / fail-soft paths ────────────────────────────────────────────────────

def test_int_env_bad_value_falls_back(monkeypatch):
    monkeypatch.setenv("SMITH_REFUSAL_TEST_INT", "not-a-number")
    assert rf._int_env("SMITH_REFUSAL_TEST_INT", 45) == 45
    monkeypatch.setenv("SMITH_REFUSAL_TEST_INT", "12")
    assert rf._int_env("SMITH_REFUSAL_TEST_INT", 45) == 12


def test_project_transcript_dir_shape():
    d = rf._project_transcript_dir()
    assert ".claude" in str(d) and "projects" in str(d)


def test_read_tail_events_edge_cases(tmp_path):
    assert rf._read_tail_events(tmp_path / "missing.jsonl") == []          # OSError -> []
    p = tmp_path / "mixed.jsonl"
    p.write_text("\n{bad json\n" + json.dumps(_assistant("ok")) + "\n")    # blank + bad + good
    assert len(rf._read_tail_events(p)) == 1                               # only the good line
    big = tmp_path / "big.jsonl"
    _write(big, [_assistant(f"line {i}") for i in range(50)])              # many short lines
    tail = rf._read_tail_events(big, max_bytes=200)                        # seek-to-tail path
    assert tail and tail[-1]["message"]["content"][0]["text"] == "line 49"  # got the true tail


def test_terminal_assistant_text_no_assistant_returns_empty():
    assert rf._terminal_assistant_text([_user("hi")]) == ""
    assert rf._terminal_assistant_text([]) == ""


def test_tail_has_pentest_tooluse_ignores_nonlist_content():
    assert not rf._tail_has_pentest_tooluse([_assistant_str("plain string content")])


def test_evaluate_empty_transcript_returns_none(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("")
    assert rf._evaluate_transcript(p, require_scan_relevance=False) is None


def test_recorded_smith_sid_returns_and_failsoft(monkeypatch):
    v = rf._recorded_smith_sid()
    assert v is None or isinstance(v, str)
    import core.session as cs
    monkeypatch.setattr(cs, "get_smith_session_id", lambda: (_ for _ in ()).throw(RuntimeError()))
    assert rf._recorded_smith_sid() is None


def test_find_wedged_empty_dir_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "_project_transcript_dir", lambda: tmp_path)
    monkeypatch.setattr(rf, "_recorded_smith_sid", lambda: None)
    (tmp_path / "notes.txt").write_text("x")   # dir exists but no scan transcripts
    assert rf._find_wedged_transcript(now=1e12) is None


def test_newest_scan_transcript_skips_out_of_window(tmp_path):
    import os
    import time
    p = tmp_path / "old.jsonl"
    _write(p, [_pentest_call(), _assistant("x")])
    os.utime(p, (time.time() - 99999, time.time() - 99999))
    assert rf._newest_scan_transcript(tmp_path, now=time.time()) is None


def test_active_skill_variants():
    assert rf._active_skill({"skill": "web-exploit"}) == "web-exploit"
    assert rf._active_skill({"skill": "unknown", "skill_history": [{"skill": "osint"}]}) == "osint"
    assert rf._active_skill({}) == ""
    assert rf._active_skill({"skill": "unknown"}) == ""


def test_enqueue_skip_directive_swallows_errors(monkeypatch):
    import core.steering as cs
    monkeypatch.setattr(cs.steering_queue, "add_directive",
                        lambda **k: (_ for _ in ()).throw(RuntimeError("boom")))
    rf._enqueue_skip_directive("s")   # must not raise


def test_notify_refusal_headless_branch(monkeypatch):
    captured = []
    monkeypatch.setattr(smith, "_watchdog_notify",
                        lambda title, body, code: captured.append((body, code)))
    rf._notify_refusal("", interactive=False)      # no-skill + headless branch
    assert captured and captured[0][1] == "POLICY_REFUSAL" and "watchdog will respawn" in captured[0][0]


def test_escalate_hir_skips_when_already_paused(monkeypatch):
    import core.session.intervention as iv
    called = []
    monkeypatch.setattr(iv, "get_intervention", lambda: {"code": "X"})
    monkeypatch.setattr(iv, "trigger_intervention", lambda **k: called.append(k))
    rf._escalate_refusal_hir("s")
    assert not called                              # already paused -> did not stack


def test_escalate_hir_swallows_errors(monkeypatch):
    import core.session.intervention as iv
    monkeypatch.setattr(iv, "get_intervention", lambda: None)
    monkeypatch.setattr(iv, "trigger_intervention",
                        lambda **k: (_ for _ in ()).throw(RuntimeError("boom")))
    rf._escalate_refusal_hir("s")                  # must not raise


@pytest.mark.asyncio
async def test_loop_ticks_swallows_errors_and_reraises_cancel(monkeypatch):
    monkeypatch.setattr(rf, "_REFUSAL_POLL_SECONDS", 0)
    seq = [RuntimeError("boom"), asyncio.CancelledError()]
    calls = []

    async def fake_tick(now):
        calls.append(now)
        raise seq.pop(0)

    monkeypatch.setattr(rf, "_refusal_monitor_tick", fake_tick)
    with pytest.raises(asyncio.CancelledError):
        await rf._refusal_monitor_loop()
    assert len(calls) == 2   # 1st (RuntimeError) swallowed, 2nd (CancelledError) re-raised
