"""Tests for the stuck-triggered, technique-focused retrieval escalation.

Progress-gated recovery: when a deep-pivot scan stalls on an unsolved web target
(no new finding for a while), force a RETRIEVAL escalation that HARNESS-DELIVERS the
technique (reads the local ref and injects a bounded slice inline) rather than only
telling the model to go read/research — because the benchmark model never opens a ref
or webfetches on its own. Must NOT fire for a non-deep-pivot scan, before recon, while
findings are still flowing, or while the web-exploit chain is actually producing.

Two guards were loosened after the first benchmark pass fired the check 0 times:
  Fix 1  web-exploit recency no longer muzzles it outright — only when a finding has
         landed SINCE web-exploit ran (chain is helping). 022 stalled behind this.
  (023)  an UNRELATED pending directive (MISSING_WEB_EXPLOIT) no longer suppresses it;
         only a still-outstanding STUCK directive does (no stacking STUCK on STUCK).

Fixtures use the PRODUCTION schema — findings/skill_history carry their time under
"timestamp" (core.findings.append / gates.set_skill) and the session start stamp is
"started" (lifecycle). The check originally read "ts"/"started_at", phantom keys that
made every time-based guard compare empty strings (the real reason it never fired).
"""
from datetime import datetime, timedelta, timezone

import pytest

import core.qa_agent.checks_skills as cs


def _iso(delta_min=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=delta_min)).isoformat()


DEEP = {"depth": "danger", "skill_history": []}
COV = {"endpoints": [{"path": "/x"}], "matrix": [{"injection_type": "ssti", "status": "pending"}]}


def _finding(delta_min):
    return {"timestamp": _iso(delta_min)}


def _sess(delta_min=None, skill_delta_min=None):
    """Session dict in the production schema (started / skill_history timestamps)."""
    s = {"depth": "danger", "skill_history": []}
    if delta_min is not None:
        s["started"] = _iso(delta_min)
    if skill_delta_min is not None:
        s["skill_history"] = [{"skill": "web-exploit", "timestamp": _iso(skill_delta_min)}]
    return s


class _Dir:
    def __init__(self, trigger):
        self.trigger = trigger


@pytest.fixture
def directives(monkeypatch):
    """Capture injected directives + force no-pending so the check proceeds."""
    calls = []
    monkeypatch.setattr(cs._qa, "_has_pending_directives", lambda: False)
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "add_directive", lambda **k: calls.append(k))
    monkeypatch.setattr(st.steering_queue, "get_active", lambda: [])
    return calls


@pytest.fixture
def refs_dir(tmp_path, monkeypatch):
    """A deterministic local ssti ref so Fix 2's inline injection is machine-independent."""
    d = tmp_path / "refs"
    d.mkdir()
    (d / "ssti.md").write_text(
        "### Ref: Server-Side Template Injection (SSTI)\n"
        "Ladder rung 1 — direct-globals gadgets (Flask/Jinja2).\n"
        "Ladder rung 4 — filter bypass via |attr() when dots/underscores are blocked.\n"
        "Blind SSTI via include sink: upload a Jinja-laden file under static/images/.\n"
    )
    monkeypatch.setattr(cs, "_REFS_DIRS", [str(d)])
    return d


def test_not_deep_pivot_no_fire():
    assert cs._check_stuck_retrieval_escalation([], {}, {"depth": "standard"}, COV) == []


def test_before_recon_no_fire():
    assert cs._check_stuck_retrieval_escalation([], {}, DEEP, {"endpoints": []}) == []


def test_findings_still_flowing_not_stuck(directives):
    fd = {"findings": [_finding(0)]}  # a finding just landed (production "timestamp")
    entries = [{"type": "TOOL", "name": "http_request", "ts": _iso(-30)}]  # old first entry
    assert cs._check_stuck_retrieval_escalation(entries, fd, DEEP, COV) == []
    assert directives == []


def test_stalled_fires_with_technique_framing(directives, refs_dir):
    fd = {"findings": [_finding(-10)]}  # no new finding for ~10 min
    alerts = cs._check_stuck_retrieval_escalation([], fd, DEEP, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"
    assert directives and directives[0]["trigger"] == "STUCK_RETRIEVAL_ESCALATION"
    msg = directives[0]["message"]
    assert "refs/ssti.md" in msg                    # the right technique ref, attributed
    assert "hacktricks" in msg.lower()              # + a methodology source to research
    assert "ADAPT" in msg and "payload list" in msg.lower()  # technique, not payloads


def test_fix2_harness_injects_technique_text_inline(directives, refs_dir):
    """Fix 2: the actual ref CONTENT is delivered in the directive, not just a path."""
    fd = {"findings": [_finding(-10)]}
    cs._check_stuck_retrieval_escalation([], fd, DEEP, COV)
    msg = directives[0]["message"]
    assert "HARNESS-PROVIDED TECHNIQUE REFERENCE" in msg
    assert "Ladder rung 1" in msg          # real ref body, inline
    assert "|attr()" in msg                # the bypass the model kept fumbling toward


def test_fix1_web_exploit_ran_with_finding_since_suppressed(directives, refs_dir):
    """web-exploit ran 2min ago AND a finding landed after it → chain producing → hold off."""
    sess = _sess(skill_delta_min=-2)
    fd = {"findings": [_finding(-1)]}  # finding AFTER web-exploit
    assert cs._check_stuck_retrieval_escalation([], fd, sess, COV) == []


def test_fix1_web_exploit_ran_but_no_finding_since_fires(directives, refs_dir):
    """022 case: web-exploit ran recently but produced nothing since → chain didn't help → FIRE."""
    sess = _sess(skill_delta_min=-2)
    fd = {"findings": [_finding(-10)]}  # last finding predates web-exploit
    alerts = cs._check_stuck_retrieval_escalation([], fd, sess, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"


def test_023_unrelated_pending_directive_does_not_suppress(directives, refs_dir, monkeypatch):
    """023 case: a pending MISSING_WEB_EXPLOIT must not muzzle retrieval escalation."""
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "get_active", lambda: [_Dir("MISSING_WEB_EXPLOIT")])
    fd = {"findings": []}  # zero findings — the most-stuck state
    alerts = cs._check_stuck_retrieval_escalation([], fd, _sess(-30), COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"


def test_stuck_directive_already_pending_suppresses(directives, monkeypatch):
    """Don't stack STUCK on STUCK: an outstanding STUCK directive does suppress."""
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "get_active", lambda: [_Dir("STUCK_RETRIEVAL_ESCALATION")])
    fd = {"findings": [_finding(-10)]}
    assert cs._check_stuck_retrieval_escalation([], fd, DEEP, COV) == []


def test_zero_findings_past_recon_is_stuck(directives, refs_dir):
    """A 0-finding run (the most-stuck possible) must trip once past recon."""
    fd = {"findings": []}
    alerts = cs._check_stuck_retrieval_escalation([], fd, _sess(-20), COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"


def test_stuck_directive_lands_alongside_pending_chain_directive(refs_dir, tmp_path, monkeypatch):
    """Regression (force=True): the STUCK directive shares code+skill (CHAIN_REQUIRED +
    web-exploit) with the MISSING_* chain directives. The queue's non-force dedup on
    code+skill used to silently swallow it — alert fired, brief never delivered (the
    exact trap COMPOSE_REQUIRED was split out for). With a REAL queue file: a pending
    MISSING_WEB_EXPLOIT must not block the STUCK directive from landing."""
    import core.steering as st
    monkeypatch.setattr(st, "_STEERING_FILE", tmp_path / "steering_queue.json")
    st.steering_queue.add_directive(
        code=st.CHAIN_REQUIRED, skill="web-exploit",
        message="Spider has crawled the application but /web-exploit was never started.",
        trigger="MISSING_WEB_EXPLOIT")
    assert len(st.steering_queue.get_active()) == 1
    fd = {"findings": []}
    alerts = cs._check_stuck_retrieval_escalation([], fd, _sess(-20), COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"
    active = st.steering_queue.get_active()
    assert len(active) == 2, "STUCK directive was swallowed by the chain directive's dedup slot"
    assert any(d.trigger == "STUCK_RETRIEVAL_ESCALATION" for d in active)
    assert any(d.trigger == "MISSING_WEB_EXPLOIT" for d in active)  # chain one untouched


def test_sources_are_methodology_urls():
    for c in ("ssti", "sqli", "cmdi", "xxe", "ssrf", "traversal", "deserialization"):
        ref, url = cs._RETRIEVAL_SOURCES[c]
        assert ref.endswith(".md") and url.startswith("https://")


def test_load_technique_brief_failsoft(monkeypatch, tmp_path):
    """No readable ref AND no KB content → empty string, never an exception.
    (The KB hook is patched out — on a machine with a built kb/index.db the real
    hook returns SKILL.md content, which is the designed fallback, not a miss.)"""
    monkeypatch.setattr(cs, "_REFS_DIRS", [str(tmp_path / "nope")])
    monkeypatch.setattr(cs, "_kb_recall_brief", lambda area, classes: "")
    assert cs._load_technique_brief(cs._WEB_AREA, ["ssti", "sqli"]) == ""


def test_load_technique_brief_kb_fallback(monkeypatch, tmp_path):
    """No local ref → the KB recall hook supplies the brief (non-web areas rely on it)."""
    monkeypatch.setattr(cs, "_REFS_DIRS", [str(tmp_path / "nope")])
    monkeypatch.setattr(cs, "_kb_recall_brief",
                        lambda area, classes: "TECHNIQUE kb-doc (kb:x):\nKB BODY")
    out = cs._load_technique_brief(cs._WEB_AREA, ["ssti"])
    assert "KB BODY" in out and "kb-doc" in out


# ── Generic across attack areas (not just web) ────────────────────────────────

def _ad_entries():
    return [
        {"type": "TOOL", "name": "kali", "command": "netexec smb 10.0.0.5 -u u -p p --shares"},
        {"type": "TOOL", "name": "kali", "command": "GetUserSPNs.py -request -dc-ip 10.0.0.1"},
    ]


def test_detect_ad_area_from_tooling():
    a = cs._detect_stuck_area(_ad_entries(), None)
    assert a is not None and a["area"] == "ad" and a["skill"] == "ad-assessment"


def test_detect_postex_area_from_tooling():
    a = cs._detect_stuck_area([{"type": "TOOL", "name": "kali", "command": "./linpeas.sh"}], None)
    assert a["area"] == "post-ex" and a["skill"] == "post-exploit"


def test_detect_web_fallback():
    a = cs._detect_stuck_area([{"type": "TOOL", "name": "http_request", "command": ""}], None)
    assert a["area"] == "web" and a["skill"] == "web-exploit"


def test_ad_stall_fires_and_points_at_ad_skill(directives):
    """A stalled AD phase fires the SAME escalation, pointed at the AD skill (generic)."""
    fd = {"findings": []}
    alerts = cs._check_stuck_retrieval_escalation(_ad_entries(), fd, _sess(-20), None)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"
    assert "/ad-assessment" in alerts[0]["message"]
    msg = directives[0]["message"]
    assert "ad-assessment" in msg                      # points at the AD skill
    assert "active-directory" in msg.lower()           # the AD methodology URL
    assert directives[0]["skill"] == "ad-assessment"   # directive is skill-scoped


def test_detect_unknown_area_is_silent():
    """A stall with NO distinctive tooling and NO coverage endpoints must classify as
    None (escalation stays silent) — not web. Otherwise a non-web stall (AD/post-ex/
    cloud on a target whose endpoints were never registered) gets a WEB brief."""
    entries = [{"type": "TOOL", "name": "kali", "command": "nmap -sV -p 88,389 10.0.0.5"}]
    assert cs._detect_stuck_area(entries, None) is None
    assert cs._detect_stuck_area(entries, {"endpoints": []}) is None


def test_detect_web_via_registered_endpoints():
    """No web tooling in the blob, but coverage holds web endpoints → web."""
    entries = [{"type": "TOOL", "name": "kali", "command": "gobuster dir -u x"}]
    a = cs._detect_stuck_area(entries, COV)
    assert a is not None and a["area"] == "web"


# ── _slice_ref: the delivered slice carries the payload fences, not just the head ──

_SLICE_REF = (
    "### Ref: Example technique\n\nRoot pattern prose explaining the bug. "
    + "Recognition guidance " * 40 + "\n\n"
    "```jinja2\n{{cycler.__init__.__globals__.os.popen('id').read()}}\n```\n\n"
    "Middle prose outside fences is never delivered.\n\n"
    "```python\n" + "pad" * 400 + " second-gadget-end\n```\n"
)


def test_slice_ref_prefers_fences_over_head_prose():
    out = cs._slice_ref(_SLICE_REF, budget=800)
    assert "popen('id')" in out            # the payload fence made the cut
    assert "Root pattern prose" in out     # intro context kept (bounded)
    assert "second-gadget-end" not in out  # oversized later fence cut before its payload
    assert "Middle prose outside fences" not in out  # prose BETWEEN fences is dropped


def test_slice_ref_short_ref_returned_whole():
    short = "### Ref: T\none-liner"
    assert cs._slice_ref(short, budget=1400) == short


def test_slice_ref_flat_prose_falls_back_to_head_cut():
    flat = "recognition prose " * 500       # no fences at all
    out = cs._slice_ref(flat, budget=200)
    assert out == flat[:200].rstrip()
