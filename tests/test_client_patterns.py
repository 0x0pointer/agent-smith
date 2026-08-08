"""Track 2: shared client-recognition + gate-keyword modules.

Guards the single-source-of-truth contract: process detection and the Smith
liveness check both resolve through core.client_patterns, and report_tools'
gate-firing keywords come from core.gate_keywords.
"""
import core.client_patterns as cp
from core.client_patterns import classify_client, looks_like_smith


class TestClassifyClient:
    def test_claude_needs_flag(self):
        assert classify_client("claude --dangerously-skip-permissions") == "claude"
        assert classify_client("claude -p 'do a scan'") == "claude"
        # bare TUI is intentionally not classified as a driving client
        assert classify_client("claude") is None

    def test_opencode_shapes(self):
        assert classify_client("node /Users/x/.opencode/bin/opencode run") == "opencode"
        assert classify_client("node /opt/opencode/dist/index.js") == "opencode"
        assert classify_client("opencode run --model qwen") == "opencode"

    def test_codex(self):
        assert classify_client("codex run") == "codex"
        assert classify_client("codex mcp") == "codex"

    def test_unrelated_is_none(self):
        assert classify_client("/usr/bin/python -m vllm.serve") is None
        assert classify_client("") is None

    def test_case_insensitive(self):
        assert classify_client("CODEX RUN") == "codex"


class TestLooksLikeSmith:
    def test_strict_needles(self):
        assert looks_like_smith("claude --dangerously-skip-permissions foo") is True
        assert looks_like_smith("node /Users/x/.opencode/bin/opencode run") is True
        assert looks_like_smith("codex mcp serve") is True

    def test_stricter_than_classifier(self):
        # bare opencode/claude are NOT liveness needles (avoid false-positives)
        assert looks_like_smith("opencode") is False
        assert looks_like_smith("claude") is False

    def test_case_insensitive(self):
        assert looks_like_smith("CLAUDE --DANGEROUSLY-SKIP-PERMISSIONS") is True


def test_process_detect_uses_shared_classifier():
    import core.session.process_detect as pd
    assert pd.classify_client is classify_client


def test_smith_uses_shared_liveness():
    import core.api_server.smith as smith
    assert smith.looks_like_smith is looks_like_smith


def test_report_tools_uses_shared_gate_keywords():
    import core.gate_keywords as gk
    import mcp_server.report_tools as rt
    # aliased to historical _-prefixed names, but must be the shared objects
    assert rt._RCE_KEYWORDS is gk.RCE_KEYWORDS
    assert rt._AUTH_WEAKNESS_KEYWORDS is gk.AUTH_WEAKNESS_KEYWORDS
    assert rt._GATE_BENIGN_MARKERS is gk.GATE_BENIGN_MARKERS


def test_needles_tuple_is_stable_shape():
    assert isinstance(cp.SMITH_PROC_NEEDLES, tuple)
    assert all(isinstance(n, str) for n in cp.SMITH_PROC_NEEDLES)
