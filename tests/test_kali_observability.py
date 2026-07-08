"""
Kali timeout-as-signal (Layer 3) + activity-feed observability (command/outcome
surfaced in the quick_log entry instead of a bare 'kali').
"""
import mcp_server.kali_tools as kt
from mcp_server.scan_engine.envelope.quick_log import (
    _build_quick_log_entry, _enrich_kali_entry, _redact_cmd,
)


class _R:
    def __init__(self, evidence=None):
        self.evidence = evidence or {}


# ── Layer 3: timeout-as-signal ───────────────────────────────────────────────

class TestKaliTimeoutDetect:
    def test_curl_operation_timeout(self):
        assert kt._kali_timed_out("curl: (28) Operation timed out after 30001 ms")

    def test_partial_timeout_marker(self):
        assert kt._kali_timed_out("[partial — command timed out]\n<some output>")

    def test_connection_timed_out(self):
        assert kt._kali_timed_out("Connection timed out")

    def test_normal_output_is_not_a_timeout(self):
        assert not kt._kali_timed_out("HTTP/1.1 200 OK\n412 bytes")

    def test_empty_output(self):
        assert not kt._kali_timed_out("")


# ── Observability: command preview + redaction ───────────────────────────────

class TestRedactCmd:
    def test_redacts_bearer_token(self):
        out = _redact_cmd("curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1Qiabcdefghijklmnop' http://t/x")
        assert "eyJ0eXAiOiJKV1Q" not in out and ("<redacted>" in out or "<jwt>" in out)

    def test_collapses_whitespace_and_truncates(self):
        out = _redact_cmd("curl   \n  http://t/x " + "A" * 400, limit=120)
        assert "\n" not in out and len(out) <= 120 and out.endswith("…")

    def test_short_command_untouched(self):
        assert _redact_cmd("curl http://t/x") == "curl http://t/x"


class TestEnrichKaliEntry:
    def test_kali_entry_gets_command_timeout_artifact(self):
        e = {"type": "TOOL", "name": "kali", "target": ""}
        _enrich_kali_entry(e, "kali", _R({"artifact_id": "kali_123"}),
                           {"command": "curl http://t/x", "timed_out": True})
        assert e["command"] == "curl http://t/x"
        assert e["timed_out"] is True
        assert e["artifact_id"] == "kali_123"

    def test_sqlmap_variant_also_enriched(self):
        e = {"type": "TOOL", "name": "kali_sqlmap"}
        _enrich_kali_entry(e, "kali_sqlmap", None, {"command": "sqlmap -u http://t/x?id=1"})
        assert e["command"].startswith("sqlmap")

    def test_non_kali_tool_untouched(self):
        e = {"type": "TOOL", "name": "http_request"}
        _enrich_kali_entry(e, "http_request", None, {"command": "should be ignored"})
        assert "command" not in e

    def test_no_ctx_is_noop(self):
        e = {"type": "TOOL", "name": "kali"}
        _enrich_kali_entry(e, "kali", None, None)
        assert "command" not in e

    def test_build_entry_end_to_end(self):
        entry = _build_quick_log_entry(
            "kali", "", "ran a probe", None, {"command": "curl -s http://t/x", "timed_out": False})
        assert entry["type"] == "TOOL" and entry["name"] == "kali"
        assert entry["command"] == "curl -s http://t/x"
        assert "timed_out" not in entry  # falsy → omitted
