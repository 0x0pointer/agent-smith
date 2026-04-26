"""
Tests for the scan_engine module: envelope, artifacts, budget, summarizers.
"""
import json
import os
import pytest

from mcp_server.scan_engine.envelope import wrap, Envelope
from mcp_server.scan_engine.artifacts import store_artifact, retrieve_artifact, _ARTIFACTS_DIR
from mcp_server.scan_engine.budget import enforce_budget, ToolBudget, TOOL_BUDGETS
from mcp_server.scan_engine.summarizers import summarize, SummaryResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolate_artifacts(tmp_path, monkeypatch):
    """Redirect artifact storage to temp directory."""
    import mcp_server.scan_engine.artifacts as art_mod
    monkeypatch.setattr(art_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")


# ---------------------------------------------------------------------------
# Artifact tests
# ---------------------------------------------------------------------------

class TestArtifacts:
    def test_store_and_retrieve_summary(self):
        aid = store_artifact("httpx", "line1\nline2\nline3\nline4\nline5")
        assert "httpx" in aid
        result = json.loads(retrieve_artifact(aid, mode="summary", max_chars=10))
        assert result["artifact_id"] == aid
        assert result["chars_returned"] == 10
        assert result["truncated"] is True
        assert result["content"] == "line1\nline"

    def test_retrieve_head(self):
        aid = store_artifact("test", "ABCDEFGHIJ" * 100)
        result = json.loads(retrieve_artifact(aid, mode="head", max_chars=20))
        assert result["content"] == "ABCDEFGHIJ" * 2

    def test_retrieve_tail(self):
        aid = store_artifact("test", "A" * 50 + "TAIL_MARKER")
        result = json.loads(retrieve_artifact(aid, mode="tail", max_chars=20))
        assert "TAIL_MARKER" in result["content"]

    def test_retrieve_grep(self):
        raw = "info: nothing here\nCRITICAL: found vuln\ninfo: boring\nCRITICAL: another"
        aid = store_artifact("test", raw)
        result = json.loads(retrieve_artifact(aid, mode="grep", pattern="CRITICAL"))
        assert result["content"].count("CRITICAL") == 2
        assert "boring" not in result["content"]

    def test_retrieve_grep_no_pattern_errors(self):
        aid = store_artifact("test", "data")
        result = json.loads(retrieve_artifact(aid, mode="grep", pattern=""))
        assert "error" in result

    def test_retrieve_nonexistent_artifact(self):
        result = json.loads(retrieve_artifact("nonexistent_abc123"))
        assert "error" in result

    def test_retrieve_full(self):
        raw = "X" * 100
        aid = store_artifact("test", raw)
        result = json.loads(retrieve_artifact(aid, mode="full", max_chars=50))
        assert result["chars_returned"] == 50
        assert result["truncated"] is True

    def test_retrieve_unknown_mode(self):
        aid = store_artifact("test", "data")
        result = json.loads(retrieve_artifact(aid, mode="unknown_mode"))
        assert "error" in result


# ---------------------------------------------------------------------------
# Budget tests
# ---------------------------------------------------------------------------

class TestBudget:
    def test_within_budget_unchanged(self):
        env = Envelope(
            summary="Short summary",
            facts=["fact1", "fact2"],
            evidence={"key": "val"},
        )
        budget = ToolBudget(max_chars=5000, max_facts=10, max_evidence_chars=2000)
        result = enforce_budget(env, budget, "art_123")
        assert len(result.facts) == 2
        assert result.warnings == []

    def test_facts_truncated_when_over_max(self):
        env = Envelope(
            summary="Summary",
            facts=[f"fact_{i}" for i in range(30)],
            evidence={},
        )
        budget = ToolBudget(max_chars=10000, max_facts=5, max_evidence_chars=2000)
        result = enforce_budget(env, budget, "art_123")
        assert len(result.facts) == 5
        assert any("Truncated 25 fact(s)" in w for w in result.warnings)

    def test_evidence_truncated_when_over_max(self):
        env = Envelope(
            summary="Summary",
            facts=[],
            evidence={f"key_{i}": "x" * 200 for i in range(20)},
        )
        budget = ToolBudget(max_chars=10000, max_facts=50, max_evidence_chars=500)
        result = enforce_budget(env, budget, "art_123")
        assert len(json.dumps(result.evidence)) <= 600  # some slack for structure
        assert any("Evidence truncated" in w for w in result.warnings)

    def test_emergency_truncation_on_total_overage(self):
        env = Envelope(
            summary="A" * 200,
            facts=[f"fact that is somewhat long number {i}" for i in range(100)],
            evidence={},
        )
        budget = ToolBudget(max_chars=500, max_facts=100, max_evidence_chars=200)
        result = enforce_budget(env, budget, "art_123")
        serialized = result.to_json()
        assert len(serialized) <= 600  # allow some slack for JSON structure

    def test_all_tools_have_budgets(self):
        """Every tool we wire must have an explicit budget."""
        for tool in ("httpx", "http_request", "kali_sqlmap", "kali"):
            assert tool in TOOL_BUDGETS, f"Missing budget for {tool}"
        assert "_default" in TOOL_BUDGETS


# ---------------------------------------------------------------------------
# Summarizer tests
# ---------------------------------------------------------------------------

class TestSummarizers:
    def test_httpx_json_output(self):
        raw = json.dumps({
            "status_code": 200,
            "url": "http://target.com",
            "tech": ["Flask", "jQuery"],
            "webserver": "nginx",
            "title": "My App",
            "content_type": "text/html",
        })
        result = summarize("httpx", raw, {"url": "http://target.com"})
        assert "200" in result.summary
        assert "nginx" in result.summary
        assert any("Flask" in f for f in result.facts)
        assert result.evidence["status"] == 200

    def test_httpx_text_output(self):
        raw = "http://target.com [200] [nginx] [text/html] [My App]"
        result = summarize("httpx", raw, {"url": "http://target.com"})
        assert "200" in result.summary
        assert result.evidence["status"] == 200

    def test_httpx_empty_output(self):
        result = summarize("httpx", "", {"url": "http://target.com"})
        assert "could not parse" in result.summary.lower() or result.summary

    def test_http_request_success(self):
        raw = json.dumps({
            "status": 200,
            "headers": {
                "Content-Type": "text/html",
                "Server": "Apache",
            },
            "body": "<html>Hello</html>",
        })
        result = summarize("http_request", raw, {"url": "http://target.com/test", "method": "GET"})
        assert "200" in result.summary
        assert any("Apache" in f for f in result.facts)

    def test_http_request_error(self):
        raw = json.dumps({"error": "Connection refused", "hint": "Check target"})
        result = summarize("http_request", raw, {"url": "http://target.com", "method": "GET"})
        assert "ERROR" in result.summary
        assert len(result.anomalies) > 0

    def test_http_request_werkzeug_detection(self):
        raw = json.dumps({
            "status": 500,
            "headers": {},
            "body": "<html>Werkzeug Debugger is active</html>",
        })
        result = summarize("http_request", raw, {"url": "http://target.com", "method": "GET"})
        assert any("werkzeug" in a.lower() for a in result.anomalies)

    def test_sqlmap_vulnerable(self):
        raw = """
[INFO] testing 'AND boolean-based blind'
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: q=test' AND 5234=5234 AND 'abc'='abc

[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
[*] information_schema
[*] app_db
[*] mysql
        """
        result = summarize("kali_sqlmap", raw, {})
        assert "CONFIRMED" in result.summary
        assert result.evidence["vulnerable"] is True
        assert "q (GET)" in result.evidence["injectable_params"]
        assert "MySQL" in result.evidence["dbms"]

    def test_sqlmap_not_injectable(self):
        raw = """
[WARNING] all tested parameters do not appear to be injectable
[INFO] testing concluded
        """
        result = summarize("kali_sqlmap", raw, {})
        assert "no injection" in result.summary.lower()

    def test_generic_fallback(self):
        result = summarize("unknown_tool", "line1\nline2\nline3", {"_tool": "unknown_tool"})
        assert "3 line(s)" in result.summary

    def test_naabu_json_output(self):
        raw = (
            '{"host":"example.com","ip":"1.2.3.4","port":80,"protocol":"tcp"}\n'
            '{"host":"example.com","ip":"1.2.3.4","port":443,"protocol":"tcp"}\n'
            '{"host":"example.com","ip":"1.2.3.4","port":8080,"protocol":"tcp"}\n'
        )
        result = summarize("naabu", raw, {})
        assert "3" in result.summary
        assert 80 in result.evidence["ports"]
        assert 443 in result.evidence["ports"]

    def test_subfinder_output(self):
        raw = "api.example.com\nwww.example.com\nstaging.example.com\n"
        result = summarize("subfinder", raw, {})
        assert "3 subdomain" in result.summary
        assert "api.example.com" in result.facts

    def test_nuclei_json_output(self):
        raw = json.dumps({
            "template-id": "cve-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical"},
            "matched-at": "http://target.com/api",
        })
        result = summarize("nuclei", raw, {})
        assert "1 issue" in result.summary
        assert "critical" in result.summary

    def test_nuclei_no_findings(self):
        result = summarize("nuclei", "", {})
        assert "no vulnerabilities" in result.summary.lower()

    def test_spider_output(self):
        raw = "http://t.com/\nhttp://t.com/login\nhttp://t.com/api/users\n"
        result = summarize("spider", raw, {})
        assert "3 URL" in result.summary
        assert "3 unique endpoint" in result.summary
        # Concrete registration commands in required
        assert any("report(action='coverage'" in r for r in result.required)
        assert any("/login" in r for r in result.required)

    def test_ffuf_json_output(self):
        raw = json.dumps({"results": [
            {"url": "http://t.com/admin", "status": 200, "length": 1234},
            {"url": "http://t.com/.env", "status": 200, "length": 56},
        ]})
        result = summarize("ffuf", raw, {})
        assert "2 path" in result.summary


# ---------------------------------------------------------------------------
# Envelope integration tests
# ---------------------------------------------------------------------------

class TestEnvelope:
    def test_wrap_returns_valid_json(self):
        raw = json.dumps({
            "status_code": 200,
            "url": "http://target.com",
            "tech": ["Flask"],
            "webserver": "nginx",
        })
        result = wrap("httpx", raw, {"url": "http://target.com"})
        parsed = json.loads(result)
        assert "summary" in parsed
        assert "facts" in parsed
        assert "artifact" in parsed
        assert parsed["artifact"] is not None

    def test_wrap_artifact_is_retrievable(self):
        raw = "FULL RAW OUTPUT " * 100
        result = json.loads(wrap("http_request", json.dumps({
            "status": 200, "headers": {}, "body": raw,
        }), {"url": "http://t.com", "method": "GET"}))
        artifact_id = result["artifact"]
        retrieved = json.loads(retrieve_artifact(artifact_id, mode="full", max_chars=100))
        assert retrieved["total_chars"] > 100

    def test_wrap_respects_budget(self):
        raw = json.dumps({
            "status_code": 200,
            "url": "http://target.com",
            "tech": ["Flask"],
            "webserver": "nginx",
        })
        result = wrap("httpx", raw, {"url": "http://target.com"})
        budget = TOOL_BUDGETS["httpx"]
        assert len(result) <= budget.max_chars + 200  # allow slack for JSON formatting

    def test_envelope_shape_is_canonical(self):
        """Every envelope must have exactly these top-level keys."""
        raw = "some output"
        result = json.loads(wrap("httpx", raw, {"url": "http://t.com"}))
        expected_keys = {"summary", "facts", "anomalies", "evidence", "next",
                         "artifact", "session_state", "warnings"}
        assert set(result.keys()) == expected_keys

    def test_next_has_required_and_recommended(self):
        raw = json.dumps({"status_code": 200, "url": "http://t.com", "tech": []})
        result = json.loads(wrap("httpx", raw, {"url": "http://t.com"}))
        assert "required" in result["next"]
        assert "recommended" in result["next"]
