"""
Tests for the AI/LLM/MCP red-team additions:
  - core.taxonomy: LLM/MCP applicability, endpoint classification, gate types
  - core.coverage.add_endpoint: LLM endpoints fan out to LLM cells (+ endpoint-level)
  - scan_engine.summarizers: garak/promptfoo/pyrit/fuzzyai structured parsing
"""
import json
import pytest

import core.coverage
import core.taxonomy as tax
from core.coverage.classify import _applicable_types, classify_endpoint
from mcp_server.scan_engine.summarizers import summarize


# ---------------------------------------------------------------------------
# taxonomy
# ---------------------------------------------------------------------------

def test_llm_prompt_fans_out_to_llm_cells():
    cells = _applicable_types("llm_prompt", "")
    assert {"prompt_injection", "jailbreak", "system_prompt_leak",
            "excessive_agency", "model_extraction"}.issubset(set(cells))


def test_mcp_tool_arg_fans_out_to_mcp_cells():
    cells = _applicable_types("mcp_tool_arg", "")
    assert {"mcp_command_injection", "mcp_tool_poisoning",
            "mcp_token_exposure"}.issubset(set(cells))


@pytest.mark.parametrize("path", [
    "/v1/chat/completions", "/api/messages", "/mcp", "/sse",
    "/tools/call", "/api/generate", "/v1/embeddings",
])
def test_ai_endpoints_classify_as_ai_redteam(path):
    assert classify_endpoint(path) == "ai-redteam"


def test_generic_api_still_classifies_as_api_not_ai():
    assert classify_endpoint("/api/users") == "api"
    assert classify_endpoint("/api/v2/orders") == "api"


def test_llm_types_are_auth_gated_and_bypass_required():
    assert "jailbreak" in tax.AUTH_GATED_TYPES
    assert "prompt_injection" in tax.AUTH_GATED_TYPES
    assert "prompt_injection" in tax.BYPASS_REQUIRED_TYPES
    assert "jailbreak" in tax.BYPASS_REQUIRED_TYPES


def test_ai_redteam_trigger_gate_registered():
    import core.session as sess
    entry = sess._TRIGGER_MAP.get("ai-redteam")
    assert entry and entry["required_skills"] == ["ai-redteam"]


# ---------------------------------------------------------------------------
# coverage matrix — LLM endpoint registration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_llm_endpoint_generates_llm_and_endpoint_level_cells(coverage_file):
    await core.coverage.add_endpoint(
        path="/v1/chat/completions", method="POST",
        params=[{"name": "message", "type": "llm_prompt", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    inj = {c["injection_type"] for c in data["matrix"]}
    # per-param LLM cells
    assert "prompt_injection" in inj and "jailbreak" in inj
    # endpoint-level LLM cells (AI endpoints only)
    assert "rag_poisoning" in inj and "embedding_manipulation" in inj
    # cross-cutting endpoint cells still present
    assert "cors" in inj


@pytest.mark.asyncio
async def test_non_ai_endpoint_has_no_llm_endpoint_cells(coverage_file):
    await core.coverage.add_endpoint(
        path="/search", method="GET",
        params=[{"name": "q", "type": "query", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    inj = {c["injection_type"] for c in data["matrix"]}
    assert "rag_poisoning" not in inj
    assert "embedding_manipulation" not in inj


@pytest.mark.asyncio
async def test_mcp_tool_arg_endpoint_generates_mcp_cells(coverage_file):
    await core.coverage.add_endpoint(
        path="/mcp", method="POST",
        params=[{"name": "path", "type": "mcp_tool_arg", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    inj = {c["injection_type"] for c in data["matrix"]}
    assert "mcp_command_injection" in inj and "mcp_intent_subversion" in inj


# ---------------------------------------------------------------------------
# AI summarizers
# ---------------------------------------------------------------------------

def test_garak_summarizer_extracts_hits():
    raw = "progress\n=== GARAK REPORT JSONL ===\n" + "\n".join([
        '{"entry_type":"eval","probe":"dan.DanInTheWild","detector":"mitigation.MitigationBypass","passed":7,"total":10}',
        '{"entry_type":"eval","probe":"encoding.InjectBase64","detector":"encoding.DecodeMatch","passed":10,"total":10}',
    ])
    r = summarize("garak", raw, {"target": "x"})
    assert r.evidence["eval_entries"] == 2
    assert len(r.evidence["hits"]) == 1
    assert any("dan.DanInTheWild" in a for a in r.anomalies)


def test_promptfoo_summarizer_flags_failures():
    raw = '=== PROMPTFOO RESULTS JSON ===\n' + json.dumps({
        "results": {"stats": {"successes": 4, "failures": 1},
                    "results": [{"success": True},
                                {"success": False,
                                 "testCase": {"metadata": {"pluginId": "prompt-injection"}}}]}
    })
    r = summarize("promptfoo", raw, {"target": "x"})
    assert r.evidence["failed"] == 1
    assert any("prompt-injection" in a for a in r.anomalies)


def test_pyrit_summarizer_detects_success_and_degradation():
    raw = ("[*] PyRIT\n[!] No attacker-LLM key for provider 'openai'\n"
           "[*] Attack result: objective achieved\nscore: true")
    r = summarize("pyrit", raw, {"attack": "jailbreak"})
    assert r.evidence["objective_achieved"] is True
    assert r.evidence["degraded"] is True


def test_ai_summarizers_degrade_without_crashing():
    # No structured section present — must produce a useful summary, not raise.
    assert summarize("garak", "garbage", {}).summary
    assert summarize("promptfoo", "garbage", {}).summary
    assert summarize("fuzzyai", "ran some stuff", {}).summary


# ---------------------------------------------------------------------------
# deepen / completion gate (P4)
# ---------------------------------------------------------------------------

def test_empty_matrix_with_ai_tool_blocks_completion(monkeypatch):
    """An AI-only scan with an empty matrix must hit the AI empty-matrix blocker
    (previously: no blocker fired because only web tools were checked)."""
    import mcp_server.session_tools as st
    monkeypatch.setattr(st, "_session_tools_called", {"garak"})
    blockers = st._coverage_blockers({"meta": {"total_cells": 0}}, ctf_mode=False)
    assert any("EMPTY AI COVERAGE MATRIX" in b for b in blockers)


def test_empty_matrix_no_ai_no_web_no_blocker(monkeypatch):
    import mcp_server.session_tools as st
    monkeypatch.setattr(st, "_session_tools_called", set())
    blockers = st._coverage_blockers({"meta": {"total_cells": 0}}, ctf_mode=False)
    assert blockers == []


def test_deepen_brief_detects_ai_surface_via_tool(monkeypatch, tmp_path):
    """has_ai_ep must fire from an AI tool having run, even with no AI-looking
    endpoint path registered (the spider-only substring check missed this)."""
    import core.session as scan_session
    import core.findings as findings_store_mod
    import core.coverage as cov_mod
    import mcp_server.session_tools as st
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
    monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
    monkeypatch.setattr(cov_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir()
    monkeypatch.setattr(st, "_session_tools_called", {"pyrit"})
    scan_session.start("https://example.com", depth="thorough")
    # No AI-looking endpoint, no ai-redteam skill — only the tool signal.
    result = st._deepen_brief(1)
    assert "ai-redteam" in result


@pytest.mark.asyncio
async def test_garak_handler_builds_rest_config_invocation(monkeypatch):
    """Lock the garak invocation verified against the installed garak 0.15.0:
    config-driven REST generator via `--model_type rest -G`, not the old
    no-op `--generator_option api_base=`."""
    import tools.kali_runner as kr
    import mcp_server.scan_engine as se
    cap = {}
    async def fake_exec(cmd, timeout=900):
        cap["cmd"] = cmd
        return "raw"
    monkeypatch.setattr(kr, "exec_command", fake_exec)
    monkeypatch.setattr(se, "wrap", lambda tool, raw, ctx=None: f"WRAP:{tool}")
    from mcp_server.scan_tools import _handle_garak
    out = await _handle_garak("http://t/chat", "", {"probes": "dan,encoding"})
    assert out == "WRAP:garak"
    assert "--model_type rest -G" in cap["cmd"]
    assert "garak_rest.json" in cap["cmd"]
    assert "api_base=" not in cap["cmd"]      # the old broken form is gone
    assert "probes.dan,probes.encoding" in cap["cmd"]


@pytest.mark.asyncio
async def test_promptfoo_handler_builds_generate_then_eval(monkeypatch):
    """Lock the two-step verified against promptfoo 0.121.2: `redteam generate`
    then `eval -o <results.json>` (NOT `redteam run -o`, where -o is the test file)."""
    import tools.kali_runner as kr
    import mcp_server.scan_engine as se
    cap = {}
    async def fake_exec(cmd, timeout=900):
        cap["cmd"] = cmd
        return "raw"
    monkeypatch.setattr(kr, "exec_command", fake_exec)
    monkeypatch.setattr(se, "wrap", lambda tool, raw, ctx=None: f"WRAP:{tool}")
    from mcp_server.scan_tools import _handle_promptfoo
    out = await _handle_promptfoo("http://t/chat", "", {})
    assert out == "WRAP:promptfoo"
    assert "promptfoo redteam generate -c" in cap["cmd"]
    assert "promptfoo eval -c" in cap["cmd"] and "promptfoo_out.json" in cap["cmd"]


@pytest.mark.asyncio
async def test_pyrit_handler_passes_new_flags(monkeypatch):
    """Lock the pyrit invocation: --provider/--body-key are present (the
    --body-key omission was the argparse-exit(2) crash) and wrap() is used."""
    import tools.kali_runner as kr
    import mcp_server.scan_engine as se
    cap = {}
    async def fake_exec(cmd, timeout=900):
        cap["cmd"] = cmd
        return "raw"
    monkeypatch.setattr(kr, "exec_command", fake_exec)
    monkeypatch.setattr(se, "wrap", lambda tool, raw, ctx=None: f"WRAP:{tool}")
    from mcp_server.scan_tools import _handle_pyrit
    out = await _handle_pyrit("http://t/chat", "", {"attack": "jailbreak", "provider": "anthropic"})
    assert out == "WRAP:pyrit"
    assert "pyrit-runner" in cap["cmd"]
    assert "--body-key" in cap["cmd"] and "--provider" in cap["cmd"]


def test_deepen_brief_no_false_positive_on_plain_paths(monkeypatch, tmp_path):
    """/detail, /email must NOT be misread as an AI surface."""
    import core.session as scan_session
    import core.findings as findings_store_mod
    import core.coverage as cov_mod
    import mcp_server.session_tools as st
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
    monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
    monkeypatch.setattr(cov_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir()
    monkeypatch.setattr(st, "_session_tools_called", {"httpx", "spider"})
    scan_session.start("https://example.com", depth="thorough")
    current = scan_session.get()
    current["known_assets"] = {"endpoints": ["/detail", "/email", "/maintenance"]}
    scan_session._flush()
    result = st._deepen_brief(1)
    assert "Re-invoke /ai-redteam" not in result
