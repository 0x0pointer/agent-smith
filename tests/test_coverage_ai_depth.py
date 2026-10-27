"""First-try-fallacy closure gates for AI/LLM cells (issue #248).

An LLM cell must not close off a single bare http() probe: LLM output is
non-deterministic and guardrails are probabilistic. These tests cover the
toolchain-artifact gate, the attempt-budget gate, and the needs_reproduction tag.
"""
import json

import pytest

import core.coverage as cov
from core.coverage import validation as v


def _artifact(monkeypatch, tmp_path, aid, payload):
    monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path, raising=False)
    body = payload if isinstance(payload, str) else json.dumps(payload)
    (tmp_path / f"{aid}.txt").write_text(body, encoding="utf-8")
    return aid


# ── toolchain-artifact gate ─────────────────────────────────────────────────────

def test_toolchain_gate_rejects_http_artifact_on_jailbreak():
    cell = {"id": "c1", "injection_type": "jailbreak"}
    msg = v._validate_llm_toolchain("http_request_101112_abcd1234", "tested_clean", cell)
    assert "REJECTED" in msg and "first-try fallacy" in msg


def test_toolchain_gate_accepts_redteam_and_garak():
    cell = {"id": "c1", "injection_type": "system_prompt_leak"}
    assert v._validate_llm_toolchain("redteam_101112_abcd1234", "tested_clean", cell) == ""
    assert v._validate_llm_toolchain("garak_101112_abcd1234", "vulnerable", cell) == ""


def test_toolchain_gate_ignores_non_required_ai_type():
    # content_bias is an AI cell but NOT in the toolchain-required set
    cell = {"id": "c1", "injection_type": "content_bias"}
    assert v._validate_llm_toolchain("http_request_101112_abcd1234", "tested_clean", cell) == ""


def test_toolchain_gate_ignores_non_ai_cell():
    cell = {"id": "c1", "injection_type": "sqli"}
    assert v._validate_llm_toolchain("http_request_101112_abcd1234", "tested_clean", cell) == ""


# ── attempt-budget gate ─────────────────────────────────────────────────────────

def test_budget_gate_rejects_thin_redteam_run(monkeypatch, tmp_path):
    monkeypatch.setattr(v, "_scan_depth", lambda: "standard")   # needs >=10 attempts, >=2 techs
    aid = _artifact(monkeypatch, tmp_path, "redteam_1_a",
                    {"attempts": 3, "transcript": [{"technique": "direct"}]})
    cell = {"id": "c1", "injection_type": "jailbreak"}
    msg = v._validate_llm_attempt_budget(aid, "tested_clean", cell)
    assert "REJECTED" in msg and "too thin" in msg


def test_budget_gate_accepts_full_redteam_run(monkeypatch, tmp_path):
    monkeypatch.setattr(v, "_scan_depth", lambda: "standard")
    aid = _artifact(monkeypatch, tmp_path, "redteam_1_b",
                    {"attempts": 14, "transcript": [{"technique": "direct"},
                                                    {"technique": "roleplay"}]})
    cell = {"id": "c1", "injection_type": "jailbreak"}
    assert v._validate_llm_attempt_budget(aid, "tested_clean", cell) == ""


def test_budget_gate_depth_scales(monkeypatch, tmp_path):
    aid = _artifact(monkeypatch, tmp_path, "redteam_1_c",
                    {"attempts": 6, "transcript": [{"technique": "direct"},
                                                   {"technique": "authority"}]})
    cell = {"id": "c1", "injection_type": "jailbreak"}
    monkeypatch.setattr(v, "_scan_depth", lambda: "quick")      # quick needs only 5
    assert v._validate_llm_attempt_budget(aid, "tested_clean", cell) == ""
    monkeypatch.setattr(v, "_scan_depth", lambda: "thorough")   # thorough needs 20
    assert "REJECTED" in v._validate_llm_attempt_budget(aid, "tested_clean", cell)


def test_budget_gate_passes_garak_and_vulnerable(monkeypatch, tmp_path):
    cell = {"id": "c1", "injection_type": "jailbreak"}
    # garak isn't a redteam transcript -> budget doesn't apply (hundreds of probes)
    assert v._validate_llm_attempt_budget("garak_1_a", "tested_clean", cell) == ""
    # budget only gates tested_clean, never vulnerable
    assert v._validate_llm_attempt_budget("redteam_1_z", "vulnerable", cell) == ""


# ── needs_reproduction tag ──────────────────────────────────────────────────────

def test_needs_reproduction_on_n1_vulnerable(monkeypatch, tmp_path):
    aid = _artifact(monkeypatch, tmp_path, "redteam_2_a", {"jailbroken": True})  # no k/N
    cell = {"id": "c1", "injection_type": "prompt_injection"}
    assert v.llm_needs_reproduction(aid, "vulnerable", cell) is True


def test_no_reproduction_flag_when_kn_present(monkeypatch, tmp_path):
    aid = _artifact(monkeypatch, tmp_path, "redteam_2_b", {"reproducibility": {"k": 4, "n": 5}})
    cell = {"id": "c1", "injection_type": "prompt_injection"}
    assert v.llm_needs_reproduction(aid, "vulnerable", cell) is False


def test_garak_counts_as_reproduced():
    cell = {"id": "c1", "injection_type": "jailbreak"}
    assert v.llm_needs_reproduction("garak_1_a", "vulnerable", cell) is False


def test_reproduction_only_for_ai_vulnerable():
    cell = {"id": "c1", "injection_type": "sqli"}
    assert v.llm_needs_reproduction("http_request_1_a", "vulnerable", cell) is False
    ai = {"id": "c2", "injection_type": "jailbreak"}
    assert v.llm_needs_reproduction("redteam_1_a", "tested_clean", ai) is False  # clean, not vuln


# ── write path tags the cell + emits a warning ─────────────────────────────────

def test_write_cell_fields_tags_needs_reproduction(monkeypatch, tmp_path):
    from core.coverage import operations as ops
    aid = _artifact(monkeypatch, tmp_path, "redteam_3_a", {"jailbroken": True})
    cell = {"id": "c1", "injection_type": "jailbreak", "status": "in_progress"}
    ops._write_cell_fields(cell, "vulnerable", "found it", "", aid, "finding-xyz")
    assert cell.get("needs_reproduction") is True
    assert "NEEDS REPRODUCTION" in ops._reproduction_warning(cell, "vulnerable")


def test_write_cell_fields_clears_tag_when_reproduced(monkeypatch, tmp_path):
    from core.coverage import operations as ops
    aid = _artifact(monkeypatch, tmp_path, "redteam_3_b", {"reproducibility": {"k": 5, "n": 5}})
    cell = {"id": "c1", "injection_type": "jailbreak", "status": "in_progress",
            "needs_reproduction": True}
    ops._write_cell_fields(cell, "vulnerable", "", "", aid, "finding-xyz")
    assert "needs_reproduction" not in cell


# ── end-to-end through update_cell ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_cell_rejects_http_close_on_jailbreak(monkeypatch, tmp_path):
    monkeypatch.setattr(cov, "COVERAGE_FILE", tmp_path / "coverage.json", raising=False)
    monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path, raising=False)
    (tmp_path / "http_request_9_a.txt").write_text(json.dumps({"status": 200}), encoding="utf-8")
    cov.COVERAGE_FILE.write_text(json.dumps({"matrix": [
        {"id": "j1", "injection_type": "jailbreak", "status": "in_progress", "endpoint_id": "e1"}]}),
        encoding="utf-8")
    from core.coverage.operations import update_cell
    res = await update_cell("j1", "tested_clean", artifact_id="http_request_9_a")
    assert isinstance(res, str) and "REJECTED" in res
    # the cell must stay in_progress — a rejected close never mutates it
    assert cov._load()["matrix"][0]["status"] == "in_progress"
