"""
Tests for core.model_detect — model-name → profile classification and the
environment resolution order.
"""
import pytest

from core import model_detect as md

_ALL_ENV = list(md._MODEL_ENV_VARS) + ["OLLAMA_HOST", "SMITH_MODEL_PROFILE"]


@pytest.fixture
def clean_env(monkeypatch):
    for v in _ALL_ENV:
        monkeypatch.delenv(v, raising=False)


# ── classify_model ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expected", [
    ("claude-opus-4-8", "full"),
    ("gpt-4o", "full"),
    ("gemini-2.0-flash", "full"),
    ("qwen2.5:32b", "small"),
    ("qwen3-27b-instruct", "small"),
    ("llama3.1:8b", "small"),
    ("mistral-7b", "small"),
    ("llama-3.1-70b", "medium"),
    ("qwen2.5:72b", "medium"),
])
def test_classify(name, expected):
    profile, _reason = md.classify_model(name)
    assert profile == expected, (name, profile)


def test_classify_unknown_returns_none():
    profile, _ = md.classify_model("some-bespoke-model-x")
    assert profile is None


# ── detect_profile resolution order ─────────────────────────────────────────

def test_explicit_wins(clean_env, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")  # would say small
    assert md.detect_profile("full")[0] == "full"


def test_smith_override_env(clean_env, monkeypatch):
    monkeypatch.setenv("SMITH_MODEL_PROFILE", "medium")
    monkeypatch.setenv("OPENCODE_MODEL", "qwen2.5:32b")  # would say small
    assert md.detect_profile(None)[0] == "medium"


def test_opencode_model_classified(clean_env, monkeypatch):
    monkeypatch.setenv("OPENCODE_MODEL", "qwen3-27b")
    assert md.detect_profile(None)[0] == "small"


def test_client_var_beats_global_openai(clean_env, monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")        # frontier
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:32b")   # local — checked first
    assert md.detect_profile(None)[0] == "small"


def test_ollama_host_bare_signal(clean_env, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    assert md.detect_profile(None)[0] == "small"


def test_no_signal_defaults_full(clean_env):
    assert md.detect_profile(None)[0] == "full"


def test_frontier_env_stays_full(clean_env, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-4-8")
    assert md.detect_profile(None)[0] == "full"
