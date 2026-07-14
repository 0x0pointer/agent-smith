"""API-key separation (PR #162): the AI-testing anthropic key (AITEST_ANTHROPIC_API_KEY) reaches the
red-team tools AS ANTHROPIC_API_KEY, while no bare ANTHROPIC_API_KEY is exposed for an interactive
`claude` to bill to your account."""
import tools.fuzzyai
import tools.kali_runner as kali


def test_kali_forwards_aitest_as_anthropic():
    # AITEST_ANTHROPIC_API_KEY is forwarded into the container AS ANTHROPIC_API_KEY (what pyrit reads)
    assert kali._forward_ai_keys({"AITEST_ANTHROPIC_API_KEY": "sk-ant-test"}) == ["-e", "ANTHROPIC_API_KEY=sk-ant-test"]


def test_kali_real_anthropic_overrides_aitest():
    flags = kali._forward_ai_keys({"AITEST_ANTHROPIC_API_KEY": "aitest", "ANTHROPIC_API_KEY": "real"})
    assert "ANTHROPIC_API_KEY=real" in flags and "ANTHROPIC_API_KEY=aitest" not in flags
    assert sum(1 for f in flags if f.startswith("ANTHROPIC_API_KEY=")) == 1   # deduped by destination


def test_kali_forwards_openai_and_azure_directly():
    flags = kali._forward_ai_keys({"OPENAI_API_KEY": "o", "AZURE_OPENAI_API_KEY": "z"})
    assert "OPENAI_API_KEY=o" in flags and "AZURE_OPENAI_API_KEY=z" in flags


def test_kali_no_keys_gives_no_flags():
    assert kali._forward_ai_keys({}) == []


def test_fuzzyai_forwards_the_renamed_key_as_alias():
    fe = tools.fuzzyai.TOOL.forward_env
    assert "AITEST_ANTHROPIC_API_KEY:ANTHROPIC_API_KEY" in fe   # renamed key mapped into the tool
    assert "OPENAI_API_KEY" in fe
