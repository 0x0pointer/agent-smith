from __future__ import annotations

from tools.base import Tool


def _build_args(
    target:   str,
    attack:   str = "jailbreak",
    provider: str = "openai",
    model:    str = "",
    flags:    str = "",
) -> list[str]:
    """Build CLI args for FuzzyAI (CyberArk).

    Common attack types: jailbreak, harmful-content, pii-extraction,
    system-prompt-leak, xss-injection, prompt-injection.
    Providers: openai, anthropic, azure, ollama, rest.
    """
    args = ["--target", target, "--attack", attack, "--provider", provider]
    if model:
        args += ["--model", model]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "fuzzyai",
    image           = "ghcr.io/cyberark/fuzzyai",
    build_args      = _build_args,
    default_timeout = 900,
    risk_level      = "intrusive",
    max_output      = 12_000,
    forward_env     = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY"],
    description     = (
        "AI/LLM security fuzzer (CyberArk FuzzyAI). "
        "Args: target (required — URL of the LLM endpoint), "
        "attack (jailbreak | harmful-content | pii-extraction | system-prompt-leak | "
        "xss-injection | prompt-injection — default: jailbreak), "
        "provider (openai | anthropic | azure | ollama | rest — default: openai), "
        "model (model name, e.g. gpt-4o — optional), "
        "flags (extra FuzzyAI flags)."
    ),
)
