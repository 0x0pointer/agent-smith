"""
Unit tests for tool _build_args functions.
These are pure functions — no Docker or network needed.
"""
import pytest
from tools.nmap import _build_args as nmap_args
from tools.naabu import _build_args as naabu_args
from tools.httpx import _build_args as httpx_args
from tools.nuclei import _build_args as nuclei_args
from tools.ffuf import _build_args as ffuf_args
from tools.subfinder import _build_args as subfinder_args
from tools.fuzzyai import _build_args as fuzzyai_args


# ── nmap ──────────────────────────────────────────────────────────────────────

def test_nmap_default_ports():
    args = nmap_args("example.com")
    assert "--top-ports" in args
    assert "1000" in args

def test_nmap_full_ports():
    args = nmap_args("example.com", ports="full")
    assert "-p-" in args

def test_nmap_custom_ports():
    args = nmap_args("example.com", ports="80,443")
    assert "-p" in args
    assert "80,443" in args

def test_nmap_flags_appended():
    args = nmap_args("example.com", flags="-sV -O")
    assert "-sV" in args
    assert "-O" in args

def test_nmap_host_last():
    args = nmap_args("example.com")
    assert args[-1] == "example.com"

def test_nmap_open_flag():
    args = nmap_args("example.com")
    assert "--open" in args


# ── naabu ─────────────────────────────────────────────────────────────────────

def test_naabu_default_top100():
    args = naabu_args("example.com")
    assert "-top-ports" in args
    assert "100" in args

def test_naabu_full_ports():
    args = naabu_args("example.com", ports="full")
    assert "-p" in args
    assert "-" in args

def test_naabu_custom_ports():
    args = naabu_args("example.com", ports="8080-8090")
    assert "-p" in args
    assert "8080-8090" in args

def test_naabu_flags():
    args = naabu_args("example.com", flags="-rate 100")
    assert "-rate" in args
    assert "100" in args

def test_naabu_json_output():
    args = naabu_args("example.com")
    assert "-json" in args


# ── httpx ─────────────────────────────────────────────────────────────────────

def test_httpx_required_flags():
    args = httpx_args("http://example.com")
    assert "-json" in args
    assert "-title" in args
    assert "-status-code" in args

def test_httpx_url_included():
    args = httpx_args("http://example.com")
    assert "http://example.com" in args

def test_httpx_extra_flags():
    args = httpx_args("http://example.com", flags="-timeout 10")
    assert "-timeout" in args
    assert "10" in args


# ── nuclei ────────────────────────────────────────────────────────────────────

def test_nuclei_url_included():
    args = nuclei_args("http://example.com")
    assert "http://example.com" in args

def test_nuclei_default_tags():
    args = nuclei_args("http://example.com")
    assert "-tags" in args
    idx = args.index("-tags")
    assert "cve" in args[idx + 1]

def test_nuclei_custom_templates():
    args = nuclei_args("http://example.com", templates="takeover,tech")
    idx = args.index("-tags")
    assert "takeover" in args[idx + 1]

def test_nuclei_no_templates():
    args = nuclei_args("http://example.com", templates="")
    assert "-tags" not in args

def test_nuclei_flags():
    args = nuclei_args("http://example.com", flags="-severity critical")
    assert "-severity" in args

def test_nuclei_jsonl_output():
    args = nuclei_args("http://example.com")
    assert "-jsonl" in args


# ── ffuf ──────────────────────────────────────────────────────────────────────

def test_ffuf_fuzz_appended_to_url():
    args = ffuf_args("http://example.com")
    assert any("FUZZ" in a for a in args)

def test_ffuf_wordlist_included():
    args = ffuf_args("http://example.com", wordlist="/tmp/list.txt")
    assert "/tmp/list.txt" in args

def test_ffuf_extensions():
    args = ffuf_args("http://example.com", extensions=".php,.html")
    assert "-e" in args
    assert ".php,.html" in args

def test_ffuf_no_extensions_by_default():
    args = ffuf_args("http://example.com")
    assert "-e" not in args

def test_ffuf_extra_flags():
    args = ffuf_args("http://example.com", flags="-mc 200")
    assert "-mc" in args
    assert "200" in args


# ── subfinder ─────────────────────────────────────────────────────────────────

def test_subfinder_domain_included():
    args = subfinder_args("example.com")
    assert "example.com" in args

def test_subfinder_silent():
    args = subfinder_args("example.com")
    assert "-silent" in args

def test_subfinder_extra_flags():
    args = subfinder_args("example.com", flags="-timeout 30")
    assert "-timeout" in args
    assert "30" in args


# ── fuzzyai ───────────────────────────────────────────────────────────────────

def test_fuzzyai_target_included():
    args = fuzzyai_args("http://example.com/chat")
    assert "http://example.com/chat" in args

def test_fuzzyai_default_attack():
    args = fuzzyai_args("http://example.com/chat")
    assert "--attack" in args
    idx = args.index("--attack")
    assert args[idx + 1] == "jailbreak"

def test_fuzzyai_custom_attack():
    args = fuzzyai_args("http://example.com/chat", attack="prompt-injection")
    idx = args.index("--attack")
    assert args[idx + 1] == "prompt-injection"

def test_fuzzyai_provider():
    args = fuzzyai_args("http://example.com/chat", provider="anthropic")
    idx = args.index("--provider")
    assert args[idx + 1] == "anthropic"

def test_fuzzyai_model_included():
    args = fuzzyai_args("http://example.com/chat", model="gpt-4o")
    assert "--model" in args
    idx = args.index("--model")
    assert args[idx + 1] == "gpt-4o"

def test_fuzzyai_no_model_by_default():
    args = fuzzyai_args("http://example.com/chat")
    assert "--model" not in args

def test_fuzzyai_extra_flags():
    args = fuzzyai_args("http://example.com/chat", flags="--verbose")
    assert "--verbose" in args
