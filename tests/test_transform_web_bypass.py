"""Tests for web-exploitation filter-bypass generators (#6 generator tools).

The JSFuck encoder is validated by *executing* its output in node (the gold
standard — structural asserts alone can't prove a payload runs). Node tests
skip cleanly when node is absent, but the pure-Python round-trips always run.
"""
import json
import re
import shutil
import subprocess

import pytest

from mcp_server.transforms import web_bypass as w
from mcp_server.transforms.registry import CATEGORIES, TRANSFORMS

_NODE = shutil.which("node")
requires_node = pytest.mark.skipif(not _NODE, reason="node not installed")

_SIX = set("[]()!+")


def _node_eval_string(expr: str) -> str | None:
    """Return String(eval(expr)) from node, or None on error."""
    js = ("try{process.stdout.write(JSON.stringify(String(eval(" + json.dumps(expr) +
          "))))}catch(e){process.stdout.write('null')}")
    r = subprocess.run([_NODE, "-e", js], capture_output=True, text=True, timeout=60)
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def _node_run_payload(payload: str) -> list | None:
    """Execute a JSFuck payload with alert/fetch/print hooked; return what fired."""
    probe = (
        "let F=null;"
        "globalThis.alert=x=>F=['alert',x];"
        "globalThis.print=x=>F=['print',x];"
        "globalThis.fetch=x=>{F=['fetch',x];return{then(){return{catch(){}}}}};"
        "try{eval(" + json.dumps(payload) + ")}catch(e){F=['ERR',String(e)]}"
        "process.stdout.write(JSON.stringify(F))"
    )
    r = subprocess.run([_NODE, "-e", probe], capture_output=True, text=True, timeout=60)
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


# ── JSFuck ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("code", ["alert(1)", "alert(document)", "fetch(`/flag`)", "print(1)"])
def test_jsfuck_pure_charset(code):
    assert set(w.jsfuck(code)) <= _SIX
    assert set(w.jsfuck_string(code)) <= _SIX


def test_jsfuck_string_empty():
    assert w.jsfuck_string("") == "([]+[])"


@requires_node
@pytest.mark.parametrize("text", ["alert(1)", "XSS", "a<b>c&d", "日本語€", "';--", "\\x00\\n"])
def test_jsfuck_string_evaluates(text):
    assert _node_eval_string(w.jsfuck_string(text)) == text


@requires_node
def test_jsfuck_executes_alert():
    assert _node_run_payload(w.jsfuck("alert(1)")) == ["alert", 1]


@requires_node
def test_jsfuck_executes_fetch():
    assert _node_run_payload(w.jsfuck("fetch(`/flag`)")) == ["fetch", "/flag"]


@requires_node
def test_jsfuck_full_ascii_each_char_round_trips():
    """Every printable ASCII char survives jsfuck_string -> node eval."""
    printable = "".join(chr(c) for c in range(0x20, 0x7F))
    assert _node_eval_string(w.jsfuck_string(printable)) == printable


# ── JS string construction (reversible) ──────────────────────────────────────

@pytest.mark.parametrize("name", ["js_fromcharcode", "js_unicode_escape", "js_hex_escape"])
@pytest.mark.parametrize("text", ["alert(1)", "admin'||'1", "日本€", "<svg/onload>"])
def test_js_encoders_round_trip(name, text):
    spec = TRANSFORMS[name]
    assert spec["decode"](spec["encode"](text)) == text


@requires_node
@pytest.mark.parametrize("text", ["alert(1)", "a\"b'c", "日€"])
def test_fromcharcode_evaluates(text):
    assert _node_eval_string(w._fromcharcode_encode(text)) == text


@requires_node
@pytest.mark.parametrize("enc", [w._unicode_escape_encode, w._hex_escape_encode])
@pytest.mark.parametrize("text", ["alert", "a b€", "x\"y"])
def test_js_escapes_evaluate_inside_string(enc, text):
    # The escape forms are valid inside a JS double-quoted string literal.
    assert _node_eval_string('"' + enc(text) + '"') == text


# ── SQL keyword bypass ───────────────────────────────────────────────────────

def test_sql_keyword_bypass_variants_present():
    vs = w.sql_keyword_bypass("' UNION SELECT 1,2,3-- -")
    techs = {v["technique"] for v in vs}
    assert {"case_toggle", "inline_comment_split", "double_keyword",
            "mysql_version_comment", "url_encode_keyword"} <= techs
    for v in vs:
        assert v["payload"] and "defeats" in v


def test_double_keyword_survives_single_strip():
    """double_keyword must reduce to the original keyword after one removal pass."""
    vs = w.sql_keyword_bypass("UNION SELECT", keywords=["UNION", "SELECT"])
    dk = next(v for v in vs if v["technique"] == "double_keyword")["payload"]
    stripped = re.sub("UNION", "", dk, count=1, flags=re.I)
    stripped = re.sub("SELECT", "", stripped, count=1, flags=re.I)
    assert "UNION" in stripped.upper() and "SELECT" in stripped.upper()


def test_inline_comment_strips_back_to_keyword():
    vs = w.sql_keyword_bypass("UNION SELECT", keywords=["UNION", "SELECT"])
    ic = next(v for v in vs if v["technique"] == "inline_comment_split")["payload"]
    assert ic.replace("/**/", "") == "UNION SELECT"


# ── XSS filter bypass ────────────────────────────────────────────────────────

def test_xss_alphanumeric_blocked_is_jsfuck():
    vs = w.xss_filter_bypass("alert(1)", "alphanumeric_blocked")
    bare = next(v for v in vs if v["technique"] == "jsfuck_bare")["payload"]
    assert set(bare) <= _SIX


def test_xss_unclosed_tag_has_no_closing_bracket():
    vs = w.xss_filter_bypass("alert(1)", "html")
    unclosed = next(v for v in vs if v["technique"] == "unclosed_tag")["payload"]
    # the vector must not terminate the tag it opens (defeats complete-tag strip)
    assert unclosed.count("<") > unclosed.count(">")


def test_xss_attribute_context_breaks_out():
    vs = w.xss_filter_bypass("alert(1)", "attribute")
    assert all(v["payload"].startswith('">') for v in vs if v["technique"] != "jsfuck_bare")


# ── registry + tool wiring ───────────────────────────────────────────────────

def test_registry_exposes_web_category():
    assert "web" in CATEGORIES
    assert {"jsfuck", "js_fromcharcode", "js_unicode_escape", "js_hex_escape"} <= set(TRANSFORMS)


def test_jsfuck_not_reversible_flag():
    assert TRANSFORMS["jsfuck"]["reversible"] is False


def test_webgen_tool_dispatch():
    from mcp_server.transform_tools import _do_webgen
    out = json.loads(_do_webgen("alert(1)", {"kind": "jsfuck", "save_artifact": False}))
    assert out["charset"] == "[]()!+" and out["output_len"] > 0
    sql = json.loads(_do_webgen("UNION SELECT", {"kind": "sql_keyword"}))
    assert sql["count"] >= 5
    xss = json.loads(_do_webgen("alert(1)", {"kind": "xss_filter", "context": "alphanumeric_blocked"}))
    assert xss["count"] >= 1
