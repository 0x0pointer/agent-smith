"""_sanitize_mermaid — make agent-authored diagram Mermaid robust to the common
edge-label breakage (unescaped '(' etc.) WITHOUT corrupting valid node shapes."""
from mcp_server.report_tools._common import _sanitize_mermaid, _mermaid_label


def test_edge_label_parens_are_escaped():
    src = "graph LR\n  A -->|T1078 - Valid Accounts (Privileged Creation)| B"
    out = _sanitize_mermaid(src)
    # the raw '(' / ')' inside the edge label are entity-escaped so Mermaid won't mis-parse
    assert "(Privileged" not in out
    assert "#40;" in out and "#41;" in out
    # structure (the pipes + nodes) is preserved
    assert out.startswith("graph LR")
    assert "A -->|" in out and "| B" in out


def test_quoted_edge_label_inner_quotes_stripped_then_escaped():
    src = 'graph LR\n  A -->|"has (parens)"| B'
    out = _sanitize_mermaid(src)
    assert "#40;" in out  # parens escaped
    assert '"has' not in out  # surrounding quotes stripped


def test_clean_edge_label_unchanged():
    src = "graph LR\n  A -->|leads to| B"
    assert _sanitize_mermaid(src) == src  # nothing special -> byte-identical


def test_node_shapes_not_corrupted():
    # cylinders / circles / rectangles have NO pipes, so the edge-label-only pass leaves
    # them exactly as-is (the whole point of scoping to |...| and not node shapes).
    src = ('flowchart TD\n'
           '  DB[("PostgreSQL Database")]\n'
           '  C((Circle Node))\n'
           '  R["Admin: /console (Werkzeug Debugger)"]')
    assert _sanitize_mermaid(src) == src


def test_empty_and_none_safe():
    assert _sanitize_mermaid("") == ""
    assert _sanitize_mermaid(None) is None


def test_mermaid_label_still_escapes_breakers():
    # the underlying escaper the sanitiser reuses
    assert _mermaid_label("a(b)|c") == "a#40;b#41;#124;c"
