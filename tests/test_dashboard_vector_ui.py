from pathlib import Path


def test_setup_gates_uses_vector_vaults_not_kb_docs():
    root = Path(__file__).resolve().parent.parent / "dashboard"
    html = (root / "tabs" / "setup-gates.html").read_text()
    js = (root / "js" / "setup-gates.js").read_text()

    assert "Vector vaults" in html
    assert "/api/vector/docs" in js
    assert "Engagement documents" not in html
    assert "_uploadKbDocs" not in js
