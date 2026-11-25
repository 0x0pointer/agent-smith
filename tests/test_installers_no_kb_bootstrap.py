from __future__ import annotations

import pathlib


def test_installers_do_not_invoke_build_kb_or_accept_kb_flags():
    for rel in ("installers/install.sh", "installers/install_codex.sh", "installers/install_opencode.sh"):
        text = pathlib.Path(rel).read_text(encoding="utf-8")
        assert "build_kb.py" not in text, rel
        assert "--with-kb" not in text, rel
        assert "--no-kb" not in text, rel
        assert "SMITH_INSTALL_KB" not in text, rel
