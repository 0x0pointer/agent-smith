"""
Dashboard mermaid rendering.

Extracts ```mermaid blocks from markdown and renders each to an SVG via the
mermaid CLI, remapping light-theme colours to dark-mode equivalents first.
Results are cached by content hash (``core.api_server._svg_cache``) so polls
don't re-shell-out on every request.
"""
from __future__ import annotations

import os
from pathlib import Path

import core.api_server as _api

# Remap light-theme inline styles to dark-mode equivalents
_DARK_REMAP = {
    # Reds (danger/critical)
    "fill:#f44": "fill:#5c1a1a", "fill:#f88": "fill:#6b1a1a",
    "fill:#faa": "fill:#5c1a1a", "fill:#fcc": "fill:#4d1a1a",
    "fill:#e53e3e": "fill:#7f1d1d", "fill:#fc8181": "fill:#6b2020",
    # Yellows/oranges (warning)
    "fill:#ffd": "fill:#3d3000", "fill:#ffa": "fill:#3d3000",
    # Greens (safe/mitigated)
    "fill:#68d391": "fill:#14532d", "fill:#48bb78": "fill:#14532d",
    # Blues
    "fill:#ddf": "fill:#1a2a4a", "fill:#bbf": "fill:#1a2040",
    "fill:#63b3ed": "fill:#1e3a5f",
    # Strokes
    "stroke:#c00": "stroke:#ff6666", "stroke:#a00": "stroke:#ff5555",
    "stroke:#c44": "stroke:#ff8888", "stroke:#aa0": "stroke:#ddcc00",
    "stroke:#44a": "stroke:#6699ff", "stroke:#c53030": "stroke:#f87171",
    "stroke:#e53e3e": "stroke:#f87171", "stroke:#38a169": "stroke:#4ade80",
    # Text color overrides — force light text
    "color:#fff": "color:#e5e7eb", "color:#000": "color:#e5e7eb",
}


def _remap_mermaid_dark(src: str) -> str:
    for light, dark in _DARK_REMAP.items():
        src = src.replace(light, dark)
    return src


def _render_mermaid_svgs(content: str) -> dict[str, str]:
    """Extract mermaid blocks from markdown and render each to SVG via mmdc.
    Results are cached by content hash to avoid blocking on every poll."""
    import hashlib
    import re
    import subprocess
    import tempfile

    content_hash = hashlib.sha256(content.encode()).hexdigest()
    if content_hash in _api._svg_cache:
        return _api._svg_cache[content_hash]

    blocks = re.findall(r'```mermaid\n(.*?)```', content, re.DOTALL)
    svgs: dict[str, str] = {}
    config_path = _api._REPO_ROOT / 'core' / 'mermaid-config.json'

    for i, block in enumerate(blocks):
        try:
            with tempfile.NamedTemporaryFile(suffix='.mmd', mode='w', delete=False) as f:
                f.write(_remap_mermaid_dark(block))
                inp = f.name
            out = inp.replace('.mmd', '.svg')
            subprocess.run(
                ['npx', '@mermaid-js/mermaid-cli', '-i', inp, '-o', out,
                 '-c', str(config_path),
                 '--backgroundColor', 'transparent'],
                capture_output=True, text=True, timeout=60,
                cwd=str(_api._REPO_ROOT),
            )
            if os.path.exists(out):
                svgs[str(i)] = Path(out).read_text()
                os.unlink(out)
            os.unlink(inp)
        except Exception:
            pass

    _api._svg_cache[content_hash] = svgs
    return svgs
