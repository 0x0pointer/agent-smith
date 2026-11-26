from __future__ import annotations

from core.sources import SOURCE_REGISTRY_FILE, list_sources, resolve_source


def test_resolve_source_known_loopback(tmp_path):
    reg = tmp_path / "sources.yaml"
    reg.write_text(
        "sources:\n"
        "  prod-web:\n"
        "    url: http://127.0.0.1:7801\n",
        encoding="utf-8",
    )
    out = resolve_source("prod-web", reg)
    assert out["source"] == {"name": "prod-web", "url": "http://127.0.0.1:7801"}
    assert out["available"] == ["prod-web"]
    assert out["error"] is None


def test_resolve_source_unknown_lists_available(tmp_path):
    reg = tmp_path / "sources.yaml"
    reg.write_text(
        "sources:\n"
        "  prod-web: {url: http://localhost:7801}\n"
        "  internal-ad:\n"
        "    url: http://[::1]:7802\n",
        encoding="utf-8",
    )
    out = resolve_source("missing", reg)
    assert out["source"] is None
    assert out["available"] == ["internal-ad", "prod-web"]
    assert "not available" in out["error"]


def test_resolve_source_rejects_non_loopback_and_malformed(tmp_path):
    reg = tmp_path / "sources.yaml"
    reg.write_text(
        "sources:\n"
        "  good:\n"
        "    url: http://127.0.0.1:7801\n"
        "  bad-host:\n"
        "    url: http://10.0.0.9:7802\n"
        "  bad-scheme: {url: https://127.0.0.1:7803}\n"
        "  malformed:\n"
        "    url: not-a-url\n",
        encoding="utf-8",
    )
    listed = list_sources(reg)
    assert listed == {"good": {"name": "good", "url": "http://127.0.0.1:7801"}}
    out = resolve_source("bad-host", reg)
    assert out["source"] is None
    assert out["available"] == ["good"]
    assert out["errors"] == ["bad-host: invalid url", "bad-scheme: invalid url", "malformed: invalid url"]


def test_source_registry_env_override(tmp_path, monkeypatch):
    reg = tmp_path / "custom-sources.yaml"
    reg.write_text("prod-web:\n  url: http://127.0.0.1:7999\n", encoding="utf-8")
    monkeypatch.setenv("SOURCE_REGISTRY", str(reg))
    assert SOURCE_REGISTRY_FILE.name == "sources.yaml"
    assert resolve_source("prod-web")["source"]["url"] == "http://127.0.0.1:7999"
