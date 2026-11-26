from __future__ import annotations

from core.sources import SOURCE_REGISTRY_FILE, _validate_source_url, list_sources, resolve_source


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


def test_resolve_source_empty_name_and_comment_only_registry(tmp_path):
    reg = tmp_path / "sources.yaml"
    reg.write_text("# comment only\n\n", encoding="utf-8")
    out = resolve_source("", reg)
    assert out["source"] is None
    assert out["available"] == []
    assert out["error"] == "No Source was bound to this engagement."


def test_list_sources_missing_registry_and_root_level_entries(tmp_path):
    missing = tmp_path / "missing.yaml"
    assert list_sources(missing) == {}
    assert "not found" in resolve_source("prod-web", missing)["errors"][0]

    reg = tmp_path / "sources.yaml"
    reg.write_text(
        "prod-web:\n"
        "  url: http://127.0.0.1:7801/\n"
        "ignored:\n"
        "  note: no url here\n",
        encoding="utf-8",
    )
    assert list_sources(reg) == {"prod-web": {"name": "prod-web", "url": "http://127.0.0.1:7801"}}


def test_validate_source_url_rejects_bad_inputs():
    assert _validate_source_url("") is None
    assert _validate_source_url("http://user:pass@127.0.0.1:7801") is None
    assert _validate_source_url("http://127.0.0.1:bad") is None
