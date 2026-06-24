"""
Tests for mcp_server.scan_engine.discovery — the spider auto-discovery enrichment.

Covers the I/O-free parsers (parse_openapi for OpenAPI 3 + Swagger 2,
extract_form_endpoints, extract_js_routes, _spider_endpoints) and the
discover_and_register orchestration with _fetch monkeypatched.
"""
import pytest

from mcp_server.scan_engine import discovery as disc


# ── parse_openapi: OpenAPI 3.x ────────────────────────────────────────────────

def test_parse_openapi3_expands_every_operation_with_params():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/users/{id}": {
                "parameters": [
                    {"in": "path", "name": "id", "schema": {"type": "integer"}},
                ],
                "get": {
                    "parameters": [
                        {"in": "query", "name": "filter", "schema": {"type": "string"}},
                    ],
                },
                "delete": {},
            },
            "/login": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                }},
                            },
                        },
                    },
                },
            },
        },
    }
    eps = disc.parse_openapi(spec)
    by_key = {(e["method"], e["path"]): e for e in eps}

    # one endpoint per operation (GET + DELETE on users, POST on login)
    assert ("GET", "/api/v1/users/{id}") in by_key
    assert ("DELETE", "/api/v1/users/{id}") in by_key
    assert ("POST", "/login") in by_key

    # path-level param merges into each method; query param present; types mapped
    get_users = by_key[("GET", "/api/v1/users/{id}")]
    names = {p["name"]: p for p in get_users["params"]}
    assert names["id"]["type"] == "path" and names["id"]["value_hint"] == "integer"
    assert names["filter"]["type"] == "query"

    # JSON body fields become body_json params
    login = by_key[("POST", "/login")]
    login_params = {p["name"]: p["type"] for p in login["params"]}
    assert login_params == {"username": "body_json", "password": "body_json"}
    assert all(e["discovered_by"] == "openapi-spec" for e in eps)


def test_parse_openapi3_form_urlencoded_body_is_body_form():
    spec = {
        "openapi": "3.0.1",
        "paths": {"/submit": {"post": {"requestBody": {"content": {
            "application/x-www-form-urlencoded": {"schema": {"properties": {"q": {"type": "string"}}}},
        }}}}},
    }
    eps = disc.parse_openapi(spec)
    assert eps[0]["params"] == [{"name": "q", "type": "body_form", "value_hint": "string"}]


# ── parse_openapi: Swagger 2.0 ────────────────────────────────────────────────

def test_parse_swagger2_body_and_formdata_and_basepath():
    spec = {
        "swagger": "2.0",
        "basePath": "/api/v2",
        "paths": {
            "/transfer": {
                "post": {
                    "parameters": [
                        {"in": "body", "name": "body", "schema": {"properties": {
                            "amount": {"type": "number"}, "to_account": {"type": "string"}}}},
                        {"in": "query", "name": "dry_run", "type": "boolean"},
                    ],
                },
            },
        },
    }
    eps = disc.parse_openapi(spec)
    assert len(eps) == 1
    ep = eps[0]
    assert ep["path"] == "/api/v2/transfer" and ep["method"] == "POST"
    ptypes = {p["name"]: p["type"] for p in ep["params"]}
    assert ptypes == {"amount": "body_json", "to_account": "body_json", "dry_run": "query"}
    amount = next(p for p in ep["params"] if p["name"] == "amount")
    assert amount["value_hint"] == "integer"  # number → integer hint


def test_parse_openapi_handles_garbage():
    assert disc.parse_openapi({}) == []
    assert disc.parse_openapi({"paths": "nope"}) == []
    assert disc.parse_openapi(None) == []
    assert disc.parse_openapi({"openapi": "3.0", "paths": {"/x": {"get": "notadict"}}}) == []


def test_parse_openapi_caps_operations():
    spec = {"openapi": "3.0.0", "paths": {f"/p{i}": {"get": {}} for i in range(disc._MAX_OPS + 50)}}
    assert len(disc.parse_openapi(spec)) == disc._MAX_OPS


# ── extract_form_endpoints ────────────────────────────────────────────────────

def test_extract_form_endpoints_reads_input_fields():
    html = """
    <html><body>
      <form action="/login" method="post">
        <input name="username" type="text">
        <input name="password" type="password">
        <input type="submit" value="Go">
      </form>
      <form action="/search">
        <input name="q" type="text">
      </form>
    </body></html>
    """
    eps = disc.extract_form_endpoints(html, "http://t/page")
    login = next(e for e in eps if e["path"] == "/login")
    assert login["method"] == "POST"
    names = {p["name"]: p["type"] for p in login["params"]}
    assert names == {"username": "body_form", "password": "body_form"}  # submit dropped

    search = next(e for e in eps if e["path"] == "/search")
    assert search["method"] == "GET"
    assert search["params"][0]["type"] == "query"  # GET form → query params
    assert all(e["discovered_by"] == "form" for e in eps)


def test_extract_form_endpoints_resolves_relative_action():
    html = '<form action="../do/it" method="post"><input name="x"></form>'
    eps = disc.extract_form_endpoints(html, "http://t/a/b/page")
    assert eps[0]["path"] == "/a/do/it"


# ── extract_js_routes ─────────────────────────────────────────────────────────

def test_extract_js_routes_mines_fetch_axios_and_literals():
    js = """
      fetch('/api/v1/transactions').then(r => r.json());
      axios.post("/api/transfer", body);
      const u = { url: '/api/ai/chat' };
      const x = "/internal/secret";
      const tmpl = `/api/users/${id}/posts`;
      const asset = '/static/app.css';
    """
    routes = disc.extract_js_routes(js)
    assert "/api/v1/transactions" in routes
    assert "/api/transfer" in routes
    assert "/api/ai/chat" in routes
    assert "/internal/secret" in routes
    assert "/api/users/" in routes          # template literal truncated at ${
    assert "/static/app.css" not in routes  # static asset filtered


# ── _spider_endpoints ─────────────────────────────────────────────────────────

def test_spider_endpoints_filter_static_and_extract_params():
    urls = [
        "http://t/",
        "http://t/app.js",                      # static → dropped
        "http://t/search?q=hi&__cb=1",          # query param, __ dropped
        "http://t/profile/42",                  # numeric path param
        "http://t/profile/99",                  # dedup with /profile/{id}
    ]
    eps = disc._spider_endpoints(urls)
    paths = {e["path"] for e in eps}
    assert "/app.js" not in str(paths)
    search = next(e for e in eps if e["path"] == "/search")
    assert [p["name"] for p in search["params"]] == ["q"]
    # /profile/42 and /profile/99 dedup to a single endpoint
    assert sum(1 for e in eps if e["path"].startswith("/profile")) == 1


# ── _fetch reads the FULL body (chunked), not just the first chunk ────────────

@pytest.mark.asyncio
async def test_fetch_reads_full_chunked_body(monkeypatch):
    """Regression: a spec split across TCP chunks must be read whole.

    The original _fetch used content.read(n), which returns only the first
    available chunk — a 50 KB spec arrived as ~1 KB and JSON parsing failed,
    silently skipping spec expansion. iter_chunked must accumulate all chunks.
    """
    import aiohttp

    class FakeContent:
        def __init__(self, chunks):
            self._chunks = chunks

        async def iter_chunked(self, _n):
            for c in self._chunks:
                yield c

    class FakeResp:
        status = 200

        def __init__(self, chunks):
            self.content = FakeContent(chunks)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, *a, **k):
            return FakeResp([b'{"openapi":"3.0.0",', b'"paths":', b'{}}'])

    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: FakeSession())
    status, text = await disc._fetch("http://t/openapi.json")
    assert status == 200
    assert text == '{"openapi":"3.0.0","paths":{}}'  # all 3 chunks joined, not truncated


# ── discover_and_register (orchestration, _fetch monkeypatched) ────────────────

@pytest.mark.asyncio
async def test_discover_and_register_registers_spec_and_forms(monkeypatch, coverage_file):
    import core.coverage
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/forgot-password": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"properties": {"username": {"type": "string"}}}}}}}},
            "/transfer": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"properties": {"amount": {"type": "number"}}}}}}}},
        },
    }
    import json as _json

    async def fake_fetch(url):
        if url.endswith("/openapi.json"):
            return 200, _json.dumps(spec)
        if url.endswith("/login"):
            return 200, '<form action="/login" method="post"><input name="username"><input name="password"></form>'
        return 404, ""

    monkeypatch.setattr(disc, "_fetch", fake_fetch)

    out = await disc.discover_and_register(
        "http://t:30081", ["http://t:30081/login", "http://t:30081/openapi.json"],
    )
    assert out["spec_found"] is True
    assert out["registered"] >= 3          # 2 spec ops + /login form (+ spider /login GET)
    assert out["cells"] > 0
    assert out["by_source"].get("openapi-spec") == 2

    # the spec operations are now in the matrix with their params
    data = _json.loads(coverage_file.read_text())
    reg_paths = {e["path"] for e in data["endpoints"]}
    assert "/api/v1/forgot-password" in reg_paths
    assert "/transfer" in reg_paths
    transfer = next(e for e in data["endpoints"] if e["path"] == "/transfer")
    assert any(p["name"] == "amount" for p in transfer["params"])
