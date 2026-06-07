"""
Tests for envelope helpers added on this branch:

  • _is_zero_status         — type-safe HTTP status=0 detection
  • _is_auth_attempt        — generic detector (body/query/known endpoint)
  • _request_carries_auth   — detects auth across all common patterns
  • _filter_qa_alerts_by_dedup
  • _persist_http_auth_assets
  • _inject_missing_auth_warning
  • wrap() SCAN_COMPLETED  guard
  • wrap() HUMAN_INTERVENTION_REQUIRED guard
"""
import json
from unittest.mock import patch, MagicMock

import pytest

import core.session as scan_session
from mcp_server.scan_engine.envelope import (
    Envelope,
    _is_zero_status,
    _is_auth_attempt,
    _request_carries_auth,
    _filter_qa_alerts_by_dedup,
    _qa_alert_last_shown,
    _persist_http_auth_assets,
    _inject_missing_auth_warning,
    wrap,
)


# ---------------------------------------------------------------------------
# _is_zero_status — type-safe failure-status detection
# ---------------------------------------------------------------------------

class TestIsZeroStatus:

    @pytest.mark.parametrize("raw, expected", [
        (0,        True),
        ("0",      True),
        (" 0 ",    True),
        (None,     False),
        ("",       False),
        (200,      False),
        ("200",    False),
        ("abc",    False),
    ])
    def test_zero_status_matrix(self, raw, expected):
        assert _is_zero_status(raw) is expected


# ---------------------------------------------------------------------------
# _is_auth_attempt — detect credential-validation calls
# ---------------------------------------------------------------------------

class TestIsAuthAttempt:

    def test_password_in_json_body(self):
        ctx = {"body": '{"username":"a","password":"b"}'}
        assert _is_auth_attempt(ctx) is True

    def test_api_key_in_form_body(self):
        assert _is_auth_attempt({"body": "user=a&api_key=secret"}) is True

    def test_otp_field(self):
        assert _is_auth_attempt({"body": '{"otp":"123456"}'}) is True

    def test_refresh_token_field(self):
        assert _is_auth_attempt({"body": '{"refresh_token":"abc"}'}) is True

    def test_no_auth_field_returns_false(self):
        ctx = {"body": '{"to_account":"x","amount":1}'}
        assert _is_auth_attempt(ctx) is False

    def test_empty_body_returns_false(self):
        assert _is_auth_attempt({"body": ""}) is False

    def test_query_string_credentials_detected(self):
        assert _is_auth_attempt({"query": "password=foo"}) is True

    def test_known_endpoint_path_marks_attempt(self, tmp_path, monkeypatch):
        # Seed a session with a known auth endpoint and confirm a request
        # to that URL is treated as a credential attempt even when the body
        # has no auth keywords.
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("https://example.com")
        scan_session.update_known_assets("auth_endpoints", [
            {"path": "https://example.com/api/login", "method": "POST"},
        ])
        ctx = {"url": "https://example.com/api/login", "body": "{}"}
        assert _is_auth_attempt(ctx) is True
        scan_session._current = None


# ---------------------------------------------------------------------------
# _request_carries_auth — does the request have ANY auth signal?
# ---------------------------------------------------------------------------

class TestRequestCarriesAuth:

    @pytest.mark.parametrize("ctx", [
        {"url": "http://x/api", "headers": {"Authorization": "Bearer abc"}},
        {"url": "http://x/api", "headers": {"Authorization": "Basic abc"}},
        {"url": "http://x/api", "headers": {"Cookie": "sessionid=abc"}},
        {"url": "http://x/api", "headers": {"X-Api-Key": "abc"}},
        {"url": "http://x/api", "headers": {"X-Auth-Token": "abc"}},
        {"url": "http://x/api", "headers": {"X-Session-Id": "abc"}},
        {"url": "http://x/api", "headers": {"X-Access-Key": "abc"}},
        {"url": "http://x/api", "headers": {"X-CSRF-Token": "abc"}},
        {"url": "http://x/api?token=abc", "headers": {}},
        {"url": "http://x/api?foo=1&access_token=abc", "headers": {}},
        {"url": "http://x/api?api_key=abc", "headers": {}},
    ])
    def test_positive_signals(self, ctx):
        assert _request_carries_auth(ctx) is True

    def test_negative_signals(self):
        ctx = {"url": "http://x/api", "headers": {"Content-Type": "application/json"}}
        assert _request_carries_auth(ctx) is False


# ---------------------------------------------------------------------------
# _filter_qa_alerts_by_dedup — content-based dedup with cooldown
# ---------------------------------------------------------------------------

class TestQaAlertDedup:

    def setup_method(self):
        # The dedup map is module-level state; clear between tests.
        _qa_alert_last_shown.clear()

    def test_first_call_returns_all(self):
        alerts = [{"code": "C1", "message": "m1"}, {"code": "C2", "message": "m2"}]
        out = _filter_qa_alerts_by_dedup(alerts, "2026-06-07T10:00:00+00:00")
        assert len(out) == 2

    def test_immediate_repeat_is_suppressed(self):
        alerts = [{"code": "C1", "message": "m1"}]
        _filter_qa_alerts_by_dedup(alerts, "2026-06-07T10:00:00+00:00")
        out = _filter_qa_alerts_by_dedup(alerts, "2026-06-07T10:01:00+00:00")
        assert out == []

    def test_changed_message_re_fires(self):
        first = [{"code": "C1", "message": "553 cells"}]
        _filter_qa_alerts_by_dedup(first, "2026-06-07T10:00:00+00:00")
        second = [{"code": "C1", "message": "612 cells"}]
        out = _filter_qa_alerts_by_dedup(second, "2026-06-07T10:01:00+00:00")
        assert len(out) == 1

    def test_cooldown_expires(self):
        alerts = [{"code": "C1", "message": "m1"}]
        _filter_qa_alerts_by_dedup(alerts, "2026-06-07T10:00:00+00:00")
        # 31 min later — past the 30-min cooldown
        out = _filter_qa_alerts_by_dedup(alerts, "2026-06-07T10:31:00+00:00")
        assert len(out) == 1

    def test_unparseable_timestamp_passes_through(self):
        # Falls back to no dedup when the current_ts can't be parsed
        out = _filter_qa_alerts_by_dedup(
            [{"code": "C", "message": "m"}], "not-a-real-timestamp"
        )
        assert len(out) == 1


# ---------------------------------------------------------------------------
# _persist_http_auth_assets — auto-extract JWTs + credentials
# ---------------------------------------------------------------------------

class TestPersistHttpAuthAssets:

    def test_extracts_jwt_from_response_body(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("https://x.test")
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZm9vIn0.signature_part"
        evidence = {"status": 200, "body_preview": f'{{"token":"{jwt}"}}'}
        ctx = {"url": "https://x.test/api/me", "method": "GET"}
        _persist_http_auth_assets(scan_session, evidence, ctx)
        tokens = scan_session.get()["known_assets"]["auth_tokens"]
        assert any(t["value"] == jwt for t in tokens)
        scan_session._current = None

    def test_records_credentials_on_login_success(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("https://x.test")
        evidence = {"status": 200, "body_preview": '{"ok":true}'}
        ctx = {
            "url": "https://x.test/login",
            "method": "POST",
            "body": '{"username":"admin","password":"hunter2"}',
        }
        _persist_http_auth_assets(scan_session, evidence, ctx)
        creds = scan_session.get()["known_assets"]["credentials"]
        assert any(c["username"] == "admin" for c in creds)
        eps = scan_session.get()["known_assets"]["auth_endpoints"]
        assert any("login" in e["path"] for e in eps)
        scan_session._current = None

    def test_non_2xx_does_not_record_credentials(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("https://x.test")
        evidence = {"status": 401, "body_preview": "wrong creds"}
        ctx = {
            "url": "https://x.test/login",
            "method": "POST",
            "body": '{"username":"admin","password":"wrong"}',
        }
        _persist_http_auth_assets(scan_session, evidence, ctx)
        creds = scan_session.get()["known_assets"]["credentials"]
        assert creds == []
        scan_session._current = None


# ---------------------------------------------------------------------------
# _inject_missing_auth_warning
# ---------------------------------------------------------------------------

class TestInjectMissingAuthWarning:

    def _make_env(self, status: int) -> Envelope:
        env = Envelope(summary="orig", evidence={"status": status})
        return env

    def test_no_warning_when_status_is_200(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        scan_session.update_known_assets("auth_tokens", [
            {"value": "eyJtoken", "type": "jwt"},
        ])
        env = self._make_env(200)
        _inject_missing_auth_warning(env, {"url": "http://x/api", "headers": {}})
        assert "AUTH_MISSING" not in env.summary
        scan_session._current = None

    def test_warning_when_401_and_no_auth_sent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        scan_session.update_known_assets("auth_tokens", [
            {"value": "eyJ_realtoken", "type": "jwt"},
        ])
        env = self._make_env(401)
        _inject_missing_auth_warning(env, {"url": "http://x/api", "headers": {}})
        assert "AUTH_MISSING" in env.summary
        scan_session._current = None

    def test_no_warning_when_auth_was_sent(self, tmp_path, monkeypatch):
        # 401 + Authorization header → token rejected, not missing — skip warning.
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        scan_session.update_known_assets("auth_tokens", [{"value": "eyJt", "type": "jwt"}])
        env = self._make_env(401)
        _inject_missing_auth_warning(env, {
            "url": "http://x/api",
            "headers": {"Authorization": "Bearer something"},
        })
        assert "AUTH_MISSING" not in env.summary
        scan_session._current = None

    def test_no_warning_when_no_tokens_yet(self, tmp_path, monkeypatch):
        # 401 with no auth and no tokens to suggest — we have nothing useful
        # to put in the warning so we don't emit one.
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        env = self._make_env(401)
        _inject_missing_auth_warning(env, {"url": "http://x/api", "headers": {}})
        assert "AUTH_MISSING" not in env.summary
        scan_session._current = None

    def test_skips_credential_attempts(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        scan_session.update_known_assets("auth_tokens", [{"value": "eyJt", "type": "jwt"}])
        env = self._make_env(401)
        # Body has password → this is Smith trying to log in, not forgetting auth.
        _inject_missing_auth_warning(env, {
            "url": "http://x/login",
            "headers": {},
            "body": '{"username":"a","password":"b"}',
        })
        assert "AUTH_MISSING" not in env.summary
        scan_session._current = None


# ---------------------------------------------------------------------------
# wrap() — terminal status + intervention guards
# ---------------------------------------------------------------------------

class TestWrapGuards:

    def test_scan_completed_blocks_non_session_tool(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        scan_session._current["status"] = "complete"
        out = wrap("http_request", json.dumps({"status": 200, "body": "x"}),
                   {"url": "http://x", "method": "GET"})
        parsed = json.loads(out)
        assert parsed["status"] == "SCAN_COMPLETED"
        assert parsed["scan_status"] == "complete"
        scan_session._current = None

    def test_terminal_status_does_not_block_session_tool(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        scan_session._current["status"] = "complete"
        # session() tool goes around both guards
        out = wrap("session", "raw-output", {})
        parsed = json.loads(out)
        assert parsed.get("status") != "SCAN_COMPLETED"
        scan_session._current = None

    def test_intervention_blocks_non_session_tool(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session.start("http://x")
        # Trigger the HIR state
        scan_session.trigger_intervention(
            code="HIR_TEST", situation="t", tried=[], options=["A", "B"],
        )
        out = wrap("http_request", json.dumps({"status": 200}),
                   {"url": "http://x", "method": "GET"})
        parsed = json.loads(out)
        assert parsed["status"] == "HUMAN_INTERVENTION_REQUIRED"
        assert parsed["code"] == "HIR_TEST"
        scan_session._current = None
