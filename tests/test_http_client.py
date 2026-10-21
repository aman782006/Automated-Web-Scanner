"""
tests/test_http_client.py

Tests for scanner.http_client — safe HTTP client behavior.

All tests use mocked responses; no real network requests are made.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from scanner.http_client import (
    ScanSession,
    SafeResponse,
    fetch_response,
    fetch_with_redirect_chain,
    create_session,
    _sanitise_headers,
    _SAFE_REQUEST_HEADERS,
)
from scanner.validator import ValidatedTarget, ValidationError


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_target(hostname="example.com", ip="93.184.216.34"):
    return ValidatedTarget(
        url=f"https://{hostname}/",
        scheme="https",
        hostname=hostname,
        resolved_ip=ip,
    )


def _make_session(**overrides):
    session = ScanSession(validated_target=_make_target())
    for k, v in overrides.items():
        setattr(session, k, v)
    return session


# ── _sanitise_headers ─────────────────────────────────────────────────────────

class TestSanitiseHeaders:
    def test_forbidden_headers_stripped(self):
        extra = {
            "Authorization": "Bearer token123",
            "Cookie": "session=abc",
            "X-Api-Key": "secret",
            "Accept": "text/html",  # allowed
        }
        result = _sanitise_headers(extra)
        assert "Authorization" not in result
        assert "Cookie" not in result
        assert "X-Api-Key" not in result
        assert result["Accept"] == "text/html"

    def test_default_headers_always_present(self):
        result = _sanitise_headers(None)
        assert "User-Agent" in result
        assert "Accept" in result

    def test_none_extra_returns_defaults(self):
        result = _sanitise_headers(None)
        for k in _SAFE_REQUEST_HEADERS:
            assert k in result


# ── ScanSession limits ────────────────────────────────────────────────────────

class TestScanSessionLimits:
    def test_request_limit_raises(self):
        session = _make_session(max_requests=2)
        session.request_count = 2
        with pytest.raises(RuntimeError, match="Request limit"):
            session.check_limits()

    def test_duration_limit_raises(self, mocker):
        import time
        session = _make_session(max_duration=0.0)
        # Start time in the past
        session.start_time = time.monotonic() - 1.0
        with pytest.raises(RuntimeError, match="duration"):
            session.check_limits()

    def test_within_limits_no_raise(self):
        session = _make_session(max_requests=10)
        session.request_count = 3
        session.check_limits()  # Should not raise


# ── fetch_response ────────────────────────────────────────────────────────────

def _mock_requests_get(status_code=200, headers=None, is_redirect=False, location=None):
    """Create a mock requests.Response object."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    resp_headers = dict(headers or {})
    if location:
        resp_headers["location"] = location
    mock_resp.headers = resp_headers
    mock_resp.is_redirect = is_redirect
    mock_resp.raw = MagicMock()
    mock_resp.raw.read = MagicMock(return_value=b"")
    mock_resp.close = MagicMock()
    return mock_resp


class TestFetchResponse:
    def test_successful_fetch(self, mocker):
        mock_resp = _mock_requests_get(
            status_code=200,
            headers={"content-type": "text/html", "x-frame-options": "DENY"},
        )
        mocker.patch("requests.request", return_value=mock_resp)
        session = _make_session()
        result = fetch_response(session, "https://example.com/")
        assert result.status_code == 200
        assert result.headers.get("x-frame-options") == "DENY"
        assert result.error is None

    def test_headers_normalised_lowercase(self, mocker):
        mock_resp = _mock_requests_get(
            status_code=200,
            headers={"X-Content-Type-Options": "nosniff"},
        )
        mocker.patch("requests.request", return_value=mock_resp)
        session = _make_session()
        result = fetch_response(session, "https://example.com/")
        assert "x-content-type-options" in result.headers

    def test_ssl_error_returns_error_response(self, mocker):
        import requests.exceptions
        mocker.patch(
            "requests.request",
            side_effect=requests.exceptions.SSLError("cert error"),
        )
        session = _make_session()
        result = fetch_response(session, "https://example.com/")
        assert result.status_code == 0
        assert "TLS" in result.error or "cert" in result.error.lower()

    def test_timeout_returns_error_response(self, mocker):
        import requests.exceptions
        mocker.patch(
            "requests.request",
            side_effect=requests.exceptions.Timeout("timed out"),
        )
        session = _make_session()
        result = fetch_response(session, "https://example.com/")
        assert result.error is not None
        assert "Timeout" in result.error

    def test_connection_error_returns_error_response(self, mocker):
        import requests.exceptions
        mocker.patch(
            "requests.request",
            side_effect=requests.exceptions.ConnectionError("refused"),
        )
        session = _make_session()
        result = fetch_response(session, "https://example.com/")
        assert result.error is not None

    def test_request_increments_counter(self, mocker):
        mock_resp = _mock_requests_get(status_code=200)
        mocker.patch("requests.request", return_value=mock_resp)
        session = _make_session()
        assert session.request_count == 0
        fetch_response(session, "https://example.com/")
        assert session.request_count == 1

    def test_redirect_detected(self, mocker):
        mock_resp = _mock_requests_get(
            status_code=301,
            headers={"location": "https://example.com/new"},
            is_redirect=True,
            location="https://example.com/new",
        )
        mocker.patch("requests.request", return_value=mock_resp)
        session = _make_session()
        result = fetch_response(session, "https://example.com/old")
        assert result.is_redirect is True
        assert result.redirect_location == "https://example.com/new"


# ── fetch_with_redirect_chain ─────────────────────────────────────────────────

class TestFetchWithRedirectChain:
    def test_no_redirect_returns_single_response(self, mocker):
        mock_resp = _mock_requests_get(status_code=200)
        mocker.patch("requests.request", return_value=mock_resp)
        session = _make_session()
        responses, error = fetch_with_redirect_chain(session, "https://example.com/")
        assert len(responses) == 1
        assert error is None

    def test_cross_host_redirect_blocked(self, mocker):
        # First response redirects to different host
        mock_redirect = _mock_requests_get(
            status_code=301,
            headers={"location": "https://attacker.com/"},
            is_redirect=True,
            location="https://attacker.com/",
        )
        mocker.patch("requests.request", return_value=mock_redirect)
        # DNS mock for attacker.com returns valid public IP
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.2.3.4", 0))],
        )
        session = _make_session()
        responses, error = fetch_with_redirect_chain(session, "https://example.com/")
        assert error is not None
        assert "scope" in error.lower() or "cross" in error.lower()


# ── create_session ─────────────────────────────────────────────────────────────

class TestCreateSession:
    def test_defaults(self):
        target = _make_target()
        session = create_session(target)
        assert session.max_requests == 10
        assert session.verify_tls is True

    def test_config_overrides(self):
        target = _make_target()

        class FakeConfig:
            MAX_REQUESTS_PER_SCAN = 5
            MAX_SCAN_DURATION = 15.0
            REQUEST_TIMEOUT_CONNECT = 3.0
            REQUEST_TIMEOUT_READ = 7.0
            MAX_RESPONSE_SIZE = 512000
            VERIFY_TLS = False

        session = create_session(target, FakeConfig())
        assert session.max_requests == 5
        assert session.verify_tls is False
