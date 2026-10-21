"""
tests/test_https.py

Tests for scanner.https — HTTPS and redirect analyzer.

All HTTP calls are mocked; no real network access is made.
"""

import pytest
from unittest.mock import patch, MagicMock

from scanner.https import analyze_https, HTTPSAnalysisResult
from scanner.http_client import ScanSession, SafeResponse
from scanner.validator import ValidatedTarget


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_target(scheme="https"):
    hostname = "example.com"
    url = f"{scheme}://{hostname}/"
    return ValidatedTarget(
        url=url, scheme=scheme, hostname=hostname, resolved_ip="93.184.216.34"
    )


def _make_session(scheme="https"):
    return ScanSession(validated_target=_make_target(scheme))


def _make_safe_response(
    url="https://example.com/",
    status_code=200,
    headers=None,
    is_redirect=False,
    redirect_location=None,
    error=None,
):
    return SafeResponse(
        url=url,
        status_code=status_code,
        headers=dict(headers or {}),
        is_redirect=is_redirect,
        redirect_location=redirect_location,
        tls_verified=True,
        elapsed_ms=50.0,
        error=error,
    )


# ── HTTPS target ──────────────────────────────────────────────────────────────

class TestHTTPSTarget:
    def test_uses_https_true(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(
                headers={"strict-transport-security": "max-age=31536000"}
            )], None),
        )
        session = _make_session("https")
        result = analyze_https(session, "https://example.com/")
        assert result.uses_https is True

    def test_hsts_present_on_https(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(
                headers={"strict-transport-security": "max-age=31536000"}
            )], None),
        )
        session = _make_session("https")
        result = analyze_https(session, "https://example.com/")
        assert result.hsts_present is True
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-006" in rule_ids  # HSTS present finding

    def test_hsts_absent_on_https(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(headers={})], None),
        )
        session = _make_session("https")
        result = analyze_https(session, "https://example.com/")
        assert result.hsts_present is False
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-007" in rule_ids  # HSTS absent warning

    def test_tls_error_detected(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(
                error="TLS error: certificate verify failed"
            )], "TLS error: certificate verify failed"),
        )
        session = _make_session("https")
        result = analyze_https(session, "https://example.com/")
        assert result.tls_valid is False
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-005" in rule_ids

    def test_uses_https_informational_finding(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(
                headers={"strict-transport-security": "max-age=31536000"}
            )], None),
        )
        session = _make_session("https")
        result = analyze_https(session, "https://example.com/")
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-001" in rule_ids


# ── HTTP target ───────────────────────────────────────────────────────────────

class TestHTTPTarget:
    def test_uses_https_false_for_http_target(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(
                url="http://example.com/",
                status_code=301,
                is_redirect=True,
                redirect_location="https://example.com/",
            )], None),
        )
        session = _make_session("http")
        result = analyze_https(session, "http://example.com/")
        assert result.uses_https is False

    def test_http_to_https_redirect_detected(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(
                url="http://example.com/",
                status_code=301,
                is_redirect=True,
                redirect_location="https://example.com/",
            )], None),
        )
        session = _make_session("http")
        result = analyze_https(session, "http://example.com/")
        assert result.redirects_to_https is True
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-003" in rule_ids

    def test_http_no_redirect_flagged(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(
                url="http://example.com/",
                status_code=200,
            )], None),
        )
        session = _make_session("http")
        result = analyze_https(session, "http://example.com/")
        assert result.redirects_to_https is False
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-004" in rule_ids

    def test_http_target_insecure_finding(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response(status_code=200)], None),
        )
        session = _make_session("http")
        result = analyze_https(session, "http://example.com/")
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-002" in rule_ids

    def test_excessive_redirects_flagged(self, mocker):
        # 4 redirect responses → triggers HTTPS-009
        responses = [
            _make_safe_response(url=f"http://example.com/r{i}", status_code=301,
                                is_redirect=True, redirect_location=f"http://example.com/r{i+1}")
            for i in range(4)
        ]
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=(responses, "Redirect limit exceeded."),
        )
        session = _make_session("http")
        result = analyze_https(session, "http://example.com/")
        rule_ids = [f.rule_id for f in result.findings]
        assert "HTTPS-009" in rule_ids


# ── Return type ───────────────────────────────────────────────────────────────

class TestReturnType:
    def test_returns_https_analysis_result(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response()], None),
        )
        session = _make_session("https")
        result = analyze_https(session, "https://example.com/")
        assert isinstance(result, HTTPSAnalysisResult)

    def test_findings_is_list(self, mocker):
        mocker.patch(
            "scanner.https.fetch_with_redirect_chain",
            return_value=([_make_safe_response()], None),
        )
        session = _make_session("https")
        result = analyze_https(session, "https://example.com/")
        assert isinstance(result.findings, list)
