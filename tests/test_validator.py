"""
tests/test_validator.py

Tests for scanner.validator — URL validation and SSRF protection.
"""

import pytest
from scanner.validator import (
    validate_target,
    validate_redirect_target,
    ValidationError,
    _is_blocked_ip,
    _normalise_url,
)


# ── _is_blocked_ip ────────────────────────────────────────────────────────────

class TestBlockedIPs:
    def test_loopback_ipv4(self):
        assert _is_blocked_ip("127.0.0.1") is True

    def test_loopback_ipv6(self):
        assert _is_blocked_ip("::1") is True

    def test_private_10(self):
        assert _is_blocked_ip("10.0.0.1") is True

    def test_private_172(self):
        assert _is_blocked_ip("172.16.5.5") is True

    def test_private_192(self):
        assert _is_blocked_ip("192.168.1.1") is True

    def test_link_local(self):
        assert _is_blocked_ip("169.254.0.1") is True

    def test_multicast(self):
        assert _is_blocked_ip("224.0.0.1") is True

    def test_documentation_range(self):
        assert _is_blocked_ip("192.0.2.1") is True

    def test_public_ipv4_not_blocked(self):
        assert _is_blocked_ip("8.8.8.8") is False

    def test_public_ipv4_cloudflare(self):
        assert _is_blocked_ip("1.1.1.1") is False


# ── _normalise_url ────────────────────────────────────────────────────────────

class TestNormaliseURL:
    def test_http_accepted(self):
        url, scheme, host = _normalise_url("http://example.com/path")
        assert scheme == "http"
        assert host == "example.com"

    def test_https_accepted(self):
        url, scheme, host = _normalise_url("https://example.com")
        assert scheme == "https"

    def test_ftp_rejected(self):
        with pytest.raises(ValidationError, match="scheme"):
            _normalise_url("ftp://example.com")

    def test_file_rejected(self):
        with pytest.raises(ValidationError):
            _normalise_url("file:///etc/passwd")

    def test_no_hostname_rejected(self):
        with pytest.raises(ValidationError, match="hostname"):
            _normalise_url("http://")

    def test_url_too_long(self):
        with pytest.raises(ValidationError, match="length"):
            _normalise_url("http://example.com/" + "a" * 3000)

    def test_credentials_stripped(self):
        url, scheme, host = _normalise_url("http://user:pass@example.com/")
        assert "user" not in url
        assert "pass" not in url

    def test_fragment_stripped(self):
        url, scheme, host = _normalise_url("http://example.com/page#section")
        assert "#section" not in url

    def test_private_ip_literal_rejected(self):
        with pytest.raises(ValidationError, match="blocked"):
            _normalise_url("http://192.168.1.1/admin")

    def test_loopback_ip_literal_rejected(self):
        with pytest.raises(ValidationError, match="blocked"):
            _normalise_url("http://127.0.0.1/")


# ── validate_target (mocked DNS) ─────────────────────────────────────────────

class TestValidateTarget:
    def test_valid_url_succeeds(self, mocker):
        # Patch DNS so we don't make real network calls in tests
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 0))],
        )
        result = validate_target("https://example.com/path")
        assert result.scheme == "https"
        assert result.hostname == "example.com"
        assert result.resolved_ip == "93.184.216.34"

    def test_private_resolved_ip_blocked(self, mocker):
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("192.168.1.5", 0))],
        )
        with pytest.raises(ValidationError, match="blocked"):
            validate_target("https://internal.example.com/")

    def test_dns_failure_raises(self, mocker):
        import socket as sock
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            side_effect=sock.gaierror("NXDOMAIN"),
        )
        with pytest.raises(ValidationError, match="DNS"):
            validate_target("https://this-domain-does-not-exist-xyz.invalid/")

    def test_empty_url_rejected(self):
        with pytest.raises(ValidationError):
            validate_target("")

    def test_http_url_accepted(self, mocker):
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 0))],
        )
        result = validate_target("http://example.com")
        assert result.scheme == "http"


# ── validate_redirect_target ─────────────────────────────────────────────────

class TestValidateRedirectTarget:
    def test_same_host_accepted(self, mocker):
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 0))],
        )
        result = validate_redirect_target(
            "https://example.com/new-path", "example.com"
        )
        assert result.hostname == "example.com"

    def test_cross_host_redirect_blocked(self, mocker):
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.2.3.4", 0))],
        )
        with pytest.raises(ValidationError, match="scope"):
            validate_redirect_target(
                "https://attacker.com/steal", "example.com"
            )

    def test_redirect_to_private_blocked(self, mocker):
        mocker.patch(
            "scanner.validator.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("10.0.0.1", 0))],
        )
        with pytest.raises(ValidationError):
            validate_redirect_target(
                "https://internal.example.com/", "internal.example.com"
            )
