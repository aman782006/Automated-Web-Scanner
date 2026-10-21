"""
tests/test_headers.py

Tests for scanner.headers — HTTP security header analyzer.
"""

import pytest
from scanner.headers import analyze_headers, HeaderFinding


def _h(**kwargs) -> dict:
    """Build a lowercase-key headers dict."""
    return {k.lower(): v for k, v in kwargs.items()}


class TestCSPCheck:
    def test_missing_csp(self):
        findings = analyze_headers(_h())
        csp = next(f for f in findings if f.header_name == "Content-Security-Policy")
        assert csp.status == "missing"
        assert csp.severity == "Medium"
        assert csp.rule_id == "HDR-CSP-001"

    def test_present_safe_csp(self):
        findings = analyze_headers(_h(**{"Content-Security-Policy": "default-src 'self'"}))
        csp = next(f for f in findings if f.header_name == "Content-Security-Policy")
        assert csp.status == "present"
        assert csp.severity == "Informational"

    def test_unsafe_inline_csp(self):
        findings = analyze_headers(_h(**{"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}))
        csp = next(f for f in findings if f.header_name == "Content-Security-Policy")
        assert csp.status == "weak"
        assert "unsafe-inline" in csp.evidence

    def test_unsafe_eval_csp(self):
        findings = analyze_headers(_h(**{"Content-Security-Policy": "script-src 'unsafe-eval'"}))
        csp = next(f for f in findings if f.header_name == "Content-Security-Policy")
        assert csp.status == "weak"


class TestHSTSCheck:
    def test_missing_hsts(self):
        findings = analyze_headers(_h())
        hsts = next(f for f in findings if f.header_name == "Strict-Transport-Security")
        assert hsts.status == "missing"
        assert hsts.severity == "Medium"

    def test_good_hsts(self):
        findings = analyze_headers(_h(**{"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}))
        hsts = next(f for f in findings if f.header_name == "Strict-Transport-Security")
        assert hsts.status == "present"
        assert hsts.severity == "Informational"

    def test_short_max_age_hsts(self):
        findings = analyze_headers(_h(**{"Strict-Transport-Security": "max-age=60"}))
        hsts = next(f for f in findings if f.header_name == "Strict-Transport-Security")
        assert hsts.status == "weak"

    def test_zero_max_age_hsts(self):
        findings = analyze_headers(_h(**{"Strict-Transport-Security": "max-age=0"}))
        hsts = next(f for f in findings if f.header_name == "Strict-Transport-Security")
        assert hsts.status == "weak"


class TestXContentTypeCheck:
    def test_missing_xcto(self):
        findings = analyze_headers(_h())
        xcto = next(f for f in findings if f.header_name == "X-Content-Type-Options")
        assert xcto.status == "missing"
        assert xcto.severity == "Low"

    def test_correct_nosniff(self):
        findings = analyze_headers(_h(**{"X-Content-Type-Options": "nosniff"}))
        xcto = next(f for f in findings if f.header_name == "X-Content-Type-Options")
        assert xcto.status == "present"

    def test_wrong_value(self):
        findings = analyze_headers(_h(**{"X-Content-Type-Options": "sniff"}))
        xcto = next(f for f in findings if f.header_name == "X-Content-Type-Options")
        assert xcto.status == "weak"


class TestXFrameOptionsCheck:
    def test_missing_no_csp(self):
        findings = analyze_headers(_h())
        xfo = next(f for f in findings if f.header_name == "X-Frame-Options")
        assert xfo.status == "missing"
        assert xfo.severity == "Medium"

    def test_deny_valid(self):
        findings = analyze_headers(_h(**{"X-Frame-Options": "DENY"}))
        xfo = next(f for f in findings if f.header_name == "X-Frame-Options")
        assert xfo.status == "present"

    def test_sameorigin_valid(self):
        findings = analyze_headers(_h(**{"X-Frame-Options": "SAMEORIGIN"}))
        xfo = next(f for f in findings if f.header_name == "X-Frame-Options")
        assert xfo.status == "present"

    def test_missing_with_csp_frame_ancestors(self):
        findings = analyze_headers(_h(**{
            "Content-Security-Policy": "frame-ancestors 'none'"
        }))
        xfo = next(f for f in findings if f.header_name == "X-Frame-Options")
        assert xfo.status == "inconclusive"
        assert xfo.severity == "Informational"

    def test_invalid_value(self):
        findings = analyze_headers(_h(**{"X-Frame-Options": "ALLOWALL"}))
        xfo = next(f for f in findings if f.header_name == "X-Frame-Options")
        assert xfo.status == "weak"


class TestReferrerPolicyCheck:
    def test_missing(self):
        findings = analyze_headers(_h())
        rp = next(f for f in findings if f.header_name == "Referrer-Policy")
        assert rp.status == "missing"

    def test_strict_value(self):
        findings = analyze_headers(_h(**{"Referrer-Policy": "strict-origin-when-cross-origin"}))
        rp = next(f for f in findings if f.header_name == "Referrer-Policy")
        assert rp.status == "present"

    def test_unsafe_url(self):
        findings = analyze_headers(_h(**{"Referrer-Policy": "unsafe-url"}))
        rp = next(f for f in findings if f.header_name == "Referrer-Policy")
        assert rp.status == "weak"


class TestPermissionsPolicyCheck:
    def test_missing(self):
        findings = analyze_headers(_h())
        pp = next(f for f in findings if f.header_name == "Permissions-Policy")
        assert pp.status == "missing"

    def test_present(self):
        findings = analyze_headers(_h(**{"Permissions-Policy": "camera=(), microphone=()"}))
        pp = next(f for f in findings if f.header_name == "Permissions-Policy")
        assert pp.status == "present"


class TestAnalyzeHeadersReturnType:
    def test_returns_list(self):
        findings = analyze_headers({})
        assert isinstance(findings, list)

    def test_returns_six_findings(self):
        """One finding per checked header."""
        findings = analyze_headers({})
        assert len(findings) == 6

    def test_all_are_header_findings(self):
        findings = analyze_headers({})
        assert all(isinstance(f, HeaderFinding) for f in findings)
