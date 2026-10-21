"""
tests/test_cors.py

Tests for scanner.cors — CORS misconfiguration analyzer.
"""

import pytest
from scanner.cors import analyze_cors, CORSFinding


def _h(**kwargs) -> dict:
    return {k.lower(): v for k, v in kwargs.items()}


class TestNoCORSHeaders:
    def test_no_cors_headers_returns_informational(self):
        findings = analyze_cors(_h())
        assert len(findings) == 1
        f = findings[0]
        assert f.status == "missing"
        assert f.severity == "Informational"
        assert f.rule_id == "CORS-000"

    def test_message_explains_same_origin_policy(self):
        findings = analyze_cors(_h())
        assert "same-origin" in findings[0].explanation.lower()


class TestWildcardWithCredentials:
    def test_wildcard_with_credentials_flagged(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }))
        rules = [f.rule_id for f in findings]
        assert "CORS-001" in rules

    def test_wildcard_with_credentials_medium_severity(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }))
        f = next(f for f in findings if f.rule_id == "CORS-001")
        assert f.severity == "Medium"


class TestNullOrigin:
    def test_null_origin_flagged(self):
        findings = analyze_cors(_h(**{"Access-Control-Allow-Origin": "null"}))
        rules = [f.rule_id for f in findings]
        assert "CORS-002" in rules

    def test_null_origin_with_credentials_high_severity(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        }))
        f = next(f for f in findings if f.rule_id == "CORS-002")
        assert f.severity == "High"

    def test_null_origin_without_credentials_medium_severity(self):
        findings = analyze_cors(_h(**{"Access-Control-Allow-Origin": "null"}))
        f = next(f for f in findings if f.rule_id == "CORS-002")
        assert f.severity == "Medium"


class TestWildcardNoCredentials:
    def test_wildcard_without_credentials_is_informational(self):
        findings = analyze_cors(_h(**{"Access-Control-Allow-Origin": "*"}))
        # Should NOT produce CORS-001 (that requires credentials)
        rules = [f.rule_id for f in findings]
        assert "CORS-001" not in rules
        # Should produce CORS-003 (informational note)
        assert "CORS-003" in rules

    def test_wildcard_no_credentials_severity(self):
        findings = analyze_cors(_h(**{"Access-Control-Allow-Origin": "*"}))
        f = next(f for f in findings if f.rule_id == "CORS-003")
        assert f.severity == "Informational"


class TestDangerousMethods:
    def test_delete_method_flagged(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Methods": "GET, POST, DELETE",
        }))
        rules = [f.rule_id for f in findings]
        assert "CORS-004" in rules

    def test_safe_methods_not_flagged(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Methods": "GET, POST",
        }))
        rules = [f.rule_id for f in findings]
        assert "CORS-004" not in rules

    def test_delete_with_credentials_higher_severity(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Methods": "DELETE",
            "Access-Control-Allow-Credentials": "true",
        }))
        f = next(f for f in findings if f.rule_id == "CORS-004")
        assert f.severity == "Medium"


class TestMissingVary:
    def test_missing_vary_flagged_for_specific_origin(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "https://trusted.example.com",
        }))
        rules = [f.rule_id for f in findings]
        assert "CORS-005" in rules

    def test_present_vary_not_flagged(self):
        findings = analyze_cors(_h(**{
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Vary": "Origin, Accept-Encoding",
        }))
        rules = [f.rule_id for f in findings]
        assert "CORS-005" not in rules

    def test_wildcard_does_not_trigger_vary_check(self):
        findings = analyze_cors(_h(**{"Access-Control-Allow-Origin": "*"}))
        rules = [f.rule_id for f in findings]
        assert "CORS-005" not in rules


class TestReturnType:
    def test_returns_list(self):
        assert isinstance(analyze_cors({}), list)

    def test_each_item_is_cors_finding(self):
        findings = analyze_cors({})
        assert all(isinstance(f, CORSFinding) for f in findings)
