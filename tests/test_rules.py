"""
tests/test_rules.py

Tests for scanner.rules — risk classification and summary generation.
"""

import pytest
from scanner.rules import (
    classify_header_findings,
    classify_cors_findings,
    classify_https_findings,
    build_summary,
    Finding,
    SEVERITY_ORDER,
)
from scanner.headers import HeaderFinding
from scanner.cors import CORSFinding
from scanner.https import HTTPSFinding


TIMESTAMP = "2024-01-01T00:00:00+00:00"
TARGET = "https://example.com/"


# ── Helper factories ──────────────────────────────────────────────────────────

def _make_header_finding(rule_id="HDR-TEST-001", status="missing",
                          severity="Medium", header="X-Test"):
    return HeaderFinding(
        rule_id=rule_id,
        header_name=header,
        status=status,
        observed_value=None,
        severity=severity,
        confidence="High",
        title="Test header finding",
        explanation="Explanation.",
        potential_impact="Impact.",
        remediation="Fix it.",
        evidence="No header.",
    )


def _make_cors_finding(rule_id="CORS-TEST", status="potentially_risky",
                        severity="High"):
    return CORSFinding(
        rule_id=rule_id,
        status=status,
        observed_headers={},
        severity=severity,
        confidence="High",
        title="Test CORS finding",
        explanation="Explanation.",
        potential_impact="Impact.",
        remediation="Fix it.",
        evidence="Evidence.",
    )


def _make_https_finding(rule_id="HTTPS-TEST", status="insecure",
                         severity="High"):
    return HTTPSFinding(
        rule_id=rule_id,
        status=status,
        severity=severity,
        confidence="High",
        title="Test HTTPS finding",
        explanation="Explanation.",
        potential_impact="Impact.",
        remediation="Fix it.",
        evidence="Evidence.",
    )


# ── classify_header_findings ──────────────────────────────────────────────────

class TestClassifyHeaderFindings:
    def test_returns_list_of_findings(self):
        raw = [_make_header_finding()]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        assert isinstance(results, list)
        assert all(isinstance(f, Finding) for f in results)

    def test_missing_status_maps_to_potential(self):
        raw = [_make_header_finding(status="missing")]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        assert results[0].status == "potential"

    def test_present_status_maps_to_informational(self):
        raw = [_make_header_finding(status="present")]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        assert results[0].status == "informational"

    def test_deduplication(self):
        raw = [
            _make_header_finding(rule_id="HDR-SAME-001"),
            _make_header_finding(rule_id="HDR-SAME-001"),  # duplicate
        ]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        assert len(results) == 1

    def test_finding_id_is_unique_uuid(self):
        raw = [
            _make_header_finding(rule_id="HDR-A-001"),
            _make_header_finding(rule_id="HDR-B-001"),
        ]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        ids = [f.finding_id for f in results]
        assert len(set(ids)) == 2

    def test_category_is_headers(self):
        raw = [_make_header_finding()]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        assert results[0].category == "Headers"

    def test_target_url_preserved(self):
        raw = [_make_header_finding()]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        assert results[0].target_url == TARGET

    def test_invalid_severity_falls_back_to_informational(self):
        raw = [_make_header_finding(severity="SuperCritical")]
        results = classify_header_findings(raw, TARGET, TIMESTAMP)
        assert results[0].severity == "Informational"


# ── classify_cors_findings ────────────────────────────────────────────────────

class TestClassifyCORSFindings:
    def test_returns_findings(self):
        raw = [_make_cors_finding()]
        results = classify_cors_findings(raw, TARGET, TIMESTAMP)
        assert len(results) == 1
        assert results[0].category == "CORS"

    def test_potentially_risky_maps_to_potential(self):
        raw = [_make_cors_finding(status="potentially_risky")]
        results = classify_cors_findings(raw, TARGET, TIMESTAMP)
        assert results[0].status == "potential"

    def test_safe_maps_to_informational(self):
        raw = [_make_cors_finding(status="safe")]
        results = classify_cors_findings(raw, TARGET, TIMESTAMP)
        assert results[0].status == "informational"


# ── classify_https_findings ───────────────────────────────────────────────────

class TestClassifyHTTPSFindings:
    def test_returns_findings(self):
        raw = [_make_https_finding()]
        results = classify_https_findings(raw, TARGET, TIMESTAMP)
        assert len(results) == 1
        assert results[0].category == "HTTPS"

    def test_insecure_maps_to_confirmed(self):
        raw = [_make_https_finding(status="insecure")]
        results = classify_https_findings(raw, TARGET, TIMESTAMP)
        assert results[0].status == "confirmed"

    def test_secure_maps_to_informational(self):
        raw = [_make_https_finding(status="secure")]
        results = classify_https_findings(raw, TARGET, TIMESTAMP)
        assert results[0].status == "informational"


# ── build_summary ─────────────────────────────────────────────────────────────

class TestBuildSummary:
    def _make_finding(self, severity="Medium"):
        return Finding(
            finding_id="id",
            rule_id="RULE-001",
            title="T",
            category="Headers",
            severity=severity,
            confidence="High",
            status="potential",
            target_url=TARGET,
            observed_value=None,
            explanation="E",
            potential_impact="I",
            remediation="R",
            evidence="Ev",
            scan_timestamp=TIMESTAMP,
        )

    def test_empty_findings(self):
        summary = build_summary([])
        assert summary["total"] == 0
        assert summary["critical"] == 0

    def test_counts_by_severity(self):
        findings = [
            self._make_finding("Critical"),
            self._make_finding("Critical"),
            self._make_finding("High"),
            self._make_finding("Medium"),
            self._make_finding("Low"),
            self._make_finding("Informational"),
        ]
        summary = build_summary(findings)
        assert summary["total"] == 6
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["informational"] == 1

    def test_to_dict_roundtrip(self):
        finding = self._make_finding("High")
        d = finding.to_dict()
        assert d["severity"] == "High"
        assert d["rule_id"] == "RULE-001"
        assert "finding_id" in d
