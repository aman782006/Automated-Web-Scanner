"""
tests/test_json_report.py

Tests for reports.json_report — JSON export generation.
"""

import json
import pytest

from scanner.engine import ScanResult
from scanner.rules import Finding, build_summary
from reports.json_report import generate_json_report, safe_filename


TIMESTAMP = "2024-01-01T00:00:00+00:00"


def _make_finding(rule_id="HDR-TEST-001", severity="High"):
    return Finding(
        finding_id="finding-id-" + rule_id,
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        category="Headers",
        severity=severity,
        confidence="High",
        status="potential",
        target_url="https://example.com/",
        observed_value=None,
        explanation="Explanation.",
        potential_impact="Impact.",
        remediation="Remediation.",
        evidence="Evidence.",
        scan_timestamp=TIMESTAMP,
        tags=["headers"],
    )


def _make_result(findings=None, status="completed"):
    if findings is None:
        findings = [_make_finding()]
    return ScanResult(
        scan_id="scan-id-001",
        target_url="https://example.com/",
        timestamp=TIMESTAMP,
        status=status,
        http_status=200,
        findings=findings,
        summary=build_summary(findings),
        errors=[],
        redirect_chain=[],
        elapsed_s=1.5,
    )


class TestGenerateJSONReport:
    def test_returns_valid_json(self):
        result = _make_result()
        output = generate_json_report(result)
        data = json.loads(output)  # must not raise
        assert isinstance(data, dict)

    def test_contains_required_top_level_keys(self):
        result = _make_result()
        data = json.loads(generate_json_report(result))
        for key in ("report_metadata", "scan_metadata", "summary", "findings",
                    "disclaimer", "limitations"):
            assert key in data, f"Missing key: {key}"

    def test_target_url_in_output(self):
        result = _make_result()
        data = json.loads(generate_json_report(result))
        assert data["scan_metadata"]["target_url"] == "https://example.com/"

    def test_findings_list_populated(self):
        result = _make_result()
        data = json.loads(generate_json_report(result))
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "HDR-TEST-001"

    def test_empty_findings(self):
        result = _make_result(findings=[])
        data = json.loads(generate_json_report(result))
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0

    def test_scan_status_preserved(self):
        result = _make_result(status="partial")
        data = json.loads(generate_json_report(result))
        assert data["scan_metadata"]["scan_status"] == "partial"

    def test_disclaimer_present(self):
        result = _make_result()
        data = json.loads(generate_json_report(result))
        assert len(data["disclaimer"]) > 10

    def test_severity_counts_match(self):
        findings = [
            _make_finding("A", "High"),
            _make_finding("B", "Medium"),
            _make_finding("C", "Medium"),
        ]
        result = _make_result(findings=findings)
        data = json.loads(generate_json_report(result))
        assert data["summary"]["high"] == 1
        assert data["summary"]["medium"] == 2

    def test_no_credentials_in_output(self):
        result = _make_result()
        output = generate_json_report(result)
        # None of these should appear
        for sensitive in ("password", "api_key", "authorization", "cookie"):
            assert sensitive not in output.lower()


class TestSafeFilename:
    def test_returns_json_extension(self):
        assert safe_filename("abc-123").endswith(".json")

    def test_strips_special_chars(self):
        name = safe_filename("abc/../../etc/passwd")
        assert "/" not in name
        assert ".." not in name

    def test_max_length(self):
        long_id = "a" * 100
        name = safe_filename(long_id)
        assert len(name) <= 60
