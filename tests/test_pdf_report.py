"""
tests/test_pdf_report.py

Tests for reports.pdf_report — PDF report generation.
"""

import pytest

from scanner.engine import ScanResult
from scanner.rules import Finding, build_summary
from reports.pdf_report import generate_pdf_report, safe_filename


TIMESTAMP = "2024-01-01T00:00:00+00:00"


def _make_finding(rule_id="HDR-PDF-001", severity="High"):
    return Finding(
        finding_id="finding-" + rule_id,
        rule_id=rule_id,
        title=f"PDF Finding {rule_id}",
        category="Headers",
        severity=severity,
        confidence="High",
        status="potential",
        target_url="https://example.com/",
        observed_value="observed-value",
        explanation="This is the explanation.",
        potential_impact="Potential impact description.",
        remediation="How to fix it.",
        evidence="Evidence text here.",
        scan_timestamp=TIMESTAMP,
        tags=["headers"],
    )


def _make_result(findings=None, status="completed"):
    if findings is None:
        findings = [_make_finding()]
    return ScanResult(
        scan_id="scan-pdf-001",
        target_url="https://example.com/",
        timestamp=TIMESTAMP,
        status=status,
        http_status=200,
        findings=findings,
        summary=build_summary(findings),
        errors=[],
        redirect_chain=[],
        elapsed_s=1.0,
    )


class TestGeneratePDFReport:
    def test_returns_bytes(self):
        result = _make_result()
        output = generate_pdf_report(result)
        assert isinstance(output, bytes)

    def test_output_starts_with_pdf_magic(self):
        result = _make_result()
        output = generate_pdf_report(result)
        assert output[:4] == b"%PDF"

    def test_non_empty_output(self):
        result = _make_result()
        output = generate_pdf_report(result)
        assert len(output) > 1000  # A real PDF is at minimum several KB

    def test_empty_findings_generates_pdf(self):
        result = _make_result(findings=[])
        output = generate_pdf_report(result)
        assert output[:4] == b"%PDF"

    def test_partial_status_generates_pdf(self):
        result = _make_result(status="partial")
        output = generate_pdf_report(result)
        assert output[:4] == b"%PDF"

    def test_multiple_findings_generates_pdf(self):
        findings = [
            _make_finding("RULE-A", "Critical"),
            _make_finding("RULE-B", "High"),
            _make_finding("RULE-C", "Medium"),
            _make_finding("RULE-D", "Low"),
            _make_finding("RULE-E", "Informational"),
        ]
        result = _make_result(findings=findings)
        output = generate_pdf_report(result)
        assert output[:4] == b"%PDF"

    def test_special_characters_in_text(self):
        """Ensure XML-special characters in findings don't crash ReportLab."""
        finding = Finding(
            finding_id="special-id",
            rule_id="RULE-SPECIAL",
            title="Finding with <tags> & 'quotes' and \"double quotes\"",
            category="Headers",
            severity="Medium",
            confidence="Medium",
            status="potential",
            target_url="https://example.com/",
            observed_value="value with <html> & ampersand",
            explanation="Explanation with <b>tags</b> & special chars.",
            potential_impact="Impact < 100%",
            remediation="Use & encode properly.",
            evidence="Evidence: key=value&other=value",
            scan_timestamp=TIMESTAMP,
        )
        result = _make_result(findings=[finding])
        output = generate_pdf_report(result)
        assert output[:4] == b"%PDF"

    def test_long_text_does_not_crash(self):
        """Very long text fields should not crash PDF generation."""
        long_text = "A" * 5000
        finding = _make_finding()
        finding = Finding(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            status=finding.status,
            target_url=finding.target_url,
            observed_value=long_text,
            explanation=long_text,
            potential_impact=long_text,
            remediation=long_text,
            evidence=long_text,
            scan_timestamp=finding.scan_timestamp,
        )
        result = _make_result(findings=[finding])
        output = generate_pdf_report(result)
        assert output[:4] == b"%PDF"


class TestSafePDFFilename:
    def test_returns_pdf_extension(self):
        assert safe_filename("abc-123").endswith(".pdf")

    def test_strips_special_chars(self):
        name = safe_filename("abc/../../etc/passwd")
        assert "/" not in name
        assert ".." not in name
