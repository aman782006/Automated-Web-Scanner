"""
tests/test_routes.py

Flask route integration tests.

Uses TestingConfig (CSRF disabled for POST tests) and a mocked scan engine
so no real HTTP requests are made to external hosts.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from app import create_app
from config import TestingConfig
from scanner.engine import ScanResult
from scanner.rules import Finding, build_summary


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def app():
    application = create_app(TestingConfig())
    return application


@pytest.fixture
def client(app):
    return app.test_client()


TIMESTAMP = "2024-01-01T00:00:00+00:00"


def _make_finding(rule_id="HDR-TEST-001", severity="Medium"):
    return Finding(
        finding_id="test-finding-id-" + rule_id,
        rule_id=rule_id,
        title=f"Test Finding {rule_id}",
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


def _make_scan_result(scan_id="test-scan-id-001", status="completed",
                       findings=None):
    if findings is None:
        findings = [_make_finding()]
    return ScanResult(
        scan_id=scan_id,
        target_url="https://example.com/",
        timestamp=TIMESTAMP,
        status=status,
        http_status=200,
        findings=findings,
        summary=build_summary(findings),
        errors=[],
        redirect_chain=[],
        elapsed_s=0.5,
    )


# ── GET / ─────────────────────────────────────────────────────────────────────

class TestIndexRoute:
    def test_index_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_index_contains_scan_form(self, client):
        resp = client.get("/")
        assert b"target_url" in resp.data or b"Scan" in resp.data

    def test_index_contains_app_name(self, client):
        resp = client.get("/")
        assert b"Scanner" in resp.data


# ── POST /scan ────────────────────────────────────────────────────────────────

class TestScanRoute:
    def test_empty_url_redirects_to_index(self, client):
        resp = client.post("/scan", data={"target_url": ""})
        # Should redirect (form validation failure) or return 400
        assert resp.status_code in (302, 400)

    def test_valid_scan_redirects_to_results(self, client):
        mock_result = _make_scan_result()
        with patch("app.run_scan", return_value=mock_result):
            resp = client.post(
                "/scan",
                data={"target_url": "https://example.com/"},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert "/results/" in resp.headers["Location"]

    def test_failed_scan_redirects_to_index(self, client):
        mock_result = _make_scan_result(
            status="failed",
            findings=[],
        )
        mock_result.errors = ["Validation failed: blocked IP"]
        with patch("app.run_scan", return_value=mock_result):
            resp = client.post(
                "/scan",
                data={"target_url": "http://192.168.1.1/"},
                follow_redirects=False,
            )
        assert resp.status_code == 302

    def test_internal_exception_redirects_gracefully(self, client):
        with patch("app.run_scan", side_effect=Exception("unexpected")):
            resp = client.post(
                "/scan",
                data={"target_url": "https://example.com/"},
                follow_redirects=False,
            )
        assert resp.status_code == 302


# ── GET /results/<scan_id> ────────────────────────────────────────────────────

class TestResultsRoute:
    def _store_scan(self, client, app, result):
        """Push a scan result into the app's in-memory store via the scan route."""
        with patch("app.run_scan", return_value=result):
            client.post(
                "/scan",
                data={"target_url": result.target_url},
            )

    def test_results_page_returns_200(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, app, result)
        resp = client.get(f"/results/{result.scan_id}")
        assert resp.status_code == 200

    def test_unknown_scan_id_returns_404(self, client):
        resp = client.get("/results/nonexistent-scan-id")
        assert resp.status_code == 404

    def test_results_page_shows_target_url(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, app, result)
        resp = client.get(f"/results/{result.scan_id}")
        assert b"example.com" in resp.data

    def test_severity_filter_returns_200(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, app, result)
        resp = client.get(f"/results/{result.scan_id}?severity=High")
        assert resp.status_code == 200


# ── GET /finding/<finding_id> ─────────────────────────────────────────────────

class TestFindingDetailRoute:
    def _store_scan(self, client, result):
        with patch("app.run_scan", return_value=result):
            client.post("/scan", data={"target_url": result.target_url})

    def test_finding_detail_returns_200(self, app, client):
        finding = _make_finding("HDR-DETAIL-001")
        result = _make_scan_result(findings=[finding])
        self._store_scan(client, result)
        resp = client.get(f"/finding/{finding.finding_id}")
        assert resp.status_code == 200

    def test_unknown_finding_id_returns_404(self, client):
        resp = client.get("/finding/unknown-finding-id")
        assert resp.status_code == 404

    def test_finding_page_shows_title(self, app, client):
        finding = _make_finding("HDR-SHOW-001")
        result = _make_scan_result(findings=[finding])
        self._store_scan(client, result)
        resp = client.get(f"/finding/{finding.finding_id}")
        assert b"Test Finding" in resp.data


# ── GET /export/<scan_id>/json ────────────────────────────────────────────────

class TestExportJSONRoute:
    def _store_scan(self, client, result):
        with patch("app.run_scan", return_value=result):
            client.post("/scan", data={"target_url": result.target_url})

    def test_json_export_returns_200(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, result)
        resp = client.get(f"/export/{result.scan_id}/json")
        assert resp.status_code == 200

    def test_json_export_content_type(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, result)
        resp = client.get(f"/export/{result.scan_id}/json")
        assert "application/json" in resp.content_type

    def test_json_export_valid_json(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, result)
        resp = client.get(f"/export/{result.scan_id}/json")
        data = json.loads(resp.data)
        assert "findings" in data
        assert "summary" in data

    def test_json_export_unknown_scan_404(self, client):
        resp = client.get("/export/nonexistent/json")
        assert resp.status_code == 404


# ── GET /export/<scan_id>/pdf ─────────────────────────────────────────────────

class TestExportPDFRoute:
    def _store_scan(self, client, result):
        with patch("app.run_scan", return_value=result):
            client.post("/scan", data={"target_url": result.target_url})

    def test_pdf_export_returns_200(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, result)
        resp = client.get(f"/export/{result.scan_id}/pdf")
        assert resp.status_code == 200

    def test_pdf_export_content_type(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, result)
        resp = client.get(f"/export/{result.scan_id}/pdf")
        assert "application/pdf" in resp.content_type

    def test_pdf_starts_with_pdf_magic(self, app, client):
        result = _make_scan_result()
        self._store_scan(client, result)
        resp = client.get(f"/export/{result.scan_id}/pdf")
        assert resp.data[:4] == b"%PDF"

    def test_pdf_unknown_scan_404(self, client):
        resp = client.get("/export/nonexistent/pdf")
        assert resp.status_code == 404


# ── POST /clear-results ───────────────────────────────────────────────────────

class TestClearResultsRoute:
    def test_clear_redirects_to_index(self, client):
        resp = client.post("/clear-results", follow_redirects=False)
        assert resp.status_code == 302
        assert "/" in resp.headers["Location"]

    def test_after_clear_scan_is_gone(self, app, client):
        result = _make_scan_result()
        with patch("app.run_scan", return_value=result):
            client.post("/scan", data={"target_url": result.target_url})

        client.post("/clear-results")
        resp = client.get(f"/results/{result.scan_id}")
        assert resp.status_code == 404


# ── Error handlers ────────────────────────────────────────────────────────────

class TestErrorHandlers:
    def test_404_returns_error_page(self, client):
        resp = client.get("/this/path/does/not/exist")
        assert resp.status_code == 404
        assert b"404" in resp.data or b"not found" in resp.data.lower()
