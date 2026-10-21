"""
app.py

Flask application entry point.

Routes
------
GET  /                      — Main dashboard
POST /scan                  — Submit a scan
GET  /results/<scan_id>     — View scan results
GET  /finding/<finding_id>  — View finding details
GET  /export/<scan_id>/json — Download JSON report
GET  /export/<scan_id>/pdf  — Download PDF report
POST /clear-results         — Clear all in-memory results

In-memory storage
-----------------
All scan results are held in a module-level dictionary protected by a
threading.Lock.  Results are lost when the application restarts and are
not shared across multiple worker processes.  See store.py for details.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Optional

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField
from wtforms.validators import DataRequired, Length, URL

from config import get_config
from scanner.engine import run_scan, ScanResult
from reports.json_report import generate_json_report, safe_filename as json_filename
from reports.pdf_report import generate_pdf_report, safe_filename as pdf_filename


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(config=None) -> Flask:
    app = Flask(__name__)

    cfg = config or get_config()
    app.config.from_object(cfg)

    csrf = CSRFProtect(app)

    # ------------------------------------------------------------------ #
    # In-memory scan store
    # ------------------------------------------------------------------ #

    _store_lock = threading.Lock()
    # OrderedDict preserves insertion order for "recent scans" display
    _scan_store: OrderedDict[str, ScanResult] = OrderedDict()
    _finding_index: dict[str, ScanResult] = {}   # finding_id → ScanResult
    MAX_SCANS = app.config.get("MAX_STORED_SCANS", 20)

    def _store_result(result: ScanResult) -> None:
        with _store_lock:
            _scan_store[result.scan_id] = result
            for f in result.findings:
                _finding_index[f.finding_id] = result
            # Evict oldest entries beyond MAX_SCANS
            while len(_scan_store) > MAX_SCANS:
                oldest_id, oldest = next(iter(_scan_store.items()))
                for f in oldest.findings:
                    _finding_index.pop(f.finding_id, None)
                del _scan_store[oldest_id]

    def _get_result(scan_id: str) -> Optional[ScanResult]:
        with _store_lock:
            return _scan_store.get(scan_id)

    def _get_finding(finding_id: str) -> Optional[tuple[ScanResult, object]]:
        with _store_lock:
            result = _finding_index.get(finding_id)
            if not result:
                return None
            for f in result.findings:
                if f.finding_id == finding_id:
                    return result, f
            return None

    def _clear_all() -> None:
        with _store_lock:
            _scan_store.clear()
            _finding_index.clear()

    def _recent_scans(limit: int = 10) -> list[ScanResult]:
        with _store_lock:
            items = list(_scan_store.values())
        return list(reversed(items))[:limit]

    # ------------------------------------------------------------------ #
    # WTForms
    # ------------------------------------------------------------------ #

    class ScanForm(FlaskForm):
        target_url = StringField(
            "Target URL",
            validators=[
                DataRequired(message="Please enter a URL."),
                Length(min=7, max=2048, message="URL must be between 7 and 2048 characters."),
            ],
        )

    # ------------------------------------------------------------------ #
    # Template context helpers
    # ------------------------------------------------------------------ #

    @app.context_processor
    def inject_globals():
        return {
            "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "app_name": "Automated Web Security Scanner",
        }

    # ------------------------------------------------------------------ #
    # Routes
    # ------------------------------------------------------------------ #

    @app.route("/", methods=["GET"])
    def index():
        form = ScanForm()
        recent = _recent_scans(10)

        # Aggregate stats across all in-memory scans
        total_scans = len(_scan_store)
        total_findings = sum(r.summary.get("total", 0) for r in _scan_store.values())
        severity_totals = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0
        }
        for r in _scan_store.values():
            for sev, cnt in r.summary.get("by_severity", {}).items():
                severity_totals[sev] = severity_totals.get(sev, 0) + cnt

        return render_template(
            "index.html",
            form=form,
            recent_scans=recent,
            stats={
                "total_scans": total_scans,
                "total_findings": total_findings,
                "severity_totals": severity_totals,
            },
        )

    @app.route("/scan", methods=["POST"])
    def scan():
        form = ScanForm()
        if not form.validate_on_submit():
            errors = "; ".join(
                e for field_errors in form.errors.values()
                for e in field_errors
            )
            flash(f"Invalid input: {errors}", "danger")
            return redirect(url_for("index"))

        raw_url = form.target_url.data.strip()

        try:
            result = run_scan(raw_url, config=cfg)
        except Exception as exc:
            flash(f"Scan failed unexpectedly: {exc}", "danger")
            return redirect(url_for("index"))

        if result.status == "failed":
            flash(
                f"Scan could not be completed: {'; '.join(result.errors)}",
                "danger",
            )
            return redirect(url_for("index"))

        _store_result(result)
        return redirect(url_for("results", scan_id=result.scan_id))

    @app.route("/results/<scan_id>", methods=["GET"])
    def results(scan_id: str):
        result = _get_result(scan_id)
        if result is None:
            abort(404)

        severity_filter = request.args.get("severity", "").strip()
        category_filter = request.args.get("category", "").strip()
        search_q = request.args.get("q", "").strip().lower()

        findings = result.findings

        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]
        if category_filter:
            findings = [f for f in findings if f.category == category_filter]
        if search_q:
            findings = [f for f in findings
                        if search_q in f.title.lower() or search_q in f.rule_id.lower()]

        # Sort by severity
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        findings_sorted = sorted(findings, key=lambda f: (sev_order.get(f.severity, 9), f.rule_id))

        categories = sorted({f.category for f in result.findings})
        severities = ["Critical", "High", "Medium", "Low", "Informational"]

        return render_template(
            "results.html",
            result=result,
            findings=findings_sorted,
            categories=categories,
            severities=severities,
            current_severity=severity_filter,
            current_category=category_filter,
            search_q=search_q,
        )

    @app.route("/finding/<finding_id>", methods=["GET"])
    def finding_detail(finding_id: str):
        pair = _get_finding(finding_id)
        if pair is None:
            abort(404)
        result, finding = pair
        return render_template("finding_details.html", result=result, finding=finding)

    @app.route("/export/<scan_id>/json", methods=["GET"])
    def export_json(scan_id: str):
        result = _get_result(scan_id)
        if result is None:
            abort(404)
        json_str = generate_json_report(result)
        response = make_response(json_str)
        fname = json_filename(scan_id)
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
        return response

    @app.route("/export/<scan_id>/pdf", methods=["GET"])
    def export_pdf(scan_id: str):
        result = _get_result(scan_id)
        if result is None:
            abort(404)
        try:
            pdf_bytes = generate_pdf_report(result)
        except Exception as exc:
            abort(500, description=f"PDF generation failed: {exc}")
        fname = pdf_filename(scan_id)
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
        return response

    @app.route("/clear-results", methods=["POST"])
    def clear_results():
        _clear_all()
        flash("All scan results have been cleared.", "success")
        return redirect(url_for("index"))

    # ------------------------------------------------------------------ #
    # Error handlers
    # ------------------------------------------------------------------ #

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="The requested resource was not found.",
                               description=str(e)), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500,
                               message="An internal server error occurred.",
                               description=str(e)), 500

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400,
                               message="Bad request.",
                               description=str(e)), 400

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
