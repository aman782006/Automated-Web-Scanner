"""
scanner/engine.py

Scan orchestrator.

Coordinates validation → HTTP fetch → header analysis → CORS analysis
→ HTTPS analysis → risk classification → structured result.

Partial failures in individual analyzers do not crash the scan; they are
recorded and the scan status is set to "partial".

No database, no file I/O, no credentials.  Results are returned as plain
Python dicts / dataclasses for the caller to store in memory.
"""

from __future__ import annotations

import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Optional

from config import get_config
from scanner.validator import validate_target, ValidationError
from scanner.http_client import create_session, fetch_response
from scanner.headers import analyze_headers
from scanner.cors import analyze_cors
from scanner.https import analyze_https
from scanner.rules import (
    classify_header_findings,
    classify_cors_findings,
    classify_https_findings,
    build_summary,
    Finding,
)


# ---------------------------------------------------------------------------
# Scan result structure
# ---------------------------------------------------------------------------

class ScanResult:
    """Complete result of a single scan run."""

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        timestamp: str,
        status: str,          # "completed" | "partial" | "failed"
        http_status: Optional[int],
        findings: list[Finding],
        summary: dict,
        errors: list[str],
        redirect_chain: list[dict],
        elapsed_s: float,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.timestamp = timestamp
        self.status = status
        self.http_status = http_status
        self.findings = findings
        self.summary = summary
        self.errors = errors
        self.redirect_chain = redirect_chain
        self.elapsed_s = round(elapsed_s, 2)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "status": self.status,
            "http_status": self.http_status,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "redirect_chain": self.redirect_chain,
            "elapsed_s": self.elapsed_s,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def run_scan(raw_url: str, config=None) -> ScanResult:
    """
    Execute a full scan against *raw_url*.

    1. Validate the URL (SSRF protection).
    2. Create a safe HTTP session.
    3. Fetch the target page headers.
    4. Run header analyzer.
    5. Run CORS analyzer.
    6. Run HTTPS/redirect analyzer.
    7. Classify findings via the rules engine.
    8. Return a :class:`ScanResult`.

    Partial failures are caught per-module and do not abort the scan.
    """
    if config is None:
        config = get_config()

    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    start_time = time.monotonic()
    errors: list[str] = []
    all_findings: list[Finding] = []
    http_status: Optional[int] = None
    redirect_chain: list[dict] = []

    # ------------------------------------------------------------------ #
    # Step 1 – Validate the submitted URL
    # ------------------------------------------------------------------ #
    try:
        validated = validate_target(raw_url)
    except ValidationError as exc:
        return ScanResult(
            scan_id=scan_id,
            target_url=raw_url,
            timestamp=timestamp,
            status="failed",
            http_status=None,
            findings=[],
            summary=build_summary([]),
            errors=[f"Validation failed: {exc}"],
            redirect_chain=[],
            elapsed_s=time.monotonic() - start_time,
        )

    target_url = validated.url

    # ------------------------------------------------------------------ #
    # Step 2 – Create a safe HTTP session
    # ------------------------------------------------------------------ #
    session = create_session(validated, config)

    # ------------------------------------------------------------------ #
    # Step 3 – Fetch response headers
    # ------------------------------------------------------------------ #
    initial_response = fetch_response(session, target_url)

    if initial_response.error:
        errors.append(f"Initial fetch error: {initial_response.error}")
        # Proceed with empty headers but mark partial
        response_headers: dict = {}
        status_flag = "partial"
    else:
        response_headers = initial_response.headers
        http_status = initial_response.status_code
        status_flag = "completed"

    # ------------------------------------------------------------------ #
    # Step 4 – Header analysis
    # ------------------------------------------------------------------ #
    try:
        header_raw = analyze_headers(response_headers)
        all_findings += classify_header_findings(header_raw, target_url, timestamp)
    except Exception as exc:
        errors.append(f"Header analysis error: {exc}")
        if config.DEBUG:
            errors.append(traceback.format_exc())
        status_flag = "partial"

    # ------------------------------------------------------------------ #
    # Step 5 – CORS analysis
    # ------------------------------------------------------------------ #
    try:
        cors_raw = analyze_cors(response_headers)
        all_findings += classify_cors_findings(cors_raw, target_url, timestamp)
    except Exception as exc:
        errors.append(f"CORS analysis error: {exc}")
        if config.DEBUG:
            errors.append(traceback.format_exc())
        status_flag = "partial"

    # ------------------------------------------------------------------ #
    # Step 6 – HTTPS / redirect analysis
    # ------------------------------------------------------------------ #
    try:
        https_result = analyze_https(session, target_url)
        redirect_chain = https_result.redirect_chain
        all_findings += classify_https_findings(
            https_result.findings, target_url, timestamp
        )
        if https_result.error:
            errors.append(f"HTTPS analysis warning: {https_result.error}")
    except Exception as exc:
        errors.append(f"HTTPS analysis error: {exc}")
        if config.DEBUG:
            errors.append(traceback.format_exc())
        status_flag = "partial"

    # ------------------------------------------------------------------ #
    # Step 7 – Deduplicate findings by rule_id + target_url
    # ------------------------------------------------------------------ #
    seen: set[str] = set()
    unique_findings: list[Finding] = []
    for f in all_findings:
        key = f"{f.rule_id}:{f.target_url}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    elapsed_s = time.monotonic() - start_time

    if elapsed_s > getattr(config, "MAX_SCAN_DURATION", 30):
        errors.append("Scan duration limit exceeded; some checks may be incomplete.")
        status_flag = "partial"

    return ScanResult(
        scan_id=scan_id,
        target_url=target_url,
        timestamp=timestamp,
        status=status_flag,
        http_status=http_status,
        findings=unique_findings,
        summary=build_summary(unique_findings),
        errors=errors,
        redirect_chain=redirect_chain,
        elapsed_s=elapsed_s,
    )
