"""
scanner/rules.py

Risk classification engine.

Converts raw analyzer findings (HeaderFinding, CORSFinding, HTTPSFinding)
into the canonical Finding structure used throughout the application.

Each Finding has a unique ID, consistent severity/confidence levels,
deduplication logic, and a complete evidence record.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Severity / Confidence constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}

CONFIDENCE_LEVELS = {"High", "Medium", "Low"}
SEVERITY_LEVELS = set(SEVERITY_ORDER.keys())

OBSERVATION_STATUSES = {
    "confirmed",
    "potential",
    "informational",
    "inconclusive",
    "error",
}


# ---------------------------------------------------------------------------
# Canonical Finding structure
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    finding_id: str           # UUID-based unique identifier
    rule_id: str              # e.g. "HDR-CSP-001"
    title: str
    category: str             # "Headers" | "CORS" | "HTTPS" | "TLS"
    severity: str
    confidence: str
    status: str               # observation status
    target_url: str
    observed_value: Optional[str]
    explanation: str
    potential_impact: str
    remediation: str
    evidence: str
    scan_timestamp: str       # ISO-8601 UTC string
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "target_url": self.target_url,
            "observed_value": self.observed_value,
            "explanation": self.explanation,
            "potential_impact": self.potential_impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "scan_timestamp": self.scan_timestamp,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# Mapping helpers – convert raw analyzer results
# ---------------------------------------------------------------------------

def _severity_valid(s: str) -> str:
    return s if s in SEVERITY_LEVELS else "Informational"


def _confidence_valid(c: str) -> str:
    return c if c in CONFIDENCE_LEVELS else "Medium"


def _obs_status_from_header_status(status: str) -> str:
    mapping = {
        "missing": "potential",
        "weak": "potential",
        "present": "informational",
        "inconclusive": "inconclusive",
    }
    return mapping.get(status, "informational")


def _obs_status_from_cors_status(status: str) -> str:
    mapping = {
        "safe": "informational",
        "potentially_risky": "potential",
        "missing": "informational",
        "inconclusive": "inconclusive",
        "error": "error",
    }
    return mapping.get(status, "informational")


def _obs_status_from_https_status(status: str) -> str:
    mapping = {
        "secure": "informational",
        "insecure": "confirmed",
        "warning": "potential",
        "informational": "informational",
        "error": "error",
    }
    return mapping.get(status, "informational")


# ---------------------------------------------------------------------------
# Public conversion functions
# ---------------------------------------------------------------------------

def classify_header_findings(
    header_findings: list,
    target_url: str,
    timestamp: str,
) -> list[Finding]:
    """Convert HeaderFinding objects into canonical Finding objects."""
    results: list[Finding] = []
    seen_rules: set[str] = set()

    for hf in header_findings:
        if hf.rule_id in seen_rules:
            continue
        seen_rules.add(hf.rule_id)

        results.append(Finding(
            finding_id=str(uuid.uuid4()),
            rule_id=hf.rule_id,
            title=hf.title,
            category="Headers",
            severity=_severity_valid(hf.severity),
            confidence=_confidence_valid(hf.confidence),
            status=_obs_status_from_header_status(hf.status),
            target_url=target_url,
            observed_value=hf.observed_value,
            explanation=hf.explanation,
            potential_impact=hf.potential_impact,
            remediation=hf.remediation,
            evidence=hf.evidence,
            scan_timestamp=timestamp,
            tags=["headers", hf.header_name.lower().replace("-", "_")],
        ))

    return results


def classify_cors_findings(
    cors_findings: list,
    target_url: str,
    timestamp: str,
) -> list[Finding]:
    """Convert CORSFinding objects into canonical Finding objects."""
    results: list[Finding] = []
    seen_rules: set[str] = set()

    for cf in cors_findings:
        if cf.rule_id in seen_rules:
            continue
        seen_rules.add(cf.rule_id)

        results.append(Finding(
            finding_id=str(uuid.uuid4()),
            rule_id=cf.rule_id,
            title=cf.title,
            category="CORS",
            severity=_severity_valid(cf.severity),
            confidence=_confidence_valid(cf.confidence),
            status=_obs_status_from_cors_status(cf.status),
            target_url=target_url,
            observed_value=str(cf.observed_headers) if cf.observed_headers else None,
            explanation=cf.explanation,
            potential_impact=cf.potential_impact,
            remediation=cf.remediation,
            evidence=cf.evidence,
            scan_timestamp=timestamp,
            tags=["cors"],
        ))

    return results


def classify_https_findings(
    https_findings: list,
    target_url: str,
    timestamp: str,
) -> list[Finding]:
    """Convert HTTPSFinding objects into canonical Finding objects."""
    results: list[Finding] = []
    seen_rules: set[str] = set()

    for hf in https_findings:
        if hf.rule_id in seen_rules:
            continue
        seen_rules.add(hf.rule_id)

        results.append(Finding(
            finding_id=str(uuid.uuid4()),
            rule_id=hf.rule_id,
            title=hf.title,
            category="HTTPS",
            severity=_severity_valid(hf.severity),
            confidence=_confidence_valid(hf.confidence),
            status=_obs_status_from_https_status(hf.status),
            target_url=target_url,
            observed_value=None,
            explanation=hf.explanation,
            potential_impact=hf.potential_impact,
            remediation=hf.remediation,
            evidence=hf.evidence,
            scan_timestamp=timestamp,
            tags=["https", "tls"],
        ))

    return results


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def build_summary(findings: list[Finding]) -> dict:
    """Return a severity-keyed count dict plus totals."""
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "total": len(findings),
        "by_severity": counts,
        "critical": counts.get("Critical", 0),
        "high": counts.get("High", 0),
        "medium": counts.get("Medium", 0),
        "low": counts.get("Low", 0),
        "informational": counts.get("Informational", 0),
    }
