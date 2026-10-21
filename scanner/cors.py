"""
scanner/cors.py

Analyzes Cross-Origin Resource Sharing (CORS) headers for potentially
risky configurations.

This module inspects CORS headers present in HTTP responses.  It does NOT
attempt to retrieve private data, exploit authenticated sessions, or make
more than the minimum number of safe preflight-style requests required for
analysis.

Observations are distinguished from potential vulnerabilities.  A wildcard
origin or broad method list alone is not classified as a confirmed
vulnerability without supporting evidence.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CORSFinding:
    """Raw finding produced by the CORS analyzer before rule enrichment."""
    rule_id: str
    status: str            # "safe" | "potentially_risky" | "missing" | "inconclusive"
    observed_headers: dict
    severity: str
    confidence: str
    title: str
    explanation: str
    potential_impact: str
    remediation: str
    evidence: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_allow_origin(value: Optional[str]) -> tuple[str, bool, bool]:
    """
    Returns (normalized_value, is_wildcard, is_null).
    """
    if not value:
        return ("", False, False)
    v = value.strip()
    return (v, v == "*", v.lower() == "null")


def _is_credentials_true(value: Optional[str]) -> bool:
    return (value or "").strip().lower() == "true"


def _dangerous_methods(methods_str: Optional[str]) -> list[str]:
    if not methods_str:
        return []
    dangerous = {"DELETE", "PUT", "PATCH", "CONNECT", "TRACE"}
    methods = {m.strip().upper() for m in methods_str.split(",")}
    return sorted(methods & dangerous)


# ---------------------------------------------------------------------------
# Individual CORS checks
# ---------------------------------------------------------------------------

def _check_allow_origin_wildcard_with_credentials(
    acao: str, acac: Optional[str], observed: dict
) -> Optional[CORSFinding]:
    """
    Wildcard origin combined with credentials=true is blocked by browsers,
    but some implementations inadvertently reflect origins instead.
    """
    is_wildcard = acao.strip() == "*"
    credentials = _is_credentials_true(acac)

    if is_wildcard and credentials:
        return CORSFinding(
            rule_id="CORS-001",
            status="potentially_risky",
            observed_headers=observed,
            severity="Medium",
            confidence="High",
            title="Wildcard ACAO with Access-Control-Allow-Credentials: true",
            explanation=(
                "The response specifies Access-Control-Allow-Origin: * alongside "
                "Access-Control-Allow-Credentials: true. Modern browsers reject this "
                "combination, but it indicates a configuration error that may also "
                "affect other parts of the CORS policy. Some frameworks or proxy "
                "layers may translate this into origin reflection."
            ),
            potential_impact=(
                "If a proxy or middleware transforms the wildcard into an origin "
                "reflection, authenticated cross-origin requests from any origin "
                "would be permitted, potentially exposing user-specific data."
            ),
            remediation=(
                "If credentials must be supported, specify an explicit trusted "
                "origin instead of a wildcard:\n"
                "Access-Control-Allow-Origin: https://trusted.example.com\n"
                "Access-Control-Allow-Credentials: true\n"
                "Validate the Origin header against a server-side allowlist."
            ),
            evidence=(
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}"
            ),
        )
    return None


def _check_null_origin(acao: str, acac: Optional[str],
                        observed: dict) -> Optional[CORSFinding]:
    _, _, is_null = _parse_allow_origin(acao)
    if not is_null:
        return None

    credentials = _is_credentials_true(acac)
    severity = "High" if credentials else "Medium"
    return CORSFinding(
        rule_id="CORS-002",
        status="potentially_risky",
        observed_headers=observed,
        severity=severity,
        confidence="High",
        title="Access-Control-Allow-Origin set to 'null'",
        explanation=(
            "The server allows cross-origin requests from the 'null' origin. "
            "The 'null' origin is produced by sandboxed iframes, local files, "
            "and certain redirects. An attacker can craft a sandboxed iframe on "
            "a malicious page that sends requests with Origin: null, which the "
            "server would accept."
        ),
        potential_impact=(
            "An attacker hosting a malicious page could make credentialed requests "
            "to this server by using a sandboxed iframe, potentially bypassing "
            "same-origin protections."
            + (" With credentials permitted, this risk is elevated." if credentials else "")
        ),
        remediation=(
            "Do not allow the 'null' origin. Use an explicit allowlist of trusted "
            "origins. Validate the Origin header server-side."
        ),
        evidence=(
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac or '(absent)'}"
        ),
    )


def _check_wildcard_origin_no_credentials(
    acao: str, observed: dict
) -> Optional[CORSFinding]:
    """
    Wildcard origin without credentials is acceptable for public APIs but
    should be flagged as informational for awareness.
    """
    if acao.strip() == "*":
        return CORSFinding(
            rule_id="CORS-003",
            status="inconclusive",
            observed_headers=observed,
            severity="Informational",
            confidence="High",
            title="Access-Control-Allow-Origin: * (wildcard, no credentials)",
            explanation=(
                "The server allows cross-origin requests from any origin without "
                "credentials. This is acceptable for fully public, unauthenticated "
                "resources such as public API endpoints or CDN assets, but may be "
                "overly permissive if the resource contains any user-specific data."
            ),
            potential_impact=(
                "Any website may read the response content of this resource. "
                "This is expected for public APIs. If the resource serves private "
                "or user-specific data, this is a misconfiguration."
            ),
            remediation=(
                "Confirm that this resource is intended to be publicly accessible. "
                "If so, no change is needed. If the resource serves user-specific "
                "data, restrict Access-Control-Allow-Origin to explicit trusted origins."
            ),
            evidence=f"Access-Control-Allow-Origin: {acao}",
        )
    return None


def _check_dangerous_methods(
    acam: Optional[str], acao: str, acac: Optional[str],
    observed: dict
) -> Optional[CORSFinding]:
    dangerous = _dangerous_methods(acam)
    if not dangerous:
        return None
    credentials = _is_credentials_true(acac)
    severity = "Medium" if credentials else "Low"
    return CORSFinding(
        rule_id="CORS-004",
        status="potentially_risky",
        observed_headers=observed,
        severity=severity,
        confidence="Medium",
        title=f"Access-Control-Allow-Methods includes potentially dangerous methods: {', '.join(dangerous)}",
        explanation=(
            "The CORS preflight response permits methods that can modify server "
            f"state: {', '.join(dangerous)}. When combined with a permissive "
            "origin policy, cross-origin callers may trigger destructive operations."
        ),
        potential_impact=(
            "Depending on the application logic, cross-origin callers may be able "
            "to delete, update, or otherwise modify server-side resources."
            + (" Credentials are also permitted, increasing risk." if credentials else "")
        ),
        remediation=(
            "Restrict Access-Control-Allow-Methods to the minimum set of methods "
            "required. Combine with proper server-side authorisation checks."
        ),
        evidence=(
            f"Access-Control-Allow-Methods: {acam}\n"
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac or '(absent)'}"
        ),
    )


def _check_missing_vary(
    acao: str, vary: Optional[str], observed: dict
) -> Optional[CORSFinding]:
    """
    When ACAO is not a wildcard, responses are origin-dependent and the Vary
    header should include 'Origin' to prevent caching issues.
    """
    if acao == "*":
        return None
    if not acao:
        return None
    vary_lower = (vary or "").lower()
    if "origin" in vary_lower:
        return None

    return CORSFinding(
        rule_id="CORS-005",
        status="potentially_risky",
        observed_headers=observed,
        severity="Low",
        confidence="Medium",
        title="Vary: Origin header absent for origin-dependent CORS response",
        explanation=(
            "When Access-Control-Allow-Origin reflects a specific origin (not *), "
            "the response content is origin-dependent. The Vary: Origin header "
            "tells caches to store separate entries per origin. Without it, a "
            "cache may serve a CORS response intended for one origin to a request "
            "from a different origin."
        ),
        potential_impact=(
            "A caching proxy might serve the wrong CORS headers to an unintended "
            "origin, inadvertently granting access or denying legitimate requests."
        ),
        remediation="Add Vary: Origin to all responses where ACAO reflects an origin.",
        evidence=(
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Vary: {vary or '(absent)'}"
        ),
    )


def _cors_safe_summary(observed: dict) -> CORSFinding:
    """No actionable CORS issues detected."""
    acao = observed.get("access-control-allow-origin", "(absent)")
    return CORSFinding(
        rule_id="CORS-000",
        status="safe",
        observed_headers=observed,
        severity="Informational",
        confidence="High",
        title="No significant CORS misconfigurations detected",
        explanation=(
            "The CORS headers observed do not match any known high-risk patterns. "
            "This does not guarantee the CORS configuration is correct for all "
            "use cases — a manual review is recommended."
        ),
        potential_impact="None identified from this observation alone.",
        remediation=(
            "Periodically review CORS policy and ensure the Origin allowlist is "
            "maintained as the application evolves."
        ),
        evidence=f"Access-Control-Allow-Origin: {acao}",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_cors(headers: dict) -> list[CORSFinding]:
    """
    Analyze CORS-related *headers* (lowercase-key dict) and return a list
    of :class:`CORSFinding` objects.

    Returns at least one informational finding if no CORS headers are present.
    """
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials")
    acam = headers.get("access-control-allow-methods")
    vary = headers.get("vary")

    observed = {
        k: headers[k]
        for k in (
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
            "access-control-max-age",
            "vary",
        )
        if k in headers
    }

    if not acao:
        return [CORSFinding(
            rule_id="CORS-000",
            status="missing",
            observed_headers=observed,
            severity="Informational",
            confidence="High",
            title="No CORS headers present",
            explanation=(
                "The response does not include any Access-Control-* headers. "
                "This means cross-origin requests to this endpoint are blocked by "
                "the browser's same-origin policy by default."
            ),
            potential_impact="None. Absence of CORS headers is the restrictive default.",
            remediation=(
                "No action needed unless cross-origin access is required. "
                "Add CORS headers only for resources that must be accessible "
                "cross-origin."
            ),
            evidence="No Access-Control-Allow-Origin header found.",
        )]

    findings: list[CORSFinding] = []

    f = _check_allow_origin_wildcard_with_credentials(acao, acac, observed)
    if f:
        findings.append(f)

    f = _check_null_origin(acao, acac, observed)
    if f:
        findings.append(f)

    # Only report wildcard-without-credentials if no higher-severity finding
    if not findings:
        f = _check_wildcard_origin_no_credentials(acao, observed)
        if f:
            findings.append(f)

    f = _check_dangerous_methods(acam, acao, acac, observed)
    if f:
        findings.append(f)

    f = _check_missing_vary(acao, vary, observed)
    if f:
        findings.append(f)

    if not findings:
        findings.append(_cors_safe_summary(observed))

    return findings
