"""
scanner/https.py

Analyzes HTTPS configuration and redirect behavior for a target URL.

Checks performed:
  - Whether the target uses HTTPS.
  - Whether HTTP redirects to HTTPS (safe, in-scope check only).
  - Whether the redirect chain stays within the authorised scope.
  - Whether TLS certificate validation succeeded.
  - Whether HSTS is present on HTTPS responses.
  - Whether redirect loops or excessive redirect chains exist.

All requests are made through the shared safe HTTP client.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from scanner.http_client import ScanSession, SafeResponse, fetch_with_redirect_chain
from scanner.validator import ValidationError


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HTTPSFinding:
    """Raw finding from the HTTPS/redirect analyzer."""
    rule_id: str
    status: str        # "secure" | "insecure" | "warning" | "informational" | "error"
    severity: str
    confidence: str
    title: str
    explanation: str
    potential_impact: str
    remediation: str
    evidence: str


@dataclass
class HTTPSAnalysisResult:
    uses_https: bool
    redirects_to_https: Optional[bool]
    tls_valid: Optional[bool]
    hsts_present: Optional[bool]
    redirect_chain: list[dict]
    findings: list[HTTPSFinding]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _finding_uses_https(url: str) -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-001",
        status="secure",
        severity="Informational",
        confidence="High",
        title="Target uses HTTPS",
        explanation="The target URL uses the HTTPS scheme.",
        potential_impact="None. HTTPS provides transport-layer encryption.",
        remediation="Ensure TLS configuration remains up to date.",
        evidence=f"URL scheme is HTTPS: {url}",
    )


def _finding_no_https(url: str) -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-002",
        status="insecure",
        severity="High",
        confidence="High",
        title="Target does not use HTTPS",
        explanation=(
            "The target URL uses plain HTTP. Data transmitted over HTTP is not "
            "encrypted and may be intercepted, read, or modified by network "
            "intermediaries."
        ),
        potential_impact=(
            "Sensitive data (credentials, session tokens, personal information) "
            "transmitted over HTTP is exposed to network eavesdropping and "
            "man-in-the-middle attacks."
        ),
        remediation=(
            "Migrate to HTTPS. Obtain a TLS certificate (Let's Encrypt provides "
            "free certificates). Configure the server to redirect all HTTP traffic "
            "to HTTPS. Add Strict-Transport-Security."
        ),
        evidence=f"URL scheme is HTTP: {url}",
    )


def _finding_http_redirects_to_https(chain_summary: str) -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-003",
        status="secure",
        severity="Informational",
        confidence="High",
        title="HTTP redirects to HTTPS",
        explanation="The server redirects HTTP requests to the HTTPS equivalent.",
        potential_impact=(
            "First-visit HTTP requests are unencrypted until the redirect completes. "
            "HSTS preloading eliminates this window."
        ),
        remediation=(
            "Consider adding Strict-Transport-Security with the preload directive "
            "and submitting to the HSTS preload list."
        ),
        evidence=chain_summary,
    )


def _finding_http_no_redirect(url: str, status: int) -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-004",
        status="insecure",
        severity="Medium",
        confidence="High",
        title="HTTP does not redirect to HTTPS",
        explanation=(
            "The server does not redirect plain HTTP requests to HTTPS. Users who "
            "access the site over HTTP will receive unencrypted responses."
        ),
        potential_impact=(
            "Unencrypted HTTP traffic exposes users to eavesdropping and "
            "man-in-the-middle attacks even if an HTTPS version exists."
        ),
        remediation=(
            "Configure the server to redirect all HTTP requests to the HTTPS "
            "equivalent (HTTP 301 or 308 redirect)."
        ),
        evidence=f"HTTP request to {url} returned status {status} with no Location header pointing to HTTPS.",
    )


def _finding_tls_error(url: str, error: str) -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-005",
        status="error",
        severity="High",
        confidence="High",
        title="TLS certificate validation failed",
        explanation=(
            "The TLS certificate for this host could not be validated. This may "
            "indicate an expired certificate, a hostname mismatch, an untrusted "
            "certificate authority, or a misconfigured certificate chain."
        ),
        potential_impact=(
            "Browsers will display certificate warnings to users, reducing trust. "
            "In some configurations, traffic may be exposed to man-in-the-middle attacks."
        ),
        remediation=(
            "Renew or replace the TLS certificate. Ensure the certificate is issued "
            "for the correct hostname, is signed by a trusted CA, and that the full "
            "certificate chain is served."
        ),
        evidence=f"TLS error for {url}: {error}",
    )


def _finding_hsts_present() -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-006",
        status="secure",
        severity="Informational",
        confidence="High",
        title="HSTS header present on HTTPS response",
        explanation="Strict-Transport-Security is configured on the HTTPS endpoint.",
        potential_impact="None. HSTS reduces downgrade attack risk.",
        remediation="Verify max-age is set to at least one year.",
        evidence="Strict-Transport-Security header observed in HTTPS response.",
    )


def _finding_hsts_absent_on_https() -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-007",
        status="warning",
        severity="Medium",
        confidence="High",
        title="HSTS header absent on HTTPS response",
        explanation=(
            "The server responds over HTTPS but does not include a "
            "Strict-Transport-Security header. HSTS instructs browsers to use "
            "HTTPS exclusively for future visits."
        ),
        potential_impact=(
            "Without HSTS, users may be vulnerable to SSL stripping attacks on "
            "subsequent visits if an attacker can intercept the first HTTP request."
        ),
        remediation=(
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
        evidence="No Strict-Transport-Security header in HTTPS response.",
    )


def _finding_redirect_out_of_scope(from_url: str, to_url: str) -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-008",
        status="warning",
        severity="Informational",
        confidence="High",
        title="Redirect destination is outside the authorised scan scope",
        explanation=(
            "The server redirects to a different hostname than the one submitted "
            "for scanning. The scan does not follow cross-host redirects to prevent "
            "inadvertently scanning unauthorised targets."
        ),
        potential_impact="No direct security impact; informational observation.",
        remediation="Verify that the redirect destination is intended.",
        evidence=f"Redirect from {from_url} to {to_url} blocked (cross-host).",
    )


def _finding_excessive_redirects(count: int) -> HTTPSFinding:
    return HTTPSFinding(
        rule_id="HTTPS-009",
        status="warning",
        severity="Low",
        confidence="High",
        title="Excessive or looping redirect chain detected",
        explanation=(
            f"The server produced {count} redirect(s) before the chain was "
            "terminated. Excessive redirects may indicate a redirect loop or "
            "misconfiguration, which degrades user experience and may confuse "
            "security tools."
        ),
        potential_impact=(
            "Users may encounter slow page loads or browser errors. Redirect loops "
            "can exhaust browser redirect limits."
        ),
        remediation=(
            "Investigate and simplify the redirect chain. Ensure there are no "
            "circular redirects between HTTP and HTTPS or between subdomains."
        ),
        evidence=f"Redirect chain contained {count} hop(s) before termination.",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_https(session: ScanSession, target_url: str) -> HTTPSAnalysisResult:
    """
    Perform HTTPS and redirect analysis for *target_url* using *session*.

    Returns an :class:`HTTPSAnalysisResult` with findings.
    """
    uses_https = target_url.lower().startswith("https://")
    findings: list[HTTPSFinding] = []
    redirect_chain_summary: list[dict] = []
    tls_valid: Optional[bool] = None
    hsts_present: Optional[bool] = None
    redirects_to_https: Optional[bool] = None

    if uses_https:
        findings.append(_finding_uses_https(target_url))

        # Fetch the HTTPS URL to check TLS validity and HSTS
        responses, error = fetch_with_redirect_chain(
            session, target_url, max_hops=3
        )

        for r in responses:
            redirect_chain_summary.append({
                "url": r.url,
                "status_code": r.status_code,
                "redirect_to": r.redirect_location,
                "error": r.error,
            })

        if responses and responses[0].error:
            tls_error_msg = responses[0].error
            if "TLS" in tls_error_msg or "SSL" in tls_error_msg or "certificate" in tls_error_msg.lower():
                tls_valid = False
                findings.append(_finding_tls_error(target_url, tls_error_msg))
            else:
                findings.append(HTTPSFinding(
                    rule_id="HTTPS-010",
                    status="error",
                    severity="Medium",
                    confidence="High",
                    title="Connection error during HTTPS check",
                    explanation="The HTTPS request failed with a connection error.",
                    potential_impact="The site may be unreachable or misconfigured.",
                    remediation="Verify the server is reachable and properly configured.",
                    evidence=f"Error: {tls_error_msg}",
                ))
        elif responses:
            tls_valid = True
            first = responses[0]
            hsts_val = first.headers.get("strict-transport-security")
            hsts_present = bool(hsts_val)
            if hsts_present:
                findings.append(_finding_hsts_present())
            else:
                findings.append(_finding_hsts_absent_on_https())

        if error and ("cross-host" in error.lower() or "scope" in error.lower()):
            # Extract the redirect destination from the error
            findings.append(_finding_redirect_out_of_scope(target_url, error))

        # Redirect chain length
        if len(responses) > 3:
            findings.append(_finding_excessive_redirects(len(responses)))

    else:
        # Target is HTTP – check whether it redirects to HTTPS
        findings.append(_finding_no_https(target_url))

        responses, error = fetch_with_redirect_chain(
            session, target_url, max_hops=3
        )

        for r in responses:
            redirect_chain_summary.append({
                "url": r.url,
                "status_code": r.status_code,
                "redirect_to": r.redirect_location,
                "error": r.error,
            })

        did_redirect_https = False
        for r in responses:
            if r.redirect_location and r.redirect_location.lower().startswith("https://"):
                did_redirect_https = True
                break

        redirects_to_https = did_redirect_https

        if did_redirect_https:
            chain_desc = " → ".join(
                f"{r.url} ({r.status_code})" for r in responses
            )
            findings.append(_finding_http_redirects_to_https(chain_desc))
        elif responses and not responses[0].error:
            first = responses[0]
            findings.append(_finding_http_no_redirect(target_url, first.status_code))

        if error and ("cross-host" in error.lower() or "scope" in error.lower()):
            findings.append(_finding_redirect_out_of_scope(target_url, error))

        if len(responses) > 3:
            findings.append(_finding_excessive_redirects(len(responses)))

    return HTTPSAnalysisResult(
        uses_https=uses_https,
        redirects_to_https=redirects_to_https,
        tls_valid=tls_valid,
        hsts_present=hsts_present,
        redirect_chain=redirect_chain_summary,
        findings=findings,
        error=None,
    )
