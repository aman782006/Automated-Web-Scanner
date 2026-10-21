"""
scanner/headers.py

Analyzes HTTP response security headers.

For each header the analyzer:
  1. Checks presence / absence.
  2. Inspects the actual value for known weaknesses.
  3. Assigns an observation status, severity, and confidence.
  4. Returns structured evidence for the rules engine.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HeaderFinding:
    """Raw finding produced by the header analyzer before rule enrichment."""
    rule_id: str
    header_name: str
    status: str           # "missing" | "present" | "weak" | "inconclusive"
    observed_value: Optional[str]
    severity: str         # "Critical" | "High" | "Medium" | "Low" | "Informational"
    confidence: str       # "High" | "Medium" | "Low"
    title: str
    explanation: str
    potential_impact: str
    remediation: str
    evidence: str


# ---------------------------------------------------------------------------
# Individual header checks
# ---------------------------------------------------------------------------

def _check_csp(headers: dict) -> HeaderFinding:
    raw = headers.get("content-security-policy")
    if not raw:
        return HeaderFinding(
            rule_id="HDR-CSP-001",
            header_name="Content-Security-Policy",
            status="missing",
            observed_value=None,
            severity="Medium",
            confidence="High",
            title="Content-Security-Policy header is absent",
            explanation=(
                "Content-Security-Policy (CSP) allows web servers to restrict the "
                "sources from which browsers may load resources such as scripts, "
                "stylesheets, and images. Without CSP, the browser enforces no "
                "source restrictions, which broadens the attack surface for "
                "Cross-Site Scripting (XSS) and data-injection attacks."
            ),
            potential_impact=(
                "Absence of CSP increases exposure to XSS attacks. An attacker who "
                "can inject script content faces no browser-level source restriction."
            ),
            remediation=(
                "Add a Content-Security-Policy header. Start with a restrictive "
                "policy such as: Content-Security-Policy: default-src 'self'. "
                "Gradually allow trusted origins. Use a CSP evaluator tool to "
                "validate the policy before deployment."
            ),
            evidence="Header not present in response.",
        )

    # Look for obviously weak directives
    value_lower = raw.lower()
    weak_directives = []

    if "unsafe-inline" in value_lower:
        weak_directives.append("'unsafe-inline' allows inline scripts/styles")
    if "unsafe-eval" in value_lower:
        weak_directives.append("'unsafe-eval' allows eval() and similar constructs")
    if "data:" in value_lower and "script-src" in value_lower:
        weak_directives.append("data: URI in script-src can allow code injection")
    if "*" in raw and "default-src" in value_lower:
        weak_directives.append("Wildcard (*) in default-src defeats origin restrictions")

    if weak_directives:
        return HeaderFinding(
            rule_id="HDR-CSP-002",
            header_name="Content-Security-Policy",
            status="weak",
            observed_value=raw,
            severity="Medium",
            confidence="Medium",
            title="Content-Security-Policy contains potentially unsafe directives",
            explanation=(
                "A Content-Security-Policy header is present but contains directives "
                "that may weaken its protective effect."
            ),
            potential_impact=(
                "Weak directives may allow script injection or bypass the protections "
                "CSP is designed to provide."
            ),
            remediation=(
                "Review and tighten the CSP policy. Remove 'unsafe-inline' and "
                "'unsafe-eval' where possible. Use nonces or hashes for inline "
                "scripts instead. Avoid wildcard origins in script-src."
            ),
            evidence=(
                f"Observed value: {raw}\n"
                f"Potentially weak directives: {'; '.join(weak_directives)}"
            ),
        )

    return HeaderFinding(
        rule_id="HDR-CSP-003",
        header_name="Content-Security-Policy",
        status="present",
        observed_value=raw,
        severity="Informational",
        confidence="High",
        title="Content-Security-Policy header is present",
        explanation="A Content-Security-Policy header was observed with no obvious weak directives.",
        potential_impact="None identified from this observation alone.",
        remediation="Periodically review the policy against CSP best practices.",
        evidence=f"Observed value: {raw}",
    )


def _check_hsts(headers: dict) -> HeaderFinding:
    raw = headers.get("strict-transport-security")
    if not raw:
        return HeaderFinding(
            rule_id="HDR-HSTS-001",
            header_name="Strict-Transport-Security",
            status="missing",
            observed_value=None,
            severity="Medium",
            confidence="High",
            title="Strict-Transport-Security (HSTS) header is absent",
            explanation=(
                "HSTS instructs browsers to interact with the site exclusively over "
                "HTTPS, preventing protocol-downgrade attacks and cookie hijacking "
                "over plain HTTP."
            ),
            potential_impact=(
                "Without HSTS, a network attacker may intercept and downgrade an HTTPS "
                "connection to HTTP before the browser establishes a secure channel."
            ),
            remediation=(
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                "Consider submitting the domain to the HSTS preload list after testing."
            ),
            evidence="Header not present in response.",
        )

    value_lower = raw.lower()
    issues = []

    # Check max-age
    import re
    ma_match = re.search(r"max-age\s*=\s*(\d+)", value_lower)
    max_age = int(ma_match.group(1)) if ma_match else 0

    if max_age == 0:
        issues.append("max-age=0 effectively disables HSTS")
    elif max_age < 86400:
        issues.append(f"max-age={max_age} is very short (recommend ≥ 31536000)")
    elif max_age < 31536000:
        issues.append(f"max-age={max_age} is shorter than the recommended 1 year (31536000)")

    if issues:
        return HeaderFinding(
            rule_id="HDR-HSTS-002",
            header_name="Strict-Transport-Security",
            status="weak",
            observed_value=raw,
            severity="Low",
            confidence="High",
            title="Strict-Transport-Security header has a short or disabled max-age",
            explanation="HSTS is present but configured with a weak max-age value.",
            potential_impact=(
                "A short max-age reduces the window during which browsers enforce "
                "HTTPS, limiting the protection HSTS provides."
            ),
            remediation=(
                "Set max-age to at least 31536000 (one year). "
                "Add includeSubDomains if applicable."
            ),
            evidence=f"Observed value: {raw}\nIssues: {'; '.join(issues)}",
        )

    return HeaderFinding(
        rule_id="HDR-HSTS-003",
        header_name="Strict-Transport-Security",
        status="present",
        observed_value=raw,
        severity="Informational",
        confidence="High",
        title="Strict-Transport-Security header is present and appears adequate",
        explanation="HSTS header present with an acceptable max-age.",
        potential_impact="None identified from this observation alone.",
        remediation="Consider adding the preload directive and submitting to HSTS preload list.",
        evidence=f"Observed value: {raw}",
    )


def _check_x_content_type(headers: dict) -> HeaderFinding:
    raw = headers.get("x-content-type-options")
    if not raw:
        return HeaderFinding(
            rule_id="HDR-XCTO-001",
            header_name="X-Content-Type-Options",
            status="missing",
            observed_value=None,
            severity="Low",
            confidence="High",
            title="X-Content-Type-Options header is absent",
            explanation=(
                "X-Content-Type-Options: nosniff prevents browsers from performing "
                "MIME-type sniffing on responses, reducing the risk of attacks that "
                "exploit incorrect MIME-type handling."
            ),
            potential_impact=(
                "Without this header, older browsers may attempt MIME sniffing and "
                "execute content as a different type than intended (e.g., executing "
                "a script disguised as an image)."
            ),
            remediation="Add: X-Content-Type-Options: nosniff",
            evidence="Header not present in response.",
        )

    if raw.strip().lower() != "nosniff":
        return HeaderFinding(
            rule_id="HDR-XCTO-002",
            header_name="X-Content-Type-Options",
            status="weak",
            observed_value=raw,
            severity="Low",
            confidence="Medium",
            title="X-Content-Type-Options has an unexpected value",
            explanation=(
                "The only valid value for X-Content-Type-Options is 'nosniff'. "
                "Any other value is not recognised by browsers and provides no protection."
            ),
            potential_impact="MIME-sniffing protection is not in effect.",
            remediation="Set the header value to exactly: nosniff",
            evidence=f"Observed value: {raw}",
        )

    return HeaderFinding(
        rule_id="HDR-XCTO-003",
        header_name="X-Content-Type-Options",
        status="present",
        observed_value=raw,
        severity="Informational",
        confidence="High",
        title="X-Content-Type-Options is correctly set to nosniff",
        explanation="MIME-sniffing protection is active.",
        potential_impact="None identified.",
        remediation="No action required.",
        evidence=f"Observed value: {raw}",
    )


def _check_x_frame_options(headers: dict) -> HeaderFinding:
    raw = headers.get("x-frame-options")
    # CSP frame-ancestors supersedes X-Frame-Options in modern browsers
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not raw:
        if has_frame_ancestors:
            return HeaderFinding(
                rule_id="HDR-XFO-003",
                header_name="X-Frame-Options",
                status="inconclusive",
                observed_value=None,
                severity="Informational",
                confidence="Medium",
                title="X-Frame-Options absent but CSP frame-ancestors present",
                explanation=(
                    "X-Frame-Options is absent, but the Content-Security-Policy "
                    "header includes a frame-ancestors directive, which provides "
                    "equivalent clickjacking protection in modern browsers."
                ),
                potential_impact=(
                    "Older browsers not supporting CSP frame-ancestors may remain "
                    "vulnerable to clickjacking."
                ),
                remediation=(
                    "Consider adding X-Frame-Options: DENY or SAMEORIGIN for "
                    "compatibility with older browsers."
                ),
                evidence=f"X-Frame-Options absent. CSP observed: {csp}",
            )

        return HeaderFinding(
            rule_id="HDR-XFO-001",
            header_name="X-Frame-Options",
            status="missing",
            observed_value=None,
            severity="Medium",
            confidence="High",
            title="X-Frame-Options header is absent",
            explanation=(
                "X-Frame-Options controls whether the browser allows the page to "
                "be rendered in a frame, iframe, or object. Absence may expose the "
                "application to clickjacking attacks."
            ),
            potential_impact=(
                "An attacker could embed the page in a transparent frame on a "
                "malicious site and trick users into performing unintended actions."
            ),
            remediation=(
                "Add: X-Frame-Options: DENY (preferred) or X-Frame-Options: SAMEORIGIN\n"
                "Alternatively, use CSP: Content-Security-Policy: frame-ancestors 'none'"
            ),
            evidence="Neither X-Frame-Options nor CSP frame-ancestors directive found.",
        )

    value_upper = raw.strip().upper()
    if value_upper in ("DENY", "SAMEORIGIN"):
        return HeaderFinding(
            rule_id="HDR-XFO-004",
            header_name="X-Frame-Options",
            status="present",
            observed_value=raw,
            severity="Informational",
            confidence="High",
            title="X-Frame-Options is present and valid",
            explanation="Clickjacking protection via X-Frame-Options is active.",
            potential_impact="None identified.",
            remediation="No action required.",
            evidence=f"Observed value: {raw}",
        )

    return HeaderFinding(
        rule_id="HDR-XFO-002",
        header_name="X-Frame-Options",
        status="weak",
        observed_value=raw,
        severity="Low",
        confidence="Medium",
        title="X-Frame-Options has an unexpected or non-standard value",
        explanation=(
            "The recognised values for X-Frame-Options are DENY and SAMEORIGIN. "
            "ALLOW-FROM is deprecated and not supported in modern browsers. "
            "Other values provide no protection."
        ),
        potential_impact="Clickjacking protection may not be in effect in all browsers.",
        remediation="Use X-Frame-Options: DENY or SAMEORIGIN.",
        evidence=f"Observed value: {raw}",
    )


def _check_referrer_policy(headers: dict) -> HeaderFinding:
    raw = headers.get("referrer-policy")
    _STRICT_VALUES = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    _WEAK_VALUES = {
        "unsafe-url",
        "origin-when-cross-origin",
    }

    if not raw:
        return HeaderFinding(
            rule_id="HDR-RP-001",
            header_name="Referrer-Policy",
            status="missing",
            observed_value=None,
            severity="Low",
            confidence="High",
            title="Referrer-Policy header is absent",
            explanation=(
                "Without an explicit Referrer-Policy, browsers apply their default "
                "policy (commonly 'strict-origin-when-cross-origin' in modern "
                "browsers), but older browsers may send the full URL as a Referer "
                "header on cross-origin requests, leaking sensitive URL parameters."
            ),
            potential_impact=(
                "Sensitive path and query-string information may be leaked to "
                "third-party sites referenced by the page."
            ),
            remediation=(
                "Add: Referrer-Policy: strict-origin-when-cross-origin\n"
                "or: Referrer-Policy: no-referrer (most restrictive)"
            ),
            evidence="Header not present in response.",
        )

    policy = raw.strip().lower()
    if policy in _WEAK_VALUES:
        return HeaderFinding(
            rule_id="HDR-RP-002",
            header_name="Referrer-Policy",
            status="weak",
            observed_value=raw,
            severity="Low",
            confidence="High",
            title="Referrer-Policy is set to a permissive value",
            explanation=(
                f"The policy '{policy}' allows the full URL (including sensitive "
                "query parameters) to be sent as a Referer header on cross-origin requests."
            ),
            potential_impact=(
                "Sensitive information in URLs (session tokens, user identifiers) "
                "may be disclosed to third-party origins."
            ),
            remediation="Use strict-origin-when-cross-origin or no-referrer.",
            evidence=f"Observed value: {raw}",
        )

    return HeaderFinding(
        rule_id="HDR-RP-003",
        header_name="Referrer-Policy",
        status="present",
        observed_value=raw,
        severity="Informational",
        confidence="High",
        title="Referrer-Policy header is present",
        explanation=f"A Referrer-Policy of '{policy}' is configured.",
        potential_impact="None identified from this value.",
        remediation="Verify the policy matches the intended data-sharing requirements.",
        evidence=f"Observed value: {raw}",
    )


def _check_permissions_policy(headers: dict) -> HeaderFinding:
    raw = (
        headers.get("permissions-policy")
        or headers.get("feature-policy")   # legacy name
    )
    if not raw:
        return HeaderFinding(
            rule_id="HDR-PP-001",
            header_name="Permissions-Policy",
            status="missing",
            observed_value=None,
            severity="Low",
            confidence="Medium",
            title="Permissions-Policy header is absent",
            explanation=(
                "Permissions-Policy (formerly Feature-Policy) allows the server to "
                "control which browser features and APIs (camera, microphone, "
                "geolocation, etc.) are available to the page and embedded frames."
            ),
            potential_impact=(
                "Without this header, embedded content may access powerful browser "
                "features unless other restrictions (e.g., sandbox attributes) are "
                "in place."
            ),
            remediation=(
                "Add a Permissions-Policy header restricting features not required "
                "by the application. Example:\n"
                "Permissions-Policy: camera=(), microphone=(), geolocation=()"
            ),
            evidence="Header not present in response.",
        )

    return HeaderFinding(
        rule_id="HDR-PP-002",
        header_name="Permissions-Policy",
        status="present",
        observed_value=raw,
        severity="Informational",
        confidence="Medium",
        title="Permissions-Policy header is present",
        explanation="Permissions-Policy is configured. Review directives for appropriateness.",
        potential_impact="None identified from this observation alone.",
        remediation="Verify that no unnecessary features are enabled for untrusted origins.",
        evidence=f"Observed value: {raw}",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_headers(headers: dict) -> list[HeaderFinding]:
    """
    Analyze *headers* (a lowercase-key dict of response headers) and return
    one :class:`HeaderFinding` per checked header.
    """
    checks = [
        _check_csp,
        _check_hsts,
        _check_x_content_type,
        _check_x_frame_options,
        _check_referrer_policy,
        _check_permissions_policy,
    ]
    return [check(headers) for check in checks]
