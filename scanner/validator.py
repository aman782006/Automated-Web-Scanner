"""
scanner/validator.py

Validates submitted URLs and resolves hostnames before any HTTP request is
made.  Blocks private, loopback, link-local, multicast, reserved, and
unspecified address ranges to prevent Server-Side Request Forgery (SSRF).

All public methods raise ValidationError on rejection so callers can treat
validation uniformly.
"""

import ipaddress
import socket
import urllib.parse
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Raised when a submitted URL or resolved address fails validation."""


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

class ValidatedTarget(NamedTuple):
    url: str            # Normalised URL (scheme + host + path)
    scheme: str         # "http" or "https"
    hostname: str       # Original hostname as supplied
    resolved_ip: str    # First resolved IPv4/IPv6 address


# ---------------------------------------------------------------------------
# Blocked address ranges
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # Unspecified
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
    # IETF / documentation / benchmark ranges
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Broadcast
    ipaddress.ip_network("255.255.255.255/32"),
    # Carrier-grade NAT
    ipaddress.ip_network("100.64.0.0/10"),
]

ALLOWED_SCHEMES = {"http", "https"}
MAX_HOSTNAME_LENGTH = 253
MAX_URL_LENGTH = 2048


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_blocked_ip(addr: str) -> bool:
    """Return True if *addr* falls within any blocked network range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable → block
    return any(ip in net for net in _BLOCKED_NETWORKS)


def _resolve_hostname(hostname: str) -> str:
    """
    Resolve *hostname* to its first address via getaddrinfo.

    Raises ValidationError on DNS failure or if the resolved address is
    blocked.
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC,
                                     socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationError(
            f"DNS resolution failed for '{hostname}': {exc}"
        ) from exc

    if not results:
        raise ValidationError(
            f"DNS resolution returned no results for '{hostname}'"
        )

    resolved_ip = results[0][4][0]

    if _is_blocked_ip(resolved_ip):
        raise ValidationError(
            f"Hostname '{hostname}' resolves to a blocked address "
            f"({resolved_ip}). Internal/private targets are not permitted."
        )

    return resolved_ip


def _normalise_url(raw: str) -> tuple[str, str, str]:
    """
    Parse and normalise *raw* into (normalised_url, scheme, hostname).

    Returns the URL with its path/query/fragment preserved but with the
    scheme lowercased and any default ports stripped.

    Raises ValidationError for malformed or disallowed input.
    """
    raw = raw.strip()

    if len(raw) > MAX_URL_LENGTH:
        raise ValidationError(
            f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."
        )

    parsed = urllib.parse.urlparse(raw)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValidationError(
            f"URL scheme '{scheme}' is not allowed. "
            f"Only {sorted(ALLOWED_SCHEMES)} are accepted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("URL does not contain a valid hostname.")

    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise ValidationError(
            f"Hostname exceeds maximum allowed length of "
            f"{MAX_HOSTNAME_LENGTH} characters."
        )

    # Reject bare IP literals that are already in blocked ranges so we
    # fail fast before a DNS round-trip.
    try:
        ip_literal = ipaddress.ip_address(hostname)
        # Successfully parsed as an IP — now check if it's blocked
        if _is_blocked_ip(str(ip_literal)):
            raise ValidationError(
                f"IP address '{hostname}' is in a blocked range. "
                "Internal/private targets are not permitted."
            )
    except ValidationError:
        raise  # Re-raise ValidationError so it's not swallowed below
    except (ValueError, Exception):
        pass  # Not an IP literal — will be resolved below

    # Reconstruct a clean URL (strip credentials if somehow present)
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"

    normalised = urllib.parse.urlunparse((
        scheme,
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",          # strip fragment — not sent to server
    ))

    return normalised, scheme, hostname


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_target(raw_url: str) -> ValidatedTarget:
    """
    Fully validate *raw_url* for use as a scan target.

    Steps:
    1. Normalise and parse the URL.
    2. Reject disallowed schemes.
    3. Reject blocked IP literals.
    4. Resolve the hostname via DNS.
    5. Reject if the resolved address is private/internal (SSRF prevention).

    Returns a :class:`ValidatedTarget` on success.
    Raises :class:`ValidationError` on any failure.
    """
    normalised_url, scheme, hostname = _normalise_url(raw_url)
    resolved_ip = _resolve_hostname(hostname)
    return ValidatedTarget(
        url=normalised_url,
        scheme=scheme,
        hostname=hostname,
        resolved_ip=resolved_ip,
    )


def validate_redirect_target(redirect_url: str, original_hostname: str) -> ValidatedTarget:
    """
    Validate a redirect destination.

    In addition to the standard checks, this function verifies that the
    redirect stays within the same registered hostname as the original target
    (same-host scope check) to prevent redirect-based SSRF bypasses.

    A redirect to a *different* host is blocked unless the caller explicitly
    allows it in higher-level policy.  Here we raise so that the HTTP client
    can decide whether to follow.
    """
    target = validate_target(redirect_url)

    if target.hostname.lower() != original_hostname.lower():
        raise ValidationError(
            f"Redirect destination '{target.hostname}' is outside the "
            f"authorised scan scope (original host: '{original_hostname}'). "
            "Cross-host redirects are blocked to prevent SSRF."
        )

    return target
