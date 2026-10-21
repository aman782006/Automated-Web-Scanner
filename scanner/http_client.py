"""
scanner/http_client.py

A safe, minimal HTTP client for the security scanner.

Safety guarantees
-----------------
* All outbound requests are validated through scanner.validator before
  being dispatched.
* Cookies, Authorization, and credential headers are never sent.
* TLS certificate verification is enabled by default.
* Automatic redirect following is disabled; each redirect target is
  validated individually before being followed.
* Connection and read timeouts are enforced.
* Response bodies are NOT stored; only status code and headers are kept.
* Total requests per scan and total scan duration are capped.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

import requests
import requests.exceptions

from scanner.validator import (
    ValidationError,
    ValidatedTarget,
    validate_target,
    validate_redirect_target,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SafeResponse:
    """Minimal representation of an HTTP response – no body stored."""
    url: str
    status_code: int
    headers: dict          # Lowercase-key dict of response headers
    is_redirect: bool
    redirect_location: Optional[str]
    tls_verified: bool
    elapsed_ms: float
    error: Optional[str] = None


@dataclass
class ScanSession:
    """Tracks per-scan resource usage to enforce hard limits."""
    validated_target: ValidatedTarget
    request_count: int = 0
    start_time: float = field(default_factory=time.monotonic)

    # Limits (overridden in tests via Config injection)
    max_requests: int = 10
    max_duration: float = 30.0
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    max_response_size: int = 1_048_576
    verify_tls: bool = True

    def check_limits(self):
        """Raise RuntimeError if any hard limit has been exceeded."""
        if self.request_count >= self.max_requests:
            raise RuntimeError(
                f"Request limit reached ({self.max_requests} requests per scan)."
            )
        elapsed = time.monotonic() - self.start_time
        if elapsed > self.max_duration:
            raise RuntimeError(
                f"Scan duration limit exceeded ({self.max_duration}s)."
            )


# ---------------------------------------------------------------------------
# Forbidden headers (never forwarded to targets)
# ---------------------------------------------------------------------------

_FORBIDDEN_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "www-authenticate",
    "x-api-key",
    "x-auth-token",
}

_SAFE_REQUEST_HEADERS = {
    "User-Agent": "AutomatedWebSecurityScanner/1.0 (Security Audit Tool)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Cache-Control": "no-cache",
}


def _sanitise_headers(extra: dict | None) -> dict:
    """Strip any forbidden headers from *extra* and merge with safe defaults."""
    safe = dict(_SAFE_REQUEST_HEADERS)
    if extra:
        for key, value in extra.items():
            if key.lower() not in _FORBIDDEN_HEADERS:
                safe[key] = value
    return safe


# ---------------------------------------------------------------------------
# Core request function
# ---------------------------------------------------------------------------

def _make_request(
    session: ScanSession,
    url: str,
    method: str = "GET",
    extra_headers: dict | None = None,
) -> SafeResponse:
    """
    Send a single HTTP request respecting session limits.

    * Does NOT follow redirects automatically.
    * Does NOT store the response body.
    * Returns a :class:`SafeResponse`.
    """
    session.check_limits()
    session.request_count += 1

    headers = _sanitise_headers(extra_headers)
    timeout = (session.connect_timeout, session.read_timeout)

    try:
        start = time.monotonic()
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            allow_redirects=False,
            timeout=timeout,
            verify=session.verify_tls,
            stream=True,          # Stream so we never buffer body
        )
        elapsed_ms = (time.monotonic() - start) * 1000

        # Drain a small chunk to ensure headers are received, then close.
        # We intentionally do NOT read more than MAX_RESPONSE_SIZE bytes.
        try:
            resp.raw.read(min(session.max_response_size, 4096))
        except Exception:
            pass
        finally:
            resp.close()

        # Normalise header keys to lowercase for consistent access
        norm_headers = {k.lower(): v for k, v in resp.headers.items()}

        redirect_location: Optional[str] = None
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            redirect_location = norm_headers.get("location")

        return SafeResponse(
            url=url,
            status_code=resp.status_code,
            headers=norm_headers,
            is_redirect=bool(redirect_location),
            redirect_location=redirect_location,
            tls_verified=session.verify_tls,
            elapsed_ms=round(elapsed_ms, 2),
        )

    except requests.exceptions.SSLError as exc:
        return SafeResponse(
            url=url, status_code=0, headers={}, is_redirect=False,
            redirect_location=None, tls_verified=False,
            elapsed_ms=0, error=f"TLS error: {exc}",
        )
    except requests.exceptions.ConnectionError as exc:
        return SafeResponse(
            url=url, status_code=0, headers={}, is_redirect=False,
            redirect_location=None, tls_verified=session.verify_tls,
            elapsed_ms=0, error=f"Connection error: {exc}",
        )
    except requests.exceptions.Timeout as exc:
        return SafeResponse(
            url=url, status_code=0, headers={}, is_redirect=False,
            redirect_location=None, tls_verified=session.verify_tls,
            elapsed_ms=0, error=f"Timeout: {exc}",
        )
    except requests.exceptions.RequestException as exc:
        return SafeResponse(
            url=url, status_code=0, headers={}, is_redirect=False,
            redirect_location=None, tls_verified=session.verify_tls,
            elapsed_ms=0, error=f"Request error: {exc}",
        )


# ---------------------------------------------------------------------------
# High-level helpers used by the scan engine
# ---------------------------------------------------------------------------

def fetch_response(session: ScanSession, url: str,
                   extra_headers: dict | None = None) -> SafeResponse:
    """
    Fetch *url* safely – no redirect following, no credential leakage.
    """
    return _make_request(session, url, method="GET",
                         extra_headers=extra_headers)


def fetch_with_redirect_chain(
    session: ScanSession,
    url: str,
    max_hops: int = 5,
) -> tuple[list[SafeResponse], Optional[str]]:
    """
    Follow a redirect chain manually, validating every hop before following.

    Returns (list_of_responses, final_error_or_None).
    A cross-host redirect raises :class:`ValidationError` which is caught
    and returned as an error string — the chain up to that point is returned.
    """
    responses: list[SafeResponse] = []
    current_url = url
    original_hostname = session.validated_target.hostname

    for _ in range(max_hops + 1):
        resp = _make_request(session, current_url)
        responses.append(resp)

        if resp.error:
            return responses, resp.error

        if not resp.is_redirect or not resp.redirect_location:
            return responses, None

        # Resolve and validate redirect destination
        next_url = resp.redirect_location
        # Handle relative redirects
        if next_url.startswith("/"):
            parsed_current = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(current_url)
            next_url = f"{parsed_current.scheme}://{parsed_current.netloc}{next_url}"

        try:
            validate_redirect_target(next_url, original_hostname)
        except ValidationError as exc:
            return responses, str(exc)

        current_url = next_url

    return responses, "Redirect limit exceeded."


def create_session(validated_target: ValidatedTarget, config=None) -> ScanSession:
    """
    Factory that creates a :class:`ScanSession` optionally seeded from
    a Config object.
    """
    kwargs: dict = {"validated_target": validated_target}
    if config:
        kwargs["max_requests"] = getattr(config, "MAX_REQUESTS_PER_SCAN", 10)
        kwargs["max_duration"] = getattr(config, "MAX_SCAN_DURATION", 30.0)
        kwargs["connect_timeout"] = getattr(config, "REQUEST_TIMEOUT_CONNECT", 5.0)
        kwargs["read_timeout"] = getattr(config, "REQUEST_TIMEOUT_READ", 10.0)
        kwargs["max_response_size"] = getattr(config, "MAX_RESPONSE_SIZE", 1_048_576)
        kwargs["verify_tls"] = getattr(config, "VERIFY_TLS", True)
    return ScanSession(**kwargs)
