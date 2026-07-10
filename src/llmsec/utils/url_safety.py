"""Best-effort SSRF and URL-safety guards.

Limitations (see docs/threat-model.md): this performs a static check on the URL's literal
scheme/host at validation time. It does not resolve DNS names, so it cannot detect DNS
rebinding (a hostname that resolves to a private/loopback address after this check runs), and
it does not re-validate the final destination of HTTP redirects beyond capping their count
(see constants.MAX_HTTP_REDIRECTS and targets/generic_http.py). Treat it as defense-in-depth,
not a complete SSRF mitigation.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from llmsec.exceptions import UnsafeTargetError

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

_LOCAL_HOSTNAMES: frozenset[str] = frozenset({"localhost"})


def _is_private_or_loopback_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def is_local_target(url: str) -> bool:
    """Return True if the URL's host is a literal loopback/private address or "localhost"."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in _LOCAL_HOSTNAMES:
        return True
    return _is_private_or_loopback_ip(host)


def validate_target_url(url: str, *, allow_external: bool) -> None:
    """Raise UnsafeTargetError if the target URL is not safe to scan.

    Rules:
    - scheme must be http or https.
    - a hostname must be present.
    - if allow_external is False, the host must be "localhost" or a literal
      loopback/private/link-local IP address. Public IPs and arbitrary DNS names are
      rejected in that mode, since this framework defaults to local-lab-only scanning.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError(
            f"Target URL scheme {parsed.scheme!r} is not allowed; use http or https."
        )

    if not parsed.hostname:
        raise UnsafeTargetError(f"Target URL {url!r} has no hostname.")

    if not allow_external and not is_local_target(url):
        raise UnsafeTargetError(
            f"Target host {parsed.hostname!r} is not local/private and "
            "security.allow_external_targets is false. Set it to true in your config "
            "only if you are authorized to test this target."
        )
