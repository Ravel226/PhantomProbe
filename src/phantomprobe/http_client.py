#!/usr/bin/env python3
"""
Shared HTTP helper.

Every outbound fetch goes through safe_urlopen so that the URL scheme is
validated in one place. This matters because some URLs are taken from the
target's own markup (script src attributes): without a scheme allowlist a
hostile page could point the scanner at file:// and have it read local files.
"""

import ssl
from typing import Optional, Union
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ALLOWED_SCHEMES = ("http", "https")


class UnsupportedScheme(ValueError):
    """Raised when a URL uses a scheme PhantomProbe refuses to fetch."""


def validate_url(url: str) -> str:
    """Return the URL if its scheme is fetchable, else raise UnsupportedScheme."""
    scheme = urlparse(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsupportedScheme(
            f"refusing to fetch {scheme or 'scheme-less'} URL: {url[:120]}"
        )
    return url


def unverified_context() -> ssl.SSLContext:
    """
    A TLS context that does not verify certificates.

    Reconnaissance deliberately targets hosts with broken, self-signed or
    expired certificates - refusing to connect would hide exactly the findings
    the scanner exists to report. Certificate problems are reported separately
    by the SSL analysis in passive.py.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def safe_urlopen(request: Union[Request, str], timeout: int = 10,
                 context: Optional[ssl.SSLContext] = None):
    """
    urlopen wrapper that enforces the scheme allowlist.

    Returns the same context-manager response object urlopen does.
    """
    url = request.full_url if isinstance(request, Request) else request
    validate_url(url)

    if context is not None:
        return urlopen(request, timeout=timeout, context=context)  # nosec B310 - scheme validated above
    return urlopen(request, timeout=timeout)  # nosec B310 - scheme validated above
