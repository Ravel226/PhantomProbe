"""
Unit tests for the shared HTTP helper.

The scheme allowlist is a security control: JS analysis feeds it URLs taken
straight from the target's markup, so these tests guard a real attack path.
"""
import pytest

from phantomprobe.http_client import (
    ALLOWED_SCHEMES,
    UnsupportedScheme,
    safe_urlopen,
    unverified_context,
    validate_url,
)


@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://example.com",
    "https://example.com/path?q=1",
    "HTTPS://EXAMPLE.COM",
])
def test_allows_http_and_https(url):
    assert validate_url(url) == url


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "file://C:/Windows/win.ini",
    "ftp://example.com/x",
    "gopher://example.com",
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(1)",
    "/etc/passwd",
    "example.com",
])
def test_rejects_everything_else(url):
    """A hostile page must not be able to redirect the scanner off-protocol."""
    with pytest.raises(UnsupportedScheme):
        validate_url(url)


def test_rejected_url_is_never_opened(monkeypatch):
    """Validation must happen before the request is issued."""
    called = []
    monkeypatch.setattr(
        "phantomprobe.http_client.urlopen",
        lambda *a, **k: called.append(a),
    )

    with pytest.raises(UnsupportedScheme):
        safe_urlopen("file:///etc/passwd")

    assert called == []


def test_allowed_url_is_passed_through(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(
        "phantomprobe.http_client.urlopen",
        lambda *a, **k: sentinel,
    )

    assert safe_urlopen("https://example.com") is sentinel


def test_accepts_request_objects(monkeypatch):
    from urllib.request import Request

    sentinel = object()
    monkeypatch.setattr("phantomprobe.http_client.urlopen", lambda *a, **k: sentinel)

    assert safe_urlopen(Request("https://example.com")) is sentinel

    with pytest.raises(UnsupportedScheme):
        safe_urlopen(Request("file:///etc/passwd"))


def test_allowed_schemes_are_only_http_family():
    assert set(ALLOWED_SCHEMES) == {"http", "https"}


def test_unverified_context_does_not_verify():
    """Recon must still reach hosts with broken certificates."""
    import ssl

    ctx = unverified_context()

    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE
