"""
Tests for the phase 3 active probes.

HTTP is stubbed. The cases that matter are the calibration ones the live run
confirmed: a bare CORS "*" is not a finding, a public S3 bucket is, and an
off-site Location is an open redirect while a same-site one is not.
"""
from email.message import Message

import pytest

from phantomprobe.aggressive import AggressiveScanner
from phantomprobe.models import Severity


def resp(status=200, header_pairs=None, body=b""):
    message = Message()
    for key, value in (header_pairs or []):
        message[key] = value
    return status, message, body


@pytest.fixture
def scanner():
    return AggressiveScanner("victim.com")


def ids(findings):
    return {f.id for f in findings}


class TestCors:
    def test_reflected_origin_with_credentials_is_high(self, scanner, monkeypatch):
        from phantomprobe.aggressive import HOSTILE_ORIGIN
        monkeypatch.setattr(scanner, "_get", lambda url, headers=None: resp(
            header_pairs=[("Access-Control-Allow-Origin", HOSTILE_ORIGIN),
                          ("Access-Control-Allow-Credentials", "true")]))
        scanner.check_cors()
        assert scanner.findings[0].id == "CORS-ReflectedWithCredentials"
        assert scanner.findings[0].severity is Severity.HIGH

    def test_reflected_origin_without_credentials_is_low(self, scanner, monkeypatch):
        from phantomprobe.aggressive import HOSTILE_ORIGIN
        monkeypatch.setattr(scanner, "_get", lambda url, headers=None: resp(
            header_pairs=[("Access-Control-Allow-Origin", HOSTILE_ORIGIN)]))
        scanner.check_cors()
        assert scanner.findings[0].severity is Severity.LOW

    def test_wildcard_is_not_a_finding(self, scanner, monkeypatch):
        """
        github.com returns '*' without credentials, and browsers block the
        dangerous use, so reporting it would be a false positive.
        """
        monkeypatch.setattr(scanner, "_get", lambda url, headers=None: resp(
            header_pairs=[("Access-Control-Allow-Origin", "*")]))
        scanner.check_cors()
        assert scanner.findings == []

    def test_null_origin_is_reported(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_get", lambda url, headers=None: resp(
            header_pairs=[("Access-Control-Allow-Origin", "null")]))
        scanner.check_cors()
        assert "CORS-NullOrigin" in ids(scanner.findings)

    def test_no_cors_header_is_silent(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_get", lambda url, headers=None: resp())
        scanner.check_cors()
        assert scanner.findings == []


class TestOpenRedirect:
    def _fetch(self, monkeypatch, status, location):
        def fake(url, timeout=10):
            message = Message()
            if location:
                message["Location"] = location
            return status, message
        monkeypatch.setattr("phantomprobe.http_checks._fetch_no_redirect", fake)

    def test_offsite_redirect_is_a_finding(self, scanner, monkeypatch):
        self._fetch(monkeypatch, 302, "https://phantomprobe.example/")
        scanner.check_open_redirect()
        assert scanner.findings[0].id == "REDIRECT-Open"
        assert scanner.findings[0].severity is Severity.MEDIUM

    def test_protocol_relative_redirect_is_caught(self, scanner, monkeypatch):
        self._fetch(monkeypatch, 301, "//phantomprobe.example/x")
        scanner.check_open_redirect()
        assert "REDIRECT-Open" in ids(scanner.findings)

    def test_same_site_redirect_is_not_a_finding(self, scanner, monkeypatch):
        """The param echoing back to the target's own host is not a redirect out."""
        self._fetch(monkeypatch, 302, "https://victim.com/dashboard")
        scanner.check_open_redirect()
        assert scanner.findings == []

    def test_no_redirect_is_silent(self, scanner, monkeypatch):
        self._fetch(monkeypatch, 200, None)
        scanner.check_open_redirect()
        assert scanner.findings == []


class TestHpp:
    def test_status_change_is_an_informational_hint(self, scanner, monkeypatch):
        calls = {"n": 0}

        def fake_get(url, headers=None):
            calls["n"] += 1
            # single -> 200, double -> 500
            return resp(status=500 if "&" in url else 200)

        monkeypatch.setattr(scanner, "_get", fake_get)
        scanner.check_hpp()
        assert scanner.findings[0].id == "HPP-StatusChange"
        assert scanner.findings[0].severity is Severity.INFORMATIONAL

    def test_same_status_is_not_reported(self, scanner, monkeypatch):
        """Length wobble is ignored on purpose; only a status change counts."""
        monkeypatch.setattr(scanner, "_get",
                            lambda url, headers=None: resp(status=200, body=b"x" * 999))
        scanner.check_hpp()
        assert scanner.findings == []


class TestS3:
    def test_public_listing_is_high(self, scanner, monkeypatch):
        def fake_get(url, headers=None):
            if url.startswith("https://victim.com.s3"):
                return resp(body=b"<ListBucketResult><Name>victim.com</Name>")
            return resp(status=404, body=b"<Error><Code>NoSuchBucket</Code></Error>")
        monkeypatch.setattr(scanner, "_get", fake_get)
        scanner.check_s3_buckets()
        highs = [f for f in scanner.findings if f.severity is Severity.HIGH]
        assert highs and highs[0].id.startswith("S3-Public-")

    def test_access_denied_bucket_is_informational(self, scanner, monkeypatch):
        def fake_get(url, headers=None):
            if url.startswith("https://victim.com.s3"):
                return resp(status=403, body=b"<Error><Code>AccessDenied</Code></Error>")
            return resp(status=404, body=b"<Error><Code>NoSuchBucket</Code></Error>")
        monkeypatch.setattr(scanner, "_get", fake_get)
        scanner.check_s3_buckets()
        assert any(f.id.startswith("S3-Exists-") for f in scanner.findings)

    def test_no_bucket_produces_nothing(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_get", lambda url, headers=None: resp(
            status=404, body=b"<Error><Code>NoSuchBucket</Code></Error>"))
        scanner.check_s3_buckets()
        assert scanner.findings == []

    def test_bucket_names_derive_from_the_domain(self, scanner):
        names = scanner._bucket_names()
        assert "victim.com" in names
        assert "victim-com" in names
        assert "victim" in names
        assert "victim-backup" in names
        assert len(names) == len(set(names))
