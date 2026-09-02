"""
Tests for subdomain takeover detection.

The DoH resolver (doh.py) and the HTTP fetch are stubbed so the two-signal
logic is exercised offline. The stub returns the Google DNS-JSON shape the real endpoint
uses: a Status code and an Answer list whose CNAME records have type 5.
"""
import json
import re

import pytest

from phantomprobe.models import Severity
from phantomprobe.takeover import _TAKEOVER_FINGERPRINTS, TakeoverScanner


class _Resp:
    """Minimal context-manager response wrapping a byte body."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self, *_):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def doh_response(status=0, cname=None):
    answer = []
    if cname:
        answer = [{"name": "x", "type": 5, "data": cname}]
    return json.dumps({"Status": status, "Answer": answer}).encode()


@pytest.fixture
def scanner():
    return TakeoverScanner("victim.com")


class TestFingerprintTable:
    """The embedded table is generated from can-i-take-over-xyz; guard its shape."""

    def test_table_is_populated(self):
        assert len(_TAKEOVER_FINGERPRINTS) >= 20

    def test_every_entry_has_a_cname_and_a_signal(self):
        for entry in _TAKEOVER_FINGERPRINTS:
            assert entry["cnames"], f"{entry['service']} has no cname"
            assert entry["fingerprint"], f"{entry['service']} has no fingerprint"

    def test_no_cname_is_an_ip_or_url(self):
        """A CNAME target is always a hostname, so those patterns never match."""
        for entry in _TAKEOVER_FINGERPRINTS:
            for cname in entry["cnames"]:
                assert "/" not in cname
                assert not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", cname)

    def test_every_body_fingerprint_compiles(self):
        for entry in _TAKEOVER_FINGERPRINTS:
            if entry["fingerprint"] != "NXDOMAIN":
                re.compile(entry["fingerprint"])


class TestServiceMatching:
    def test_matches_on_a_label_boundary(self):
        entry = TakeoverScanner.match_service("my-bucket.s3.amazonaws.com")
        assert entry and entry["service"] == "AWS/S3"

    def test_does_not_match_a_lookalike_suffix(self):
        # not-s3.amazonaws.com.evil.com must not match s3.amazonaws.com
        assert TakeoverScanner.match_service("s3.amazonaws.com.evil.com") is None

    def test_unknown_target_returns_none(self):
        assert TakeoverScanner.match_service("cdn.cloudfront.net") is None


class TestTwoSignalLogic:
    """A finding requires the CNAME match AND the unclaimed signal."""

    def _wire(self, scanner, monkeypatch, cname, body=None, a_status=0):
        def fake_doh(request, timeout=None):
            url = request.full_url
            if "type=CNAME" in url:
                return _Resp(doh_response(cname=cname))
            return _Resp(doh_response(status=a_status))

        monkeypatch.setattr("phantomprobe.doh.safe_urlopen", fake_doh)
        monkeypatch.setattr(scanner, "fetch_body", lambda host: body)

    def test_body_fingerprint_match_is_a_finding(self, scanner, monkeypatch):
        self._wire(scanner, monkeypatch, cname="victim.s3.amazonaws.com",
                   body="<Code>NoSuchBucket</Code> The specified bucket does not exist")
        finding = scanner.check_host("assets.victim.com")
        assert finding is not None
        assert finding.severity is Severity.HIGH
        assert "AWS/S3" in finding.evidence

    def test_matching_cname_without_fingerprint_is_not_a_finding(self, scanner, monkeypatch):
        """A live, claimed S3 bucket has the same CNAME but no error page."""
        self._wire(scanner, monkeypatch, cname="victim.s3.amazonaws.com",
                   body="<html>our real marketing site</html>")
        assert scanner.check_host("assets.victim.com") is None

    def test_nxdomain_service_confirmed_by_dead_target(self, scanner, monkeypatch):
        # Azure: CNAME resolves, but the target A lookup is NXDOMAIN.
        self._wire(scanner, monkeypatch, cname="gone.cloudapp.net", a_status=3)
        finding = scanner.check_host("app.victim.com")
        assert finding is not None
        assert "cloudapp.net" in finding.evidence

    def test_nxdomain_service_with_live_target_is_not_a_finding(self, scanner, monkeypatch):
        self._wire(scanner, monkeypatch, cname="live.cloudapp.net", a_status=0)
        assert scanner.check_host("app.victim.com") is None

    def test_no_cname_is_not_a_finding(self, scanner, monkeypatch):
        self._wire(scanner, monkeypatch, cname=None)
        assert scanner.check_host("www.victim.com") is None

    def test_a_transient_doh_failure_is_not_a_takeover(self, scanner, monkeypatch):
        """
        NXDOMAIN must be authoritative. If the target A lookup fails to reach
        the resolver, that is not proof the resource is gone.
        """
        calls = {"n": 0}

        def flaky_doh(request, timeout=None):
            if "type=CNAME" in request.full_url:
                return _Resp(doh_response(cname="gone.cloudapp.net"))
            raise OSError("network down")

        monkeypatch.setattr("phantomprobe.doh.safe_urlopen", flaky_doh)
        # target_resolves must treat the failure as "still there".
        assert scanner.target_resolves("gone.cloudapp.net") is True
        assert scanner.check_host("app.victim.com") is None


class TestRun:
    def test_run_dedupes_and_includes_the_target(self, scanner, monkeypatch):
        checked = []
        monkeypatch.setattr(scanner, "check_host",
                            lambda host: checked.append(host) or None)
        scanner.run(["www.victim.com", "www.victim.com", "api.victim.com"])
        assert checked == ["victim.com", "www.victim.com", "api.victim.com"]

    def test_run_collects_findings(self, scanner, monkeypatch):
        from phantomprobe.models import Finding

        def one(host):
            if host == "assets.victim.com":
                return Finding("T", "t", "d", Severity.HIGH, "Subdomain Takeover",
                               "e", "r", [], "", "victim.com")
            return None

        monkeypatch.setattr(scanner, "check_host", one)
        found = scanner.run(["assets.victim.com", "www.victim.com"])
        assert len(found) == 1
