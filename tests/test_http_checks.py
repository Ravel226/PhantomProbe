"""
Tests for the HTTP posture checks: HSTS preload, redirect chain, security.txt.

The HSTS thresholds are the ones hstspreload.org publishes today, not the
10886400 that older write-ups still carry, so the boundary cases here are the
point of the file.
"""
from email.message import Message

import pytest

from phantomprobe.http_checks import (
    HSTS_PRELOAD_MIN_AGE,
    HstsPreloadScanner,
    RedirectScanner,
    SecurityTxtScanner,
    evaluate_hsts_preload,
)
from phantomprobe.models import Severity


def headers(pairs):
    message = Message()
    for key, value in pairs:
        message[key] = value
    return message


class TestHstsPreload:
    def test_the_minimum_is_one_year(self):
        """hstspreload.org requires 31536000; 10886400 no longer qualifies."""
        assert HSTS_PRELOAD_MIN_AGE == 31536000

    def test_a_qualifying_header_is_eligible(self):
        eligible, reasons = evaluate_hsts_preload(
            "max-age=31536000; includeSubDomains; preload")
        assert eligible is True and reasons == []

    def test_real_github_header_is_eligible(self):
        """GitHub spells it "includeSubdomains"; matching must ignore case."""
        eligible, _ = evaluate_hsts_preload(
            "max-age=31536000; includeSubdomains; preload")
        assert eligible is True

    def test_the_old_threshold_no_longer_qualifies(self):
        eligible, reasons = evaluate_hsts_preload(
            "max-age=10886400; includeSubDomains; preload")
        assert eligible is False
        assert any("max-age" in r for r in reasons)

    @pytest.mark.parametrize("header,missing", [
        ("max-age=31536000; preload", "includeSubDomains"),
        ("max-age=31536000; includeSubDomains", "preload"),
    ])
    def test_each_missing_directive_is_named(self, header, missing):
        _, reasons = evaluate_hsts_preload(header)
        assert any(missing.lower() in r.lower() for r in reasons)

    def test_absent_header_yields_no_reasons(self):
        """
        The missing-header case belongs to the security-header check; repeating
        it here would count the same gap twice.
        """
        assert evaluate_hsts_preload(None) == (False, [])
        assert evaluate_hsts_preload("") == (False, [])

    def test_scanner_is_silent_when_the_header_is_absent(self):
        assert HstsPreloadScanner("x.com").analyze(headers([])) == []

    def test_scanner_is_silent_when_already_eligible(self):
        message = headers([("Strict-Transport-Security",
                            "max-age=31536000; includeSubDomains; preload")])
        assert HstsPreloadScanner("x.com").analyze(message) == []

    def test_short_max_age_is_low_but_a_missing_directive_is_informational(self):
        """A short max-age leaves a real stripping window; the rest is hardening."""
        short = HstsPreloadScanner("x.com").analyze(headers([
            ("Strict-Transport-Security", "max-age=300; includeSubDomains; preload")]))
        assert short[0].severity is Severity.LOW

        no_preload = HstsPreloadScanner("x.com").analyze(headers([
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains")]))
        assert no_preload[0].severity is Severity.INFORMATIONAL


class TestRedirectChain:
    def _wire(self, monkeypatch, hops):
        """hops maps a URL to (status, Location)."""
        def fake(url, timeout=10):
            if url not in hops:
                return None
            status, location = hops[url]
            message = Message()
            if location:
                message["Location"] = location
            return status, message

        monkeypatch.setattr("phantomprobe.http_checks._fetch_no_redirect", fake)

    def test_http_upgraded_to_https_is_informational(self, monkeypatch):
        self._wire(monkeypatch, {
            "http://x.com": (301, "https://x.com/"),
            "https://x.com/": (200, None),
        })
        findings = RedirectScanner("x.com").run()
        assert findings[0].id == "REDIRECT-Chain"
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_http_never_reaching_https_is_medium(self, monkeypatch):
        self._wire(monkeypatch, {"http://x.com": (200, None)})
        findings = RedirectScanner("x.com").run()
        assert findings[0].id == "REDIRECT-NoHttpsUpgrade"
        assert findings[0].severity is Severity.MEDIUM

    def test_relative_location_is_resolved(self, monkeypatch):
        self._wire(monkeypatch, {
            "http://x.com": (302, "/en/"),
            "http://x.com/en/": (301, "https://x.com/en/"),
            "https://x.com/en/": (200, None),
        })
        findings = RedirectScanner("x.com").run()
        assert "http://x.com/en/" in findings[0].evidence

    def test_offsite_redirect_is_reported(self, monkeypatch):
        self._wire(monkeypatch, {
            "http://x.com": (301, "https://cdn.other.net/"),
            "https://cdn.other.net/": (200, None),
        })
        ids = {f.id for f in RedirectScanner("x.com").run()}
        assert "REDIRECT-Offsite" in ids

    def test_a_redirect_loop_terminates(self, monkeypatch):
        self._wire(monkeypatch, {
            "http://x.com": (301, "http://x.com"),
        })
        findings = RedirectScanner("x.com").run()
        # MAX_REDIRECTS caps the walk instead of looping forever.
        assert findings

    def test_unreachable_host_produces_nothing(self, monkeypatch):
        monkeypatch.setattr("phantomprobe.http_checks._fetch_no_redirect",
                            lambda url, timeout=10: None)
        assert RedirectScanner("x.com").run() == []


class TestSecurityTxt:
    def test_fields_are_parsed(self):
        body = (
            "# comment line\n"
            "Contact: mailto:security@x.com\n"
            "Expires: 2027-01-01T00:00:00.000Z\n"
            "Policy: https://x.com/policy\n"
        )
        fields = SecurityTxtScanner.parse(body)
        assert fields["Contact"] == "mailto:security@x.com"
        assert fields["Policy"] == "https://x.com/policy"

    def test_repeated_fields_are_kept(self):
        """Contact legitimately appears more than once."""
        fields = SecurityTxtScanner.parse(
            "Contact: mailto:a@x.com\nContact: https://x.com/report\n")
        assert "a@x.com" in fields["Contact"] and "report" in fields["Contact"]

    def test_pgp_envelope_is_skipped(self):
        body = ("-----BEGIN PGP SIGNED MESSAGE-----\n"
                "Hash: SHA256\n"
                "Contact: mailto:s@x.com\n"
                "-----BEGIN PGP SIGNATURE-----\n")
        fields = SecurityTxtScanner.parse(body)
        assert fields["Contact"] == "mailto:s@x.com"

    def test_absence_is_informational_not_a_weakness(self, monkeypatch):
        def refuse(*args, **kwargs):
            raise OSError("404")

        monkeypatch.setattr("phantomprobe.http_client.safe_urlopen", refuse)
        findings = SecurityTxtScanner("x.com").run()
        assert findings[0].id == "SECURITYTXT-Missing"
        assert findings[0].severity is Severity.INFORMATIONAL
