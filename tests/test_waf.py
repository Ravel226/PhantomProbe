"""
Tests for WAF/CDN detection.

Detection is pure header matching, so these build real HTTPMessage objects
(which is what analyze_headers hands it) and assert on the matches. The point of
interest is Set-Cookie: it repeats, and only get_all sees every copy.
"""
from email.message import Message

import pytest

from phantomprobe.models import Severity
from phantomprobe.waf import _WAF_SIGNATURES, WafScanner, detect_waf


def headers(pairs):
    message = Message()
    for key, value in pairs:
        message[key] = value
    return message


class TestSignatureTable:
    def test_table_is_populated(self):
        assert len(_WAF_SIGNATURES) >= 50

    def test_entries_are_well_formed(self):
        for header, needle, name in _WAF_SIGNATURES:
            assert header == header.lower(), f"{header} should be lowercased"
            assert needle is None or isinstance(needle, str)
            assert name

    def test_modern_cloudflare_cookies_are_present(self):
        """The web-check port predates these; they were added and verified live."""
        cookies = {n for h, n, name in _WAF_SIGNATURES
                   if name == "Cloudflare" and h == "set-cookie"}
        assert "__cf_bm" in cookies
        assert "cf_clearance" in cookies


class TestDetection:
    def test_presence_signal_matches_on_header_alone(self):
        # cf-ray has no needle: its presence is the signal.
        assert detect_waf(headers([("cf-ray", "7d2-LHR")])) == ["Cloudflare"]

    def test_needle_must_appear_in_the_value(self):
        assert detect_waf(headers([("Server", "AkamaiGHost")])) == ["Akamai"]

    def test_matching_is_case_insensitive(self):
        assert detect_waf(headers([("Server", "CloudFlare")])) == ["Cloudflare"]

    def test_a_cookie_signature_survives_multiple_set_cookie(self):
        """
        The reason detection reads the raw message, not a dict: a plain dict
        keeps only the last Set-Cookie, dropping the one that matches.
        """
        message = headers([
            ("Set-Cookie", "_ga=GA1.2.x"),
            ("Set-Cookie", "incap_ses_1=abc"),
            ("Set-Cookie", "session=z"),
        ])
        assert detect_waf(message) == ["Imperva Incapsula"]

    def test_plain_server_is_not_a_waf(self):
        assert detect_waf(headers([("Server", "nginx/1.24.0")])) == []

    def test_each_waf_reported_once(self):
        message = headers([
            ("Server", "cloudflare"),
            ("cf-ray", "7d2"),
            ("Set-Cookie", "__cf_bm=x"),
        ])
        assert detect_waf(message) == ["Cloudflare"]

    def test_multiple_distinct_wafs(self):
        # A Sucuri-fronted origin behind Cloudflare, say.
        message = headers([("Server", "cloudflare"), ("x-sucuri-id", "12")])
        result = detect_waf(message)
        assert "Cloudflare" in result and "Sucuri CloudProxy WAF" in result

    def test_plain_dict_fallback(self):
        # Callers may pass a plain mapping; single-value headers still match.
        assert detect_waf({"server": "cloudflare"}) == ["Cloudflare"]


class TestWafScanner:
    def test_produces_an_informational_finding(self):
        findings = WafScanner("victim.com").analyze(
            headers([("Server", "cloudflare")]))
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFORMATIONAL
        assert findings[0].category == "WAF Detection"
        assert "Cloudflare" in findings[0].title

    def test_no_waf_no_findings(self):
        findings = WafScanner("victim.com").analyze(
            headers([("Server", "nginx")]))
        assert findings == []
