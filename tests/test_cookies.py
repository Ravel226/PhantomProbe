"""
Tests for cookie security analysis.

The parser cases are real Set-Cookie values observed on live sites, because
that is where the awkward shapes come from: inconsistent attribute casing in a
single response, and values containing "=" and JSON.
"""
from email.message import Message

import pytest

from phantomprobe.cookies import (
    CookieScanner,
    is_session_cookie,
    parse_set_cookie,
)
from phantomprobe.models import Severity


def headers(cookies):
    message = Message()
    for cookie in cookies:
        message["Set-Cookie"] = cookie
    return message


def by_id(findings):
    return {f.id: f for f in findings}


class TestParser:
    def test_flags_and_values_are_separated(self):
        name, attrs = parse_set_cookie(
            "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        assert name == "sid"
        assert attrs["secure"] is True and attrs["httponly"] is True
        assert attrs["samesite"] == "Lax"

    def test_attribute_casing_is_normalised(self):
        """GitHub sends "secure" and "HttpOnly" in the same response."""
        _, attrs = parse_set_cookie("x=1; secure; HttpOnly; SAMESITE=Strict")
        assert attrs["secure"] is True
        assert attrs["httponly"] is True
        assert attrs["samesite"] == "Strict"

    def test_value_containing_equals_and_json(self):
        # Observed on cloudflare.com.
        raw = 'cfz_google-analytics_v4={"nzcr_ga4":{"v":"330c","e":1822}}; Path=/'
        name, attrs = parse_set_cookie(raw)
        assert name == "cfz_google-analytics_v4"
        assert "secure" not in attrs

    def test_empty_value_is_handled(self):
        assert parse_set_cookie("") == ("", {})

    @pytest.mark.parametrize("name,expected", [
        ("_gh_sess", True), ("PHPSESSID", True), ("auth_token", True),
        ("logged_in", True), ("jwt", True),
        ("_ga", False), ("theme", False), ("cfz_adobe", False),
    ])
    def test_session_cookie_detection(self, name, expected):
        assert is_session_cookie(name) is expected


class TestFindings:
    def test_missing_secure_is_medium(self):
        findings = CookieScanner("x.com").analyze(headers(["a=1; HttpOnly; SameSite=Lax"]))
        finding = by_id(findings)["COOKIE-NoSecure"]
        assert finding.severity is Severity.MEDIUM
        assert "a" in finding.evidence

    def test_missing_httponly_on_a_tracking_cookie_is_low(self):
        """A tracking cookie readable by script is usually deliberate."""
        findings = CookieScanner("x.com").analyze(headers(["_ga=1; Secure; SameSite=Lax"]))
        assert by_id(findings)["COOKIE-NoHttpOnly"].severity is Severity.LOW

    def test_missing_httponly_on_a_session_cookie_is_medium(self):
        """There it turns any XSS into session theft."""
        findings = CookieScanner("x.com").analyze(
            headers(["PHPSESSID=1; Secure; SameSite=Lax"]))
        finding = by_id(findings)["COOKIE-NoHttpOnly"]
        assert finding.severity is Severity.MEDIUM
        assert "PHPSESSID" in finding.description

    def test_samesite_none_without_secure_is_reported(self):
        """Browsers reject this pairing, so it is broken as well as insecure."""
        findings = CookieScanner("x.com").analyze(headers(["a=1; SameSite=None"]))
        finding = by_id(findings)["COOKIE-SameSiteNoneInsecure"]
        assert finding.severity is Severity.MEDIUM

    def test_missing_samesite_is_only_low(self):
        """Current browsers already default it to Lax, so this is hardening."""
        findings = CookieScanner("x.com").analyze(headers(["a=1; Secure; HttpOnly"]))
        assert by_id(findings)["COOKIE-NoSameSite"].severity is Severity.LOW

    def test_a_fully_hardened_cookie_produces_nothing(self):
        findings = CookieScanner("x.com").analyze(
            headers(["sid=1; Secure; HttpOnly; SameSite=Lax"]))
        assert findings == []

    def test_no_cookies_produces_nothing(self):
        assert CookieScanner("x.com").analyze(headers([])) == []

    def test_every_cookie_is_seen_not_just_the_last(self):
        """
        Set-Cookie repeats, and a dict would keep only the final one. Two of
        these three lack Secure and both must be listed.
        """
        findings = CookieScanner("x.com").analyze(headers([
            "a=1; HttpOnly; SameSite=Lax",
            "b=2; Secure; HttpOnly; SameSite=Lax",
            "c=3; HttpOnly; SameSite=Lax",
        ]))
        evidence = by_id(findings)["COOKIE-NoSecure"].evidence
        assert "a" in evidence and "c" in evidence
        assert "2 of 3" in evidence

    def test_findings_are_grouped_not_one_per_cookie(self):
        """Twenty weak cookies must not become twenty findings."""
        findings = CookieScanner("x.com").analyze(
            headers([f"c{i}=1" for i in range(20)]))
        assert len(findings) == 3  # no Secure, no HttpOnly, no SameSite
