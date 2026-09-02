"""
Tests for the DNS security checks.

DoH is stubbed, which matters here because the well-configured domains used to
develop this produce no email findings at all. The paths worth proving are the
ones a healthy domain never takes: a missing SPF, a +all record, a p=none
policy.
"""
import pytest

from phantomprobe.dns_security import (
    DnsSecurityScanner,
    detect_mail_provider,
    parse_dmarc_policy,
    parse_spf_all,
)
from phantomprobe.models import Severity


@pytest.fixture
def scanner(monkeypatch):
    """A scanner whose DoH answers come from a dict the test fills in."""
    scanner = DnsSecurityScanner("victim.com")
    scanner._answers = {}

    def fake_records(name, rtype, timeout=10):
        return scanner._answers.get((name, rtype.upper()), [])

    monkeypatch.setattr("phantomprobe.dns_security.doh.records", fake_records)
    monkeypatch.setattr("phantomprobe.dns_security.doh.is_dnssec_validated",
                        lambda name, timeout=10: True)
    return scanner


def ids(findings):
    return {f.id for f in findings}


def one(findings, finding_id):
    return next(f for f in findings if f.id == finding_id)


class TestParsers:
    @pytest.mark.parametrize("record,expected", [
        ("v=spf1 include:_spf.google.com ~all", "~"),
        ("v=spf1 -all", "-"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 +all", "+"),
        ("v=spf1 include:x.com", None),
    ])
    def test_spf_all_qualifier(self, record, expected):
        assert parse_spf_all(record) == expected

    @pytest.mark.parametrize("record,expected", [
        ("v=DMARC1; p=reject; rua=mailto:a@b.c", "reject"),
        # example.com publishes this without spaces.
        ("v=DMARC1;p=reject;sp=reject;adkim=s", "reject"),
        ("v=DMARC1; p=none", "none"),
        ("v=DMARC1; rua=mailto:a@b.c", None),
    ])
    def test_dmarc_policy(self, record, expected):
        assert parse_dmarc_policy(record) == expected

    def test_mail_provider_from_mx(self):
        # Real MX answers are "<priority> <host>."
        assert detect_mail_provider(
            ["0 github-com.mail.protection.outlook.com."]) == ["Microsoft 365"]

    def test_unknown_provider_is_not_guessed(self):
        assert detect_mail_provider(["10 mail.selfhosted.example."]) == []


class TestSpf:
    def test_missing_spf_is_medium(self, scanner):
        scanner.check_spf()
        finding = one(scanner.findings, "DNS-NoSPF")
        assert finding.severity is Severity.MEDIUM

    def test_pass_all_is_high(self, scanner):
        """+all is worse than no record: it asserts the forgery is legitimate."""
        scanner._answers[("victim.com", "TXT")] = ["v=spf1 +all"]
        scanner.check_spf()
        assert one(scanner.findings, "DNS-SPFPassAll").severity is Severity.HIGH

    def test_neutral_is_low(self, scanner):
        scanner._answers[("victim.com", "TXT")] = ["v=spf1 ?all"]
        scanner.check_spf()
        assert one(scanner.findings, "DNS-SPFNeutral").severity is Severity.LOW

    def test_softfail_is_accepted_silently(self, scanner):
        scanner._answers[("victim.com", "TXT")] = ["v=spf1 include:x ~all"]
        scanner.check_spf()
        assert scanner.findings == []

    def test_hardfail_is_accepted_silently(self, scanner):
        """A domain that sends no mail should publish exactly this."""
        scanner._answers[("victim.com", "TXT")] = ["v=spf1 -all"]
        scanner.check_spf()
        assert scanner.findings == []

    def test_multiple_records_are_reported(self, scanner):
        """RFC 7208 makes this a permanent error, so SPF stops being evaluated."""
        scanner._answers[("victim.com", "TXT")] = ["v=spf1 -all", "v=spf1 ~all"]
        scanner.check_spf()
        assert "DNS-MultipleSPF" in ids(scanner.findings)

    def test_unrelated_txt_records_are_ignored(self, scanner):
        scanner._answers[("victim.com", "TXT")] = [
            "google-site-verification=abc", "v=spf1 -all"]
        scanner.check_spf()
        assert scanner.findings == []


class TestDmarc:
    def test_missing_dmarc_is_medium(self, scanner):
        scanner.check_dmarc()
        assert one(scanner.findings, "DNS-NoDMARC").severity is Severity.MEDIUM

    def test_policy_none_is_low(self, scanner):
        """Monitoring only: spoofed mail is still delivered."""
        scanner._answers[("_dmarc.victim.com", "TXT")] = ["v=DMARC1; p=none"]
        scanner.check_dmarc()
        assert one(scanner.findings, "DNS-DMARCNone").severity is Severity.LOW

    @pytest.mark.parametrize("policy", ["quarantine", "reject"])
    def test_enforcing_policies_are_silent(self, scanner, policy):
        scanner._answers[("_dmarc.victim.com", "TXT")] = [f"v=DMARC1; p={policy}"]
        scanner.check_dmarc()
        assert scanner.findings == []

    def test_record_without_policy_is_reported(self, scanner):
        scanner._answers[("_dmarc.victim.com", "TXT")] = ["v=DMARC1; rua=mailto:a@b"]
        scanner.check_dmarc()
        assert "DNS-DMARCNoPolicy" in ids(scanner.findings)


class TestDkim:
    def test_found_selector_is_reported(self, scanner):
        scanner._answers[("default._domainkey.victim.com", "TXT")] = [
            "v=DKIM1; k=rsa; p=MIGfMA0GCSq"]
        scanner.check_dkim()
        assert "DNS-DKIM" in ids(scanner.findings)

    def test_absence_is_not_reported(self, scanner):
        """
        A selector is an arbitrary label, so silence from the probe list is not
        evidence that DKIM is missing. Claiming otherwise would be a false
        finding.
        """
        scanner.check_dkim()
        assert scanner.findings == []

    def test_revoked_key_is_not_counted(self, scanner):
        """An empty p= is a revoked key, not a working one."""
        scanner._answers[("default._domainkey.victim.com", "TXT")] = ["v=DKIM1; p="]
        scanner.check_dkim()
        assert scanner.findings == []


class TestCaaAndDnssec:
    def test_caa_present_is_informational(self, scanner):
        scanner._answers[("victim.com", "CAA")] = ['0 issue "letsencrypt.org"']
        scanner.check_caa()
        assert one(scanner.findings, "DNS-CAA").severity is Severity.INFORMATIONAL

    def test_caa_absent_is_only_low(self, scanner):
        """Hardening: most domains publish none."""
        scanner.check_caa()
        assert one(scanner.findings, "DNS-NoCAA").severity is Severity.LOW

    def test_dnssec_signed_is_informational(self, scanner):
        scanner._answers[("victim.com", "DNSKEY")] = ["257 3 13 abc"]
        scanner.check_dnssec()
        assert one(scanner.findings, "DNS-DNSSEC").severity is Severity.INFORMATIONAL

    def test_dnssec_absent_is_only_low(self, scanner):
        scanner.check_dnssec()
        assert one(scanner.findings, "DNS-NoDNSSEC").severity is Severity.LOW


class TestRun:
    def test_a_bare_domain_reports_the_email_gaps(self, scanner):
        """Nothing published at all: SPF and DMARC are the findings that matter."""
        found = ids(scanner.run())
        assert {"DNS-NoSPF", "DNS-NoDMARC", "DNS-NoCAA", "DNS-NoDNSSEC"} <= found

    def test_no_mx_produces_no_mx_finding(self, scanner):
        assert "DNS-MX" not in ids(scanner.run())
