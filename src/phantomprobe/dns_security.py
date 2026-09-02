#!/usr/bin/env python3
"""
DNS-derived security posture: SPF, DMARC, DKIM, CAA and DNSSEC.

All of it comes from DNS records fetched over DoH (see doh.py), so nothing is
sent to the target itself.

The email records carry the weight here. Without SPF and DMARC, anyone can put
the domain in a From: header and have it delivered, which is the cheapest
phishing route into an organisation and needs no access to its systems at all.
CAA and DNSSEC are hardening: their absence is common and is reported as such
rather than dressed up as a vulnerability.

A domain that sends no mail is not exempt. It can still be spoofed from, which
is why the correct configuration for such a domain is an explicit "v=spf1 -all"
rather than no record at all.
"""

import re
from datetime import datetime
from typing import List, Optional

from . import doh
from .models import Finding, Severity

# Selectors worth probing. A negative result proves nothing, because a selector
# is an arbitrary label chosen by the sender, so only hits are reported.
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "s1", "dkim", "mail",
)

# MX hostname to provider, for recon context.
MX_PROVIDERS = (
    (r"google(mail)?\.com$", "Google Workspace"),
    (r"outlook\.com$|microsoft\.com$|protection\.outlook\.com$", "Microsoft 365"),
    (r"protonmail\.ch$|proton\.me$", "Proton Mail"),
    (r"zoho\.(com|eu|in)$", "Zoho Mail"),
    (r"yahoodns\.net$", "Yahoo"),
    (r"mimecast\.com$", "Mimecast"),
    (r"pphosted\.com$", "Proofpoint"),
    (r"messagelabs\.com$", "Broadcom Email Security"),
    (r"iphmx\.com$", "Cisco Email Security"),
    (r"mailgun\.org$", "Mailgun"),
    (r"sendgrid\.net$", "SendGrid"),
    (r"barracudanetworks\.com$", "Barracuda"),
)


def parse_spf_all(record: str) -> Optional[str]:
    """
    Return the qualifier on the "all" mechanism: -, ~, ? or +.

    That final mechanism is what decides the fate of mail from an unlisted
    server, so it is the part of the record that matters most.
    """
    match = re.search(r"([-~?+])all\b", record, re.IGNORECASE)
    return match.group(1) if match else None


def parse_dmarc_policy(record: str) -> Optional[str]:
    """
    Return the DMARC p= policy.

    Tags are separated by semicolons with optional spaces, and real records use
    both spellings, so the split tolerates either.
    """
    for tag in record.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("p="):
            return tag[2:].strip().lower()
    return None


def detect_mail_provider(mx_records: List[str]) -> List[str]:
    """Name the mail providers behind a set of MX hostnames."""
    found = []
    for record in mx_records:
        # An MX answer is "<priority> <hostname>."
        host = record.split()[-1].rstrip(".").lower() if record.split() else ""
        for pattern, provider in MX_PROVIDERS:
            if re.search(pattern, host) and provider not in found:
                found.append(provider)
    return found


class DnsSecurityScanner:
    """Check the DNS records that govern email spoofing and trust."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.findings: List[Finding] = []

    def _add(self, finding_id, title, description, severity, category,
             evidence, remediation, references):
        self.findings.append(Finding(
            id=finding_id, title=title, description=description,
            severity=severity, category=category, evidence=evidence,
            remediation=remediation, references=references,
            discovered_at=datetime.now().isoformat(), target=self.target,
        ))

    def check_spf(self) -> None:
        txt = doh.records(self.target, "TXT", self.timeout)
        spf = [t for t in txt if t.lower().startswith("v=spf1")]

        if not spf:
            self._add(
                "DNS-NoSPF", "No SPF Record",
                "Without SPF, no server is declared as authorised to send mail "
                "for this domain, so a forged From: address has nothing to fail "
                "against. A domain that sends no mail should still publish "
                "'v=spf1 -all'.",
                Severity.MEDIUM, "Email Security",
                "No TXT record beginning v=spf1",
                "Publish an SPF record ending in -all or ~all.",
                ["https://www.rfc-editor.org/rfc/rfc7208"],
            )
            return

        if len(spf) > 1:
            # More than one SPF record is a permanent error: receivers cannot
            # choose between them, so the whole check fails open.
            self._add(
                "DNS-MultipleSPF", "Multiple SPF Records",
                "More than one SPF record is published. RFC 7208 makes this a "
                "permanent error, and receivers stop evaluating SPF entirely.",
                Severity.MEDIUM, "Email Security",
                "\n".join(spf),
                "Merge them into a single TXT record.",
                ["https://www.rfc-editor.org/rfc/rfc7208"],
            )

        qualifier = parse_spf_all(spf[0])
        if qualifier == "+":
            self._add(
                "DNS-SPFPassAll", "SPF Authorises Every Sender",
                "The record ends in '+all', which declares that any server on "
                "the internet may send mail as this domain. It is worse than "
                "having no SPF, because it asserts the forgery is legitimate.",
                Severity.HIGH, "Email Security",
                spf[0],
                "Replace +all with -all, listing legitimate senders explicitly.",
                ["https://www.rfc-editor.org/rfc/rfc7208"],
            )
        elif qualifier == "?":
            self._add(
                "DNS-SPFNeutral", "SPF Makes No Assertion",
                "The record ends in '?all' (neutral), which tells receivers "
                "nothing about unlisted senders, so it offers no protection.",
                Severity.LOW, "Email Security",
                spf[0],
                "End the record with -all, or ~all while still deploying.",
                ["https://www.rfc-editor.org/rfc/rfc7208"],
            )
        elif qualifier is None:
            self._add(
                "DNS-SPFNoAll", "SPF Record Has No 'all' Mechanism",
                "The record does not end in an 'all' mechanism, so unlisted "
                "senders fall through with no verdict.",
                Severity.LOW, "Email Security",
                spf[0],
                "Terminate the record with -all or ~all.",
                ["https://www.rfc-editor.org/rfc/rfc7208"],
            )

    def check_dmarc(self) -> None:
        txt = doh.records(f"_dmarc.{self.target}", "TXT", self.timeout)
        dmarc = [t for t in txt if t.lower().startswith("v=dmarc1")]

        if not dmarc:
            self._add(
                "DNS-NoDMARC", "No DMARC Record",
                "Without DMARC, SPF and DKIM failures carry no instruction, so "
                "receivers decide for themselves whether to deliver forged "
                "mail, and the domain owner gets no reports of abuse.",
                Severity.MEDIUM, "Email Security",
                f"No TXT record at _dmarc.{self.target}",
                "Publish a DMARC record, starting at p=none with rua= reporting "
                "and tightening to quarantine then reject.",
                ["https://www.rfc-editor.org/rfc/rfc7489"],
            )
            return

        policy = parse_dmarc_policy(dmarc[0])
        if policy == "none":
            self._add(
                "DNS-DMARCNone", "DMARC Policy Is Monitoring Only",
                "The policy is p=none, which asks receivers to report on "
                "failures but to deliver the mail anyway, so spoofed messages "
                "still reach inboxes.",
                Severity.LOW, "Email Security",
                dmarc[0],
                "Move to p=quarantine, then p=reject once reports look clean.",
                ["https://www.rfc-editor.org/rfc/rfc7489"],
            )
        elif policy is None:
            self._add(
                "DNS-DMARCNoPolicy", "DMARC Record Has No Policy",
                "The record declares no p= tag, so receivers have no "
                "instruction to apply.",
                Severity.LOW, "Email Security",
                dmarc[0],
                "Add a p= tag.",
                ["https://www.rfc-editor.org/rfc/rfc7489"],
            )

    def check_dkim(self) -> None:
        """
        Probe common DKIM selectors.

        Only hits are reported: a selector is an arbitrary label, so silence
        from this list is not evidence that DKIM is absent, and claiming
        otherwise would be a false finding.
        """
        found = []
        for selector in DKIM_SELECTORS:
            records = doh.records(
                f"{selector}._domainkey.{self.target}", "TXT", self.timeout)
            for record in records:
                if "p=" in record and "v=dkim1" in record.lower():
                    # An empty p= is a revoked key, not a working one.
                    if re.search(r"p=\s*(;|$)", record):
                        continue
                    found.append(selector)
                    break

        if found:
            self._add(
                "DNS-DKIM", "DKIM Selectors Published",
                f"DKIM keys are published for {len(found)} common selector(s).",
                Severity.INFORMATIONAL, "Email Security",
                "Selectors: " + ", ".join(found),
                "N/A - information gathering",
                ["https://www.rfc-editor.org/rfc/rfc6376"],
            )

    def check_caa(self) -> None:
        records = doh.records(self.target, "CAA", self.timeout)
        if records:
            self._add(
                "DNS-CAA", "CAA Records Published",
                "The domain restricts which certificate authorities may issue "
                "for it.",
                Severity.INFORMATIONAL, "DNS",
                "\n".join(records[:6]),
                "N/A - information gathering",
                ["https://www.rfc-editor.org/rfc/rfc8659"],
            )
        else:
            self._add(
                "DNS-NoCAA", "No CAA Record",
                "No CAA record, so any certificate authority may issue a "
                "certificate for this domain. This is hardening rather than an "
                "open door, and most domains publish none.",
                Severity.LOW, "DNS",
                "No CAA records returned",
                "Publish a CAA record naming the CAs you use.",
                ["https://www.rfc-editor.org/rfc/rfc8659"],
            )

    def check_dnssec(self) -> None:
        dnskey = doh.records(self.target, "DNSKEY", self.timeout)
        if dnskey:
            validated = doh.is_dnssec_validated(self.target, self.timeout)
            self._add(
                "DNS-DNSSEC", "DNSSEC Enabled",
                "The zone is signed"
                + (" and the resolver validated the answer." if validated
                   else ", though the resolver did not report validation."),
                Severity.INFORMATIONAL, "DNS",
                f"{len(dnskey)} DNSKEY record(s); AD flag: {validated}",
                "N/A - information gathering",
                ["https://www.rfc-editor.org/rfc/rfc4033"],
            )
        else:
            self._add(
                "DNS-NoDNSSEC", "DNSSEC Not Enabled",
                "The zone publishes no DNSKEY, so DNS answers for this domain "
                "cannot be cryptographically validated and remain open to "
                "spoofing at the resolver. Most domains are in this state.",
                Severity.LOW, "DNS",
                "No DNSKEY records returned",
                "Sign the zone and publish a DS record at the registrar.",
                ["https://www.rfc-editor.org/rfc/rfc4033"],
            )

    def check_mx(self) -> None:
        records = doh.records(self.target, "MX", self.timeout)
        if not records:
            return
        providers = detect_mail_provider(records)
        self._add(
            "DNS-MX", "Mail Servers Identified",
            f"The domain accepts mail through {len(records)} MX host(s)."
            + (f" Provider: {', '.join(providers)}." if providers else ""),
            Severity.INFORMATIONAL, "DNS",
            "\n".join(records[:6]),
            "N/A - information gathering",
            [],
        )

    def run(self) -> List[Finding]:
        print("[*] Checking DNS security records (SPF, DMARC, DKIM, CAA, DNSSEC)...")
        self.check_mx()
        self.check_spf()
        self.check_dmarc()
        self.check_dkim()
        self.check_caa()
        self.check_dnssec()
        print(f"[+] DNS security: {len(self.findings)} findings")
        return self.findings
