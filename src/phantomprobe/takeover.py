#!/usr/bin/env python3
"""
Subdomain takeover detection.

A takeover is possible when a subdomain still points, by CNAME, at a
third-party service where the underlying resource has been released: the
attacker claims the resource and serves content from the victim's name.

Detection needs two signals, and reports only when both agree, because either
one alone is noisy. A CNAME to a service proves nothing on its own, since every
live GitHub Pages or S3 site has the same CNAME; the unclaimed-resource
fingerprint can appear in unrelated content. Together they are specific.

    signal 1  the subdomain's CNAME target matches a known service pattern
    signal 2  the service reports the resource as unclaimed, shown either as
              the CNAME target failing to resolve (NXDOMAIN) or as a known
              string in the page body

CNAMEs are resolved over DNS-over-HTTPS (see doh.py), so this stays within the
standard library like the rest of the passive core: the socket module cannot
return a CNAME, and a dangling one often has no A record for getaddrinfo to
find at all.

Fingerprints are the community-maintained set from can-i-take-over-xyz
(https://github.com/EdOverflow/can-i-take-over-xyz), embedded here so the check
runs offline. Only entries the project marks Vulnerable or Edge case are kept.
"""

import re
from datetime import datetime
from typing import List, Optional
from urllib.request import Request

from . import doh
from .constants import BROWSER_USER_AGENT
from .http_client import safe_urlopen
from .models import Finding, Severity



# Curated from can-i-take-over-xyz; only entries with a real CNAME pattern and a
# usable signal. "nxdomain" means the takeover shows as the CNAME target failing
# to resolve rather than as a page string. "edge" marks services the project
# lists as edge cases, reported at lower confidence.
_TAKEOVER_FINGERPRINTS = [
    {"service": 'Agile CRM', "cnames": ['agilecrm.com'], "fingerprint": 'Sorry, this page is no longer available.'},
    {"service": 'Airee.ru', "cnames": ['airee.ru'], "fingerprint": 'Ошибка 402. Сервис Айри.рф не оплачен'},
    {"service": 'Anima', "cnames": ['animaapp.io'], "fingerprint": 'The page you were looking for does not exist.'},
    {"service": 'AWS/Elastic Beanstalk', "cnames": ['elasticbeanstalk.com'], "fingerprint": 'NXDOMAIN', "nxdomain": True},
    {"service": 'AWS/S3', "cnames": ['s3.amazonaws.com'], "fingerprint": 'The specified bucket does not exist'},
    {"service": 'Bitbucket', "cnames": ['bitbucket.io'], "fingerprint": 'Repository not found'},
    {"service": 'Discourse', "cnames": ['trydiscourse.com'], "fingerprint": 'NXDOMAIN', "nxdomain": True},
    {"service": 'Gemfury', "cnames": ['furyns.com'], "fingerprint": '404: This page could not be found.'},
    {"service": 'Ghost', "cnames": ['ghost.io'], "fingerprint": 'Site unavailable\\.|Failed to resolve DNS path for this host'},
    {"service": 'HatenaBlog', "cnames": ['hatenablog.com'], "fingerprint": '404 Blog is not found'},
    {"service": 'Help Juice', "cnames": ['helpjuice.com'], "fingerprint": "We could not find what you're looking for."},
    {"service": 'Help Scout', "cnames": ['helpscoutdocs.com'], "fingerprint": 'No settings were found for this company:'},
    {"service": 'JetBrains', "cnames": ['youtrack.cloud'], "fingerprint": 'is not a registered InCloud YouTrack'},
    {"service": 'Microsoft Azure', "cnames": ['cloudapp.net', 'cloudapp.azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'azure-api.net', 'azurehdinsight.net', 'azureedge.net', 'azurecontainer.io', 'database.windows.net', 'azuredatalakestore.net', 'search.windows.net', 'azurecr.io', 'redis.cache.windows.net', 'servicebus.windows.net', 'visualstudio.com'], "fingerprint": 'NXDOMAIN', "nxdomain": True},
    {"service": 'Ngrok', "cnames": ['ngrok.io'], "fingerprint": 'Tunnel .*.ngrok.io not found'},
    {"service": 'Readme.io', "cnames": ['readme.io'], "fingerprint": 'The creators of this project are still working on making everything perfect!'},
    {"service": 'Strikingly', "cnames": ['s.strikinglydns.com'], "fingerprint": 'PAGE NOT FOUND.'},
    {"service": 'Surge.sh', "cnames": ['na-west1.surge.sh'], "fingerprint": 'project not found'},
    {"service": 'SurveySparrow', "cnames": ['surveysparrow.com'], "fingerprint": 'Account not found.'},
    {"service": 'Uberflip', "cnames": ['read.uberflip.com'], "fingerprint": "The URL you've accessed does not provide a hub."},
    {"service": 'Uptimerobot', "cnames": ['stats.uptimerobot.com'], "fingerprint": 'page not found'},
    {"service": 'Wordpress', "cnames": ['wordpress.com'], "fingerprint": 'Do you want to register .*.wordpress.com?'},
    {"service": 'Worksites', "cnames": ['worksites.net'], "fingerprint": 'Hello! Sorry, but the website you’re looking for doesn’t exist.'},
]


class TakeoverScanner:
    """Check a domain and its subdomains for dangling-CNAME takeovers."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.findings: List[Finding] = []

    # -- DNS over HTTPS -------------------------------------------------------

    def resolve_cname(self, host: str) -> Optional[str]:
        """Return the CNAME target for host, or None if it has no CNAME."""
        targets = doh.records(host, "CNAME", timeout=self.timeout)
        return targets[0].rstrip(".").lower() if targets else None

    def target_resolves(self, host: str) -> bool:
        """
        Whether the CNAME target still exists.

        NXDOMAIN is authoritative; a transient resolver failure is treated as
        "still there", so a network blip cannot be reported as a takeover.
        """
        return doh.resolves(host, timeout=self.timeout)

    # -- HTTP body fingerprint ------------------------------------------------

    def fetch_body(self, host: str) -> Optional[str]:
        """Fetch the host over https then http, returning the body text."""
        for scheme in ("https", "http"):
            request = Request(
                f"{scheme}://{host}",
                headers={"User-Agent": BROWSER_USER_AGENT},
            )
            try:
                with safe_urlopen(request, timeout=self.timeout) as response:
                    return response.read(65536).decode("utf-8", errors="ignore")
            except Exception:
                continue
        return None

    # -- matching -------------------------------------------------------------

    @staticmethod
    def match_service(cname_target: str) -> Optional[dict]:
        """Return the fingerprint entry whose CNAME pattern the target ends in."""
        for entry in _TAKEOVER_FINGERPRINTS:
            for pattern in entry["cnames"]:
                # Suffix match on a label boundary: foo.s3.amazonaws.com matches
                # s3.amazonaws.com, but not-s3.amazonaws.com.evil.com does not.
                if cname_target == pattern or cname_target.endswith("." + pattern):
                    return entry
        return None

    def _confirm(self, host: str, cname_target: str, entry: dict) -> Optional[str]:
        """Confirm the second signal, returning evidence text if a takeover holds."""
        if entry.get("nxdomain"):
            if not self.target_resolves(cname_target):
                return f"CNAME target {cname_target} returns NXDOMAIN"
            return None

        body = self.fetch_body(host)
        if body and re.search(entry["fingerprint"], body, re.IGNORECASE):
            return f"Service returned its unclaimed-resource page for {cname_target}"
        return None

    def check_host(self, host: str) -> Optional[Finding]:
        """Check a single host for a dangling-CNAME takeover."""
        cname_target = self.resolve_cname(host)
        if not cname_target:
            return None

        entry = self.match_service(cname_target)
        if not entry:
            return None

        evidence = self._confirm(host, cname_target, entry)
        if not evidence:
            return None

        edge = entry.get("edge", False)
        service = entry["service"]
        return Finding(
            id=f"TAKEOVER-{host.replace('.', '-')}",
            title=f"Possible Subdomain Takeover: {host}",
            description=(
                f"{host} has a dangling CNAME to {service} whose backing "
                f"resource appears unclaimed, allowing takeover."
                + (" This service is an edge case; confirm manually before "
                   "acting." if edge else "")
            ),
            # Edge cases are reported one step down: still worth surfacing,
            # not worth waking someone at night for without manual confirmation.
            severity=Severity.MEDIUM if edge else Severity.HIGH,
            category="Subdomain Takeover",
            evidence=f"Host: {host}\nCNAME: {cname_target}\nService: {service}\n{evidence}",
            remediation=(
                "Remove the dangling DNS record, or reclaim the resource at "
                f"{service} before an attacker does."
            ),
            references=[
                "https://github.com/EdOverflow/can-i-take-over-xyz",
                "https://owasp.org/www-community/attacks/Subdomain_Takeover",
            ],
            discovered_at=datetime.now().isoformat(),
            target=self.target,
        )

    def run(self, hosts: Optional[List[str]] = None) -> List[Finding]:
        """
        Check the target and the given hosts for takeovers.

        hosts defaults to the target alone; the caller passes the enumerated
        subdomains so a candidate found earlier in the scan is reused rather
        than resolved twice.
        """
        candidates = [self.target] + list(hosts or [])
        # Dedupe while preserving order.
        seen = set()
        ordered = [h for h in candidates if not (h in seen or seen.add(h))]

        print(f"[*] Checking {len(ordered)} host(s) for subdomain takeover...")
        for host in ordered:
            finding = self.check_host(host)
            if finding:
                self.findings.append(finding)

        print(f"[+] Subdomain takeover: {len(self.findings)} candidate(s)")
        return self.findings
