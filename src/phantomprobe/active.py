#!/usr/bin/env python3
"""
Phase 2: active reconnaissance (port scan, subdomain enumeration, fingerprinting).

These checks send traffic directly to the target. Only run them against systems
you are authorized to test.
"""

import concurrent.futures
import re
import secrets
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.request import Request

from .http_client import safe_urlopen

from .constants import USER_AGENT
from .models import Finding, Severity
from .ports import COMMON_PORTS, PortScanner


class ActiveReconEngine:
    """Phase 2: Active Reconnaissance"""

    # The list lives with the scanner in ports.py; it stays reachable here
    # for callers that address it through the engine.
    COMMON_PORTS = COMMON_PORTS

    COMMON_SUBDOMAINS = [
        # web front doors
        'www', 'www2', 'web', 'app', 'apps', 'portal', 'secure', 'my',
        'account', 'accounts', 'login', 'sso', 'auth', 'id', 'oauth',
        # api and services
        'api', 'apis', 'api-dev', 'api-staging', 'rest', 'graphql', 'grpc',
        'gateway', 'service', 'services', 'ws', 'socket', 'rpc',
        # environments
        'dev', 'develop', 'development', 'staging', 'stage', 'stg', 'test',
        'testing', 'qa', 'uat', 'sandbox', 'demo', 'beta', 'alpha', 'preview',
        'preprod', 'prod', 'production', 'live', 'internal', 'int',
        # mail
        'mail', 'smtp', 'imap', 'pop', 'pop3', 'webmail', 'mx', 'mx1', 'mx2',
        'email', 'exchange', 'autodiscover', 'mailgun', 'newsletter',
        # infra and ops
        'vpn', 'remote', 'gitlab', 'git', 'jenkins', 'ci', 'cd', 'build',
        'deploy', 'monitor', 'monitoring', 'grafana', 'kibana', 'prometheus',
        'status', 'health', 'metrics', 'logs', 'log', 'jira', 'confluence',
        'wiki', 'nexus', 'registry', 'docker', 'k8s', 'kubernetes',
        # data
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'sql',
        'phpmyadmin', 'pma', 'adminer', 'backup', 'backups', 'ftp', 'sftp',
        'files', 'file', 'share', 'drive', 'cloud', 's3', 'storage',
        # content and cdn
        'cdn', 'static', 'assets', 'media', 'img', 'images', 'image', 'video',
        'download', 'downloads', 'uploads', 'content', 'cache', 'edge',
        # sites and apps
        'blog', 'news', 'shop', 'store', 'cart', 'checkout', 'pay', 'payment',
        'billing', 'support', 'help', 'helpdesk', 'docs', 'documentation',
        'kb', 'forum', 'community', 'events', 'careers', 'jobs', 'about',
        # admin surfaces
        'admin', 'administrator', 'adm', 'panel', 'cpanel', 'webadmin',
        'dashboard', 'manage', 'management', 'console', 'control',
        # network
        'ns', 'ns1', 'ns2', 'ns3', 'dns', 'proxy', 'lb', 'router', 'firewall',
        'gw', 'dmz', 'ipv4', 'ipv6', 'origin',
        # regions and misc
        'us', 'eu', 'uk', 'de', 'asia', 'east', 'west', 'mobile', 'm', 'wap',
        'go', 'link', 'app1', 'app2', 'web1', 'web2', 'old', 'new', 'legacy',
        'v1', 'v2', 'stats', 'analytics', 'track', 'ads', 'partner', 'partners',
    ]

    # (technology, where, pattern). `where` is a response header, or "body" for
    # markup only that technology emits. A pattern of None means the header
    # being present is the signal. Matching is case-insensitive.
    #
    # Each signature names where it may be found, and a word it must match
    # whole. The list this replaces was plain substrings searched across the
    # headers and the page together, so "java" fired on any page containing
    # "javascript", ".net" on any link to a .net domain, "s3" on "css3", and
    # "passenger" on a travel site. One real scan credited a WordPress site
    # with Java and Node.js that way.
    TECH_SIGNATURES = [
        ('nginx', 'server', r'\bnginx\b'),
        # Apache-Coyote is Tomcat's connector, not httpd.
        ('apache', 'server', r'\bapache\b(?!-coyote)'),
        ('cloudflare', 'server', r'\bcloudflare\b'),
        ('cloudflare', 'cf-ray', None),
        ('aws', 'server', r'\b(amazons3|awselb|cloudfront)\b'),
        ('aws', 'x-amz-request-id', None),
        ('aws', 'x-amz-cf-id', None),
        ('aws', 'x-amzn-requestid', None),
        ('google', 'server', r'^(gws|gse|esf|ghs|sffe|google frontend)\b'),
        ('php', 'x-powered-by', r'\bphp\b'),
        ('php', 'set-cookie', r'\bPHPSESSID(?==)'),
        ('asp.net', 'x-powered-by', r'\basp\.net\b'),
        ('asp.net', 'x-aspnet-version', None),
        ('asp.net', 'x-aspnetmvc-version', None),
        ('asp.net', 'set-cookie', r'\bASP\.NET_SessionId(?==)'),
        ('asp.net', 'set-cookie', r'\.AspNetCore\.[\w.]+(?==)'),
        ('iis', 'server', r'\bmicrosoft-iis\b'),
        ('node.js', 'x-powered-by', r'\bexpress\b'),
        ('python', 'server',
         r'\b(gunicorn|werkzeug|uvicorn|tornadoserver|wsgiserver|c?python)\b'),
        ('ruby', 'server', r'\b(passenger|webrick)\b'),
        ('ruby', 'x-powered-by', r'\bphusion passenger\b'),
        ('java', 'server', r'\b(apache-coyote|tomcat|jetty|wildfly|jboss|glassfish)\b'),
        ('java', 'x-powered-by', r'\b(servlet|jsp|jsf)\b'),
        ('java', 'set-cookie', r'\bJSESSIONID(?==)'),
        # The generator tag carries the core version, which the CVE matcher
        # can use; the asset paths identify WordPress when the tag is removed.
        ('wordpress', 'body',
         r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](WordPress[^"\']*)'),
        ('wordpress', 'body', r'/wp-(?:content|includes)/'),
        ('wordpress', 'link', r'/wp-json/|api\.w\.org'),
        ('drupal', 'x-generator', r'\bdrupal\b'),
        ('drupal', 'x-drupal-cache', None),
        ('drupal', 'body',
         r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](Drupal[^"\']*)'),
        ('joomla', 'body',
         r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](Joomla[^"\']*)'),
        ('laravel', 'set-cookie', r'\blaravel_session(?==)'),
    ]

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []
        self.subdomain_candidates: List[str] = []
        self.found_subdomains: List[str] = []

    def scan_ports(self, ports: List[int] = None) -> List[Finding]:
        """Scan common ports and record the banners services volunteer (ports.py)."""
        return PortScanner(self.target).run(ports)

    def _resolve_cnames(self, hosts: List[str]) -> dict:
        """CNAME target per host, resolved concurrently over DoH."""
        from . import doh

        def lookup(host):
            targets = doh.records(host, "CNAME")
            return host, (targets[0].rstrip(".").lower() if targets else None)

        results = {}
        if not hosts:
            return results
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for host, cname in executor.map(lookup, hosts):
                if cname:
                    results[host] = cname
        return results

    # A wildcard behind round-robin DNS hands back a different subset of its
    # addresses on each query, so several unregistered names are resolved to
    # learn the whole answer rather than one sample of it.
    WILDCARD_PROBES = 3

    @staticmethod
    def _addresses(host: str) -> Set[str]:
        """Every address a name resolves to; empty when it does not resolve."""
        try:
            return {info[4][0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror:
            return set()

    def _wildcard_answer(self) -> Tuple[Set[str], Optional[str]]:
        """
        What a name nobody registered resolves to under the target.

        Returns (addresses, cname). No addresses means no wildcard, and a
        resolving name can then be taken at face value.
        """
        probe = f"{secrets.token_hex(8)}.{self.target}"
        addresses = self._addresses(probe)
        if not addresses:
            return set(), None
        for _ in range(self.WILDCARD_PROBES - 1):
            addresses |= self._addresses(f"{secrets.token_hex(8)}.{self.target}")
        return addresses, self._resolve_cnames([probe]).get(probe)

    def _wildcard_note(self, tried: int, suppressed: int, kept: int,
                       addresses: Set[str], cname: Optional[str]) -> Finding:
        """One finding that accounts for every name the wildcard filter held back."""
        evidence = "Wildcard answer: " + ", ".join(sorted(addresses)[:6])
        if cname:
            evidence += f"\nWildcard CNAME: {cname}"
        return Finding(
            id="SUBDOMAIN-Wildcard",
            title="Wildcard DNS: Subdomain Results Filtered",
            description=(
                f"Every name under {self.target} resolves, so a name resolving "
                f"is not evidence that a host exists. Of {tried} names tried, "
                f"{suppressed} returned only the wildcard's own answer and are "
                f"not listed; {kept} answered differently and are reported. A "
                f"real host that shares the wildcard's address cannot be told "
                f"apart from it by DNS alone."
            ),
            severity=Severity.INFORMATIONAL,
            category="Subdomain Enumeration",
            evidence=evidence,
            remediation="N/A - Information gathering",
            references=["https://en.wikipedia.org/wiki/Wildcard_DNS_record"],
            discovered_at=datetime.now().isoformat(),
            target=self.target
        )

    def enumerate_subdomains(self, wordlist: List[str] = None) -> List[Finding]:
        """Enumerate common subdomains"""
        findings = []
        wordlist = wordlist or self.COMMON_SUBDOMAINS
        print(f"[*] Enumerating {len(wordlist)} common subdomains...")

        # Under wildcard DNS every name resolves, so "it resolved" stops being
        # evidence. Learn what the wildcard answers first; a candidate then
        # counts only if its own answer differs. Without this a wildcard domain
        # was credited with the entire wordlist: 198 of 198 names on a real
        # scan, nine tenths of that report.
        wildcard_ips, wildcard_cname = self._wildcard_answer()

        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.target}"
            return full_domain, self._addresses(full_domain)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            resolved = [
                (name, addresses)
                for name, addresses in executor.map(check_subdomain, wordlist)
                if addresses
            ]

        # With no wildcard the set is empty and every resolving name is kept.
        found_subdomains = [
            name for name, addresses in resolved if not addresses <= wildcard_ips
        ]

        # Record every candidate tried, not only those that resolved: a
        # dangling CNAME to a dead service has no A record, so the takeover
        # check needs the full list to catch the NXDOMAIN takeovers.
        self.subdomain_candidates = [f"{s}.{self.target}" for s in wordlist]

        # Resolve where each hit points. A CNAME onto a third party is the
        # interesting part of a subdomain finding: it names the cloud service
        # or SaaS the host depends on, which is both recon context and the
        # same signal the takeover check acts on. Only the hits are resolved,
        # so the cost stays proportional to what was actually found.
        cnames = self._resolve_cnames(found_subdomains)

        if wildcard_cname:
            # The same CNAME as the wildcard means the same record answered,
            # even when a rotating pool returned addresses not sampled above.
            found_subdomains = [
                s for s in found_subdomains if cnames.get(s) != wildcard_cname
            ]
        self.found_subdomains = found_subdomains

        if wildcard_ips:
            suppressed = len(resolved) - len(found_subdomains)
            findings.append(self._wildcard_note(
                len(wordlist), suppressed, len(found_subdomains),
                wildcard_ips, wildcard_cname))
            print(f"[*] Wildcard DNS: {suppressed} name(s) returned only the "
                  f"wildcard's answer and are not listed")

        for subdomain in found_subdomains:
            cname = cnames.get(subdomain)
            offsite = bool(cname) and not cname.endswith(self.target)
            evidence = f"{subdomain} exists"
            if cname:
                evidence += f"\nCNAME: {cname}"
                if offsite:
                    evidence += " (third-party host)"
            findings.append(Finding(
                id=f"SUBDOMAIN-{subdomain.split('.')[0]}",
                title=f"Subdomain Found: {subdomain}",
                description=(
                    f"Subdomain {subdomain} resolves"
                    + (f" via CNAME to {cname}" if cname else "")
                ),
                severity=Severity.INFORMATIONAL,
                category="Subdomain Enumeration",
                evidence=evidence,
                remediation="N/A - Information gathering",
                references=["https://en.wikipedia.org/wiki/Subdomain"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] Subdomain enumeration: {len(found_subdomains)} found")
        return findings

    def _match_signatures(self, headers, body: str) -> Dict[str, str]:
        """
        Technology to the signal that identified it; the first signature wins.

        The signal is what goes in the report, so it says where the match was
        found. Cookie values and request ids are left out of it: the name of a
        session cookie is evidence, its value is somebody's session.
        """
        from .waf import _header_values

        detected: Dict[str, str] = {}
        for tech, where, pattern in self.TECH_SIGNATURES:
            if tech in detected:
                continue
            if where == 'body':
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    shown = match.group(1) if match.groups() else match.group(0)
                    detected[tech] = f"Markup: {shown[:120]}"
                continue
            for value in _header_values(headers, where):
                if pattern is None:
                    detected[tech] = f"{where.title()} header present"
                    break
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    detected[tech] = (
                        f"Cookie: {match.group(0)}" if where == 'set-cookie'
                        else f"{where.title()}: {value[:120]}"
                    )
                    break
        return detected

    def fingerprint_tech(self) -> List[Finding]:
        """Technology fingerprinting"""
        findings = []
        print(f"[*] Fingerprinting technologies...")

        detected_tech: Dict[str, str] = {}

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = Request(f"https://{self.target}", method='GET')
            req.add_header('User-Agent', USER_AGENT)

            with safe_urlopen(req, context=ctx, timeout=10) as response:
                # Read the raw message, not dict(): a dict keeps only the last
                # Set-Cookie, and the cookie signatures need all of them.
                body = response.read(32768).decode('utf-8', errors='ignore')
                detected_tech = self._match_signatures(response.headers, body)

        except Exception as e:
            findings.append(Finding(
                id="TECH-Error",
                title="Technology Fingerprinting Error",
                description=f"Could not fingerprint: {str(e)}",
                severity=Severity.INFORMATIONAL,
                category="Technology",
                evidence=str(e),
                remediation="Check target accessibility",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        for tech, signal in detected_tech.items():
            findings.append(Finding(
                id=f"TECH-{tech.replace('.', '').replace(' ', '')}",
                title=f"Technology Detected: {tech}",
                description=f"Target appears to use {tech}",
                severity=Severity.INFORMATIONAL,
                category="Technology",
                evidence=signal,
                remediation="N/A - Information gathering",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] Technology fingerprinting: {len(detected_tech)} detected")
        return findings

    def check_takeovers(self) -> List[Finding]:
        """
        Check enumerated hosts for dangling-CNAME subdomain takeover.

        Kept separate from the resolve-only enumeration because it reaches out
        over DoH and HTTP to third-party services, which the rest of Phase 2
        does not. Runs against every candidate, resolving or not, since a
        NXDOMAIN takeover has no A record to have been found by.
        """
        from .takeover import TakeoverScanner

        hosts = self.subdomain_candidates or self.found_subdomains
        findings = TakeoverScanner(self.target).run(hosts)
        self.findings.extend(findings)
        return findings

    def run(self, check_takeover: bool = True) -> List[Finding]:
        """Run all Phase 2 active reconnaissance"""
        print()
        print("=" * 60)
        print("PHASE 2: Active Reconnaissance")
        print("=" * 60)
        print()

        # Port scanning
        port_findings = self.scan_ports()
        self.findings.extend(port_findings)

        # Subdomain enumeration
        subdomain_findings = self.enumerate_subdomains()
        self.findings.extend(subdomain_findings)

        # Technology fingerprinting
        tech_findings = self.fingerprint_tech()
        self.findings.extend(tech_findings)

        # Subdomain takeover (uses the hosts enumerated just above)
        if check_takeover:
            self.check_takeovers()

        print()
        print("=" * 60)
        print("PHASE 2 COMPLETE")
        print("=" * 60)
        print(f"Total findings: {len(self.findings)}")
        print(f"  - Ports: {len([f for f in self.findings if f.category == 'Port Scan'])}")
        # Counted from the hits, not the category: a wildcard note shares the
        # category without being a subdomain.
        print(f"  - Subdomains: {len(self.found_subdomains)}")
        print(f"  - Technologies: {len([f for f in self.findings if f.category == 'Technology'])}")
        print(f"  - Takeover: {len([f for f in self.findings if f.category == 'Subdomain Takeover'])}")
        print()

        return self.findings


