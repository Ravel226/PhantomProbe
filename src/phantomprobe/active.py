#!/usr/bin/env python3
"""
Phase 2: active reconnaissance (port scan, subdomain enumeration, fingerprinting).

These checks send traffic directly to the target. Only run them against systems
you are authorized to test.
"""

import concurrent.futures
import socket
import ssl
from datetime import datetime
from typing import List
from urllib.request import Request

from .http_client import safe_urlopen

from .constants import USER_AGENT
from .models import Finding, Severity


class ActiveReconEngine:
    """Phase 2: Active Reconnaissance"""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    ]

    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'staging',
        'test', 'app', 'portal', 'secure', 'vpn', 'cdn', 'static',
        'assets', 'img', 'images', 'shop', 'store', 'beta', 'demo'
    ]

    TECH_SIGNATURES = {
        'nginx': ['nginx'],
        'apache': ['apache', 'httpd'],
        'cloudflare': ['cloudflare', 'cf-ray'],
        'aws': ['amazon', 'aws', 'ec2', 's3'],
        'google': ['gstatic', 'google', 'gws'],
        'php': ['php', 'x-powered-by: php'],
        'asp.net': ['asp.net', 'iis', '.net'],
        'node.js': ['express', 'node'],
        'python': ['python', 'django', 'flask', 'gunicorn'],
        'ruby': ['ruby', 'rails', 'passenger'],
        'java': ['java', 'tomcat', 'jsp'],
        'wordpress': ['wordpress', 'wp-'],
        'drupal': ['drupal'],
        'joomla': ['joomla'],
        'laravel': ['laravel'],
    }

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []

    def scan_ports(self, ports: List[int] = None) -> List[Finding]:
        """Scan common ports"""
        findings = []
        ports = ports or self.COMMON_PORTS
        print(f"[*] Scanning {len(ports)} common ports...")

        open_ports = []

        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    if sock.connect_ex((self.target, port)) == 0:
                        return port
            except OSError:
                # Unreachable host, refused connection or exhausted sockets:
                # treat as closed rather than aborting the whole sweep.
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_port, ports)
            open_ports = [p for p in results if p is not None]

        for port in open_ports:
            service = self._identify_service(port)
            findings.append(Finding(
                id=f"PORT-{port}",
                title=f"Open Port: {port}",
                description=f"Port {port} is open ({service})",
                severity=Severity.INFORMATIONAL,
                category="Port Scan",
                evidence=f"Port {port}/{service} is accepting connections",
                remediation="N/A - Information gathering",
                references=["https://en.wikipedia.org/wiki/Port_scanner"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] Port scan: {len(open_ports)} open ports")
        return findings

    def _identify_service(self, port: int) -> str:
        """Identify common service by port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')

    def enumerate_subdomains(self, wordlist: List[str] = None) -> List[Finding]:
        """Enumerate common subdomains"""
        findings = []
        wordlist = wordlist or self.COMMON_SUBDOMAINS
        print(f"[*] Enumerating {len(wordlist)} common subdomains...")

        found_subdomains = []

        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target}"
                socket.getaddrinfo(full_domain, None)
                return full_domain
            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_subdomain, wordlist)
            found_subdomains = [s for s in results if s is not None]

        for subdomain in found_subdomains:
            findings.append(Finding(
                id=f"SUBDOMAIN-{subdomain.split('.')[0]}",
                title=f"Subdomain Found: {subdomain}",
                description=f"Subdomain {subdomain} resolves",
                severity=Severity.INFORMATIONAL,
                category="Subdomain Enumeration",
                evidence=f"{subdomain} exists",
                remediation="N/A - Information gathering",
                references=["https://en.wikipedia.org/wiki/Subdomain"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] Subdomain enumeration: {len(found_subdomains)} found")
        return findings

    def fingerprint_tech(self) -> List[Finding]:
        """Technology fingerprinting"""
        findings = []
        print(f"[*] Fingerprinting technologies...")

        detected_tech = set()

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = Request(f"https://{self.target}", method='GET')
            req.add_header('User-Agent', USER_AGENT)

            with safe_urlopen(req, context=ctx, timeout=10) as response:
                headers_str = str(dict(response.headers)).lower()
                content = response.read(5000).decode('utf-8', errors='ignore').lower()

                combined = headers_str + content

                for tech, signatures in self.TECH_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in combined:
                            detected_tech.add(tech)
                            break

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

        for tech in detected_tech:
            findings.append(Finding(
                id=f"TECH-{tech.replace('.', '').replace(' ', '')}",
                title=f"Technology Detected: {tech}",
                description=f"Target appears to use {tech}",
                severity=Severity.INFORMATIONAL,
                category="Technology",
                evidence=f"{tech} signature detected",
                remediation="N/A - Information gathering",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] Technology fingerprinting: {len(detected_tech)} detected")
        return findings

    def run(self) -> List[Finding]:
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

        print()
        print("=" * 60)
        print("PHASE 2 COMPLETE")
        print("=" * 60)
        print(f"Total findings: {len(self.findings)}")
        print(f"  - Ports: {len([f for f in self.findings if f.category == 'Port Scan'])}")
        print(f"  - Subdomains: {len([f for f in self.findings if f.category == 'Subdomain Enumeration'])}")
        print(f"  - Technologies: {len([f for f in self.findings if f.category == 'Technology'])}")
        print()

        return self.findings


