#!/usr/bin/env python3
"""
PhantomProbe v0.4.0
Reconnaissance Scanner for Penetration Testing
Ghost in the Machine 

Standard library only - no dependencies required
CVE matching via NVD API

Author: Ravel226
License: MIT
"""

import sys
import json
import ssl
import socket
import time
import re
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    evidence: str
    remediation: str
    references: List[str]
    discovered_at: str
    target: str


class ReconEngine:
    """Phase 1: Passive Reconnaissance"""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []

    def analyze_dns(self) -> List[Finding]:
        """Analyze DNS records using standard library"""
        findings = []
        print(f"[*] Analyzing DNS records...")

        try:
            # Get A records (IPv4)
            try:
                addr_info = socket.getaddrinfo(self.target, None, socket.AF_INET)
                ipv4s = list(set([addr[4][0] for addr in addr_info]))
                for ip in ipv4s[:3]:
                    # Try reverse DNS
                    try:
                        reverse = socket.gethostbyaddr(ip)[0]
                        findings.append(Finding(
                            id=f"DNS-A-{ip.replace('.', '-')}",
                            title="DNS A Record",
                            description=f"IPv4 address for {self.target}",
                            severity=Severity.INFORMATIONAL,
                            category="DNS",
                            evidence=f"IP: {ip}\nReverse DNS: {reverse}",
                            remediation="N/A - Information gathering",
                            references=["https://en.wikipedia.org/wiki/A_record"],
                            discovered_at=datetime.now().isoformat(),
                            target=self.target
                        ))
                    except socket.herror:
                        findings.append(Finding(
                            id=f"DNS-A-{ip.replace('.', '-')}",
                            title="DNS A Record",
                            description=f"IPv4 address for {self.target}",
                            severity=Severity.INFORMATIONAL,
                            category="DNS",
                            evidence=f"IP: {ip}",
                            remediation="N/A - Information gathering",
                            references=["https://en.wikipedia.org/wiki/A_record"],
                            discovered_at=datetime.now().isoformat(),
                            target=self.target
                        ))
            except socket.gaierror:
                pass

            # Check for IPv6
            try:
                addr_info_v6 = socket.getaddrinfo(self.target, None, socket.AF_INET6)
                ipv6s = list(set([addr[4][0] for addr in addr_info_v6]))
                for ip in ipv6s[:2]:
                    findings.append(Finding(
                        id="DNS-AAAA",
                        title="DNS AAAA Record (IPv6)",
                        description=f"IPv6 address configured for {self.target}",
                        severity=Severity.INFORMATIONAL,
                        category="DNS",
                        evidence=f"IPv6: {ip}",
                        remediation="N/A - Information gathering",
                        references=["https://en.wikipedia.org/wiki/IPv6"],
                        discovered_at=datetime.now().isoformat(),
                        target=self.target
                    ))
            except socket.gaierror:
                pass

            # Check for wildcard DNS (random subdomain)
            import hashlib
            random_sub = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
            try:
                socket.getaddrinfo(f"{random_sub}.{self.target}", None)
                findings.append(Finding(
                    id="DNS-Wildcard",
                    title="Wildcard DNS Record",
                    description=f"Subdomain {random_sub}.{self.target} resolved - wildcard DNS configured",
                    severity=Severity.INFORMATIONAL,
                    category="DNS",
                    evidence=f"Wildcard responds to: *.{self.target}",
                    remediation="N/A - Configuration info",
                    references=["https://en.wikipedia.org/wiki/Wildcard_DNS_record"],
                    discovered_at=datetime.now().isoformat(),
                    target=self.target
                ))
            except socket.gaierror:
                pass

        except Exception as e:
            findings.append(Finding(
                id="DNS-Error",
                title="DNS Analysis Error",
                description=f"DNS lookup failed: {str(e)}",
                severity=Severity.INFORMATIONAL,
                category="DNS",
                evidence=str(e),
                remediation="Check network connectivity",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] DNS analysis: {len(findings)} findings")
        return findings

    def analyze_ssl(self) -> List[Finding]:
        """Analyze SSL/TLS certificate"""
        findings = []
        print(f"[*] Analyzing SSL/TLS configuration...")

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    ssl_version = ssock.version()

                    # Cipher analysis
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                        if any(w in cipher_name for w in weak_ciphers):
                            findings.append(Finding(
                                id="SSL-WeakCipher",
                                title="Weak SSL/TLS Cipher",
                                description=f"Server negotiated weak cipher: {cipher_name}",
                                severity=Severity.HIGH,
                                category="SSL/TLS",
                                evidence=f"Cipher: {cipher_name}\nTLS Version: {ssl_version}",
                                remediation="Disable weak ciphers. Use AES-GCM or ChaCha20-Poly1305",
                                references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
                                discovered_at=datetime.now().isoformat(),
                                target=self.target
                            ))

                    # TLS version check
                    if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append(Finding(
                            id="SSL-OldTLS",
                            title=f"Deprecated TLS Version: {ssl_version}",
                            description=f"Server supports outdated {ssl_version} protocol",
                            severity=Severity.HIGH,
                            category="SSL/TLS",
                            evidence=f"Negotiated: {ssl_version}",
                            remediation="Disable TLS 1.0/1.1. Require TLS 1.2 minimum",
                            references=["https://tools.ietf.org/html/rfc8996"],
                            discovered_at=datetime.now().isoformat(),
                            target=self.target
                        ))

                    # Certificate expiry check
                    if cert and 'notAfter' in cert:
                        not_after = cert['notAfter']
                        # Parse date like "Mar 15 12:00:00 2025 GMT"
                        from datetime import datetime as dt
                        try:
                            expiry = dt.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_until = (expiry - dt.now(timezone.utc).replace(tzinfo=None)).days

                            if days_until < 0:
                                findings.append(Finding(
                                    id="SSL-Expired",
                                    title="Expired SSL Certificate",
                                    description=f"Certificate expired {abs(days_until)} days ago",
                                    severity=Severity.CRITICAL,
                                    category="SSL/TLS",
                                    evidence=f"Expired: {not_after}",
                                    remediation="Renew certificate immediately",
                                    references=["https://letsencrypt.org/"],
                                    discovered_at=datetime.now().isoformat(),
                                    target=self.target
                                ))
                            elif days_until < 30:
                                findings.append(Finding(
                                    id="SSL-Expiring",
                                    title="SSL Certificate Expiring Soon",
                                    description=f"Certificate expires in {days_until} days",
                                    severity=Severity.LOW,
                                    category="SSL/TLS",
                                    evidence=f"Expires: {not_after}",
                                    remediation="Renew certificate before expiry",
                                    references=["https://letsencrypt.org/"],
                                    discovered_at=datetime.now().isoformat(),
                                    target=self.target
                                ))
                        except ValueError:
                            pass

                    # Certificate info (informational)
                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        san = cert.get('subjectAltName', [])

                        cert_info = []
                        if 'commonName' in subject:
                            cert_info.append(f"Subject CN: {subject['commonName']}")
                        if 'commonName' in issuer:
                            cert_info.append(f"Issuer: {issuer['commonName']}")
                        cert_info.append(f"SANs: {len(san)} domains")
                        cert_info.append(f"Protocol: {ssl_version}")
                        if cipher:
                            cert_info.append(f"Cipher: {cipher[0]}")

                        findings.append(Finding(
                            id="SSL-CertInfo",
                            title="SSL Certificate Details",
                            description="TLS certificate information",
                            severity=Severity.INFORMATIONAL,
                            category="SSL/TLS",
                            evidence="\n".join(cert_info),
                            remediation="N/A - Information gathering",
                            references=["https://en.wikipedia.org/wiki/X.509"],
                            discovered_at=datetime.now().isoformat(),
                            target=self.target
                        ))

        except ssl.SSLError as e:
            if "certificate verify failed" in str(e).lower() or "CERTIFICATE_VERIFY_FAILED" in str(e):
                findings.append(Finding(
                    id="SSL-Untrusted",
                    title="Untrusted SSL Certificate",
                    description="Certificate chain verification failed",
                    severity=Severity.HIGH,
                    category="SSL/TLS",
                    evidence=str(e),
                    remediation="Install valid certificate from trusted CA",
                    references=["https://letsencrypt.org/"],
                    discovered_at=datetime.now().isoformat(),
                    target=self.target
                ))
            else:
                findings.append(Finding(
                    id="SSL-Error",
                    title="SSL Analysis Error",
                    description=f"SSL inspection failed: {str(e)}",
                    severity=Severity.INFORMATIONAL,
                    category="SSL/TLS",
                    evidence=str(e),
                    remediation="Check SSL configuration",
                    references=[],
                    discovered_at=datetime.now().isoformat(),
                    target=self.target
                ))
        except socket.error as e:
            findings.append(Finding(
                id="SSL-NoHTTPS",
                title="HTTPS Not Available",
                description=f"Could not establish TLS connection on port 443",
                severity=Severity.INFORMATIONAL,
                category="SSL/TLS",
                evidence=str(e),
                remediation="Verify HTTPS is configured on port 443",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))
        except Exception as e:
            findings.append(Finding(
                id="SSL-Error",
                title="SSL Analysis Error",
                description=f"SSL inspection failed: {str(e)}",
                severity=Severity.INFORMATIONAL,
                category="SSL/TLS",
                evidence=str(e),
                remediation="Check SSL configuration",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] SSL analysis: {len(findings)} findings")
        return findings

    def analyze_headers(self) -> List[Finding]:
        """Analyze HTTP security headers"""
        findings = []
        print(f"[*] Analyzing HTTP headers...")

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = Request(f"https://{self.target}", method='GET')
            req.add_header('User-Agent', 'PhantomProbe/0.2.0')

            with urlopen(req, context=ctx, timeout=10) as response:
                headers = dict(response.headers)

                # Check security headers
                security_headers = {
                    'X-Frame-Options': 'Missing clickjacking protection',
                    'Content-Security-Policy': 'Missing XSS protection',
                    'Strict-Transport-Security': 'Missing HSTS',
                    'X-Content-Type-Options': 'Missing MIME sniffing protection',
                    'Referrer-Policy': 'Missing referrer control',
                    'Permissions-Policy': 'Missing permissions policy'
                }

                for header, issue in security_headers.items():
                    if header not in headers:
                        findings.append(Finding(
                            id=f"HEADER-{header.replace('-', '')}",
                            title=f"Missing {header} Header",
                            description=issue,
                            severity=Severity.LOW,
                            category="Security Headers",
                            evidence="Header not present in response",
                            remediation=f"Add '{header}' header to all responses",
                            references=["https://securityheaders.com/"],
                            discovered_at=datetime.now().isoformat(),
                            target=self.target
                        ))

                # Check for info disclosure
                if 'X-Powered-By' in headers:
                    findings.append(Finding(
                        id="INFO-XPoweredBy",
                        title="Information Disclosure: X-Powered-By Header",
                        description=f"Server reveals technology: {headers.get('X-Powered-By')}",
                        severity=Severity.INFORMATIONAL,
                        category="Information Disclosure",
                        evidence=f"X-Powered-By: {headers.get('X-Powered-By')}",
                        remediation="Remove X-Powered-By header from server configuration",
                        references=["https://cheatsheetseries.owasp.org/"],
                        discovered_at=datetime.now().isoformat(),
                        target=self.target
                    ))

                # Check for server info disclosure
                server_header = headers.get('Server', '')
                if server_header and server_header not in ['', 'nginx', 'apache', 'cloudflare']:
                    findings.append(Finding(
                        id="INFO-Server",
                        title="Information Disclosure: Server Header",
                        description=f"Server banner reveals: {server_header}",
                        severity=Severity.INFORMATIONAL,
                        category="Information Disclosure",
                        evidence=f"Server: {server_header}",
                        remediation="Configure server to not disclose version information",
                        references=["https://cheatsheetseries.owasp.org/"],
                        discovered_at=datetime.now().isoformat(),
                        target=self.target
                    ))

                # Found good headers
                good_headers = []
                if 'Strict-Transport-Security' in headers:
                    good_headers.append("HSTS enabled")
                if headers.get('X-Frame-Options') in ['DENY', 'SAMEORIGIN']:
                    good_headers.append(f"Clickjacking protection ({headers['X-Frame-Options']})")
                if 'X-Content-Type-Options' in headers:
                    good_headers.append("MIME sniffing protection")
                if 'Content-Security-Policy' in headers:
                    good_headers.append("CSP configured")

                if good_headers:
                    findings.append(Finding(
                        id="HEADER-Good",
                        title="Security Headers Configured",
                        description="Multiple security headers properly implemented",
                        severity=Severity.INFORMATIONAL,
                        category="Security Headers",
                        evidence="; ".join(good_headers),
                        remediation="No action needed - maintain current configuration",
                        references=["https://cheatsheetseries.owasp.org/"],
                        discovered_at=datetime.now().isoformat(),
                        target=self.target
                    ))

        except HTTPError as e:
            findings.append(Finding(
                id=f"HTTP-{e.code}",
                title=f"HTTP {e.code} Response",
                description=f"Server returned HTTP {e.code}",
                severity=Severity.INFORMATIONAL,
                category="HTTP Response",
                evidence=str(e),
                remediation="Verify if this is expected behavior",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))
        except URLError as e:
            findings.append(Finding(
                id="ERROR-Connection",
                title="Connection Error",
                description="Could not connect to target website",
                severity=Severity.INFORMATIONAL,
                category="Connectivity",
                evidence=str(e),
                remediation="Check target availability and network connectivity",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))
        except Exception as e:
            findings.append(Finding(
                id="ERROR-Unknown",
                title="Scan Error",
                description=f"Unexpected error: {str(e)}",
                severity=Severity.INFORMATIONAL,
                category="Error",
                evidence=str(e),
                remediation="Review scanner configuration and target accessibility",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] HTTP headers analysis: {len(findings)} findings")
        return findings

    def run(self) -> List[Finding]:
        """Run all Phase 1 reconnaissance checks"""
        print()
        print("=" * 60)
        print("PHANTOMPROBE v0.2.0 - Phase 1: Passive Reconnaissance")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Started: {datetime.now().isoformat()}")
        print("=" * 60)
        print()

        # DNS analysis
        dns_findings = self.analyze_dns()
        self.findings.extend(dns_findings)

        # SSL analysis
        ssl_findings = self.analyze_ssl()
        self.findings.extend(ssl_findings)

        # HTTP headers
        header_findings = self.analyze_headers()
        self.findings.extend(header_findings)

        print()
        print("=" * 60)
        print("PHASE 1 COMPLETE")
        print("=" * 60)
        print(f"Total findings: {len(self.findings)}")
        print(f"  - DNS: {len([f for f in self.findings if f.category == 'DNS'])}")
        print(f"  - SSL/TLS: {len([f for f in self.findings if f.category == 'SSL/TLS'])}")
        print(f"  - Headers: {len([f for f in self.findings if f.category in ['Security Headers', 'Information Disclosure']])}")
        print()

        return self.findings


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
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    return port
            except:
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
            req.add_header('User-Agent', 'PhantomProbe/0.3.0')

            with urlopen(req, context=ctx, timeout=10) as response:
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


@dataclass
class CVE:
    """CVE vulnerability record"""
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_versions: List[str]
    fix_versions: List[str]
    references: List[str]
    published: str
    modified: str


class CVEMatcher:
    """Match findings to known CVEs via NVD API"""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CVE_API_BASE = "https://cveawg.mitre.org/api/cve"

    # Technology to CPE vendor/product mapping
    CPE_MAPPING = {
        'php': {'vendor': 'php', 'product': 'php'},
        'nginx': {'vendor': 'nginx', 'product': 'nginx'},
        'apache': {'vendor': 'apache', 'product': 'http_server'},
        'openssl': {'vendor': 'openssl', 'product': 'openssl'},
        'mysql': {'vendor': 'oracle', 'product': 'mysql'},
        'postgresql': {'vendor': 'postgresql', 'product': 'postgresql'},
        'redis': {'vendor': 'redis', 'product': 'redis'},
        'mongodb': {'vendor': 'mongodb', 'product': 'mongodb'},
        'node.js': {'vendor': 'nodejs', 'product': 'node.js'},
        'express': {'vendor': 'expressjs', 'product': 'express'},
        'django': {'vendor': 'djangoproject', 'product': 'django'},
        'flask': {'vendor': 'palletsprojects', 'product': 'flask'},
        'wordpress': {'vendor': 'wordpress', 'product': 'wordpress'},
        'drupal': {'vendor': 'drupal', 'product': 'drupal'},
        'joomla': {'vendor': 'joomla', 'product': 'joomla'},
        'tomcat': {'vendor': 'apache', 'product': 'tomcat'},
        'iis': {'vendor': 'microsoft', 'product': 'internet_information_server'},
        'dotnet': {'vendor': 'microsoft', 'product': '.net_framework'},
        'java': {'vendor': 'oracle', 'product': 'jdk'},
        'python': {'vendor': 'python', 'product': 'python'},
        'ruby': {'vendor': 'ruby-lang', 'product': 'ruby'},
    }

    def __init__(self):
        self.cache: Dict[str, List[CVE]] = {}
        self.session_timeout = 10

    def extract_tech_version(self, evidence: str) -> List[Tuple[str, Optional[str]]]:
        """Extract technology and version from evidence text"""
        technologies = []

        # Common patterns: "PHP/8.2.29", "nginx/1.24.0", "Apache/2.4.57"
        patterns = [
            r'(?i)(php|nginx|apache|openssl|mysql|postgresql|redis|mongodb|tomcat|iis|node|express|django|flask|wordpress|drupal|joomla|python|ruby|java)[/\s\-:]*(\d+(?:\.\d+)*)?',
            r'(?i)(\d+(?:\.\d+)+)\s*(php|nginx|apache|openssl)',
            r'X-Powered-By:\s*PHP/(\d+(?:\.\d+)*)',
            r'Server:\s*(nginx|Apache)/?(\d+(?:\.\d+)*)?',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, evidence)
            for match in matches:
                if isinstance(match, tuple):
                    tech = match[0].lower() if match[0] else None
                    version = match[1] if len(match) > 1 and match[1] else None
                    if tech and tech in self.CPE_MAPPING:
                        technologies.append((tech, version))

        return list(set(technologies))

    def build_cpe(self, tech: str, version: Optional[str] = None) -> str:
        """Build CPE 2.3 string"""
        if tech not in self.CPE_MAPPING:
            return None

        mapping = self.CPE_MAPPING[tech]
        cpe = f"cpe:2.3:a:{mapping['vendor']}:{mapping['product']}"

        if version:
            cpe += f":{version}"
        else:
            cpe += ":*"

        cpe += ":*:*:*:*:*:*:*"
        return cpe

    def query_nvd(self, cpe: str, tech: str, version: Optional[str] = None) -> List[CVE]:
        """Query NVD API for CVEs matching CPE"""
        cves = []

        try:
            # Query by CPE
            url = f"{self.NVD_API_BASE}?cpeName={quote(cpe)}&resultsPerPage=20"

            headers = {'User-Agent': 'PhantomProbe/0.4.0'}
            req = Request(url, headers=headers)

            with urlopen(req, timeout=self.session_timeout) as response:
                data = json.loads(response.read().decode())

            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})

                # Extract CVE ID
                cve_id = cve_data.get('id', '')

                # Extract CVSS score and severity
                metrics = cve_data.get('metrics', {})
                cvss_score = 0.0
                severity = 'UNKNOWN'

                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV30' in metrics:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = 'HIGH' if cvss_score >= 7.0 else 'MEDIUM' if cvss_score >= 4.0 else 'LOW'

                # Extract description
                descriptions = cve_data.get('descriptions', [])
                description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

                # Extract affected versions
                affected = []
                fix_versions = []

                for config in cve_data.get('configurations', []):
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):
                            if cpe_match.get('vulnerable'):
                                affected.append(cpe_match.get('criteria', ''))
                            elif 'versionEndIncluding' in cpe_match:
                                fix_versions.append(cpe_match.get('versionEndIncluding', ''))

                # Extract references
                references = [r.get('url', '') for r in cve_data.get('references', [])[:5]]

                # Extract dates
                published = cve_data.get('published', '')
                modified = cve_data.get('lastModified', '')

                cve = CVE(
                    cve_id=cve_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    description=description[:500] if description else '',
                    affected_versions=affected[:5],
                    fix_versions=fix_versions[:3],
                    references=references,
                    published=published,
                    modified=modified
                )
                cves.append(cve)

        except Exception as e:
            # Silently fail - CVE lookup is optional
            pass

        return cves

    def match_findings(self, findings: List[Finding]) -> List[Dict]:
        """Match findings to CVEs and return enriched findings"""
        matched = []
        tech_versions = {}

        print("[*] Matching findings to CVE database...")

        # Extract all technologies from findings
        for finding in findings:
            if finding.category in ['Information Disclosure', 'Technology', 'SSL/TLS']:
                techs = self.extract_tech_version(finding.evidence)
                for tech, version in techs:
                    if tech not in tech_versions or (version and not tech_versions.get(tech)):
                        tech_versions[tech] = version

        if not tech_versions:
            print("[+] No technology versions found for CVE matching")
            return []

        print(f"[*] Found {len(tech_versions)} technologies to check for CVEs")

        # Query CVEs for each technology
        for tech, version in tech_versions.items():
            cpe = self.build_cpe(tech, version)
            if not cpe:
                continue

            # Check cache first
            cache_key = f"{tech}:{version or 'any'}"
            if cache_key in self.cache:
                cves = self.cache[cache_key]
            else:
                print(f"    - Querying CVEs for {tech} {version or '(any version)'}...")
                cves = self.query_nvd(cpe, tech, version)
                self.cache[cache_key] = cves

            for cve in cves:
                # Filter by severity
                if cve.cvss_score >= 7.0:  # Only high/critical CVEs
                    matched.append({
                        'technology': tech,
                        'version': version,
                        'cve': cve
                    })

        # Sort by CVSS score
        matched.sort(key=lambda x: x['cve'].cvss_score, reverse=True)

        print(f"[+] Found {len(matched)} relevant CVEs (CVSS >= 7.0)")
        return matched

    def generate_cve_report(self, matched: List[Dict]) -> str:
        """Generate CVE report section"""
        if not matched:
            return ""

        lines = []
        lines.append("\n## CVE Correlation\n")

        for item in matched[:20]:  # Limit to top 20
            cve = item['cve']
            tech = item['technology']
            version = item['version'] or 'any'

            lines.append(f"### {cve.cve_id}")
            lines.append(f"")
            lines.append(f"**Technology:** {tech} ({version})")
            lines.append(f"**CVSS Score:** {cve.cvss_score} ({cve.severity})")
            lines.append(f"")
            lines.append(f"**Description:**")
            lines.append(f"{cve.description}")
            lines.append(f"")
            if cve.references:
                lines.append(f"**References:**")
                for ref in cve.references[:3]:
                    lines.append(f"- {ref}")
            lines.append(f"---")
            lines.append(f"")

        return "\n".join(lines)


class ReportGenerator:
    """Generate HackerOne-compatible reports"""

    @staticmethod
    def generate_markdown(findings: List[Finding], target: str) -> str:
        """Generate HackerOne report"""
        report = []
        report.append(f"# PhantomProbe Scan Report")
        report.append(f"")
        report.append(f"**Target:** {target}")
        report.append(f"**Scan Date:** {datetime.now().isoformat()}")
        report.append(f"**Scanner:** PhantomProbe v0.4.0")
        report.append(f"")

        # Severity summary
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]

        report.append("## Summary")
        report.append(f"")
        report.append(f"**Total Findings:** {len(findings)}")
        report.append(f"")

        for severity in severity_order:
            count = len([f for f in findings if f.severity == severity])
            if count > 0:
                report.append(f"- **{severity.value.upper()}:** {count}")

        report.append(f"")

        # Detailed findings
        for severity in severity_order:
            severity_findings = [f for f in findings if f.severity == severity]
            if severity_findings:
                report.append(f"## {severity.value.upper()} Severity")
                report.append(f"")

                for finding in severity_findings:
                    report.append(f"### {finding.id}: {finding.title}")
                    report.append(f"")
                    report.append(f"**Category:** {finding.category}")
                    report.append(f"")
                    report.append(f"**Description:**")
                    report.append(f"{finding.description}")
                    report.append(f"")
                    report.append(f"**Evidence:**")
                    report.append(f"```")
                    report.append(f"{finding.evidence}")
                    report.append(f"```")
                    report.append(f"")
                    report.append(f"**Remediation:**")
                    report.append(f"{finding.remediation}")
                    report.append(f"")
                    if finding.references:
                        report.append(f"**References:**")
                        for ref in finding.references:
                            report.append(f"- {ref}")
                        report.append(f"")
                    report.append(f"---")
                    report.append(f"")

        return "\n".join(report)

    @staticmethod
    def generate_json(findings: List[Finding], target: str) -> str:
        """Generate JSON report"""
        report = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "scanner": "PhantomProbe v0.2.0",
            "findings_count": len(findings),
            "findings": [
                {
                    **{k: v for k, v in asdict(f).items() if k != 'severity'},
                    "severity": f.severity.value
                }
                for f in findings
            ]
        }
        return json.dumps(report, indent=2)


def print_banner():
    """Print ASCII banner"""
    banner = """
     ██████╗ ██╗  ██╗ █████╗ ██╗██████╗ ██████╗ ██████╗ ██╗   ██╗██████╗ 
    ██╔════╝ ██║  ██║██╔══██╗██║██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗
    ██║      ███████║███████║██║██████╔╝██████╔╝██████╔╝██║   ██║██████╔╝
    ██║      ██╔══██║██╔══██║██║██╔═══╝ ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗
    ╚██████╗ ██║  ██║██║  ██║██║██║     ██║     ██████╔╝╚██████╔╝██║  ██║
     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
    
    Ghost in the Machine | v0.4.0
    AI-Powered Reconnaissance for Bug Bounty Hunters
    """
    print(banner)


def main():
    """Main scanner entry point"""
    if len(sys.argv) < 2:
        print_banner()
        print("Usage: python3 phantomprobe.py <target>")
        print("Example: python3 phantomprobe.py example.com")
        print("")
        print("Options:")
        print("  --phase2     Enable active reconnaissance (ports, subdomains)")
        print("  --cve        Enable CVE matching (queries NVD API)")
        print("  --verbose    Show detailed output")
        print("")
        sys.exit(1)

    target = sys.argv[1].replace("https://", "").replace("http://", "").split("/")[0]
    phase2 = "--phase2" in sys.argv or "-a" in sys.argv
    cve_match = "--cve" in sys.argv or "-c" in sys.argv

    print_banner()

    # Phase 1: Passive Reconnaissance
    recon = ReconEngine(target)
    findings = recon.run()

    # Phase 2: Active Reconnaissance (optional)
    if phase2:
        active = ActiveReconEngine(target)
        active_findings = active.run()
        findings.extend(active_findings)

    # CVE Matching (optional)
    cve_results = []
    if cve_match:
        matcher = CVEMatcher()
        cve_results = matcher.match_findings(findings)

    # Print summary
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]

    print("=" * 60)
    print("FINDINGS BY SEVERITY")
    print("=" * 60)
    for severity in severity_order:
        sev_findings = [f for f in findings if f.severity == severity]
        if sev_findings:
            print(f"\n[{severity.value.upper()}]")
            for f in sev_findings:
                print(f"  - {f.id}: {f.title}")

    # Print CVE summary
    if cve_results:
        print()
        print("=" * 60)
        print("CVE CORRELATION (HIGH/CRITICAL)")
        print("=" * 60)
        for item in cve_results[:10]:
            cve = item['cve']
            print(f"  [{cve.severity}] {cve.cve_id} (CVSS {cve.cvss_score}) - {item['technology']}")

    print()
    print("=" * 60)
    print("GENERATING REPORTS")
    print("=" * 60)

    # Generate Reports
    markdown_report = ReportGenerator.generate_markdown(findings, target)
    json_report = ReportGenerator.generate_json(findings, target)

    # Add CVE section to markdown report
    if cve_results:
        matcher = CVEMatcher()
        cve_section = matcher.generate_cve_report(cve_results)
        markdown_report = markdown_report.replace("## License", cve_section + "## License") if "## License" in markdown_report else markdown_report + "\n" + cve_section

        # Add CVEs to JSON report
        json_data = json.loads(json_report)
        json_data['cve_matches'] = [
            {
                'technology': item['technology'],
                'version': item['version'],
                'cve_id': item['cve'].cve_id,
                'cvss_score': item['cve'].cvss_score,
                'severity': item['cve'].severity,
                'description': item['cve'].description,
                'references': item['cve'].references
            }
            for item in cve_results
        ]
        json_report = json.dumps(json_data, indent=2)

    md_filename = f"report-{target}.md"
    json_filename = f"report-{target}.json"

    with open(md_filename, "w") as f:
        f.write(markdown_report)
    print(f"[+] Markdown report: {md_filename}")

    with open(json_filename, "w") as f:
        f.write(json_report)
    print(f"[+] JSON report: {json_filename}")

    print()
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Total findings: {len(findings)}")
    if cve_results:
        print(f"CVE matches: {len(cve_results)}")
    print()


if __name__ == "__main__":
    main()
