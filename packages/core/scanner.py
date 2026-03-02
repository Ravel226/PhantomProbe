#!/usr/bin/env python3
"""
PhantomProbe v0.7.0
Reconnaissance Scanner for Penetration Testing
Ghost in the Machine 

Standard library core + optional Playwright for screenshots
CVE matching via NVD API
JavaScript/endpoint discovery
Interactive Web Dashboard (FastAPI)

Author: Ravel226
License: MIT
"""

import sys
import json
import ssl
import socket
import time
import re
import base64
import hashlib
import concurrent.futures
import threading
import webbrowser
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote, urljoin, urlparse
from html.parser import HTMLParser

# FastAPI for dashboard (optional dependency)
try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


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


class ScreenshotCapture:
    """Capture website screenshots for documentation"""

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir
        self.playwright_available = self._check_playwright()

    def _check_playwright(self) -> bool:
        """Check if Playwright is available"""
        try:
            from playwright.sync_api import sync_playwright
            return True
        except ImportError:
            return False

    def capture(self, url: str, output_file: str = None, full_page: bool = True, 
                viewport_width: int = 1920, viewport_height: int = 1080,
                timeout: int = 30000) -> Optional[str]:
        """
        Capture screenshot of a URL
        
        Args:
            url: Target URL to screenshot
            output_file: Output filename (default: screenshot-{domain}.png)
            full_page: Capture full page or viewport only
            viewport_width: Browser viewport width
            viewport_height: Browser viewport height
            timeout: Page load timeout in ms
            
        Returns:
            Path to screenshot file or None if failed
        """
        if not self.playwright_available:
            print("[!] Playwright not installed. Install with: pip install playwright && playwright install chromium")
            return None

        try:
            from playwright.sync_api import sync_playwright
            
            # Parse URL
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            
            # Generate output filename
            if not output_file:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc or url.replace('https://', '').replace('http://', '').split('/')[0]
                output_file = f"screenshot-{domain}.png"
            
            output_path = f"{self.output_dir}/{output_file}"
            
            print(f"[*] Capturing screenshot: {url}")
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={'width': viewport_width, 'height': viewport_height},
                    ignore_https_errors=True
                )
                page = context.new_page()
                
                # Set timeout
                page.set_default_timeout(timeout)
                
                # Navigate and wait for load
                try:
                    page.goto(url, wait_until='networkidle', timeout=timeout)
                except Exception as e:
                    # Try with domcontentloaded if networkidle times out
                    page.goto(url, wait_until='domcontentloaded', timeout=timeout)
                
                # Take screenshot
                page.screenshot(path=output_path, full_page=full_page)
                
                browser.close()
            
            print(f"[+] Screenshot saved: {output_path}")
            return output_path
            
        except Exception as e:
            print(f"[!] Screenshot failed: {str(e)}")
            return None

    def capture_multiple(self, urls: List[str], output_dir: str = None) -> List[str]:
        """Capture screenshots for multiple URLs"""
        screenshots = []
        
        if output_dir:
            self.output_dir = output_dir
        
        for url in urls:
            screenshot = self.capture(url)
            if screenshot:
                screenshots.append(screenshot)
        
        return screenshots

    def capture_with_variants(self, domain: str) -> Dict[str, str]:
        """Capture screenshots of domain variants (http, https, www)"""
        variants = {
            'https': f"https://{domain}",
            'https_www': f"https://www.{domain}",
            'http': f"http://{domain}",
        }
        
        screenshots = {}
        
        for name, url in variants.items():
            output_file = f"screenshot-{domain}-{name}.png"
            result = self.capture(url, output_file=output_file)
            if result:
                screenshots[name] = result
        
        return screenshots


class ScriptTagParser(HTMLParser):
    """HTML parser to extract script src URLs"""
    
    def __init__(self):
        super().__init__()
        self.script_urls: List[str] = []
    
    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            for attr, value in attrs:
                if attr == 'src' and value:
                    self.script_urls.append(value)


class JSEngine:
    """JavaScript analysis for endpoint and secret discovery"""

    # Regex patterns for API endpoints
    ENDPOINT_PATTERNS = [
        r'["\']/(api|v[0-9]+|rest|graphql|query)/[a-zA-Z0-9_/-]+["\']',
        r'["\'][a-zA-Z0-9_/-]+:[a-zA-Z0-9_/-]+["\']',  # GraphQL-style
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
    ]

    # Regex patterns for secrets
    SECRET_PATTERNS = [
        (r'(?i)["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'API Key'),
        (r'(?i)["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Secret Key'),
        (r'(?i)["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'Auth Token'),
        (r'(?i)["\']?bearer["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'Bearer Token'),
        (r'(?i)["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'Access Token'),
        (r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key'),
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI API Key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
        (r'ghu_[a-zA-Z0-9]{36}', 'GitHub User Token'),
        (r'ghs_[a-zA-Z0-9]{36}', 'GitHub Server Token'),
        (r'xox[baprs]-[0-9]{10,}-[a-zA-Z0-9]{24}', 'Slack Token'),
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'JWT Token'),
        (r'(?i)["\']?private[_-]?key["\']?\s*[:=]\s*["\']-----BEGIN[^"\']+["\']', 'Private Key'),
    ]

    # Regex patterns for hidden paths
    PATH_PATTERNS = [
        r'["\']/(admin|config|backup|test|dev|staging|api|debug|console|dashboard)/[a-zA-Z0-9_/-]*["\']',
        r'["\']\.(php|asp|aspx|jsp|cgi|json|xml|yaml|yml|env|conf|config|log)["\']',
    ]

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []
        self.js_urls: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.secrets: List[Tuple[str, str, str]] = []  # (type, value, file)
        self.hidden_paths: Set[str] = set()

    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch HTML page content"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = Request(url, headers={'User-Agent': 'Mozilla/5.0 PhantomProbe/0.6.0'})
            with urlopen(req, context=ctx, timeout=15) as response:
                return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return None

    def fetch_js(self, url: str) -> Optional[str]:
        """Fetch JavaScript file content"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Handle relative URLs
            if url.startswith('//'):
                url = f'https:{url}'
            elif url.startswith('/'):
                url = f'https://{self.target}{url}'
            elif not url.startswith('http'):
                url = f'https://{self.target}/{url}'

            req = Request(url, headers={'User-Agent': 'Mozilla/5.0 PhantomProbe/0.6.0'})
            with urlopen(req, context=ctx, timeout=15) as response:
                return response.read().decode('utf-8', errors='ignore')
        except Exception:
            return None

    def extract_js_urls(self, html: str) -> List[str]:
        """Extract JavaScript URLs from HTML"""
        parser = ScriptTagParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        
        # Also find inline script tags and other JS sources
        patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\']',
            r'import\s+.*?from\s+["\']([^"\']+\.js)["\']',
        ]
        
        urls = set(parser.script_urls)
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            urls.update(matches)
        
        return list(urls)

    def analyze_js(self, js_content: str, js_url: str) -> None:
        """Analyze JavaScript content for endpoints and secrets"""
        
        # Extract API endpoints
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1] if len(match) > 1 else None
                if match and len(match) > 3:
                    self.endpoints.add(match.strip('\'"'))

        # Extract secrets
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) >= 10:
                    # Mask the secret for reporting
                    masked = match[:4] + '*' * (len(match) - 8) + match[-4:] if len(match) > 12 else '****'
                    self.secrets.append((secret_type, masked, js_url))

        # Extract hidden paths
        for pattern in self.PATH_PATTERNS:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match:
                    self.hidden_paths.add(match.strip('\'"'))

    def run(self) -> List[Finding]:
        """Run JavaScript analysis"""
        print(f"[*] Analyzing JavaScript files...")

        # Fetch main page
        main_url = f"https://{self.target}"
        html = self.fetch_page(main_url)
        
        if not html:
            # Try HTTP
            main_url = f"http://{self.target}"
            html = self.fetch_page(main_url)

        if not html:
            print(f"[!] Could not fetch main page")
            return []

        # Extract JS URLs
        js_urls = self.extract_js_urls(html)
        print(f"[*] Found {len(js_urls)} JavaScript files")

        # Fetch and analyze each JS file
        for js_url in js_urls[:20]:  # Limit to 20 files
            js_content = self.fetch_js(js_url)
            if js_content:
                self.analyze_js(js_content, js_url)

        # Create findings from discovered items
        
        # Endpoints
        for endpoint in sorted(self.endpoints)[:30]:
            self.findings.append(Finding(
                id=f"JS-ENDPOINT-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                title="API Endpoint Discovered",
                description=f"Potential API endpoint found: {endpoint}",
                severity=Severity.INFORMATIONAL,
                category="JavaScript Analysis",
                evidence=f"Endpoint: {endpoint}",
                remediation="Review if endpoint should be publicly accessible",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        # Secrets (more severe)
        for secret_type, masked_value, source in self.secrets:
            self.findings.append(Finding(
                id=f"JS-SECRET-{hashlib.md5(masked_value.encode()).hexdigest()[:8]}",
                title=f"Potential {secret_type} Exposed",
                description=f"Potential {secret_type} found in JavaScript: {masked_value}",
                severity=Severity.HIGH,
                category="Information Disclosure",
                evidence=f"Type: {secret_type}\nValue: {masked_value}\nSource: {source}",
                remediation="Remove secrets from client-side code. Use environment variables or secret management.",
                references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_GET_request"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        # Hidden paths
        for path in sorted(self.hidden_paths)[:20]:
            self.findings.append(Finding(
                id=f"JS-PATH-{hashlib.md5(path.encode()).hexdigest()[:8]}",
                title="Hidden Path Discovered",
                description=f"Potential hidden path found: {path}",
                severity=Severity.LOW,
                category="JavaScript Analysis",
                evidence=f"Path: {path}",
                remediation="Verify path doesn't expose sensitive functionality",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        # Summary finding
        if self.findings:
            summary = f"Analyzed {len(js_urls)} JS files\n"
            summary += f"Found {len(self.endpoints)} endpoints\n"
            summary += f"Found {len(self.secrets)} potential secrets\n"
            summary += f"Found {len(self.hidden_paths)} hidden paths"
            
            self.findings.append(Finding(
                id="JS-SUMMARY",
                title="JavaScript Analysis Summary",
                description=summary,
                severity=Severity.INFORMATIONAL,
                category="JavaScript Analysis",
                evidence=summary,
                remediation="Review findings and verify if sensitive data is exposed",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] JavaScript analysis: {len(self.findings)} findings")
        return self.findings


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
        report.append(f"**Scanner:** PhantomProbe v0.6.0")
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
    
    Ghost in the Machine | v0.7.0
    AI-Powered Reconnaissance for Bug Bounty Hunters
    """
    print(banner)


class DashboardServer:
    """FastAPI-based interactive dashboard for PhantomProbe"""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.findings: List[Finding] = []
        self.cve_results: List[Dict] = []
        self.target: str = ""
        self.scan_progress: Dict = {}
        self.app = None
        self.connected_clients: List[WebSocket] = []

        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI not available. Install: pip install fastapi uvicorn")

        self._create_app()

    def _create_app(self):
        """Create FastAPI application"""
        self.app = FastAPI(
            title="PhantomProbe Dashboard",
            description="Interactive reconnaissance scanner dashboard",
            version="0.7.0"
        )

        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard():
            return self._generate_html()

        @self.app.get("/api/findings")
        async def api_findings():
            return JSONResponse(content=[asdict(f) for f in self.findings])

        @self.app.get("/api/cve")
        async def api_cve():
            return JSONResponse(content=self.cve_results)

        @self.app.get("/api/stats")
        async def api_stats():
            stats = self._calculate_stats()
            return JSONResponse(content=stats)

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.connected_clients.append(websocket)
            try:
                while True:
                    data = await websocket.receive_text()
                    # Echo back for now, could implement commands
                    await websocket.send_text(json.dumps({"type": "pong", "data": data}))
            except WebSocketDisconnect:
                self.connected_clients.remove(websocket)

    def _calculate_stats(self) -> Dict:
        """Calculate scan statistics"""
        stats = {
            "target": self.target,
            "total_findings": len(self.findings),
            "severity_counts": {},
            "categories": {},
            "scan_time": datetime.now().isoformat()
        }

        for severity in Severity:
            stats["severity_counts"][severity.value] = len([f for f in self.findings if f.severity == severity])

        for finding in self.findings:
            cat = finding.category
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1

        return stats

    def update_data(self, findings: List[Finding], cve_results: List[Dict], target: str):
        """Update dashboard with new scan data"""
        self.findings = findings
        self.cve_results = cve_results
        self.target = target

    def _generate_html(self) -> str:
        """Generate interactive HTML dashboard"""
        stats = self._calculate_stats()

        # Color mapping for severity
        severity_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f39c12",
            "low": "#3498db",
            "informational": "#95a5a6"
        }

        # Build findings table
        findings_html = ""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]

        for severity in severity_order:
            sev_findings = [f for f in self.findings if f.severity == severity]
            for finding in sev_findings:
                color = severity_colors.get(severity.value, "#95a5a6")
                findings_html += f"""
                <tr style="border-left: 4px solid {color}">
                    <td><span class="badge" style="background: {color}">{severity.value.upper()}</span></td>
                    <td>{finding.id}</td>
                    <td>{finding.title}</td>
                    <td>{finding.category}</td>
                    <td><details><summary>View</summary><pre>{finding.evidence[:500]}...</pre></details></td>
                </tr>
                """

        # Build CVE table
        cve_html = ""
        for item in self.cve_results[:20]:
            cve = item['cve']
            color = severity_colors.get(cve.severity, "#95a5a6")
            cve_html += f"""
            <tr style="border-left: 4px solid {color}">
                <td><span class="badge" style="background: {color}">{cve.severity.upper()}</span></td>
                <td>{cve.cve_id}</td>
                <td>{cve.cvss_score}</td>
                <td>{item['technology']}</td>
                <td>{cve.description[:150]}...</td>
            </tr>
            """

        # Stats cards
        cards_html = ""
        for sev, count in stats["severity_counts"].items():
            if count > 0:
                color = severity_colors.get(sev, "#95a5a6")
                cards_html += f"""
                <div class="stat-card" style="border-top: 4px solid {color}">
                    <h3>{count}</h3>
                    <p>{sev.upper()}</p>
                </div>
                """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomProbe Dashboard - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .header h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .header p {{ color: #888; }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1a1a2e;
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card h3 {{
            font-size: 2.5rem;
            color: #00d4ff;
        }}
        .stat-card p {{
            color: #888;
            font-size: 0.9rem;
            text-transform: uppercase;
        }}
        .section {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .section h2 {{
            color: #00d4ff;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        th {{
            color: #00d4ff;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
        }}
        tr:hover {{ background: rgba(0, 212, 255, 0.05); }}
        .badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }}
        details {{
            cursor: pointer;
        }}
        details summary {{
            color: #00d4ff;
        }}
        details pre {{
            background: #0a0a0a;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 0.5rem;
            overflow-x: auto;
            font-size: 0.8rem;
        }}
        .empty-state {{
            text-align: center;
            padding: 3rem;
            color: #666;
        }}
        .refresh-btn {{
            background: linear-gradient(135deg, #00d4ff, #7b2cbf);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
            transition: opacity 0.2s;
        }}
        .refresh-btn:hover {{ opacity: 0.9; }}
        #connection-status {{
            position: fixed;
            top: 1rem;
            right: 1rem;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-size: 0.8rem;
        }}
        .connected {{ background: #27ae60; }}
        .disconnected {{ background: #e74c3c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🐚 PhantomProbe Dashboard</h1>
        <p>Target: <strong>{self.target}</strong> | Scan Time: {stats['scan_time']}</p>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card" style="border-top: 4px solid #00d4ff">
                <h3>{stats['total_findings']}</h3>
                <p>TOTAL FINDINGS</p>
            </div>
            {cards_html}
        </div>

        <div class="section">
            <h2>🔍 Findings</h2>
            {'<div class="empty-state">No findings yet. Run a scan to populate.</div>' if not findings_html else f'<table><thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Category</th><th>Evidence</th></tr></thead><tbody>{findings_html}</tbody></table>'}
        </div>

        <div class="section">
            <h2>🐛 CVE Matches</h2>
            {'<div class="empty-state">No CVE matches found.</div>' if not cve_html else f'<table><thead><tr><th>Severity</th><th>CVE ID</th><th>CVSS</th><th>Technology</th><th>Description</th></tr></thead><tbody>{cve_html}</tbody></table>'}
        </div>
    </div>

    <div id="connection-status" class="disconnected">● WebSocket Disconnected</div>

    <script>
        let ws;
        function connect() {{
            ws = new WebSocket('ws://{{self.host}}:{{self.port}}/ws');
            ws.onopen = () => {{
                document.getElementById('connection-status').className = 'connected';
                document.getElementById('connection-status').textContent = '● Live Updates';
            }};
            ws.onclose = () => {{
                document.getElementById('connection-status').className = 'disconnected';
                document.getElementById('connection-status').textContent = '● Reconnecting...';
                setTimeout(connect, 3000);
            }};
            ws.onmessage = (event) => {{
                const data = JSON.parse(event.data);
                console.log('Update received:', data);
                if (data.type === 'NEW_FINDING') {{
                    location.reload();
                }}
            }};
        }}
        connect();
    </script>
</body>
</html>"""
        return html

    async def broadcast_update(self, message: Dict):
        """Broadcast update to all connected clients"""
        if self.connected_clients:
            import asyncio
            disconnected = []
            for client in self.connected_clients:
                try:
                    await client.send_text(json.dumps(message))
                except:
                    disconnected.append(client)
            for client in disconnected:
                self.connected_clients.remove(client)

    def run(self, open_browser: bool = True):
        """Start the dashboard server"""
        if open_browser:
            webbrowser.open(f"http://{self.host}:{self.port}")

        print(f"[*] Starting PhantomProbe Dashboard on http://{self.host}:{self.port}")
        print(f"[*] Press Ctrl+C to stop")

        uvicorn.run(self.app, host=self.host, port=self.port, log_level="warning")


def main():
    """Main scanner entry point"""
    if len(sys.argv) < 2:
        print_banner()
        print("Usage: python3 phantomprobe.py <target>")
        print("Example: python3 phantomprobe.py example.com")
        print("")
        print("Options:")
        print("  --phase2      Enable active reconnaissance (ports, subdomains)")
        print("  --cve         Enable CVE matching (queries NVD API)")
        print("  --screenshot  Capture website screenshot (requires Playwright)")
        print("  --js          JavaScript analysis (endpoints, secrets)")
        print("  --dashboard   Start interactive web dashboard (requires FastAPI)")
        print("  --verbose     Show detailed output")
        print("")
        sys.exit(1)

    target = sys.argv[1].replace("https://", "").replace("http://", "").split("/")[0]
    phase2 = "--phase2" in sys.argv or "-a" in sys.argv
    cve_match = "--cve" in sys.argv or "-c" in sys.argv
    screenshot = "--screenshot" in sys.argv or "-s" in sys.argv
    js_analysis = "--js" in sys.argv or "-j" in sys.argv
    dashboard = "--dashboard" in sys.argv or "-d" in sys.argv

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

    # Screenshot Capture (optional)
    screenshot_path = None
    if screenshot:
        capturer = ScreenshotCapture()
        screenshot_path = capturer.capture(target)
        if screenshot_path:
            # Add finding for screenshot
            findings.append(Finding(
                id="SCREENSHOT-Captured",
                title="Website Screenshot Captured",
                description=f"Visual documentation of target website",
                severity=Severity.INFORMATIONAL,
                category="Documentation",
                evidence=f"Screenshot saved: {screenshot_path}",
                remediation="N/A - Documentation",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=target
            ))

    # JavaScript Analysis (optional)
    if js_analysis:
        js_engine = JSEngine(target)
        js_findings = js_engine.run()
        findings.extend(js_findings)

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

    # Launch Dashboard (optional)
    if dashboard:
        if FASTAPI_AVAILABLE:
            print("[*] Launching interactive dashboard...")
            dashboard_server = DashboardServer()
            dashboard_server.update_data(findings, cve_results, target)
            dashboard_server.run(open_browser=True)
        else:
            print("[!] Dashboard requires FastAPI. Install: pip install fastapi uvicorn")
            print("[*] Reports generated:")
            print(f"    - {md_filename}")
            print(f"    - {json_filename}")


if __name__ == "__main__":
    main()
