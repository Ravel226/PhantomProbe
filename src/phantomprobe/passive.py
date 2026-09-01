#!/usr/bin/env python3
"""
Phase 1: passive reconnaissance (DNS, SSL/TLS, HTTP security headers).

Nothing here sends traffic beyond an ordinary HTTPS request plus DNS lookups.
"""

import secrets
import socket
import ssl
from datetime import datetime, timezone
from typing import List
from urllib.error import HTTPError, URLError
from urllib.request import Request

from .http_client import safe_urlopen

from .constants import USER_AGENT, __version__
from .models import Finding, Severity


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

            # Check for wildcard DNS: a label nobody could have registered.
            # Timestamp-derived labels can collide across parallel scans, so
            # draw the label from the system CSPRNG instead.
            random_sub = secrets.token_hex(6)
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
            req.add_header('User-Agent', USER_AGENT)

            with safe_urlopen(req, context=ctx, timeout=10) as response:
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
        print(f"PHANTOMPROBE v{__version__} - Phase 1: Passive Reconnaissance")
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

