#!/usr/bin/env python3
"""
PhantomProbe v0.1.0
AI-Powered Reconnaissance for Bug Bounty Hunters
Ghost in the Machine 🔍

Standard library only - no dependencies required
HackerOne-compatible reporting format

Author: Ravel226
License: MIT
"""

import sys
import json
import ssl
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

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
        
    def analyze_headers(self) -> List[Finding]:
        """Analyze HTTP security headers"""
        findings = []
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = Request(f"https://{self.target}", method='GET')
            req.add_header('User-Agent', 'Ravel-VulnScanner/0.1')
            
            with urlopen(req, context=ctx, timeout=10) as response:
                headers = dict(response.headers)
                
                # Check security headers
                security_headers = {
                    'X-Frame-Options': 'Missing clickjacking protection',
                    'Content-Security-Policy': 'Missing XSS protection',
                    'Strict-Transport-Security': 'Missing HSTS',
                    'X-Content-Type-Options': 'Missing MIME sniffing protection',
                    'Referrer-Policy': 'Missing referrer control'
                }
                
                for header, issue in security_headers.items():
                    if header not in headers:
                        findings.append(Finding(
                            id=f"HEADER-{header.replace('-', '')}",
                            title=f"Missing {header} Header",
                            description=issue,
                            severity=Severity.LOW,
                            category="Security Headers",
                            evidence=f"Header not present in response",
                            remediation=f"Add '{header}: ...' to all responses",
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
                if 'Server' in headers and headers.get('Server') not in ['', 'nginx', 'apache']:
                    findings.append(Finding(
                        id="INFO-Server",
                        title="Information Disclosure: Server Header",
                        description=f"Server banner reveals: {headers.get('Server')}",
                        severity=Severity.INFORMATIONAL,
                        category="Information Disclosure",
                        evidence=f"Server: {headers.get('Server')}",
                        remediation="Configure server to not disclose version information",
                        references=["https://cheatsheetseries.owasp.org/"],
                        discovered_at=datetime.now().isoformat(),
                        target=self.target
                    ))
                
                # Check for cache/session issues
                if headers.get('Cache-Control') == 'no-store, no-cache, must-revalidate':
                    if headers.get('Expires') == 'Thu, 19 Nov 1981 08:52:00 GMT':
                        findings.append(Finding(
                            id="SESSION-Cache",
                            title="Session Handling Configuration",
                            description="PHP session using default cache headers with known timestamp",
                            severity=Severity.LOW,
                            category="Session Management",
                            evidence="Expires: Thu, 19 Nov 1981 08:52:00 GMT",
                            remediation="Configure custom session cache headers in PHP",
                            references=["https://www.php.net/manual/en/function.session-cache-limiter.php"],
                            discovered_at=datetime.now().isoformat(),
                            target=self.target
                        ))
                
                # Found good headers
                good_headers = []
                if 'Strict-Transport-Security' in headers:
                    good_headers.append("HSTS enabled")
                if 'X-Frame-Options' in headers and headers['X-Frame-Options'] == 'DENY':
                    good_headers.append("Clickjacking protection (DENY)")
                if 'X-Content-Type-Options' in headers:
                    good_headers.append("MIME sniffing protection")
                if 'Content-Security-Policy' in headers:
                    good_headers.append("CSP configured")
                
                if good_headers:
                    findings.append(Finding(
                        id="HEADER-Good",
                        title="Security Headers Well Configured",
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
                
        return findings
    
    def run(self) -> List[Finding]:
        """Run all reconnaissance checks"""
        print(f"[*] Starting Phase 1 reconnaissance on {self.target}")
        
        header_findings = self.analyze_headers()
        self.findings.extend(header_findings)
        
        print(f"[+] Phase 1 complete: {len(header_findings)} findings")
        
        return self.findings

class ReportGenerator:
    """Generate HackerOne-compatible reports"""
    
    @staticmethod
    def generate_markdown(findings: List[Finding], target: str) -> str:
        """Generate HackerOne report"""
        report = []
        report.append(f"# Vulnerability Scan Report")
        report.append(f"**Target:** {target}")
        report.append(f"**Scan Date:** {datetime.now().isoformat()}")
        report.append(f"**Scanner:** Ravel-VulnScanner v0.1")
        report.append("")
        
        # Severity summary
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
        
        report.append("## Summary")
        report.append(f"**Total Findings:** {len(findings)}\\n")
        
        for severity in severity_order:
            count = len([f for f in findings if f.severity == severity])
            if count > 0:
                report.append(f"- **{severity.value.capitalize()}:** {count}")
        
        report.append("")
        
        # Detailed findings
        for severity in severity_order:
            severity_findings = [f for f in findings if f.severity == severity]
            if severity_findings:
                report.append(f"## {severity.value.upper()} Severity")
                report.append("")
                
                for finding in severity_findings:
                    report.append(f"### {finding.id}: {finding.title}")
                    report.append("")
                    report.append(f"**Category:** {finding.category}")
                    report.append("")
                    report.append("**Description:**")
                    report.append(finding.description)
                    report.append("")
                    report.append("**Evidence:**")
                    report.append(f"```")
                    report.append(finding.evidence)
                    report.append(f"```")
                    report.append("")
                    report.append("**Remediation:**")
                    report.append(finding.remediation)
                    report.append("")
                    if finding.references:
                        report.append("**References:**")
                        for ref in finding.references:
                            report.append(f"- {ref}")
                        report.append("")
                    report.append("---")
                    report.append("")
        
        return "\n".join(report)
    
    @staticmethod
    def generate_json(findings: List[Finding], target: str) -> str:
        """Generate JSON report"""
        report = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "scanner": "Ravel-VulnScanner v0.1",
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

def main():
    """Main scanner entry point"""
    if len(sys.argv) < 2:
        print("=" * 60)
        print("Ravel-VulnScanner v0.1")
        print("Phase 1: Reconnaissance | Phase 2: Coming Soon")
        print("=" * 60)
        print()
        print("Usage: python3 ravel-vulnscanner.py <target>")
        print("Example: python3 ravel-vulnscanner.py laurellewourougou.com")
        print()
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("=" * 60)
    print("Ravel-VulnScanner v0.1")
    print("=" * 60)
    print(f"Target: {target}")
    print("=" * 60)
    print()
    
    # Phase 1: Reconnaissance
    recon = ReconEngine(target)
    findings = recon.run()
    
    # Summary
    print()
    print("=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Total Findings: {len(findings)}\\n")
    
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
    for severity in severity_order:
        count = len([f for f in findings if f.severity == severity])
        if count > 0:
            print(f"  {severity.value.upper()}: {count}")
    print()
    
    # Findings list
    print("=" * 60)
    print("FINDINGS")
    print("=" * 60)
    for finding in findings:
        print(f"[{finding.severity.value.upper()}] {finding.id}: {finding.title}")
    print()
    
    # Generate Reports
    print("[+] Generating reports...")
    
    markdown_report = ReportGenerator.generate_markdown(findings, target)
    json_report = ReportGenerator.generate_json(findings, target)
    
    md_filename = f"report-{target}.md"
    json_filename = f"report-{target}.json"
    
    with open(md_filename, "w") as f:
        f.write(markdown_report)
    print(f"[✓] Report saved: {md_filename}")
    
    with open(json_filename, "w") as f:
        f.write(json_report)
    print(f"[✓] Report saved: {json_filename}")
    
    print()
    print("=" * 60)
    print("DONE!")
    print("=" * 60)

if __name__ == "__main__":
    main()
