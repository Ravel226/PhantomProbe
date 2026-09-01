#!/usr/bin/env python3
"""
Burp Suite Professional/Enterprise integration via the Burp REST API.

Requires the optional 'requests' dependency: pip install "phantomprobe[burp]"
"""

import os
import time
from datetime import datetime
from typing import Dict, List, Optional

from .constants import __version__
from .models import Finding, Severity

try:
    import requests
    BURP_AVAILABLE = True
except ImportError:
    BURP_AVAILABLE = False


class BurpSuiteEngine:
    """Burp Suite Professional/Enterprise integration for advanced scanning"""

    def __init__(self, target: str, api_url: str = "http://127.0.0.1:1337", api_key: str = None):
        self.target = target
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key or os.environ.get('BURP_API_KEY', '')
        self.findings: List[Finding] = []
        self.scan_id: Optional[str] = None

    def _api_request(self, endpoint: str, method: str = 'GET', data: dict = None) -> Optional[dict]:
        """Make authenticated request to Burp REST API"""
        if not BURP_AVAILABLE:
            print("[!] requests library required for Burp integration")
            return None

        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f"Bearer {self.api_key}"

        url = f"{self.api_url}/{endpoint}"
        try:
            if method == 'GET':
                resp = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                resp = requests.post(url, json=data, headers=headers, timeout=30)
            else:
                return None

            resp.raise_for_status()
            return resp.json() if resp.text else {}
        except requests.exceptions.RequestException as e:
            print(f"[!] Burp API error: {e}")
            return None

    def is_burp_running(self) -> bool:
        """Check if Burp Suite API is accessible"""
        result = self._api_request('v0.1/burp/')
        return result is not None

    def send_to_proxy(self, url: str, method: str = 'GET', data: str = None, headers: dict = None) -> bool:
        """Send HTTP request through Burp Proxy for manual inspection"""
        proxy_url = f"{self.api_url}/v0.1/proxy/burp-proxy/http-history"

        payload = {
            'url': url,
            'method': method,
            'body': data or '',
            'headers': headers or {}
        }

        result = self._api_request('v0.1/proxy/', method='POST', data=payload)
        if result:
            print(f"[+] Sent to Burp Proxy: {url}")
            return True
        return False

    def start_crawl_and_audit(self, target_url: str = None) -> Optional[str]:
        """Start Burp Spider + Scanner on target"""
        if not self.is_burp_running():
            print("[!] Burp Suite not running or API key invalid")
            return None

        url = target_url or f"https://{self.target}"

        # Start spider/crawl
        crawl_config = {
            'urls': [url],
            'scan_configurations': ['Crawl strategy - fastest']
        }

        result = self._api_request('v0.1/scan/', method='POST', data=crawl_config)
        if result and 'scan_id' in result:
            self.scan_id = result['scan_id']
            print(f"[+] Burp scan started: {self.scan_id}")
            return self.scan_id
        return None

    def get_scan_issues(self) -> List[Finding]:
        """Retrieve vulnerability findings from Burp scan"""
        if not self.scan_id:
            print("[!] No active scan")
            return []

        issues = self._api_request(f'v0.1/scan/{self.scan_id}/issues')
        if not issues:
            return []

        for issue in issues.get('issues', []):
            severity_map = {
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
                'info': Severity.INFORMATIONAL
            }

            finding = Finding(
                id=f"BURP-{issue.get('serial_number', '0')}",
                title=issue.get('name', 'Burp Finding'),
                description=issue.get('issue_background', issue.get('description', '')),
                severity=severity_map.get(issue.get('severity', 'info').lower(), Severity.INFORMATIONAL),
                category=issue.get('vulnerability_classifications', 'Burp Scanner'),
                evidence=f"URL: {issue.get('origin', '')}\nPath: {issue.get('path', '')}",
                remediation=issue.get('remediation', 'Review Burp findings'),
                references=issue.get('references', []),
                discovered_at=datetime.now().isoformat(),
                target=self.target
            )
            self.findings.append(finding)

        print(f"[+] Burp scan: {len(self.findings)} issues found")
        return self.findings

    def wait_for_scan_complete(self, timeout: int = 300) -> bool:
        """Wait for Burp scan to complete"""
        if not self.scan_id:
            return False

        print(f"[*] Waiting for Burp scan (max {timeout}s)...")
        start = time.time()

        while time.time() - start < timeout:
            status = self._api_request(f'v0.1/scan/{self.scan_id}/status')
            if status and status.get('scan_status') == 'succeeded':
                print("[+] Burp scan completed")
                return True
            time.sleep(5)

        print("[!] Burp scan timeout")
        return False

    def run(self, use_proxy_only: bool = False) -> List[Finding]:
        """Run Burp Suite integration"""
        if not BURP_AVAILABLE:
            print("[!] Burp integration requires: pip install requests")
            return []

        print(f"[*] Connecting to Burp Suite at {self.api_url}...")

        if not self.is_burp_running():
            print("[!] Burp Suite not accessible. Check:")
            print("    - Burp is running with REST API enabled")
            print("    - API key is set via BURP_API_KEY env var")
            return []

        print("[+] Burp Suite connected")

        if use_proxy_only:
            # Just send target to proxy
            self.send_to_proxy(f"https://{self.target}")
            return []

        # Run full crawl + audit
        scan_id = self.start_crawl_and_audit()
        if scan_id and self.wait_for_scan_complete(timeout=180):
            return self.get_scan_issues()

        return self.findings

    def export_to_burp(self, findings: List[Finding]) -> bool:
        """Export PhantomProbe findings to Burp as manual notes"""
        if not self.is_burp_running():
            return False

        print(f"[*] Exporting {len(findings)} findings to Burp...")

        for finding in findings:
            note = {
                'comment': f"{finding.id}: {finding.title}\n\n{finding.description}\n\nRemediation: {finding.remediation}",
                'url': f"https://{self.target}",
                'highlight': finding.severity.value
            }
            self._api_request('v0.1/target/notes/', method='POST', data=note)

        print("[+] Findings exported to Burp")
        return True

    @staticmethod
    def generate_extension_template(output_path: str = "burp_extension.py") -> str:
        """Generate Burp Suite extension template for custom integration"""
        template = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhantomProbe Burp Suite Extension
Integrates PhantomProbe reconnaissance with Burp Suite Professional

Install in Burp: Extensions -> Installed -> Add -> Select file
"""

from burp import IBurpExtender, IScannerCheck, IScanIssue
import json
import urllib2

class BurpExtender(IBurpExtender, IScannerCheck):
    NAME = "PhantomProbe Integration"
    VERSION = "__PP_VERSION__"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.NAME)
        print(f"[+] {self.NAME} v{self.VERSION} loaded")

        # Register scanner check
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        """Analyze passive scan results"""
        issues = []
        # Integration logic here
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Perform active scanning"""
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return existingIssue.getIssueName() == newIssue.getIssueName()


class PhantomProbeIssue(IScanIssue):
    def __init__(self, url, name, severity, confidence, detail, remediation):
        self._url = url
        self._name = name
        self._severity = severity
        self._confidence = confidence
        self._detail = detail
        self._remediation = remediation

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return self._severity
    def getConfidence(self): return self._confidence
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return self._remediation
    def getHttpMessages(self): return None
    def getHttpService(self): return None
'''
        template = template.replace("__PP_VERSION__", __version__)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(template)

        print(f"[+] Burp extension template saved: {output_path}")
        return output_path

