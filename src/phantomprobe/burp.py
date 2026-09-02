#!/usr/bin/env python3
"""
Burp Suite Professional integration via its REST API.

Requires the optional 'requests' dependency: pip install "phantomprobe[burp]"

The API is the one Burp Professional exposes locally (Settings > Suite >
REST API), not the Enterprise GraphQL API. Two details of it shape this module:

* The API key is a path prefix, not a header. Burp mounts the whole service
  under it, so a request goes to ``<service>/<key>/v0.1/...``. Sending the key
  as ``Authorization: Bearer`` leaves the request unauthenticated.
* Starting a scan answers 201 with the task id in the ``Location`` header. The
  body is empty.

Its surface is scanning only: start a scan, poll it, read its issues. There is
no endpoint for driving the proxy or for writing notes back into Burp, so this
module does not pretend to offer either.
"""

import os
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import quote

from .constants import __version__
from .models import Finding, Severity

try:
    import requests
    BURP_AVAILABLE = True
except ImportError:
    BURP_AVAILABLE = False


DEFAULT_API_URL = "http://127.0.0.1:1337"

# Burp grades issues high/medium/low/info. It has no critical band.
BURP_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
}

# A scan stops changing once it reaches one of these.
TERMINAL_STATUSES = {"succeeded", "failed", "cancelled"}


class BurpSuiteEngine:
    """Drive a Burp Professional scan and convert its issues to Findings."""

    def __init__(
        self,
        target: str,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.target = target
        self.api_url = (
            api_url or os.environ.get("BURP_API_URL") or DEFAULT_API_URL
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("BURP_API_KEY", "")
        self.findings: List[Finding] = []
        self.task_id: Optional[str] = None

    @property
    def base_url(self) -> str:
        """
        Service root for API calls.

        Burp serves the API under the key when one is configured, and directly
        under the service URL when "allow access without API key" is on.
        """
        if not self.api_key:
            return self.api_url
        return f"{self.api_url}/{quote(self.api_key, safe='')}"

    def _request(
        self,
        path: str,
        method: str = "GET",
        data: Optional[dict] = None,
        params: Optional[dict] = None,
    ):
        """Call the API and return the response, or None if it could not be made."""
        if not BURP_AVAILABLE:
            print('[!] Burp integration requires: pip install "phantomprobe[burp]"')
            return None

        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "User-Agent": f"PhantomProbe/{__version__}",
        }
        try:
            response = requests.request(
                method, url, json=data, params=params, headers=headers, timeout=30
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as exc:
            print(f"[!] Burp API error on {method} {path}: {exc}")
            return None

    def _json(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        response = self._request(path, params=params)
        if response is None:
            return None
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            print(f"[!] Burp returned a non-JSON body for {path}")
            return None

    def is_burp_running(self) -> bool:
        """Whether the API answers. A wrong key shows up here as a 401."""
        return self._request("v0.1/") is not None

    def start_scan(
        self,
        target_url: Optional[str] = None,
        configuration: Optional[str] = None,
    ) -> Optional[str]:
        """
        Queue a crawl and audit, returning Burp's task id.

        Sending only the URL lets Burp apply its own defaults, which is what we
        want unless the caller names a saved configuration.
        """
        url = target_url or f"https://{self.target}"
        body: Dict[str, object] = {"urls": [url]}
        if configuration:
            # Named configurations are objects, not bare strings.
            body["scan_configurations"] = [
                {"name": configuration, "type": "NamedConfiguration"}
            ]

        response = self._request("v0.1/scan", method="POST", data=body)
        if response is None:
            return None

        # The id is in Location; fall back to a body field in case a future
        # version starts returning one.
        location = response.headers.get("Location", "")
        task_id = location.rstrip("/").rsplit("/", 1)[-1] if location else ""
        if not task_id and response.content:
            try:
                task_id = str(response.json().get("task_id", ""))
            except ValueError:
                task_id = ""

        if not task_id:
            print("[!] Burp accepted the scan but returned no task id")
            return None

        self.task_id = task_id
        print(f"[+] Burp scan queued: task {task_id}")
        return task_id

    def get_scan(self) -> Optional[dict]:
        """Fetch the scan record, which carries both status and issues."""
        if not self.task_id:
            return None
        return self._json(f"v0.1/scan/{quote(str(self.task_id), safe='')}")

    def wait_for_scan(self, timeout: int = 300, interval: int = 5) -> Optional[dict]:
        """
        Poll until the scan reaches a terminal status.

        Returns the final scan record, or the last one seen on timeout so a
        partial result is still usable.
        """
        if not self.task_id:
            return None

        print(f"[*] Waiting for Burp scan (up to {timeout}s)...")
        deadline = time.time() + timeout
        last: Optional[dict] = None
        status = ""

        while time.time() < deadline:
            last = self.get_scan()
            if last is None:
                return None
            status = str(last.get("scan_status", ""))
            if status in TERMINAL_STATUSES:
                print(f"[+] Burp scan {status}")
                return last
            time.sleep(interval)

        print(f"[!] Burp scan still {status or 'running'} after {timeout}s")
        return last

    def issues_to_findings(self, scan: Optional[dict]) -> List[Finding]:
        """Convert Burp's issue_events into Findings."""
        if not scan:
            return []

        findings: List[Finding] = []
        for event in scan.get("issue_events", []):
            if event.get("type") not in (None, "issue_found"):
                continue
            issue = event.get("issue") or {}

            origin = issue.get("origin", "")
            path = issue.get("path", "")
            evidence = [f"URL: {origin}{path}"]
            if issue.get("confidence"):
                evidence.append(f"Confidence: {issue['confidence']}")
            if issue.get("caption"):
                evidence.append(f"Detail: {issue['caption']}")

            findings.append(Finding(
                id=f"BURP-{issue.get('serial_number', 'unknown')}",
                title=issue.get("name", "Burp issue"),
                # Burp splits prose across these; description is the specific
                # instance and issue_background the generic explanation.
                description=(
                    issue.get("description")
                    or issue.get("issue_background")
                    or ""
                ),
                severity=BURP_SEVERITY.get(
                    str(issue.get("severity", "")).lower(), Severity.INFORMATIONAL
                ),
                category="Burp Scanner",
                evidence="\n".join(evidence),
                # The field is remediation_background; there is no "remediation".
                remediation=issue.get(
                    "remediation_background", "Review the issue in Burp"
                ),
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target,
            ))

        self.findings = findings
        return findings

    def run(self, timeout: int = 300, configuration: Optional[str] = None) -> List[Finding]:
        """Start a scan, wait for it, and return its issues as Findings."""
        if not BURP_AVAILABLE:
            print('[!] Burp integration requires: pip install "phantomprobe[burp]"')
            return []

        print(f"[*] Connecting to Burp at {self.api_url}...")
        if not self.is_burp_running():
            print("[!] Burp did not answer. Check that:")
            print("    - Burp Professional is running")
            print("    - Settings > Suite > REST API has the service enabled")
            print("    - BURP_API_KEY matches a key created there")
            print(f"    - the service is at {self.api_url} (override: BURP_API_URL)")
            return []

        print("[+] Burp connected")
        if not self.start_scan(configuration=configuration):
            return []

        scan = self.wait_for_scan(timeout=timeout)
        findings = self.issues_to_findings(scan)
        print(f"[+] Burp reported {len(findings)} issues")
        return findings

    @staticmethod
    def generate_extension_template(output_path: str = "burp_extension.py") -> str:
        """
        Write a starter Burp extension.

        Burp runs Python extensions on Jython 2.7, so the template stays inside
        that dialect: no f-strings, and urllib2 rather than urllib.request.
        """
        template = '''# -*- coding: utf-8 -*-
"""
PhantomProbe Burp extension (starter).

Burp runs Python extensions on Jython 2.7, so this file is Python 2 syntax.
Install: Extensions > Installed > Add > Extension type: Python > this file.
"""

from burp import IBurpExtender, IScannerCheck, IScanIssue


class BurpExtender(IBurpExtender, IScannerCheck):
    NAME = "PhantomProbe Integration"
    VERSION = "%s"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.NAME)
        callbacks.registerScannerCheck(self)
        print("[+] %%s v%%s loaded" %% (self.NAME, self.VERSION))

    def doPassiveScan(self, baseRequestResponse):
        return []

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0


class PhantomProbeIssue(IScanIssue):
    def __init__(self, url, name, severity, confidence, detail, remediation):
        self._url = url
        self._name = name
        self._severity = severity
        self._confidence = confidence
        self._detail = detail
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getHttpMessages(self):
        return []

    def getHttpService(self):
        return None
''' % __version__

        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(template)

        print(f"[+] Burp extension template written: {output_path}")
        return output_path
