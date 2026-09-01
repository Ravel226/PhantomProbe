#!/usr/bin/env python3
"""
CVE correlation against the NVD API.

Set NVD_API_KEY to raise NVD's rate limit from 5 to 50 requests per 30s window;
without a key the client self-throttles to stay under the anonymous limit.
"""

import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request

from .http_client import safe_urlopen

from .constants import USER_AGENT
from .models import Finding


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

    # NVD allows 5 requests / 30s anonymously, 50 / 30s with an API key.
    # Spacing requests is simpler than a sliding window and stays well clear.
    ANON_REQUEST_INTERVAL = 6.5
    KEYED_REQUEST_INTERVAL = 0.7

    def __init__(self, api_key: Optional[str] = None, results_per_page: int = 20):
        self.cache: Dict[str, List[CVE]] = {}
        self.session_timeout = 10
        self.api_key = api_key or os.environ.get('NVD_API_KEY', '') or None
        self.results_per_page = results_per_page
        self._request_interval = (
            self.KEYED_REQUEST_INTERVAL if self.api_key else self.ANON_REQUEST_INTERVAL
        )
        self._last_request_at = 0.0
        self._throttle_lock = threading.Lock()

    def _throttle(self) -> None:
        """Space out NVD requests so we stay under the published rate limit."""
        with self._throttle_lock:
            elapsed = time.monotonic() - self._last_request_at
            wait = self._request_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_request_at = time.monotonic()

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
            # cpeName= requires an exact CPE match, which almost never hits for a
            # banner-derived version. virtualMatchString matches the whole CPE
            # subtree, which is what banner fingerprinting can actually support.
            url = (
                f"{self.NVD_API_BASE}?virtualMatchString={quote(cpe)}"
                f"&resultsPerPage={self.results_per_page}"
            )

            headers = {'User-Agent': USER_AGENT}
            # An API key raises NVD's limit from 5 to 50 requests / 30s.
            if self.api_key:
                headers['apiKey'] = self.api_key
            req = Request(url, headers=headers)

            self._throttle()
            with safe_urlopen(req, timeout=self.session_timeout) as response:
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

        except HTTPError as e:
            if e.code == 403:
                print(f"    [!] NVD rejected the request for {tech} (HTTP 403). "
                      f"Set NVD_API_KEY to raise the rate limit.")
            elif e.code == 404:
                print(f"    [!] No NVD entry for {tech} {version or '(any version)'}")
            else:
                print(f"    [!] NVD HTTP {e.code} for {tech}: {e.reason}")
        except URLError as e:
            print(f"    [!] Could not reach NVD for {tech}: {e.reason}")
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"    [!] Malformed NVD response for {tech}: {e}")

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
        if not self.api_key:
            print("[*] No NVD_API_KEY set - throttling to the anonymous rate limit "
                  f"(~{self.ANON_REQUEST_INTERVAL:.0f}s between queries)")

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

