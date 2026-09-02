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
        # NVD files modern nginx CVEs under f5, which acquired it:
        # nginx:nginx returns 2 results where f5:nginx returns 41.
        'nginx': {'vendor': 'f5', 'product': 'nginx'},
        'apache': {'vendor': 'apache', 'product': 'http_server'},
        'openssl': {'vendor': 'openssl', 'product': 'openssl'},
        'mysql': {'vendor': 'oracle', 'product': 'mysql'},
        'postgresql': {'vendor': 'postgresql', 'product': 'postgresql'},
        'redis': {'vendor': 'redis', 'product': 'redis'},
        'mongodb': {'vendor': 'mongodb', 'product': 'mongodb'},
        'node.js': {'vendor': 'nodejs', 'product': 'node.js'},
        # expressjs:express returns nothing; the CPE is under openjsf.
        'express': {'vendor': 'openjsf', 'product': 'express'},
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

        # Everything below was confirmed against the live NVD API before
        # being added: a vendor guessed wrong returns nothing at all, which
        # is how expressjs:express sat here matching zero CVEs. Vue.js is
        # deliberately absent; NVD has no CPE for it under any spelling.
        'litespeed': {'vendor': 'litespeedtech', 'product': 'litespeed_web_server'},
        'openresty': {'vendor': 'openresty', 'product': 'openresty'},
        'lighttpd': {'vendor': 'lighttpd', 'product': 'lighttpd'},
        'caddy': {'vendor': 'caddyserver', 'product': 'caddy'},
        'haproxy': {'vendor': 'haproxy', 'product': 'haproxy'},
        'traefik': {'vendor': 'traefik', 'product': 'traefik'},
        'envoy': {'vendor': 'envoyproxy', 'product': 'envoy'},
        'varnish': {'vendor': 'varnish_cache_project', 'product': 'varnish_cache'},
        'jetty': {'vendor': 'eclipse', 'product': 'jetty'},
        'gunicorn': {'vendor': 'gunicorn', 'product': 'gunicorn'},
        'werkzeug': {'vendor': 'palletsprojects', 'product': 'werkzeug'},
        'tornado': {'vendor': 'tornadoweb', 'product': 'tornado'},
        'asp.net core': {'vendor': 'microsoft', 'product': 'asp.net_core'},
        'laravel': {'vendor': 'laravel', 'product': 'laravel'},
        'rails': {'vendor': 'rubyonrails', 'product': 'rails'},
        'spring': {'vendor': 'vmware', 'product': 'spring_framework'},
        'struts': {'vendor': 'apache', 'product': 'struts'},
        'symfony': {'vendor': 'sensiolabs', 'product': 'symfony'},
        'fastapi': {'vendor': 'tiangolo', 'product': 'fastapi'},
        'next.js': {'vendor': 'vercel', 'product': 'next.js'},
        'nuxt': {'vendor': 'nuxt', 'product': 'nuxt'},
        'angular': {'vendor': 'angular', 'product': 'angular'},
        'react': {'vendor': 'facebook', 'product': 'react'},
        'jquery': {'vendor': 'jquery', 'product': 'jquery'},
        'bootstrap': {'vendor': 'getbootstrap', 'product': 'bootstrap'},
        'magento': {'vendor': 'magento', 'product': 'magento'},
        'typo3': {'vendor': 'typo3', 'product': 'typo3'},
        'ghost': {'vendor': 'ghost', 'product': 'ghost'},
        'mediawiki': {'vendor': 'mediawiki', 'product': 'mediawiki'},
        'moodle': {'vendor': 'moodle', 'product': 'moodle'},
        'phpmyadmin': {'vendor': 'phpmyadmin', 'product': 'phpmyadmin'},
        'confluence': {'vendor': 'atlassian', 'product': 'confluence'},
        'jira': {'vendor': 'atlassian', 'product': 'jira'},
        'jenkins': {'vendor': 'jenkins', 'product': 'jenkins'},
        'gitlab': {'vendor': 'gitlab', 'product': 'gitlab'},
        'grafana': {'vendor': 'grafana', 'product': 'grafana'},
        'elasticsearch': {'vendor': 'elastic', 'product': 'elasticsearch'},
        'kibana': {'vendor': 'elastic', 'product': 'kibana'},
        'mariadb': {'vendor': 'mariadb', 'product': 'mariadb'},
        'memcached': {'vendor': 'memcached', 'product': 'memcached'},
        'rabbitmq': {'vendor': 'pivotal_software', 'product': 'rabbitmq'},
        'openssh': {'vendor': 'openbsd', 'product': 'openssh'},
        'proftpd': {'vendor': 'proftpd', 'product': 'proftpd'},
        'vsftpd': {'vendor': 'vsftpd_project', 'product': 'vsftpd'},
        'postfix': {'vendor': 'postfix', 'product': 'postfix'},
        'exim': {'vendor': 'exim', 'product': 'exim'},
        'dovecot': {'vendor': 'dovecot', 'product': 'dovecot'},
        'samba': {'vendor': 'samba', 'product': 'samba'},
        'bind': {'vendor': 'isc', 'product': 'bind'},
        'docker': {'vendor': 'docker', 'product': 'docker'},
        'kubernetes': {'vendor': 'kubernetes', 'product': 'kubernetes'},
        'golang': {'vendor': 'golang', 'product': 'go'},
        'perl': {'vendor': 'perl', 'product': 'perl'},
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

    # Spellings a banner may use, mapped onto the CPE_MAPPING keys. Without
    # this, "node" was captured but thrown away, because the mapping key is
    # "node.js": Node was never once correlated.
    TECH_ALIASES = {
        "php": "php",
        "nginx": "nginx",
        "apache": "apache",
        "httpd": "apache",
        "openssl": "openssl",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "postgres": "postgresql",
        "redis": "redis",
        "mongodb": "mongodb",
        "tomcat": "tomcat",
        "iis": "iis",
        "node.js": "node.js",
        "nodejs": "node.js",
        "node": "node.js",
        "express": "express",
        "django": "django",
        "flask": "flask",
        "wordpress": "wordpress",
        "drupal": "drupal",
        "joomla": "joomla",
        "python": "python",
        "ruby": "ruby",
        "java": "java",
        "asp.net": "dotnet",
        "dotnet": "dotnet",
        "litespeed": "litespeed",
        "openresty": "openresty",
        "lighttpd": "lighttpd",
        "caddy": "caddy",
        "haproxy": "haproxy",
        "traefik": "traefik",
        "envoy": "envoy",
        "varnish": "varnish",
        "jetty": "jetty",
        "gunicorn": "gunicorn",
        "werkzeug": "werkzeug",
        "tornado": "tornado",
        "asp.net core": "asp.net core",
        "kestrel": "asp.net core",
        "laravel": "laravel",
        "rails": "rails",
        "spring": "spring",
        "struts": "struts",
        "symfony": "symfony",
        "fastapi": "fastapi",
        "next.js": "next.js",
        "nextjs": "next.js",
        "nuxt": "nuxt",
        "nuxt.js": "nuxt",
        "angular": "angular",
        "react": "react",
        "jquery": "jquery",
        "bootstrap": "bootstrap",
        "magento": "magento",
        "typo3": "typo3",
        "ghost": "ghost",
        "mediawiki": "mediawiki",
        "moodle": "moodle",
        "phpmyadmin": "phpmyadmin",
        "confluence": "confluence",
        "jira": "jira",
        "jenkins": "jenkins",
        "gitlab": "gitlab",
        "grafana": "grafana",
        "elasticsearch": "elasticsearch",
        "kibana": "kibana",
        "mariadb": "mariadb",
        "memcached": "memcached",
        "rabbitmq": "rabbitmq",
        "openssh": "openssh",
        "proftpd": "proftpd",
        "vsftpd": "vsftpd",
        "postfix": "postfix",
        "exim": "exim",
        "dovecot": "dovecot",
        "samba": "samba",
        "bind": "bind",
        "docker": "docker",
        "kubernetes": "kubernetes",
        "k8s": "kubernetes",
        "golang": "golang",
        "perl": "perl",
    }

    # A product name followed by a version, the way a banner or an asset path
    # writes it: "nginx/1.24.0", "PHP/8.2.29", "jquery-3.6.0.min.js",
    # "react@18.2.0". Guarding only against a trailing digit keeps the
    # ".min.js" suffix from hiding the version, which it previously did.
    #
    # The name must not sit inside a longer word or a hostname. Unanchored,
    # "java" matched the "java" in "/api/javascript/bundle.js" and "python"
    # matched the host "python.example.com", so a site that merely served
    # JavaScript was credited with Oracle JDK vulnerabilities.
    _VERSION_RE = re.compile(
        r"(?<![\w.])(" + "|".join(
            sorted((re.escape(a) for a in TECH_ALIASES), key=len, reverse=True)
        ) + r")[/@ _(-]v?(\d+(?:\.\d+)+)(?!\d)",
        re.IGNORECASE,
    )

    def extract_tech_version(self, evidence: str) -> List[Tuple[str, str]]:
        """
        Pull (technology, version) pairs out of banner text.

        Only versioned hits are returned. Correlating a bare product name asks
        NVD for every CVE ever filed against it, most of them fixed long before
        the version in front of us, which is noise in a report rather than a
        finding.
        """
        found = {}
        for match in self._VERSION_RE.finditer(evidence or ""):
            alias, version = match.group(1).lower(), match.group(2)
            tech = self.TECH_ALIASES.get(alias)
            if tech in self.CPE_MAPPING:
                found.setdefault(tech, version)
        return sorted(found.items())

    def extract_unversioned(self, evidence: str) -> List[str]:
        """Products named without a version, so the report can say what it skipped."""
        names = "|".join(
            sorted((re.escape(a) for a in self.TECH_ALIASES), key=len, reverse=True)
        )
        seen = set()
        for match in re.finditer(
            r"(?<![\w.-])(" + names + r")(?![\w.-])", evidence or "", re.IGNORECASE
        ):
            tech = self.TECH_ALIASES.get(match.group(1).lower())
            if tech in self.CPE_MAPPING:
                seen.add(tech)
        return sorted(seen - {t for t, _ in self.extract_tech_version(evidence)})

    def build_cpe(self, tech: str, version: Optional[str] = None) -> Optional[str]:
        """
        Build the CPE match string NVD's virtualMatchString actually accepts.

        Padding the string out to all thirteen components makes NVD return
        nothing: cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:* scores 0 results where
        cpe:2.3:a:f5:nginx:1.24.0 scores 2, and the unpadded vendor:product
        form scores 41. So stop at the last component we actually know.
        """
        if tech not in self.CPE_MAPPING:
            return None

        mapping = self.CPE_MAPPING[tech]
        cpe = f"cpe:2.3:a:{mapping['vendor']}:{mapping['product']}"
        if version:
            cpe += f":{version}"
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

                # Newest scoring first. v4.0 exists on recent CVEs and was not
                # handled, so those scored 0.0 and were filtered out as if clean.
                for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'):
                    if metrics.get(key):
                        cvss_data = metrics[key][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        break
                else:
                    if metrics.get('cvssMetricV2'):
                        entry = metrics['cvssMetricV2'][0]
                        cvss_score = entry.get('cvssData', {}).get('baseScore', 0.0)
                        # v2 carries baseSeverity on the entry, not in cvssData.
                        severity = entry.get('baseSeverity') or (
                            'HIGH' if cvss_score >= 7.0
                            else 'MEDIUM' if cvss_score >= 4.0 else 'LOW'
                        )

                # Extract description
                descriptions = cve_data.get('descriptions', [])
                description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

                # Extract affected versions
                affected = []
                fix_versions = []

                # A single CVE often lists many products. Keep only the entries
                # for the product we asked about, or nginx inherits the fixed
                # versions of everything else caught by the same advisory.
                product_prefix = ":".join(cpe.split(":")[:5]) + ":"
                for config in cve_data.get('configurations', []):
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):
                            criteria = cpe_match.get('criteria', '')
                            if not cpe_match.get('vulnerable'):
                                continue
                            if not criteria.startswith(product_prefix):
                                continue
                            affected.append(criteria)
                            # versionEndExcluding is the first fixed release;
                            # versionEndIncluding is the last vulnerable one.
                            fixed = cpe_match.get('versionEndExcluding')
                            if fixed and fixed not in fix_versions:
                                fix_versions.append(fixed)

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
        unversioned = set()
        for finding in findings:
            if finding.category in ('Information Disclosure', 'Technology',
                                    'SSL/TLS', 'JavaScript Analysis'):
                for tech, version in self.extract_tech_version(finding.evidence):
                    tech_versions.setdefault(tech, version)
                unversioned.update(self.extract_unversioned(finding.evidence))

        # Say what was seen but not usable, rather than quietly dropping it.
        skipped = sorted(unversioned - set(tech_versions))
        if skipped:
            print(f"[*] Seen without a version, so not correlated: {', '.join(skipped)}")

        if not tech_versions:
            print("[+] No versioned technologies found for CVE matching")
            return []

        print(f"[*] Found {len(tech_versions)} versioned technologies to check for CVEs")
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

