#!/usr/bin/env python3
"""
CVE correlation: from what a scan saw to the vulnerabilities that matter.

Reads versions out of banners and script URLs, asks NVD about each (nvd.py),
adds real-world exploitation data from CISA KEV and EPSS, and ranks the result.
The vendor:product tables it looks technologies up in are in cpe_tables.py.
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from . import cpe_tables
from .constants import USER_AGENT
from .http_client import safe_urlopen
from .models import Finding
from .nvd import CVE, NvdClient


class CVEMatcher(NvdClient):
    """Match findings to known CVEs via NVD API"""

    CVE_API_BASE = "https://cveawg.mitre.org/api/cve"
    # Free, keyless exploitation-intelligence feeds.
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"
    # EPSS takes a comma-separated cve= list; keep each request's URL sane.
    EPSS_BATCH = 80

    # The tables live in cpe_tables.py. They stay reachable here because the
    # audit script and the tests address them through the matcher.
    CPE_MAPPING = cpe_tables.CPE_MAPPING
    CPE_SIBLINGS = cpe_tables.CPE_SIBLINGS
    CLIENT_SIDE_TECH = cpe_tables.CLIENT_SIDE_TECH
    TECH_ALIASES = cpe_tables.TECH_ALIASES

    SCRIPT_ASSET_CATEGORY = 'Script Assets'
    PORT_CATEGORY = 'Port Scan'
    SEARCHED_CATEGORIES = frozenset({
        'Information Disclosure', 'Technology', 'SSL/TLS',
        'JavaScript Analysis', SCRIPT_ASSET_CATEGORY, PORT_CATEGORY,
    })

    # Signs that a version string comes from a distribution's package. A
    # distribution fixes a vulnerability by patching the release it ships and
    # keeps the upstream version number, so "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    # can be fully patched and still match every CVE filed against 8.9. A
    # match made on such a banner is reported with that caution attached.
    DISTRIBUTION_MARKERS = (
        ('Ubuntu', r'ubuntu'),
        ('Debian', r'debian|raspbian|deb\d+u\d+'),
        ('Red Hat family', r'red ?hat|rhel|centos|rocky|almalinux|\.el\d'),
        ('SUSE', r'suse|sles'),
        ('Fedora', r'fedora'),
        ('Amazon Linux', r'amzn|amazon linux'),
        ('Alpine', r'alpine'),
        ('FreeBSD', r'freebsd'),
    )

    # A CVE is reported when it scores at least this, or when CISA lists it
    # as exploited whatever it scores.
    MIN_CVSS = 7.0

    def __init__(self, api_key: Optional[str] = None, results_per_page: int = 100):
        super().__init__(api_key=api_key, results_per_page=results_per_page)
        self.cache: Dict[str, List[CVE]] = {}
        self._kev_cache: Optional[Dict[str, bool]] = None

    # A product name followed by a version, the way a banner or an asset path
    # writes it: "nginx/1.24.0", "PHP/8.2.29", "jquery-3.6.0.min.js",
    # "react@18.2.0". Guarding only against a trailing digit keeps the
    # ".min.js" suffix from hiding the version, which it previously did.
    #
    # The name must not sit inside a longer word or a hostname. Unanchored,
    # "java" matched the "java" in "/api/javascript/bundle.js" and "python"
    # matched the host "python.example.com", so a site that merely served
    # JavaScript was credited with Oracle JDK vulnerabilities.
    #
    # A single trailing letter is part of the version when nothing but a
    # separator follows it: OpenSSL 1.1.1w and ProFTPD 1.3.5e are releases,
    # and NVD compares them as such. Dropping the letter asked about the first
    # release of the line instead, which returned 63 CVEs for OpenSSL 1.1.1
    # where 1.1.1w has 33. The "p1" of OpenSSH_8.9p1 is not taken, because a
    # digit follows the letter.
    _VERSION_RE = re.compile(
        r"(?<![\w.])(" + "|".join(
            sorted((re.escape(a) for a in TECH_ALIASES), key=len, reverse=True)
        ) + r")[/@ _(-]v?(\d+(?:\.\d+)+(?:[a-z](?![a-z0-9]))?)(?!\d)",
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
            alias, version = match.group(1).lower(), match.group(2).lower()
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
        return self._cpe_string(mapping['vendor'], mapping['product'], version)

    @staticmethod
    def _cpe_string(vendor: str, product: str, version: Optional[str] = None) -> str:
        cpe = f"cpe:2.3:a:{vendor}:{product}"
        if version:
            cpe += f":{version}"
        return cpe

    def build_cpes(self, tech: str, version: Optional[str] = None) -> List[str]:
        """
        Every match string to query for a technology.

        The primary mapping comes first, then any further identifiers NVD
        files the same software under (see CPE_SIBLINGS).
        """
        primary = self.build_cpe(tech, version)
        if primary is None:
            return []
        return [primary] + [
            self._cpe_string(sibling['vendor'], sibling['product'], version)
            for sibling in self.CPE_SIBLINGS.get(tech, [])
        ]

    def query_product(self, tech: str, version: Optional[str] = None) -> List[CVE]:
        """
        CVEs for a technology across every identifier NVD files it under.

        A CVE listed under two identifiers is kept once, in the order found.
        """
        merged: Dict[str, CVE] = {}
        for cpe in self.build_cpes(tech, version):
            for cve in self.query_nvd(cpe, tech, version):
                merged.setdefault(cve.cve_id, cve)
        return list(merged.values())

    def _load_kev(self) -> Optional[Dict[str, bool]]:
        """
        Fetch CISA's Known Exploited Vulnerabilities catalog.

        Returns {cve_id: ransomware_flag}, or None if it could not be fetched.
        One request covers every CVE, so it is fetched once and cached.
        """
        if self._kev_cache is not None:
            return self._kev_cache
        try:
            req = Request(self.KEV_URL, headers={"User-Agent": USER_AGENT})
            with safe_urlopen(req, timeout=self.session_timeout * 3) as response:
                data = json.loads(response.read().decode())
        except (HTTPError, URLError, json.JSONDecodeError, OSError) as exc:
            print(f"    [!] Could not fetch the CISA KEV catalog: {exc}")
            return None

        self._kev_cache = {
            entry.get("cveID", ""): entry.get("knownRansomwareCampaignUse") == "Known"
            for entry in data.get("vulnerabilities", [])
        }
        return self._kev_cache

    def _load_epss(self, cve_ids: List[str]) -> Dict[str, Tuple[float, float]]:
        """Batch-query EPSS scores, returning {cve_id: (score, percentile)}."""
        scores: Dict[str, Tuple[float, float]] = {}
        for start in range(0, len(cve_ids), self.EPSS_BATCH):
            batch = cve_ids[start:start + self.EPSS_BATCH]
            url = f"{self.EPSS_URL}?{urlencode({'cve': ','.join(batch)})}"
            try:
                req = Request(url, headers={"User-Agent": USER_AGENT})
                with safe_urlopen(req, timeout=self.session_timeout) as response:
                    data = json.loads(response.read().decode())
            except (HTTPError, URLError, json.JSONDecodeError, OSError) as exc:
                print(f"    [!] Could not fetch EPSS scores: {exc}")
                continue
            for row in data.get("data", []):
                try:
                    scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
                except (KeyError, ValueError, TypeError):
                    continue
        return scores

    def enrich_exploitation(self, matched: List[Dict]) -> List[Dict]:
        """
        Annotate matched CVEs with KEV membership and EPSS scores.

        A CVSS score says how bad a vulnerability is in theory; these say
        whether anyone is actually using it. Both feeds are free and keyless,
        and both fail soft: on a network error the CVEs keep their base scores.
        """
        if not matched:
            return matched

        cves = [item["cve"] for item in matched]
        print("[*] Enriching CVEs with exploitation data (CISA KEV, EPSS)...")

        kev = self._load_kev()
        if kev is not None:
            for cve in cves:
                if cve.cve_id in kev:
                    cve.in_kev = True
                    cve.kev_ransomware = kev[cve.cve_id]

        # One CVE can match two technologies; ask EPSS about it once.
        epss = self._load_epss(sorted({c.cve_id for c in cves}))
        for cve in cves:
            if cve.cve_id in epss:
                cve.epss_score, cve.epss_percentile = epss[cve.cve_id]

        in_kev = sum(1 for c in cves if c.in_kev)
        print(f"[+] Exploitation data: {in_kev} in CISA KEV, "
              f"{sum(1 for c in cves if c.epss_score is not None)} scored by EPSS")
        return matched

    @staticmethod
    def _priority(item: Dict) -> Tuple:
        """
        Rank key: actively exploited first, then likely, then severe.

        A CVE in KEV is being used right now, so it outranks a higher-CVSS one
        that never has been; EPSS breaks ties below that.
        """
        cve = item["cve"]
        return (cve.in_kev, cve.epss_score or 0.0, cve.cvss_score)

    @classmethod
    def _is_relevant(cls, cve: CVE) -> bool:
        """High or critical by score, or exploited in the wild at any score."""
        return cve.cvss_score >= cls.MIN_CVSS or cve.in_kev

    @classmethod
    def distribution_named(cls, text: str) -> Optional[str]:
        """The distribution a banner says it was packaged by, if it says so."""
        for name, pattern in cls.DISTRIBUTION_MARKERS:
            if re.search(pattern, text or "", re.IGNORECASE):
                return name
        return None

    def _searchable_lines(self, finding: Finding) -> List[str]:
        """
        The lines of a finding's evidence worth reading for a product name.

        A port finding names its service by port number ("Port 3306/MySQL"),
        which is an assumption, not something the target said. Only the banner
        the service actually sent is read.
        """
        lines = (finding.evidence or "").splitlines()
        if finding.category == self.PORT_CATEGORY:
            return [line for line in lines if line.startswith("Banner: ")]
        return lines

    def match_findings(self, findings: List[Finding]) -> List[Dict]:
        """Match findings to CVEs and return enriched findings"""
        candidates = []
        tech_versions = {}
        # Technology to the distribution its version string named, if any.
        packaged_by: Dict[str, Optional[str]] = {}

        print("[*] Matching findings to CVE database...")

        # Extract all technologies from findings, a line at a time so each
        # version stays tied to the banner it was read from.
        unversioned = set()
        for finding in findings:
            if finding.category not in self.SEARCHED_CATEGORIES:
                continue
            for line in self._searchable_lines(finding):
                versioned = self.extract_tech_version(line)
                bare = self.extract_unversioned(line)
                if finding.category == self.SCRIPT_ASSET_CATEGORY:
                    versioned = [(t, v) for t, v in versioned
                                 if t in self.CLIENT_SIDE_TECH]
                    bare = [t for t in bare if t in self.CLIENT_SIDE_TECH]
                for tech, version in versioned:
                    if tech not in tech_versions:
                        tech_versions[tech] = version
                        packaged_by[tech] = self.distribution_named(line)
                unversioned.update(bare)

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
            if tech not in self.CPE_MAPPING:
                continue

            # Check cache first
            cache_key = f"{tech}:{version or 'any'}"
            if cache_key in self.cache:
                cves = self.cache[cache_key]
            else:
                print(f"    - Querying CVEs for {tech} {version or '(any version)'}...")
                cves = self.query_product(tech, version)
                self.cache[cache_key] = cves

            for cve in cves:
                candidates.append({
                    'technology': tech,
                    'version': version,
                    'cve': cve,
                    'distribution': packaged_by.get(tech),
                })

        # Exploitation data comes before the severity cut, because the cut
        # depends on it. Cutting at CVSS 7.0 first threw away exploited CVEs
        # that score lower before KEV was ever consulted: the jQuery XSS
        # CVE-2020-11023 scores 6.1 to 6.9 and has been in KEV since 2025.
        self.enrich_exploitation(candidates)
        matched = [item for item in candidates if self._is_relevant(item['cve'])]
        matched.sort(key=self._priority, reverse=True)

        print(f"[+] Found {len(matched)} relevant CVEs (CVSS >= {self.MIN_CVSS} "
              f"or in CISA KEV) among {len(candidates)} matching the detected versions")
        return matched

    def generate_cve_report(self, matched: List[Dict]) -> str:
        """Generate CVE report section"""
        if not matched:
            return ""

        lines = []
        lines.append("\n## CVE Correlation\n")
        # A version match is not a confirmed vulnerability, and the report
        # should not read as though it were.
        lines.append(
            "Each match below is made on the version a service reports. A "
            "distribution can fix a vulnerability without changing that "
            "version, so treat a match as a lead to confirm, not as a finding."
        )
        lines.append("")

        for item in matched[:20]:  # Limit to top 20
            cve = item['cve']
            tech = item['technology']
            version = item['version'] or 'any'

            kev_tag = " [KEV: actively exploited]" if cve.in_kev else ""
            lines.append(f"### {cve.cve_id}{kev_tag}")
            lines.append(f"")
            lines.append(f"**Technology:** {tech} ({version})")
            if item.get('distribution'):
                lines.append(
                    f"**Caution:** the version was read from a "
                    f"{item['distribution']} build, which may already carry "
                    f"the fix."
                )
            lines.append(f"**CVSS Score:** {cve.cvss_score} ({cve.severity})")
            if cve.in_kev:
                ransom = ", linked to ransomware" if cve.kev_ransomware else ""
                lines.append(f"**Exploitation:** In CISA KEV{ransom}")
            if cve.epss_score is not None:
                pct = f"{cve.epss_percentile * 100:.0f}th percentile"
                lines.append(f"**EPSS:** {cve.epss_score:.4f} ({pct})")
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
