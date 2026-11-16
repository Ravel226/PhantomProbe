#!/usr/bin/env python3
"""
NVD API client: one match string in, the CVEs that match it out.

Set NVD_API_KEY to raise NVD's rate limit from 5 to 50 requests per 30s window;
without a key the client self-throttles to stay under the anonymous limit.

Everything here is about asking NVD and reading its answer. Deciding what to
ask for, and what the answers mean for a target, is cve.py.
"""

import json
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request

from .constants import USER_AGENT
from .http_client import safe_urlopen


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
    # Exploitation context, filled in by enrich_exploitation(). in_kev means
    # CISA has recorded this CVE as exploited in the wild, which outranks a
    # higher CVSS that has never been used. epss_score is the probability of
    # exploitation in the next 30 days (0..1).
    in_kev: bool = False
    kev_ransomware: bool = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None


class NvdClient:
    """Query the NVD CVE API, following pages and riding out a busy service."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # NVD allows 5 requests / 30s anonymously, 50 / 30s with an API key.
    # Spacing requests is simpler than a sliding window and stays well clear.
    ANON_REQUEST_INTERVAL = 6.5
    KEYED_REQUEST_INTERVAL = 0.7

    # NVD answers 503 when it is busy, often enough to see it several times in
    # a session, and 429 when asked too fast. It also stalls until the read
    # times out. All three pass; a product must not look clean because one
    # request landed at a bad moment.
    RETRY_STATUSES = (429, 503)
    RETRY_DELAYS = (5, 15)

    # NVD returns results oldest first, so a single short page holds the CVEs
    # least likely to matter and drops the recent ones. Pages are followed to
    # the end, up to this many results per identifier.
    MAX_RESULTS = 1000

    def __init__(self, api_key: Optional[str] = None, results_per_page: int = 100):
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

    def _pause(self, seconds: float) -> None:
        """Wait before retrying a busy NVD. Separate so tests can skip it."""
        time.sleep(seconds)

    def _fetch_nvd_page(self, cpe: str, start_index: int = 0) -> dict:
        """
        Fetch one page of results for a match string.

        cpeName= requires an exact CPE match, which almost never hits for a
        banner-derived version. virtualMatchString matches the whole CPE
        subtree and still applies each CVE's version ranges: asking for a
        release that was never made (nginx 1.24.99) returned exactly the CVEs
        whose ranges cover that number.
        """
        url = (
            f"{self.NVD_API_BASE}?virtualMatchString={quote(cpe)}"
            f"&resultsPerPage={self.results_per_page}"
        )
        if start_index:
            url += f"&startIndex={start_index}"

        headers = {'User-Agent': USER_AGENT}
        # An API key raises NVD's limit from 5 to 50 requests / 30s.
        if self.api_key:
            headers['apiKey'] = self.api_key

        for delay in self.RETRY_DELAYS + (None,):
            self._throttle()
            try:
                # A full page can run past a megabyte, so allow it longer than
                # the small exploitation-feed lookups get.
                with safe_urlopen(Request(url, headers=headers),
                                  timeout=self.session_timeout * 3) as response:
                    return json.loads(response.read().decode())
            except HTTPError as exc:
                if exc.code not in self.RETRY_STATUSES or delay is None:
                    raise
                reason = f"HTTP {exc.code}"
            except URLError as exc:
                # Only a timeout is worth another try; a refused connection or
                # a failed lookup will fail the same way a moment later.
                if not isinstance(exc.reason, self._TIMEOUTS) or delay is None:
                    raise
                reason = "timed out"
            except self._TIMEOUTS:
                # NVD also stalls part-way through a body. That is not a
                # URLError, and on a live run it cost a whole identifier.
                if delay is None:
                    raise
                reason = "timed out"
            print(f"    [*] NVD {reason}, trying again in {delay}s")
            self._pause(delay)
        return {}

    # socket.timeout only became an alias of TimeoutError in Python 3.10.
    _TIMEOUTS = (socket.timeout, TimeoutError)

    @staticmethod
    def _parse_cve(cve_data: dict, cpe: str) -> CVE:
        """Turn one NVD record into a CVE, reading only the product asked about."""
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

        descriptions = cve_data.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

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

        return CVE(
            cve_id=cve_data.get('id', ''),
            severity=severity,
            cvss_score=cvss_score,
            description=description[:500] if description else '',
            affected_versions=affected[:5],
            fix_versions=fix_versions[:3],
            references=[r.get('url', '') for r in cve_data.get('references', [])[:5]],
            published=cve_data.get('published', ''),
            modified=cve_data.get('lastModified', ''),
        )

    def query_nvd(self, cpe: str, tech: str, version: Optional[str] = None) -> List[CVE]:
        """
        Query NVD for every CVE matching one match string.

        Pages are followed until NVD has no more. On an error part-way, what
        was already read is returned and the error is printed, so a failure
        costs the remainder rather than the whole product.
        """
        cves: List[CVE] = []

        try:
            start = 0
            while True:
                data = self._fetch_nvd_page(cpe, start)
                page = data.get('vulnerabilities', [])
                for item in page:
                    cves.append(self._parse_cve(item.get('cve', {}), cpe))

                start += len(page)
                total = data.get('totalResults', start)
                if not page or start >= total:
                    break
                if start >= self.MAX_RESULTS:
                    # Say so: NVD sorts oldest first, so what is cut off here
                    # is the recent end of the list.
                    print(f"    [!] {tech}: read the first {start} of {total} "
                          f"CVEs, the newest are not included")
                    break

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
        except OSError as e:
            # A timeout while reading the body is not a URLError, and used to
            # escape and end the scan.
            print(f"    [!] Connection to NVD failed for {tech}: {e}")

        return cves
