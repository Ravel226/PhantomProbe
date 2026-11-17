"""
Unit tests for CVE correlation.

No test here touches the network: query_nvd is exercised through a stubbed
urlopen so the rate-limit and error-handling paths stay verifiable offline.
"""
import json
from urllib.error import HTTPError, URLError

import pytest

import phantomprobe.cve as cve_module
from phantomprobe.cve import CVEMatcher


@pytest.fixture
def matcher(monkeypatch):
    """A matcher with no API key and throttling disabled for speed."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    m = CVEMatcher()
    monkeypatch.setattr(m, "_throttle", lambda: None)
    return m


# --- API key handling --------------------------------------------------------

def test_api_key_read_from_environment(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret-key")

    assert CVEMatcher().api_key == "secret-key"


def test_explicit_api_key_wins(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "from-env")

    assert CVEMatcher(api_key="explicit").api_key == "explicit"


def test_no_api_key_uses_slower_interval(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    anon = CVEMatcher()

    monkeypatch.setenv("NVD_API_KEY", "k")
    keyed = CVEMatcher()

    assert anon._request_interval > keyed._request_interval


def test_api_key_is_sent_as_header(monkeypatch):
    """NVD expects the key in an apiKey header, not a query parameter."""
    monkeypatch.setenv("NVD_API_KEY", "secret-key")
    m = CVEMatcher()
    monkeypatch.setattr(m, "_throttle", lambda: None)

    captured = {}

    def fake_urlopen(req, timeout=None, context=None):
        captured["headers"] = req.headers
        captured["url"] = req.full_url
        raise URLError("stop here")

    monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", fake_urlopen)
    m.query_nvd("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*", "nginx", "1.0")

    # urllib capitalizes header names.
    assert captured["headers"].get("Apikey") == "secret-key"
    assert "secret-key" not in captured["url"]


# --- CPE construction --------------------------------------------------------

def test_build_cpe_with_version_is_not_padded():
    """
    Checked against live NVD: the padded thirteen-component form returns 0
    results, the unpadded one returns 2, and vendor:product alone returns 41.
    """
    cpe = CVEMatcher().build_cpe("nginx", "1.24.0")

    assert cpe == "cpe:2.3:a:f5:nginx:1.24.0"
    assert not cpe.endswith(":*")


def test_build_cpe_without_version_stops_at_the_product():
    assert CVEMatcher().build_cpe("nginx") == "cpe:2.3:a:f5:nginx"


def test_vendor_mappings_corrected_against_nvd():
    """
    Both of these returned almost nothing before: nginx CVEs are filed under
    f5, and expressjs:express does not exist as a CPE at all.
    """
    mapping = CVEMatcher.CPE_MAPPING
    assert mapping["nginx"] == {"vendor": "f5", "product": "nginx"}
    assert mapping["express"] == {"vendor": "openjsf", "product": "express"}


def test_build_cpe_unknown_technology_returns_none():
    assert CVEMatcher().build_cpe("not-a-real-tech") is None


def test_query_uses_virtual_match_string(matcher, monkeypatch):
    """
    cpeName= requires an exact match and almost never hits on a banner-derived
    version; virtualMatchString matches the CPE subtree instead.
    """
    captured = {}

    def fake_urlopen(req, timeout=None, context=None):
        captured["url"] = req.full_url
        raise URLError("stop here")

    monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", fake_urlopen)
    matcher.query_nvd("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*", "nginx", "1.0")

    assert "virtualMatchString=" in captured["url"]
    assert "cpeName=" not in captured["url"]


# --- Version extraction ------------------------------------------------------

def test_extract_tech_version_from_server_banner():
    found = CVEMatcher().extract_tech_version("Server: nginx/1.24.0")

    assert ("nginx", "1.24.0") in found


def test_extract_tech_version_from_powered_by():
    found = CVEMatcher().extract_tech_version("X-Powered-By: PHP/8.2.29")

    assert any(tech == "php" for tech, _ in found)


# --- Response parsing --------------------------------------------------------

def _nvd_payload(cve_id="CVE-2024-0001", score=9.8, severity="CRITICAL"):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score, "baseSeverity": severity}}
                        ]
                    },
                    "descriptions": [{"lang": "en", "value": "A test vulnerability"}],
                    "references": [{"url": "https://example.com/advisory"}],
                    "published": "2024-01-01T00:00:00",
                    "lastModified": "2024-01-02T00:00:00",
                }
            }
        ]
    }


class _FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_query_nvd_parses_cvss_v31(matcher, monkeypatch):
    monkeypatch.setattr(
        "phantomprobe.nvd.safe_urlopen",
        lambda req, timeout=None, context=None: _FakeResponse(_nvd_payload()),
    )

    cves = matcher.query_nvd("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*", "nginx", "1.0")

    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2024-0001"
    assert cves[0].cvss_score == 9.8
    assert cves[0].severity == "CRITICAL"


# --- Error handling ----------------------------------------------------------

def test_rate_limit_error_is_reported_not_swallowed(matcher, monkeypatch, capsys):
    """A 403 used to vanish silently, making --cve look like 'no CVEs found'."""
    def raise_403(req, timeout=None):
        raise HTTPError(req.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", raise_403)
    cves = matcher.query_nvd("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*", "nginx", "1.0")

    assert cves == []
    assert "NVD_API_KEY" in capsys.readouterr().out


def test_network_error_is_reported(matcher, monkeypatch, capsys):
    monkeypatch.setattr(
        "phantomprobe.nvd.safe_urlopen",
        lambda req, timeout=None, context=None: (_ for _ in ()).throw(URLError("no route")),
    )

    assert matcher.query_nvd("cpe:x", "nginx", "1.0") == []
    assert "Could not reach NVD" in capsys.readouterr().out


def test_malformed_response_is_reported(matcher, monkeypatch, capsys):
    class _BadResponse(_FakeResponse):
        def __init__(self):
            self._payload = b"not json"

    monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", lambda req, timeout=None, context=None: _BadResponse())

    assert matcher.query_nvd("cpe:x", "nginx", "1.0") == []
    assert "Malformed NVD response" in capsys.readouterr().out


# --- Regressions found by checking the client against the live NVD API -------

class TestExtractionPrecision:
    """
    The old patterns were unanchored, so a product name matched inside longer
    words and inside hostnames.
    """

    def test_javascript_is_not_java(self):
        # This credited any site serving JavaScript with Oracle JDK CVEs.
        found = CVEMatcher().extract_tech_version("Endpoint: /api/javascript/bundle.js")
        assert found == []

    def test_hostname_is_not_a_product(self):
        found = CVEMatcher().extract_tech_version("Subject CN: python.example.com")
        assert found == []

    def test_node_aliases_map_onto_the_cpe_key(self):
        """
        "node" was captured and then discarded, because the mapping key is
        "node.js": Node was never correlated once.
        """
        matcher = CVEMatcher()
        for banner in ("node.js/18.16.0", "nodejs/18.16.0", "node/18.16.0"):
            assert matcher.extract_tech_version(banner) == [("node.js", "18.16.0")]

    def test_versionless_products_are_reported_separately(self):
        matcher = CVEMatcher()
        assert matcher.extract_tech_version("Server: Apache") == []
        assert matcher.extract_unversioned("Server: Apache") == ["apache"]

    def test_cipher_strings_are_not_versions(self):
        assert CVEMatcher().extract_tech_version("Cipher: TLS_AES_256_GCM_SHA384") == []


def _payload_with_metrics(metrics, configurations=None):
    return {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en", "value": "Test issue"}],
                "metrics": metrics,
                "configurations": configurations or [],
                "references": [],
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
            }
        }]
    }


def _run_query(matcher, monkeypatch, payload, cpe="cpe:2.3:a:f5:nginx:1.24.0"):
    monkeypatch.setattr("phantomprobe.nvd.safe_urlopen",
                        lambda req, timeout=None: _FakeResponse(payload))
    monkeypatch.setattr(matcher, "_throttle", lambda: None)
    return matcher.query_nvd(cpe, "nginx", "1.24.0")


class TestScoring:
    def test_cvss_v40_is_understood(self, matcher, monkeypatch):
        """
        v4.0 was not handled, so recent CVEs scored 0.0 and were filtered out
        as though the target were clean.
        """
        payload = _payload_with_metrics({
            "cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}]
        })
        found = _run_query(matcher, monkeypatch, payload)
        assert (found[0].cvss_score, found[0].severity) == (9.3, "CRITICAL")

    def test_newer_scoring_wins_over_older(self, matcher, monkeypatch):
        payload = _payload_with_metrics({
            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
        })
        assert _run_query(matcher, monkeypatch, payload)[0].cvss_score == 7.5

    def test_v2_severity_read_from_outside_cvss_data(self, matcher, monkeypatch):
        """NVD puts baseSeverity on the entry for v2, not inside cvssData."""
        payload = _payload_with_metrics({
            "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]
        })
        found = _run_query(matcher, monkeypatch, payload)
        assert (found[0].cvss_score, found[0].severity) == (7.5, "HIGH")

    def test_missing_metrics_do_not_raise(self, matcher, monkeypatch):
        found = _run_query(matcher, monkeypatch, _payload_with_metrics({}))
        assert (found[0].cvss_score, found[0].severity) == (0.0, "UNKNOWN")


class TestFixedVersions:
    CONFIG = [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "1.25.3"},
        # Same advisory, different product: its fixed version is not nginx's.
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "2.4.58"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
    ]}]}]

    def test_fixed_version_comes_from_the_vulnerable_entry(self, matcher, monkeypatch):
        """
        The old code only looked at non-vulnerable entries, so this list was
        always empty.
        """
        payload = _payload_with_metrics(
            {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
            self.CONFIG,
        )
        assert _run_query(matcher, monkeypatch, payload)[0].fix_versions == ["1.25.3"]

    def test_other_products_in_the_same_cve_are_excluded(self, matcher, monkeypatch):
        payload = _payload_with_metrics(
            {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
            self.CONFIG,
        )
        found = _run_query(matcher, monkeypatch, payload)
        assert "2.4.58" not in found[0].fix_versions
        assert all("f5:nginx" in a for a in found[0].affected_versions)


class TestExpandedTable:
    """
    Every vendor/product pair in the table was confirmed against the live NVD
    API before being added. A wrong vendor is silent: it returns a clean 200
    with zero results, which is how expressjs:express matched nothing for as
    long as it sat here.
    """

    def test_table_covers_the_common_stack(self):
        mapping = CVEMatcher.CPE_MAPPING
        for tech in ("nginx", "apache", "php", "openssh", "mariadb", "jenkins",
                     "gitlab", "laravel", "rails", "spring", "jquery", "react",
                     "elasticsearch", "haproxy", "traefik", "kubernetes"):
            assert tech in mapping, f"{tech} missing from CPE_MAPPING"

    def test_verified_vendors_are_not_the_obvious_guess(self):
        """The pairs a reasonable guess would get wrong."""
        mapping = CVEMatcher.CPE_MAPPING
        assert mapping["nginx"]["vendor"] == "f5"
        assert mapping["express"]["vendor"] == "openjsf"
        assert mapping["varnish"]["vendor"] == "varnish_cache_project"
        assert mapping["rabbitmq"]["vendor"] == "pivotal_software"
        assert mapping["vsftpd"]["vendor"] == "vsftpd_project"
        assert mapping["jetty"]["vendor"] == "eclipse"

    def test_vue_is_absent_because_nvd_has_no_cpe_for_it(self):
        """Checked under vuejs:vue.js, vuejs:vue, vuejs:vuejs and vue:vue."""
        assert "vue.js" not in CVEMatcher.CPE_MAPPING

    def test_every_alias_resolves_to_a_real_mapping(self):
        mapping = CVEMatcher.CPE_MAPPING
        unknown = [a for a, t in CVEMatcher.TECH_ALIASES.items() if t not in mapping]
        assert unknown == []

    def test_every_mapping_is_reachable_from_some_alias(self):
        """An entry no banner spelling reaches can never fire."""
        reachable = set(CVEMatcher.TECH_ALIASES.values())
        assert [t for t in CVEMatcher.CPE_MAPPING if t not in reachable] == []


class TestBannerShapes:
    """Real banner and asset-path spellings, one per shape."""

    @pytest.mark.parametrize("text,expected", [
        ("Server: nginx/1.24.0", ("nginx", "1.24.0")),
        ("Server: LiteSpeed/1.7.16", ("litespeed", "1.7.16")),
        ("Server: Jetty(9.4.44)", ("jetty", "9.4.44")),          # parenthesised
        ("SSH-2.0-OpenSSH_8.9", ("openssh", "8.9")),             # underscore, hyphen before
        ("220 ProFTPD 1.3.7 Server", ("proftpd", "1.3.7")),      # space separated
        ("X-Powered-By: ASP.NET/4.8", ("dotnet", "4.8")),
        ("/assets/jquery-3.6.0.min.js", ("jquery", "3.6.0")),    # .min.js suffix
        ("/static/react@18.2.0/umd/react.js", ("react", "18.2.0")),  # npm style
        ("Server: gunicorn/20.1.0", ("gunicorn", "20.1.0")),
    ])
    def test_versioned_banner_is_extracted(self, text, expected):
        assert expected in CVEMatcher().extract_tech_version(text)

    @pytest.mark.parametrize("text", [
        "/api/javascript/bundle.js",     # java inside javascript
        "Subject CN: python.example.com",  # product name inside a hostname
        "myapache/2.4.1",                # product name inside a longer word
        "Cipher: TLS_AES_256_GCM_SHA384",
        "Endpoint: /api/v2/users",
        "Server: Apache-Coyote/1.1",     # Tomcat's connector, not httpd
    ])
    def test_no_false_positive(self, text):
        assert CVEMatcher().extract_tech_version(text) == []

    def test_javascript_findings_are_searched(self):
        """
        Client-side library versions only appear in asset paths, which are
        JavaScript Analysis findings. Leaving that category out made the
        jquery and react entries unreachable.
        """
        from phantomprobe.models import Finding, Severity

        finding = Finding(
            id="JS-1", title="Endpoint", description="",
            severity=Severity.INFORMATIONAL, category="JavaScript Analysis",
            evidence="Endpoint: /assets/jquery-3.6.0.min.js",
            remediation="", references=[], discovered_at="", target="example.com",
        )
        matcher = CVEMatcher()
        queried = []
        matcher.query_nvd = lambda cpe, tech, version=None: queried.append(tech) or []
        matcher.match_findings([finding])
        assert "jquery" in queried


class TestExploitationEnrichment:
    """
    KEV and EPSS say whether a CVE is actually being used, which reorders the
    report: an exploited 7.5 outranks a dormant 9.8. Both feeds are stubbed.
    """

    def _cve(self, cve_id, score):
        return {"technology": "t", "version": "1",
                "cve": cve_module.CVE(cve_id, "HIGH", score, "d", [], [], [], "", "")}

    def test_kev_and_epss_annotate_the_cve(self, matcher, monkeypatch):
        monkeypatch.setattr(matcher, "_load_kev",
                            lambda: {"CVE-2023-44487": False, "CVE-2021-44228": True})
        monkeypatch.setattr(matcher, "_load_epss",
                            lambda ids: {"CVE-2023-44487": (0.97, 0.99)})
        matched = [self._cve("CVE-2023-44487", 7.5), self._cve("CVE-2021-44228", 10.0)]
        matcher.enrich_exploitation(matched)

        a = matched[0]["cve"]
        assert a.in_kev is True and a.kev_ransomware is False
        assert a.epss_score == 0.97 and a.epss_percentile == 0.99
        assert matched[1]["cve"].kev_ransomware is True

    def test_priority_puts_exploited_above_higher_cvss(self, matcher, monkeypatch):
        monkeypatch.setattr(matcher, "_load_kev", lambda: {"CVE-2023-44487": False})
        monkeypatch.setattr(matcher, "_load_epss", lambda ids: {"CVE-2023-44487": (0.99, 0.99)})
        # A KEV 7.5 and a non-KEV 9.8.
        matched = [self._cve("CVE-2099-0001", 9.8), self._cve("CVE-2023-44487", 7.5)]
        matcher.enrich_exploitation(matched)
        matched.sort(key=matcher._priority, reverse=True)
        assert matched[0]["cve"].cve_id == "CVE-2023-44487"

    def test_kev_fetch_failure_is_soft(self, matcher, monkeypatch):
        """A network error must leave CVEs with their base scores, not crash."""
        monkeypatch.setattr(matcher, "_load_kev", lambda: None)
        monkeypatch.setattr(matcher, "_load_epss", lambda ids: {})
        matched = [self._cve("CVE-2023-44487", 7.5)]
        matcher.enrich_exploitation(matched)
        cve = matched[0]["cve"]
        assert cve.in_kev is False and cve.epss_score is None

    def test_kev_catalog_is_fetched_once(self, matcher, monkeypatch):
        calls = {"n": 0}

        def fake_open(req, timeout=None):
            calls["n"] += 1
            return _FakeResponse({"vulnerabilities": [
                {"cveID": "CVE-1", "knownRansomwareCampaignUse": "Known"}]})

        # The exploitation feeds are fetched by cve.py, not by the NVD client.
        monkeypatch.setattr("phantomprobe.cve.safe_urlopen", fake_open)
        matcher._load_kev()
        matcher._load_kev()
        assert calls["n"] == 1
        assert matcher._kev_cache == {"CVE-1": True}

    def test_epss_is_batched(self, matcher, monkeypatch):
        matcher.EPSS_BATCH = 2
        seen = []

        def fake_open(req, timeout=None):
            seen.append(req.full_url)
            return _FakeResponse({"data": [{"cve": "CVE-X", "epss": "0.5", "percentile": "0.9"}]})

        monkeypatch.setattr("phantomprobe.cve.safe_urlopen", fake_open)
        result = matcher._load_epss(["CVE-1", "CVE-2", "CVE-3"])
        # 3 ids, batch of 2 -> two requests.
        assert len(seen) == 2
        assert result["CVE-X"] == (0.5, 0.9)


# --- Regressions found by checking a known version against live NVD ----------

def _paged_urlopen(total, seen):
    """A stubbed NVD holding a number of CVEs, honouring startIndex and page size."""
    from urllib.parse import parse_qs, urlparse

    def fake(req, timeout=None):
        query = parse_qs(urlparse(req.full_url).query)
        start = int(query.get("startIndex", ["0"])[0])
        size = int(query["resultsPerPage"][0])
        seen.append(start)
        items = [
            {"cve": {"id": f"CVE-2024-{n:04d}", "metrics": {},
                     "descriptions": [], "references": []}}
            for n in range(start, min(start + size, total))
        ]
        return _FakeResponse({"totalResults": total, "startIndex": start,
                              "resultsPerPage": len(items),
                              "vulnerabilities": items})

    return fake


NGINX_CPE = "cpe:2.3:a:f5:nginx:1.24.0"


class TestPagination:
    """
    The client read one page of 20 and stopped. NVD sorts oldest first, so for
    f5:nginx that page ran from 2009 to 2014 and every later CVE was unseen.
    """

    def test_every_page_is_followed(self, matcher, monkeypatch):
        seen = []
        matcher.results_per_page = 2
        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", _paged_urlopen(5, seen))

        cves = matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")

        assert [c.cve_id for c in cves] == [f"CVE-2024-{n:04d}" for n in range(5)]
        assert seen == [0, 2, 4]

    def test_a_product_with_41_cves_is_read_whole(self, matcher, monkeypatch):
        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", _paged_urlopen(41, []))

        cves = matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")

        assert len(cves) == 41
        assert cves[-1].cve_id == "CVE-2024-0040"

    def test_a_cut_at_the_cap_is_announced(self, matcher, monkeypatch, capsys):
        """Stopping early is allowed; stopping early without saying so is not."""
        matcher.results_per_page = 2
        monkeypatch.setattr(matcher, "MAX_RESULTS", 4)
        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", _paged_urlopen(10, []))

        cves = matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")

        assert len(cves) == 4
        assert "first 4 of 10" in capsys.readouterr().out

    def test_an_error_part_way_keeps_what_was_read(self, matcher, monkeypatch, capsys):
        matcher.results_per_page = 2
        paged = _paged_urlopen(6, [])

        def fails_on_the_second_page(req, timeout=None):
            if "startIndex=2" in req.full_url:
                raise URLError("connection reset")
            return paged(req, timeout)

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", fails_on_the_second_page)
        cves = matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")

        assert [c.cve_id for c in cves] == ["CVE-2024-0000", "CVE-2024-0001"]
        assert "Could not reach NVD" in capsys.readouterr().out


class TestBusyNvd:
    """
    NVD answers 503 when it is busy, which happened several times in a couple
    of dozen requests while these fixes were being checked. One bad moment
    must not make a product look free of CVEs.
    """

    @staticmethod
    def _error(req, code):
        return HTTPError(req.full_url, code, "error", {}, None)

    def test_a_503_is_retried(self, matcher, monkeypatch):
        calls, pauses = {"n": 0}, []

        def busy_once(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise self._error(req, 503)
            return _FakeResponse(_nvd_payload())

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", busy_once)
        monkeypatch.setattr(matcher, "_pause", pauses.append)
        cves = matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")

        assert [c.cve_id for c in cves] == ["CVE-2024-0001"]
        assert pauses == [5]

    def test_a_persistent_503_is_reported_after_the_retries(
            self, matcher, monkeypatch, capsys):
        pauses = []

        def always_busy(req, timeout=None):
            raise self._error(req, 503)

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", always_busy)
        monkeypatch.setattr(matcher, "_pause", pauses.append)

        assert matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0") == []
        assert pauses == [5, 15]
        assert "NVD HTTP 503" in capsys.readouterr().out

    @pytest.mark.parametrize("code", [502, 504])
    def test_a_gateway_error_is_retried(self, matcher, monkeypatch, code):
        """
        Seen on a live run: one of 27 requests came back 502 Bad Gateway, and
        the identifier it asked about returned nothing. 504 is the same gateway
        giving up on a slow NVD. Both pass a moment later.
        """
        calls, pauses = {"n": 0}, []

        def gateway_once(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise self._error(req, code)
            return _FakeResponse(_nvd_payload())

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", gateway_once)
        monkeypatch.setattr(matcher, "_pause", pauses.append)
        cves = matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")

        assert [c.cve_id for c in cves] == ["CVE-2024-0001"]
        assert pauses == [5]

    def test_a_rejected_request_is_not_retried(self, matcher, monkeypatch):
        """403 is NVD refusing the rate; waiting a few seconds does not fix it."""
        pauses = []

        def refused(req, timeout=None):
            raise self._error(req, 403)

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", refused)
        monkeypatch.setattr(matcher, "_pause", pauses.append)

        assert matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0") == []
        assert pauses == []

    def test_a_read_timeout_does_not_end_the_scan(self, matcher, monkeypatch, capsys):
        """A timeout reading the body is not a URLError and used to escape."""
        pauses = []

        def stalls(req, timeout=None):
            raise TimeoutError("timed out")

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", stalls)
        monkeypatch.setattr(matcher, "_pause", pauses.append)

        assert matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0") == []
        assert pauses == [5, 15]
        assert "Connection to NVD failed" in capsys.readouterr().out

    def test_a_stalled_read_is_retried(self, matcher, monkeypatch):
        """
        Seen on a live run: the second identifier for nginx timed out
        mid-body, and its 15 CVEs were lost with only a warning to show for it.
        """
        import socket

        calls, pauses = {"n": 0}, []

        def stalls_once(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise socket.timeout("The read operation timed out")
            return _FakeResponse(_nvd_payload())

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", stalls_once)
        monkeypatch.setattr(matcher, "_pause", pauses.append)
        cves = matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")

        assert [c.cve_id for c in cves] == ["CVE-2024-0001"]
        assert pauses == [5]

    def test_a_connect_timeout_is_retried(self, matcher, monkeypatch):
        import socket

        calls, pauses = {"n": 0}, []

        def slow_to_connect(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise URLError(socket.timeout("timed out"))
            return _FakeResponse(_nvd_payload())

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", slow_to_connect)
        monkeypatch.setattr(matcher, "_pause", pauses.append)

        assert len(matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0")) == 1
        assert pauses == [5]

    def test_an_unreachable_host_is_not_retried(self, matcher, monkeypatch):
        """A failed lookup fails the same way a moment later."""
        pauses = []
        monkeypatch.setattr(
            "phantomprobe.nvd.safe_urlopen",
            lambda req, timeout=None: (_ for _ in ()).throw(URLError("no route")),
        )
        monkeypatch.setattr(matcher, "_pause", pauses.append)

        assert matcher.query_nvd(NGINX_CPE, "nginx", "1.24.0") == []
        assert pauses == []


def _cve(cve_id, score, severity="HIGH"):
    return cve_module.CVE(cve_id, severity, score, "d", [], [], [], "", "")


def _server_banner(evidence="Server: nginx/1.24.0"):
    from phantomprobe.models import Finding, Severity

    return Finding(
        id="INFO-Server", title="Server header", description="",
        severity=Severity.INFORMATIONAL, category="Information Disclosure",
        evidence=evidence, remediation="", references=[], discovered_at="",
        target="example.com",
    )


class TestSiblingIdentifiers:
    """
    f5:nginx returns 41 CVEs and looked healthy, yet NVD files the newer nginx
    CVEs under f5:nginx_open_source. For nginx 1.24.0 the first identifier
    gave 2 CVEs and the second 15 more, so the scanner showed 1 of the 10
    scored 7.0 or higher.
    """

    def test_nginx_is_asked_for_under_both_identifiers(self):
        assert CVEMatcher().build_cpes("nginx", "1.24.0") == [
            "cpe:2.3:a:f5:nginx:1.24.0",
            "cpe:2.3:a:f5:nginx_open_source:1.24.0",
        ]

    def test_a_technology_without_siblings_has_one_identifier(self):
        assert CVEMatcher().build_cpes("php", "8.2.29") == ["cpe:2.3:a:php:php:8.2.29"]

    def test_an_unknown_technology_has_none(self):
        assert CVEMatcher().build_cpes("not-a-real-tech", "1.0") == []

    def test_every_sibling_extends_a_mapped_technology(self):
        mapping = CVEMatcher.CPE_MAPPING
        for tech, extras in CVEMatcher.CPE_SIBLINGS.items():
            assert tech in mapping, f"{tech} has siblings but no primary mapping"
            primary = (mapping[tech]["vendor"], mapping[tech]["product"])
            for extra in extras:
                assert (extra["vendor"], extra["product"]) != primary

    def test_no_identifier_is_listed_twice_for_a_technology(self):
        """A duplicate costs a rate-limited NVD request and adds nothing."""
        mapping = CVEMatcher.CPE_MAPPING
        for tech, extras in CVEMatcher.CPE_SIBLINGS.items():
            pairs = [(mapping[tech]["vendor"], mapping[tech]["product"])]
            pairs += [(e["vendor"], e["product"]) for e in extras]
            assert len(pairs) == len(set(pairs)), f"{tech} repeats an identifier"

    def test_every_identifier_is_written_the_way_a_cpe_is(self):
        """Lowercase, no spaces, no colons: a stray one changes the match string."""
        for tech, extras in CVEMatcher.CPE_SIBLINGS.items():
            for extra in extras:
                assert set(extra) == {"vendor", "product"}, tech
                for part in extra.values():
                    assert part and part == part.lower(), f"{tech}: {part!r}"
                    assert " " not in part and ":" not in part, f"{tech}: {part!r}"

    def test_products_whose_primary_returned_nothing_have_a_second_identifier(self):
        """
        For these five the identifier in the table returned no CVEs at all for
        a real version (Joomla 3.9.0, Confluence 7.13.0, RabbitMQ 3.8.9,
        Docker 20.10.5, IIS 7.5), which is indistinguishable from a clean
        target.
        """
        for tech in ("joomla", "confluence", "rabbitmq", "docker", "iis"):
            assert CVEMatcher.CPE_SIBLINGS.get(tech), f"{tech} lost its sibling"

    def test_mysql_is_asked_for_under_all_three_identifiers(self):
        """
        Checked against NVD: MySQL 8.0.30 returned 147 CVEs under oracle:mysql
        and a further 155, none of them shared, under oracle:mysql_server.
        """
        assert CVEMatcher().build_cpes("mysql", "8.0.30") == [
            "cpe:2.3:a:oracle:mysql:8.0.30",
            "cpe:2.3:a:oracle:mysql_server:8.0.30",
            "cpe:2.3:a:mysql:mysql:8.0.30",
        ]

    def test_java_is_asked_for_under_its_earlier_owner_and_its_runtime(self):
        """
        Checked against NVD: Java 1.6.0 returned 459 CVEs under oracle:jdk, a
        further 196 under sun:jdk, 123 of them scored 7.0 or higher, and 13
        under oracle:jre.
        """
        assert CVEMatcher().build_cpes("java", "1.6.0") == [
            "cpe:2.3:a:oracle:jdk:1.6.0",
            "cpe:2.3:a:sun:jdk:1.6.0",
            "cpe:2.3:a:oracle:jre:1.6.0",
            "cpe:2.3:a:oracle:java_se:1.6.0",
        ]

    def test_exim_is_asked_for_under_an_identifier_only_cve_records_use(self):
        """
        university_of_cambridge:exim is missing from NVD's product dictionary,
        so a search of the dictionary cannot find it, yet CVEs are filed under
        it: Exim 4.20 returned 56 under exim:exim and 4 more here, three of
        them scored 7.0 or higher.
        """
        assert CVEMatcher().build_cpes("exim", "4.20") == [
            "cpe:2.3:a:exim:exim:4.20",
            "cpe:2.3:a:university_of_cambridge:exim:4.20",
        ]

    @pytest.mark.parametrize("tech, identifier", [
        ("node.js", ("joyent", "node.js")),
        ("samba", ("samba", "samba_server")),
    ])
    def test_an_identifier_whose_cves_are_not_the_products_stays_out(
            self, tech, identifier):
        """
        Both name the same software, and the study that found them lists them
        as such, but what they add is not its flaws. joyent:node.js holds two
        npm packages filed against Node.js versions, so Node.js 0.8.3 would be
        reported with a 7.5 and a 10.0 it does not have; samba:samba_server
        holds Apple's Samba on Mac OS X.
        """
        extras = CVEMatcher.CPE_SIBLINGS.get(tech, [])
        assert identifier not in [(e["vendor"], e["product"]) for e in extras]

    def test_joomla_is_asked_for_in_the_spelling_nvd_uses(self, matcher, monkeypatch):
        """
        NVD names the product joomla\\! with an escaped exclamation mark. For
        Joomla 3.9.0 the plain spelling returned 0 CVEs and this one 125, so
        the backslash has to survive into the request.
        """
        seen = []

        def record(req, timeout=None):
            seen.append(req.full_url)
            return _FakeResponse({"vulnerabilities": []})

        monkeypatch.setattr("phantomprobe.nvd.safe_urlopen", record)
        matcher.query_product("joomla", "3.9.0")

        assert len(seen) == 2
        assert "joomla%3A3.9.0" in seen[0]
        assert "joomla%5C%21%3A3.9.0" in seen[1]

    def test_results_from_both_identifiers_are_merged_once(self, matcher):
        answers = {
            "cpe:2.3:a:f5:nginx:1.24.0": ["CVE-2023-44487", "CVE-2025-23419"],
            # The same advisory can be filed under both.
            "cpe:2.3:a:f5:nginx_open_source:1.24.0": ["CVE-2024-7347", "CVE-2023-44487"],
        }
        matcher.query_nvd = lambda cpe, tech, version=None: [
            _cve(cve_id, 7.5) for cve_id in answers[cpe]]

        found = matcher.query_product("nginx", "1.24.0")

        assert [c.cve_id for c in found] == [
            "CVE-2023-44487", "CVE-2025-23419", "CVE-2024-7347"]

    def test_a_cve_known_only_to_the_second_identifier_is_reported(
            self, matcher, monkeypatch):
        matcher.query_nvd = lambda cpe, tech, version=None: (
            [_cve("CVE-2026-42945", 9.2, "CRITICAL")]
            if "nginx_open_source" in cpe else [])
        monkeypatch.setattr(matcher, "_load_kev", lambda: {})
        monkeypatch.setattr(matcher, "_load_epss", lambda ids: {})

        matched = matcher.match_findings([_server_banner()])

        assert [item["cve"].cve_id for item in matched] == ["CVE-2026-42945"]


class TestSeverityCut:
    """
    The CVSS 7.0 cut ran before KEV was consulted, so an exploited CVE scoring
    lower was gone before anything could rank it first. CVE-2020-11023, the
    jQuery XSS, scores 6.1 to 6.9 and has been in CISA KEV since January 2025.
    """

    CVES = [
        ("CVE-2099-0002", 6.1, "MEDIUM"),
        ("CVE-2020-11023", 6.9, "MEDIUM"),
        ("CVE-2099-0003", 9.8, "CRITICAL"),
    ]

    def _wire(self, matcher, monkeypatch, kev):
        matcher.query_nvd = lambda cpe, tech, version=None: (
            [_cve(*row) for row in self.CVES] if cpe == NGINX_CPE else [])
        monkeypatch.setattr(matcher, "_load_kev", lambda: kev)
        monkeypatch.setattr(matcher, "_load_epss", lambda ids: {})

    def test_an_exploited_medium_is_kept_and_ranked_first(self, matcher, monkeypatch):
        self._wire(matcher, monkeypatch, kev={"CVE-2020-11023": False})

        matched = matcher.match_findings([_server_banner()])

        assert [item["cve"].cve_id for item in matched] == [
            "CVE-2020-11023", "CVE-2099-0003"]

    def test_a_dormant_medium_is_still_left_out(self, matcher, monkeypatch):
        self._wire(matcher, monkeypatch, kev={"CVE-2020-11023": False})

        matched = matcher.match_findings([_server_banner()])

        assert "CVE-2099-0002" not in [item["cve"].cve_id for item in matched]

    def test_without_kev_data_the_score_alone_decides(self, matcher, monkeypatch):
        """KEV failing to load must not turn every medium into a finding."""
        self._wire(matcher, monkeypatch, kev=None)

        matched = matcher.match_findings([_server_banner()])

        assert [item["cve"].cve_id for item in matched] == ["CVE-2099-0003"]

    def test_epss_is_asked_about_each_cve_once(self, matcher, monkeypatch):
        asked = []
        matcher.query_nvd = lambda cpe, tech, version=None: [_cve("CVE-2023-44487", 7.5)]
        monkeypatch.setattr(matcher, "_load_kev", lambda: {})
        monkeypatch.setattr(matcher, "_load_epss", lambda ids: asked.extend(ids) or {})

        # nginx and php both return the same CVE.
        matcher.match_findings([_server_banner("Server: nginx/1.24.0 PHP/8.2.29")])

        assert asked == ["CVE-2023-44487"]


class TestScriptAssets:
    """
    Client-side library versions show only in the URL a script is served
    from. Those URLs were never recorded as findings, and JavaScript analysis
    ran after CVE matching, so jquery, react and bootstrap were never checked.
    """

    PAGE = """<html><head>
    <script src="/wp-includes/js/jquery/jquery-3.4.1.min.js"></script>
    <script src="https://cdn.example/react@17.0.2/umd/react.production.min.js"></script>
    <script src="/assets/bootstrap-4.3.1.min.js"></script>
    <script src="/js/app.js"></script>
    </head><body></body></html>"""

    @staticmethod
    def _scan(page):
        from phantomprobe.js import JSEngine

        engine = JSEngine("example.com")
        engine.fetch_page = lambda url: page
        engine.fetch_js = lambda url: "var a = 1;"
        return engine.run()

    @staticmethod
    def _queried(findings):
        matcher = CVEMatcher()
        queried = []
        matcher.query_nvd = lambda cpe, tech, version=None: (
            queried.append((tech, version)) or [])
        matcher.match_findings(findings)
        return queried

    def test_library_versions_in_script_urls_reach_the_matcher(self):
        queried = self._queried(self._scan(self.PAGE))

        assert sorted(queried) == [
            ("bootstrap", "4.3.1"), ("jquery", "3.4.1"), ("react", "17.0.2")]

    def test_only_versioned_urls_are_listed(self):
        assets = [f for f in self._scan(self.PAGE) if f.id == "JS-ASSETS"]

        assert len(assets) == 1
        assert "jquery-3.4.1.min.js" in assets[0].evidence
        assert "/js/app.js" not in assets[0].evidence

    def test_no_versioned_scripts_means_no_asset_finding(self):
        page = '<html><head><script src="/js/app.js"></script></head></html>'

        assert [f for f in self._scan(page) if f.id == "JS-ASSETS"] == []

    def test_a_script_named_like_a_server_product_is_not_correlated(self):
        """
        A script path names what the browser runs. "spring-1.2.0.js" is an
        animation library, not the Spring Framework, and "bind-2.0.1.js" is
        not a DNS server.
        """
        page = """<html><head>
        <script src="/js/spring-1.2.0.js"></script>
        <script src="/vendor/bind-2.0.1.min.js"></script>
        <script src="/lib/redis-4.6.0.js"></script>
        </head></html>"""

        assert self._queried(self._scan(page)) == []

    def test_a_server_banner_is_not_restricted_to_client_libraries(self):
        """The restriction applies to script URLs only."""
        assert ("nginx", "1.24.0") in self._queried([_server_banner()])


class TestLetteredVersions:
    """
    OpenSSL and ProFTPD number their releases with a trailing letter, and NVD
    compares them that way: it returned 63 CVEs for OpenSSL 1.1.1, 56 for
    1.1.1d and 33 for 1.1.1w. Dropping the letter asked about the oldest
    release of the line and reported fixes as open.
    """

    @pytest.mark.parametrize("text,expected", [
        ("Server: Apache/2.4.41 (Unix) OpenSSL/1.1.1d", ("openssl", "1.1.1d")),
        ("Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips", ("openssl", "1.0.2k")),
        ("Banner: 220 ProFTPD 1.3.5e Server ready", ("proftpd", "1.3.5e")),
        ("OpenSSL/1.1.1W", ("openssl", "1.1.1w")),  # NVD writes it lowercase
    ])
    def test_a_trailing_letter_is_part_of_the_version(self, text, expected):
        assert expected in CVEMatcher().extract_tech_version(text)

    @pytest.mark.parametrize("text,expected", [
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", ("openssh", "8.9")),
        ("/assets/jquery-3.6.0.min.js", ("jquery", "3.6.0")),
        ("X-Powered-By: PHP/8.2.29-1ubuntu1", ("php", "8.2.29")),
        ("Server: nginx/1.24.0", ("nginx", "1.24.0")),
        ("Server: Jetty(9.4.44.v20210927)", ("jetty", "9.4.44")),
    ])
    def test_what_follows_other_versions_is_left_alone(self, text, expected):
        assert expected in CVEMatcher().extract_tech_version(text)


class TestDistributionBuilds:
    """
    A distribution fixes a vulnerability in the release it ships and keeps
    the upstream version number. A match made on such a banner may already be
    patched, so it is reported with that caution rather than as a plain hit.
    """

    @pytest.mark.parametrize("banner,expected", [
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "Ubuntu"),
        ("Server: Apache/2.4.57 (Debian)", "Debian"),
        ("MariaDB 10.11.6 (server version string: 10.11.6-MariaDB-0+deb12u1)", "Debian"),
        ("Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips", "Red Hat family"),
        ("Server: Apache/2.4.37 (Red Hat Enterprise Linux)", "Red Hat family"),
        ("Server: nginx/1.24.0", None),
        ("SSH-2.0-OpenSSH_9.6", None),
        ("", None),
    ])
    def test_the_distribution_is_read_from_the_banner(self, banner, expected):
        assert CVEMatcher.distribution_named(banner) == expected

    def _match(self, matcher, monkeypatch, evidence):
        matcher.query_nvd = lambda cpe, tech, version=None: (
            [_cve("CVE-2099-0003", 9.8, "CRITICAL")] if cpe.startswith(
                "cpe:2.3:a:apache:http_server") else [])
        monkeypatch.setattr(matcher, "_load_kev", lambda: {})
        monkeypatch.setattr(matcher, "_load_epss", lambda ids: {})
        return matcher.match_findings([_server_banner(evidence)])

    def test_a_match_on_a_distribution_build_says_so(self, matcher, monkeypatch):
        matched = self._match(matcher, monkeypatch, "Server: Apache/2.4.57 (Debian)")
        assert matched[0]["distribution"] == "Debian"

    def test_an_upstream_banner_carries_no_caution(self, matcher, monkeypatch):
        matched = self._match(matcher, monkeypatch, "Server: Apache/2.4.57")
        assert matched[0]["distribution"] is None

    def test_the_distribution_belongs_to_the_line_the_version_came_from(
            self, matcher, monkeypatch):
        """Another line mentioning a distribution must not taint this match."""
        matched = self._match(
            matcher, monkeypatch,
            "Server: Apache/2.4.57\nNote: the mail host runs Ubuntu")
        assert matched[0]["distribution"] is None

    def test_the_report_states_the_caution(self, matcher, monkeypatch):
        matched = self._match(matcher, monkeypatch, "Server: Apache/2.4.57 (Debian)")
        report = matcher.generate_cve_report(matched)

        assert "read from a Debian build, which may already carry the fix" in report
        assert "treat a match as a lead to confirm" in report

    def test_the_report_has_no_caution_line_for_an_upstream_build(
            self, matcher, monkeypatch):
        matched = self._match(matcher, monkeypatch, "Server: Apache/2.4.57")
        assert "**Caution:**" not in matcher.generate_cve_report(matched)

    def test_the_json_report_carries_the_distribution(
            self, matcher, monkeypatch, tmp_path):
        from phantomprobe import cli

        matched = self._match(matcher, monkeypatch, "Server: Apache/2.4.57 (Debian)")
        _, json_path = cli.write_reports([], matched, "example.com", str(tmp_path))
        saved = json.loads(open(json_path, encoding="utf-8").read())

        assert saved["cve_matches"][0]["distribution_build"] == "Debian"

    def test_the_dashboard_marks_a_distribution_build(self):
        from phantomprobe.dashboard import DashboardServer, cve_result_to_dict

        item = {"technology": "apache", "version": "2.4.57",
                "cve": _cve("CVE-2099-0003", 9.8, "CRITICAL"), "distribution": "Debian"}

        assert cve_result_to_dict(item)["distribution"] == "Debian"
        assert "Debian build" in DashboardServer._build_note(item)
        assert DashboardServer._build_note({"technology": "apache"}) == ""
