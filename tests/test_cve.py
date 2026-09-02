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

    monkeypatch.setattr("phantomprobe.cve.safe_urlopen", fake_urlopen)
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

    monkeypatch.setattr("phantomprobe.cve.safe_urlopen", fake_urlopen)
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
        "phantomprobe.cve.safe_urlopen",
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

    monkeypatch.setattr("phantomprobe.cve.safe_urlopen", raise_403)
    cves = matcher.query_nvd("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*", "nginx", "1.0")

    assert cves == []
    assert "NVD_API_KEY" in capsys.readouterr().out


def test_network_error_is_reported(matcher, monkeypatch, capsys):
    monkeypatch.setattr(
        "phantomprobe.cve.safe_urlopen",
        lambda req, timeout=None, context=None: (_ for _ in ()).throw(URLError("no route")),
    )

    assert matcher.query_nvd("cpe:x", "nginx", "1.0") == []
    assert "Could not reach NVD" in capsys.readouterr().out


def test_malformed_response_is_reported(matcher, monkeypatch, capsys):
    class _BadResponse(_FakeResponse):
        def __init__(self):
            self._payload = b"not json"

    monkeypatch.setattr("phantomprobe.cve.safe_urlopen", lambda req, timeout=None, context=None: _BadResponse())

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
    monkeypatch.setattr("phantomprobe.cve.safe_urlopen",
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
