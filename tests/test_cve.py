"""
Unit tests for CVE correlation.

No test here touches the network: query_nvd is exercised through a stubbed
urlopen so the rate-limit and error-handling paths stay verifiable offline.
"""
import json
from urllib.error import HTTPError, URLError

import pytest

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

def test_build_cpe_with_version():
    cpe = CVEMatcher().build_cpe("nginx", "1.24.0")

    assert cpe.startswith("cpe:2.3:a:nginx:nginx:1.24.0")


def test_build_cpe_without_version_uses_wildcard():
    cpe = CVEMatcher().build_cpe("nginx")

    assert "cpe:2.3:a:nginx:nginx:*" in cpe


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
