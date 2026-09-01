"""
Unit tests for the PhantomProbe dashboard.
"""
from html.parser import HTMLParser

import pytest

from phantomprobe import Finding, Severity
from phantomprobe.dashboard import (
    DashboardServer,
    cve_result_to_dict,
    finding_to_dict,
    resolve_host_port,
)


def make_finding(**overrides):
    defaults = dict(
        id="TEST-001",
        title="Test Finding",
        description="Test description",
        severity=Severity.HIGH,
        category="Test",
        evidence="Test evidence",
        remediation="Fix it",
        references=[],
        discovered_at="2026-03-08T12:00:00",
        target="test.com",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class _TagCollector(HTMLParser):
    """Collect tags and inline event handlers from rendered HTML."""

    def __init__(self):
        super().__init__()
        self.tags = []
        self.event_handlers = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, _ in attrs:
            if name.startswith("on"):
                self.event_handlers.append((tag, name))


def test_dashboard_server_init(dashboard_server):
    """DashboardServer initializes with defaults and empty state."""
    assert dashboard_server.host == "127.0.0.1"
    assert dashboard_server.port == 8080
    assert dashboard_server.findings == []
    assert dashboard_server.cve_results == []


def test_dashboard_server_update_data(dashboard_server):
    """update_data stores findings and target."""
    finding = make_finding()
    dashboard_server.update_data([finding], [], "test.com")

    assert dashboard_server.findings == [finding]
    assert dashboard_server.target == "test.com"


def test_dashboard_server_calculate_stats(dashboard_server):
    """Statistics are counted per severity and per category."""
    dashboard_server.findings = [
        make_finding(id="1", severity=Severity.CRITICAL, category="Cat1"),
        make_finding(id="2", severity=Severity.HIGH, category="Cat1"),
        make_finding(id="3", severity=Severity.HIGH, category="Cat2"),
    ]
    dashboard_server.target = "test.com"

    stats = dashboard_server._calculate_stats()

    assert stats["total_findings"] == 3
    assert stats["severity_counts"]["critical"] == 1
    assert stats["severity_counts"]["high"] == 2
    assert stats["severity_counts"]["low"] == 0
    assert stats["categories"] == {"Cat1": 2, "Cat2": 1}


def test_dashboard_html_generation(dashboard_server):
    """The page renders with the target and the expected sections."""
    dashboard_server.target = "test.com"

    html = dashboard_server._generate_html()

    assert "PhantomProbe Dashboard" in html
    assert "test.com" in html
    assert "No findings yet" in html
    assert "No CVE matches found." in html


def test_dashboard_without_fastapi(monkeypatch):
    """DashboardServer refuses to start when FastAPI is missing."""
    from phantomprobe import dashboard as dashboard_module

    monkeypatch.setattr(dashboard_module, "FASTAPI_AVAILABLE", False)
    with pytest.raises(ImportError):
        DashboardServer()


# --- Regression tests for the stored-XSS fix ---------------------------------

def test_html_escapes_hostile_target(dashboard_server):
    """A target name containing markup must not become live HTML."""
    dashboard_server.target = "evil<script>alert(1)</script>.com"

    html = dashboard_server._generate_html()

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_escapes_hostile_finding_fields(dashboard_server):
    """
    Evidence is attacker-controlled: a scanned host can put markup in a header.
    It must render as inert text, never as an element.
    """
    dashboard_server.target = "test.com"
    dashboard_server.findings = [
        make_finding(
            id="<b>id</b>",
            title="<i>title</i>",
            category="<u>cat</u>",
            evidence='<img src=x onerror=alert(2)>',
        )
    ]

    html = dashboard_server._generate_html()
    collector = _TagCollector()
    collector.feed(html)

    assert "img" not in collector.tags
    assert "b" not in collector.tags
    assert collector.event_handlers == []
    # Exactly one script tag: the dashboard's own WebSocket bootstrap.
    assert collector.tags.count("script") == 1


def test_websocket_url_is_derived_client_side(dashboard_server):
    """
    The WS URL must be built from window.location, not from the bind address —
    otherwise it breaks when the server listens on 0.0.0.0 (Docker).
    """
    html = dashboard_server._generate_html()

    assert "window.location.host" in html
    # The old bug rendered the literal placeholder into the page.
    assert "{self.host}" not in html
    assert "{self.port}" not in html


# --- Serialization -----------------------------------------------------------

def test_finding_to_dict_is_json_serializable():
    """Severity is an Enum; it must be flattened for JSONResponse."""
    import json

    data = finding_to_dict(make_finding())

    assert data["severity"] == "high"
    json.dumps(data)  # must not raise


def test_cve_result_to_dict_is_json_serializable():
    """CVE entries are dataclasses; they must be flattened too."""
    import json

    from phantomprobe import CVE

    cve = CVE(
        cve_id="CVE-2024-0001",
        severity="HIGH",
        cvss_score=9.8,
        description="test",
        affected_versions=[],
        fix_versions=[],
        references=[],
        published="",
        modified="",
    )
    data = cve_result_to_dict({"technology": "nginx", "version": "1.0", "cve": cve})

    assert data["cve"]["cve_id"] == "CVE-2024-0001"
    json.dumps(data)  # must not raise


# --- Bind address resolution -------------------------------------------------

def test_resolve_host_port_defaults(monkeypatch):
    monkeypatch.delenv("PHANTOMPROBE_DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("PHANTOMPROBE_DASHBOARD_PORT", raising=False)

    assert resolve_host_port() == ("127.0.0.1", 8080)


def test_resolve_host_port_from_env(monkeypatch):
    """docker-compose sets these; the server must honour them."""
    monkeypatch.setenv("PHANTOMPROBE_DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.setenv("PHANTOMPROBE_DASHBOARD_PORT", "9000")

    assert resolve_host_port() == ("0.0.0.0", 9000)


def test_explicit_arguments_win_over_env(monkeypatch):
    monkeypatch.setenv("PHANTOMPROBE_DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.setenv("PHANTOMPROBE_DASHBOARD_PORT", "9000")

    assert resolve_host_port("10.0.0.1", 1234) == ("10.0.0.1", 1234)


def test_invalid_env_port_falls_back(monkeypatch):
    monkeypatch.delenv("PHANTOMPROBE_DASHBOARD_HOST", raising=False)
    monkeypatch.setenv("PHANTOMPROBE_DASHBOARD_PORT", "not-a-port")

    assert resolve_host_port() == ("127.0.0.1", 8080)
