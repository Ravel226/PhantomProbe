"""
Tests for the Burp Suite integration.

These run against a stub that imitates the real REST API: the key is a path
prefix, starting a scan answers 201 with the task id in Location and an empty
body, and the scan record carries both status and issue_events. The issue
fields mirror captured Burp output, which is where the previous version went
wrong: it read a "remediation" key that Burp does not send.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from phantomprobe.burp import BURP_AVAILABLE, BurpSuiteEngine
from phantomprobe.models import Severity

pytestmark = pytest.mark.skipif(
    not BURP_AVAILABLE, reason="requests is not installed"
)

API_KEY = "test-key"

ISSUE_EVENTS = [
    {
        "id": 1,
        "type": "issue_found",
        "issue": {
            "name": "TLS cookie without secure flag set",
            "serial_number": "5605602767570803712",
            "origin": "https://example.com",
            "path": "/login",
            "severity": "low",
            "confidence": "certain",
            "description": "The cookie does not have the secure flag set.",
            "caption": "/login",
            "remediation_background": "Set the secure flag on the cookie.",
        },
    },
    {
        "id": 2,
        "type": "issue_found",
        "issue": {
            "name": "Strict transport security not enforced",
            "serial_number": "42",
            "origin": "https://example.com",
            "path": "/",
            "severity": "high",
            "confidence": "firm",
            # No description and no remediation_background: both are optional
            # in real Burp output.
            "issue_background": "HSTS tells browsers to use HTTPS only.",
            "caption": "/",
        },
    },
]


class _StubBurp(BaseHTTPRequestHandler):
    """Minimal stand-in for Burp's REST service."""

    require_key = True
    statuses = ["auditing", "succeeded"]

    def _authorised(self):
        return not self.require_key or self.path.startswith(f"/{API_KEY}/")

    def _strip(self):
        prefix = f"/{API_KEY}"
        return self.path[len(prefix):] if self.path.startswith(prefix) else self.path

    def _send(self, code, body=None, headers=None):
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        payload = b"" if body is None else json.dumps(body).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self):
        if not self._authorised():
            self._send(401, {"error": "unauthorised"})
            return
        route = self._strip()
        if route.startswith("/v0.1/scan/"):
            # The last entry sticks, so a one-entry list models a scan that
            # never finishes without needing to guess how often we will poll.
            queue = type(self).statuses
            status = queue.pop(0) if len(queue) > 1 else (queue[0] if queue else "succeeded")
            self._send(200, {
                "task_id": "7",
                "scan_status": status,
                "scan_metrics": {"crawl_requests_made": 12},
                "issue_events": ISSUE_EVENTS,
            })
        elif route.rstrip("/") == "/v0.1":
            self._send(200, {"burp_version": "2026.1"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorised():
            self._send(401, {"error": "unauthorised"})
            return
        if self._strip().rstrip("/") == "/v0.1/scan":
            length = int(self.headers.get("Content-Length", 0))
            type(self).last_body = json.loads(self.rfile.read(length) or b"{}")
            # Burp answers 201 with the id in Location and no body.
            self._send(201, headers={"Location": "/v0.1/scan/7"})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):
        pass


@pytest.fixture
def burp_server():
    _StubBurp.statuses = ["auditing", "succeeded"]
    _StubBurp.require_key = True
    _StubBurp.last_body = None
    server = HTTPServer(("127.0.0.1", 0), _StubBurp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def engine(burp_server):
    return BurpSuiteEngine("example.com", api_url=burp_server, api_key=API_KEY)


class TestAuthentication:
    def test_key_is_a_path_prefix_not_a_header(self, engine):
        """
        The regression this module was rewritten for. Burp mounts the API under
        the key, so a Bearer header leaves every call unauthenticated.
        """
        assert engine.base_url.endswith(f"/{API_KEY}")
        assert engine.is_burp_running() is True

    def test_wrong_key_is_reported_as_unreachable(self, burp_server):
        wrong = BurpSuiteEngine("example.com", api_url=burp_server, api_key="nope")
        assert wrong.is_burp_running() is False

    def test_no_key_falls_back_to_the_bare_service_url(self, burp_server):
        open_engine = BurpSuiteEngine("example.com", api_url=burp_server, api_key="")
        assert open_engine.base_url == burp_server

    def test_api_url_comes_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("BURP_API_URL", "http://burp.internal:1337/")
        monkeypatch.setenv("BURP_API_KEY", "env-key")
        from_env = BurpSuiteEngine("example.com")
        assert from_env.base_url == "http://burp.internal:1337/env-key"


class TestScanLifecycle:
    def test_task_id_is_read_from_the_location_header(self, engine):
        assert engine.start_scan() == "7"
        assert engine.task_id == "7"

    def test_minimal_body_lets_burp_use_its_defaults(self, engine):
        engine.start_scan()
        assert _StubBurp.last_body == {"urls": ["https://example.com"]}

    def test_named_configuration_is_sent_as_an_object(self, engine):
        engine.start_scan(configuration="Audit checks - fast")
        assert _StubBurp.last_body["scan_configurations"] == [
            {"name": "Audit checks - fast", "type": "NamedConfiguration"}
        ]

    def test_wait_polls_until_a_terminal_status(self, engine):
        engine.start_scan()
        scan = engine.wait_for_scan(timeout=10, interval=0)
        assert scan["scan_status"] == "succeeded"

    def test_wait_returns_the_last_record_on_timeout(self, engine):
        _StubBurp.statuses = ["auditing"]
        engine.start_scan()
        scan = engine.wait_for_scan(timeout=1, interval=0)
        # Partial results still beat nothing.
        assert scan["scan_status"] == "auditing"


class TestIssueMapping:
    def test_issues_become_findings(self, engine):
        engine.start_scan()
        findings = engine.issues_to_findings(engine.wait_for_scan(timeout=10, interval=0))

        assert [f.id for f in findings] == ["BURP-5605602767570803712", "BURP-42"]
        assert findings[0].severity is Severity.LOW
        assert findings[1].severity is Severity.HIGH

    def test_remediation_comes_from_remediation_background(self, engine):
        """Burp sends remediation_background; there is no "remediation" key."""
        engine.start_scan()
        findings = engine.issues_to_findings(engine.get_scan())
        assert findings[0].remediation == "Set the secure flag on the cookie."

    def test_missing_optional_fields_do_not_break_the_mapping(self, engine):
        engine.start_scan()
        findings = engine.issues_to_findings(engine.get_scan())
        # Second issue has no description and no remediation_background.
        assert findings[1].description == "HSTS tells browsers to use HTTPS only."
        assert findings[1].remediation == "Review the issue in Burp"

    def test_evidence_carries_the_located_url(self, engine):
        engine.start_scan()
        findings = engine.issues_to_findings(engine.get_scan())
        assert "https://example.com/login" in findings[0].evidence
        assert "Confidence: certain" in findings[0].evidence

    def test_no_scan_record_yields_no_findings(self, engine):
        assert engine.issues_to_findings(None) == []


class TestRun:
    def test_run_returns_findings_end_to_end(self, engine):
        findings = engine.run(timeout=10)
        assert len(findings) == 2

    def test_run_stops_cleanly_when_burp_is_unreachable(self):
        offline = BurpSuiteEngine(
            "example.com", api_url="http://127.0.0.1:1", api_key=API_KEY
        )
        assert offline.run(timeout=1) == []


class TestExtensionTemplate:
    def test_template_is_valid_python_2_for_jython(self, tmp_path):
        """
        Burp runs extensions on Jython 2.7. The previous template used an
        f-string, which is a syntax error there, so it could never load.
        """
        path = tmp_path / "ext.py"
        BurpSuiteEngine.generate_extension_template(str(path))
        source = path.read_text(encoding="utf-8")

        assert 'print(f"' not in source
        assert "urllib2" not in source
        # Python 2 has no f-strings, so a %-format must be what is used.
        assert '%% (self.NAME' not in source
        assert "% (self.NAME, self.VERSION)" in source
