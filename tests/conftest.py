"""
Pytest configuration and fixtures for PhantomProbe tests.

The src/ layout is put on sys.path by [tool.pytest.ini_options] pythonpath in
pyproject.toml, so tests import `phantomprobe` the same way an installed
package would.
"""
import pytest

from phantomprobe import Finding, Severity


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing"""
    return Finding(
        id="TEST-001",
        title="Test Finding",
        description="Test description",
        severity=Severity.HIGH,
        category="Test Category",
        evidence="Test evidence",
        remediation="Fix the issue",
        references=["https://example.com"],
        discovered_at="2026-03-08T12:00:00",
        target="test.com",
    )


@pytest.fixture
def mock_target():
    """Mock target domain for testing"""
    return "test.example.com"


@pytest.fixture
def dashboard_server(monkeypatch):
    """
    A DashboardServer wired to a stub FastAPI app.

    Lets the dashboard be exercised without FastAPI installed, and without
    binding a socket.
    """
    from phantomprobe import dashboard as dashboard_module

    class _StubApp:
        def get(self, *args, **kwargs):
            return lambda fn: fn

        def websocket(self, *args, **kwargs):
            return lambda fn: fn

    monkeypatch.setattr(dashboard_module, "FASTAPI_AVAILABLE", True)
    monkeypatch.setattr(dashboard_module, "FastAPI", lambda *a, **k: _StubApp(), raising=False)
    # Keep env-driven config from leaking in from the developer's shell.
    monkeypatch.delenv("PHANTOMPROBE_DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("PHANTOMPROBE_DASHBOARD_PORT", raising=False)

    return dashboard_module.DashboardServer()
