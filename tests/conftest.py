"""
Pytest configuration and fixtures for PhantomProbe tests
"""
import pytest
import sys
import os

# Add src to path for tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

@pytest.fixture
def sample_finding():
    """Create a sample finding for testing"""
    from phantomprobe import Finding, Severity
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
        target="test.com"
    )

@pytest.fixture
def mock_target():
    """Mock target domain for testing"""
    return "test.example.com"
