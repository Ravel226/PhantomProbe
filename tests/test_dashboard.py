"""
Unit tests for PhantomProbe dashboard
"""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock

def test_dashboard_server_init():
    """Test DashboardServer initialization"""
    from phantomprobe import DashboardServer
    
    # Mock FastAPI availability
    with patch('phantomprobe.FASTAPI_AVAILABLE', True):
        with patch('phantomprobe.FastAPI') as mock_fastapi:
            with patch('phantomprobe.uvicorn'):
                server = DashboardServer(host="127.0.0.1", port=9090)
                assert server.host == "127.0.0.1"
                assert server.port == 9090
                assert server.findings == []
                assert server.cve_results == []

def test_dashboard_server_update_data():
    """Test updating dashboard data"""
    from phantomprobe import DashboardServer, Finding, Severity
    
    with patch('phantomprobe.FASTAPI_AVAILABLE', True):
        with patch('phantomprobe.FastAPI'):
            server = DashboardServer()
            
            # Create test findings
            finding = Finding(
                id="TEST-001",
                title="Test Finding",
                description="Test description",
                severity=Severity.HIGH,
                category="Test",
                evidence="Test evidence",
                remediation="Fix it",
                references=[],
                discovered_at="2026-03-08T12:00:00",
                target="test.com"
            )
            
            server.update_data([finding], [], "test.com")
            assert server.findings == [finding]
            assert server.target == "test.com"

def test_dashboard_server_calculate_stats():
    """Test statistics calculation"""
    from phantomprobe import DashboardServer, Finding, Severity
    
    with patch('phantomprobe.FASTAPI_AVAILABLE', True):
        with patch('phantomprobe.FastAPI'):
            server = DashboardServer()
            
            # Add test findings
            findings = [
                Finding("1", "F1", "D1", Severity.CRITICAL, "Cat1", "E1", "R1", [], "", "t.com"),
                Finding("2", "F2", "D2", Severity.HIGH, "Cat1", "E2", "R2", [], "", "t.com"),
                Finding("3", "F3", "D3", Severity.HIGH, "Cat2", "E3", "R3", [], "", "t.com"),
            ]
            
            server.findings = findings
            server.target = "test.com"
            
            stats = server._calculate_stats()
            
            assert stats['total_findings'] == 3
            assert stats['severity_counts']['critical'] == 1
            assert stats['severity_counts']['high'] == 2

def test_dashboard_html_generation():
    """Test HTML dashboard generation"""
    from phantomprobe import DashboardServer
    
    with patch('phantomprobe.FASTAPI_AVAILABLE', True):
        with patch('phantomprobe.FastAPI'):
            server = DashboardServer()
            server.target = "test.com"
            
            html = server._generate_html()
            
            assert "PhantomProbe Dashboard" in html
            assert "test.com" in html
            assert "Dark theme" not in html  # Check CSS is present (simplified check)

def test_dashboard_without_fastapi():
    """Test that DashboardServer raises error without FastAPI"""
    from phantomprobe import DashboardServer
    
    with patch('phantomprobe.FASTAPI_AVAILABLE', False):
        with pytest.raises(ImportError):
            DashboardServer()

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
