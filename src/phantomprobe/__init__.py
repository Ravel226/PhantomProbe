#!/usr/bin/env python3
"""
PhantomProbe - Reconnaissance Scanner for Penetration Testing

Public API. Optional integrations (dashboard, screenshots, Burp) are imported
lazily so that the dependency-free core keeps working without extras installed.
"""

from .active import ActiveReconEngine
from .aggressive import AggressiveScanner
from .cli import main, print_banner
from .cookies import CookieScanner
from .constants import BROWSER_USER_AGENT, USER_AGENT, __version__
from .cve import CVE, CVEMatcher
from .dns_security import DnsSecurityScanner
from .http_checks import HstsPreloadScanner, RedirectScanner, SecurityTxtScanner
from .js import JSEngine, ScriptTagParser
from .models import Finding, Severity
from .passive import ReconEngine
from .report import ReportGenerator
from .screenshot import ScreenshotCapture
from .takeover import TakeoverScanner
from .waf import WafScanner, detect_waf

__all__ = [
    "__version__",
    "USER_AGENT",
    "BROWSER_USER_AGENT",
    "Finding",
    "Severity",
    "ReconEngine",
    "ActiveReconEngine",
    "AggressiveScanner",
    "CVE",
    "CVEMatcher",
    "ScreenshotCapture",
    "TakeoverScanner",
    "WafScanner",
    "CookieScanner",
    "DnsSecurityScanner",
    "HstsPreloadScanner",
    "RedirectScanner",
    "SecurityTxtScanner",
    "detect_waf",
    "JSEngine",
    "ScriptTagParser",
    "ReportGenerator",
    "BurpSuiteEngine",
    "DashboardServer",
    "main",
    "print_banner",
]


def __getattr__(name):
    """
    Lazily expose optional components.

    Importing them eagerly would make `import phantomprobe` fail (or pay the
    import cost) when FastAPI / requests are not installed.
    """
    if name in ("DashboardServer", "FASTAPI_AVAILABLE"):
        from . import dashboard
        return getattr(dashboard, name)
    if name in ("BurpSuiteEngine", "BURP_AVAILABLE"):
        from . import burp
        return getattr(burp, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
