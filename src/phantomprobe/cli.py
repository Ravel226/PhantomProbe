#!/usr/bin/env python3
"""
Command-line interface for PhantomProbe.

Run with: phantomprobe <target> [options]   (or: python -m phantomprobe ...)
"""

import argparse
import json
import sys
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

from .active import ActiveReconEngine
from .constants import __version__
from .cve import CVEMatcher
from .js import JSEngine
from .models import Finding, Severity
from .passive import ReconEngine
from .report import ReportGenerator
from .screenshot import ScreenshotCapture

BANNER = r"""
     ██████╗ ██╗  ██╗ █████╗ ██╗██████╗ ██████╗ ██████╗ ██╗   ██╗██████╗
    ██╔════╝ ██║  ██║██╔══██╗██║██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗
    ██║      ███████║███████║██║██████╔╝██████╔╝██████╔╝██║   ██║██████╔╝
    ██║      ██╔══██║██╔══██║██║██╔═══╝ ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗
    ╚██████╗ ██║  ██║██║  ██║██║██║     ██║     ██████╔╝╚██████╔╝██║  ██║
     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝

    Ghost in the Machine | v{version}
    Reconnaissance for authorized security testing
"""

ASCII_BANNER = r"""
    PhantomProbe v{version}
    Ghost in the Machine
    Reconnaissance for authorized security testing
"""

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]


def configure_console_encoding() -> None:
    """
    Stop console encoding from aborting a scan.

    What we print includes text we do not control: banners from a dependency's
    error message, and evidence taken from the scanned host's own responses. On
    a console using a legacy code page (Windows cp1252) a single unencodable
    character makes print() raise UnicodeEncodeError, which aborted the run
    before any report was written - so a failed screenshot, or a target serving
    a header outside the code page, silently discarded every finding.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


def console_supports(text: str) -> bool:
    """Whether stdout's encoding can represent text without substitutions."""
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def print_banner():
    """
    Print the banner, falling back to plain ASCII on consoles that cannot
    encode box-drawing characters (e.g. Windows cp1252). Checked up front
    rather than caught, because configure_console_encoding makes the
    box-drawing version print as replacement characters instead of raising.
    """
    banner = BANNER if console_supports(BANNER) else ASCII_BANNER
    print(banner.format(version=__version__))


def normalize_target(raw: str) -> str:
    """
    Reduce a user-supplied target to a bare hostname.

    Accepts 'example.com', 'https://example.com/path?q=1' and 'example.com:8443'.
    """
    candidate = raw.strip()
    if "://" in candidate:
        candidate = urlparse(candidate).netloc or candidate.split("://", 1)[1]
    candidate = candidate.split("/")[0]
    # Strip credentials and an explicit port, keeping IPv6 brackets intact.
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    if candidate.startswith("["):
        return candidate
    if candidate.count(":") == 1:
        candidate = candidate.split(":")[0]
    return candidate


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="phantomprobe",
        description="Reconnaissance scanner for authorized penetration testing.",
        epilog="Use only on systems you own or are explicitly authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target hostname or URL (e.g. example.com)")
    parser.add_argument("--version", action="version", version=f"PhantomProbe {__version__}")

    parser.add_argument("-a", "--phase2", action="store_true",
                        help="Enable active reconnaissance (ports, subdomains, fingerprinting)")
    parser.add_argument("-c", "--cve", action="store_true",
                        help="Enable CVE matching via the NVD API")
    parser.add_argument("-s", "--screenshot", action="store_true",
                        help="Capture website screenshot (requires Playwright)")
    parser.add_argument("-j", "--js", action="store_true",
                        help="JavaScript analysis (endpoints, secrets, hidden paths)")
    parser.add_argument("-b", "--burp", action="store_true",
                        help="Run a Burp Professional scan and import its issues "
                             "(requires the REST API and BURP_API_KEY)")
    parser.add_argument("--burp-timeout", type=int, default=300, metavar="SECONDS",
                        help="How long to wait for the Burp scan (default: 300). "
                             "A real audit often needs considerably longer.")
    parser.add_argument("-d", "--dashboard", action="store_true",
                        help="Start the interactive web dashboard (requires FastAPI)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output")

    parser.add_argument("--output-dir", default=".",
                        help="Directory for generated reports and screenshots (default: .)")
    parser.add_argument("--dashboard-host", default=None,
                        help="Dashboard bind address (default: $PHANTOMPROBE_DASHBOARD_HOST or 127.0.0.1)")
    parser.add_argument("--dashboard-port", type=int, default=None,
                        help="Dashboard port (default: $PHANTOMPROBE_DASHBOARD_PORT or 8080)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open a browser when starting the dashboard")
    return parser


def print_summary(findings: List[Finding], cve_results: List[dict]) -> None:
    """Print the severity-ordered findings summary."""
    print("=" * 60)
    print("FINDINGS BY SEVERITY")
    print("=" * 60)
    for severity in SEVERITY_ORDER:
        sev_findings = [f for f in findings if f.severity == severity]
        if sev_findings:
            print(f"\n[{severity.value.upper()}]")
            for f in sev_findings:
                print(f"  - {f.id}: {f.title}")

    if cve_results:
        print()
        print("=" * 60)
        print("CVE CORRELATION (HIGH/CRITICAL)")
        print("=" * 60)
        for item in cve_results[:10]:
            cve = item['cve']
            print(f"  [{cve.severity}] {cve.cve_id} (CVSS {cve.cvss_score}) - {item['technology']}")


def write_reports(findings: List[Finding], cve_results: List[dict],
                  target: str, output_dir: str):
    """Generate and write the Markdown and JSON reports."""
    import os

    print()
    print("=" * 60)
    print("GENERATING REPORTS")
    print("=" * 60)

    markdown_report = ReportGenerator.generate_markdown(findings, target)
    json_report = ReportGenerator.generate_json(findings, target)

    if cve_results:
        matcher = CVEMatcher()
        markdown_report = markdown_report + "\n" + matcher.generate_cve_report(cve_results)

        json_data = json.loads(json_report)
        json_data['cve_matches'] = [
            {
                'technology': item['technology'],
                'version': item['version'],
                'cve_id': item['cve'].cve_id,
                'cvss_score': item['cve'].cvss_score,
                'severity': item['cve'].severity,
                'description': item['cve'].description,
                'references': item['cve'].references,
            }
            for item in cve_results
        ]
        json_report = json.dumps(json_data, indent=2)

    os.makedirs(output_dir, exist_ok=True)
    md_filename = os.path.join(output_dir, f"report-{target}.md")
    json_filename = os.path.join(output_dir, f"report-{target}.json")

    with open(md_filename, "w", encoding="utf-8") as f:
        f.write(markdown_report)
    print(f"[+] Markdown report: {md_filename}")

    with open(json_filename, "w", encoding="utf-8") as f:
        f.write(json_report)
    print(f"[+] JSON report: {json_filename}")

    return md_filename, json_filename


def main(argv: Optional[List[str]] = None) -> int:
    """Main scanner entry point."""
    configure_console_encoding()

    parser = build_parser()
    args = parser.parse_args(argv)

    target = normalize_target(args.target)
    if not target:
        parser.error("could not parse a hostname from the given target")

    # Initialize dashboard server first so scan progress can stream to it.
    dashboard_server = None
    if args.dashboard:
        try:
            from .dashboard import DashboardServer, FASTAPI_AVAILABLE
        except ImportError:
            FASTAPI_AVAILABLE = False

        if FASTAPI_AVAILABLE:
            print("[*] Starting dashboard server...")
            dashboard_server = DashboardServer(
                host=args.dashboard_host, port=args.dashboard_port
            )
            print("[*] Dashboard will update with scan progress")
        else:
            print("[!] Dashboard requires: pip install \"phantomprobe[dashboard]\"")

    def broadcast_progress(phase: str, message: str = ""):
        if dashboard_server:
            dashboard_server.broadcast_progress_sync("PROGRESS", {
                "phase": phase,
                "message": message,
                "target": target,
            })

    print_banner()

    # Phase 1: Passive Reconnaissance
    broadcast_progress("Phase 1: DNS Analysis")
    recon = ReconEngine(target)
    findings = recon.run()

    # Phase 2: Active Reconnaissance (optional)
    if args.phase2:
        broadcast_progress("Phase 2: Active Reconnaissance")
        findings.extend(ActiveReconEngine(target).run())

    # CVE Matching (optional)
    cve_results = []
    if args.cve:
        broadcast_progress("CVE Matching")
        cve_results = CVEMatcher().match_findings(findings)

    # Screenshot Capture (optional)
    if args.screenshot:
        broadcast_progress("Screenshot Capture")
        screenshot_path = ScreenshotCapture(output_dir=args.output_dir).capture(target)
        if screenshot_path:
            findings.append(Finding(
                id="SCREENSHOT-Captured",
                title="Website Screenshot Captured",
                description="Visual documentation of target website",
                severity=Severity.INFORMATIONAL,
                category="Documentation",
                evidence=f"Screenshot saved: {screenshot_path}",
                remediation="N/A - Documentation",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=target
            ))

    # JavaScript Analysis (optional)
    if args.js:
        broadcast_progress("JavaScript Analysis")
        findings.extend(JSEngine(target).run())

    # Burp Suite Integration (optional)
    if args.burp:
        broadcast_progress("Burp Suite Integration")
        from .burp import BURP_AVAILABLE, BurpSuiteEngine
        if BURP_AVAILABLE:
            # Burp's REST API only scans; it cannot take findings back, so the
            # results flow one way, into this report.
            findings.extend(BurpSuiteEngine(target).run(timeout=args.burp_timeout))
        else:
            print("[!] Burp integration requires: pip install \"phantomprobe[burp]\"")

    print_summary(findings, cve_results)
    md_filename, json_filename = write_reports(
        findings, cve_results, target, args.output_dir
    )

    print()
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Total findings: {len(findings)}")
    if cve_results:
        print(f"CVE matches: {len(cve_results)}")
    print()

    # Launch Dashboard (optional) - blocks until interrupted.
    if dashboard_server:
        print("[*] Launching interactive dashboard...")
        dashboard_server.update_data(findings, cve_results, target)
        dashboard_server.broadcast_progress_sync("SCAN_COMPLETE", {
            "total_findings": len(findings),
            "cve_matches": len(cve_results),
            "reports": [md_filename, json_filename],
        })
        dashboard_server.run(open_browser=not args.no_browser)

    return 0


if __name__ == "__main__":
    sys.exit(main())
