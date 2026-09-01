#!/usr/bin/env python3
"""
Interactive web dashboard (FastAPI, optional dependency).

Install with: pip install "phantomprobe[dashboard]"

Security note: every value rendered into the page originates from a scanned
target and is therefore hostile input. All interpolated content is escaped with
html.escape() before it reaches the template.
"""

import asyncio
import html
import json
import os
import webbrowser
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List, Optional

from .constants import __version__
from .models import Finding, Severity

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080

SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f39c12",
    "low": "#3498db",
    "informational": "#95a5a6",
}

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]


def finding_to_dict(finding: Finding) -> Dict:
    """Serialize a Finding to plain JSON-compatible types."""
    data = asdict(finding)
    data["severity"] = finding.severity.value
    return data


def cve_result_to_dict(item: Dict) -> Dict:
    """Serialize a CVE match entry to plain JSON-compatible types."""
    cve = item.get("cve")
    return {
        "technology": item.get("technology"),
        "version": item.get("version"),
        "cve": asdict(cve) if cve is not None else None,
    }


def resolve_host_port(host: Optional[str] = None, port: Optional[int] = None):
    """
    Resolve the dashboard bind address.

    Explicit arguments win; otherwise fall back to the PHANTOMPROBE_DASHBOARD_*
    environment variables (set by docker-compose), then to the local defaults.
    """
    resolved_host = host or os.environ.get("PHANTOMPROBE_DASHBOARD_HOST") or DEFAULT_HOST

    if port is not None:
        resolved_port = port
    else:
        env_port = os.environ.get("PHANTOMPROBE_DASHBOARD_PORT")
        try:
            resolved_port = int(env_port) if env_port else DEFAULT_PORT
        except ValueError:
            print(f"[!] Invalid PHANTOMPROBE_DASHBOARD_PORT={env_port!r}, using {DEFAULT_PORT}")
            resolved_port = DEFAULT_PORT

    return resolved_host, resolved_port


class DashboardServer:
    """FastAPI-based interactive dashboard for PhantomProbe"""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        self.host, self.port = resolve_host_port(host, port)
        self.findings: List[Finding] = []
        self.cve_results: List[Dict] = []
        self.target: str = ""
        self.scan_progress: Dict = {}
        self.app = None
        self.connected_clients: List = []

        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI not available. Install: pip install fastapi uvicorn")

        self._create_app()

    def _create_app(self):
        """Create FastAPI application"""
        self.app = FastAPI(
            title="PhantomProbe Dashboard",
            description="Interactive reconnaissance scanner dashboard",
            version=__version__
        )

        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard():
            return self._generate_html()

        @self.app.get("/api/findings")
        async def api_findings():
            return JSONResponse(content=[finding_to_dict(f) for f in self.findings])

        @self.app.get("/api/cve")
        async def api_cve():
            return JSONResponse(content=[cve_result_to_dict(i) for i in self.cve_results])

        @self.app.get("/api/stats")
        async def api_stats():
            return JSONResponse(content=self._calculate_stats())

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.connected_clients.append(websocket)
            try:
                while True:
                    data = await websocket.receive_text()
                    await websocket.send_text(json.dumps({"type": "pong", "data": data}))
            except WebSocketDisconnect:
                if websocket in self.connected_clients:
                    self.connected_clients.remove(websocket)

    def _calculate_stats(self) -> Dict:
        """Calculate scan statistics"""
        stats = {
            "target": self.target,
            "total_findings": len(self.findings),
            "severity_counts": {},
            "categories": {},
            "scan_time": datetime.now().isoformat()
        }

        for severity in Severity:
            stats["severity_counts"][severity.value] = len(
                [f for f in self.findings if f.severity == severity]
            )

        for finding in self.findings:
            cat = finding.category
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1

        return stats

    def update_data(self, findings: List[Finding], cve_results: List[Dict], target: str):
        """Update dashboard with new scan data"""
        self.findings = findings
        self.cve_results = cve_results
        self.target = target

    def _build_findings_rows(self) -> str:
        """Build the findings table body. All target-controlled data is escaped."""
        rows = ""
        for severity in SEVERITY_ORDER:
            color = SEVERITY_COLORS.get(severity.value, "#95a5a6")
            for finding in [f for f in self.findings if f.severity == severity]:
                evidence = finding.evidence or ""
                truncated = evidence[:500] + ("..." if len(evidence) > 500 else "")
                rows += f"""
                <tr style="border-left: 4px solid {color}">
                    <td><span class="badge" style="background: {color}">{html.escape(severity.value.upper())}</span></td>
                    <td>{html.escape(finding.id)}</td>
                    <td>{html.escape(finding.title)}</td>
                    <td>{html.escape(finding.category)}</td>
                    <td><details><summary>View</summary><pre>{html.escape(truncated)}</pre></details></td>
                </tr>
                """
        return rows

    def _build_cve_rows(self) -> str:
        """Build the CVE table body. All NVD-sourced data is escaped."""
        rows = ""
        for item in self.cve_results[:20]:
            cve = item['cve']
            color = SEVERITY_COLORS.get(str(cve.severity).lower(), "#95a5a6")
            description = cve.description or ""
            truncated = description[:150] + ("..." if len(description) > 150 else "")
            rows += f"""
            <tr style="border-left: 4px solid {color}">
                <td><span class="badge" style="background: {color}">{html.escape(str(cve.severity).upper())}</span></td>
                <td>{html.escape(str(cve.cve_id))}</td>
                <td>{html.escape(str(cve.cvss_score))}</td>
                <td>{html.escape(str(item['technology']))}</td>
                <td>{html.escape(truncated)}</td>
            </tr>
            """
        return rows

    def _build_stat_cards(self, stats: Dict) -> str:
        """Build the severity stat cards."""
        cards = ""
        for sev, count in stats["severity_counts"].items():
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "#95a5a6")
                cards += f"""
                <div class="stat-card" style="border-top: 4px solid {color}">
                    <h3>{count}</h3>
                    <p>{html.escape(sev.upper())}</p>
                </div>
                """
        return cards

    def _generate_html(self) -> str:
        """Generate interactive HTML dashboard"""
        stats = self._calculate_stats()

        findings_html = self._build_findings_rows()
        cve_html = self._build_cve_rows()
        cards_html = self._build_stat_cards(stats)

        # Target and timestamp are rendered into the page: escape them too.
        safe_target = html.escape(self.target)
        safe_scan_time = html.escape(stats['scan_time'])

        # The browser connects back to the address it loaded the page from, so
        # the WebSocket URL is derived client-side. Hardcoding the bind address
        # breaks whenever the server listens on 0.0.0.0 (e.g. in Docker).
        findings_table = (
            '<div class="empty-state">No findings yet. Run a scan to populate.</div>'
            if not findings_html
            else '<table><thead><tr><th>Severity</th><th>ID</th><th>Title</th>'
                 '<th>Category</th><th>Evidence</th></tr></thead>'
                 f'<tbody>{findings_html}</tbody></table>'
        )
        cve_table = (
            '<div class="empty-state">No CVE matches found.</div>'
            if not cve_html
            else '<table><thead><tr><th>Severity</th><th>CVE ID</th><th>CVSS</th>'
                 '<th>Technology</th><th>Description</th></tr></thead>'
                 f'<tbody>{cve_html}</tbody></table>'
        )

        html_page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomProbe Dashboard - {safe_target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .header h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .header p {{ color: #888; }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1a1a2e;
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card h3 {{
            font-size: 2.5rem;
            color: #00d4ff;
        }}
        .stat-card p {{
            color: #888;
            font-size: 0.9rem;
            text-transform: uppercase;
        }}
        .section {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .section h2 {{
            color: #00d4ff;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        th {{
            color: #00d4ff;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
        }}
        tr:hover {{ background: rgba(0, 212, 255, 0.05); }}
        .badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }}
        details {{
            cursor: pointer;
        }}
        details summary {{
            color: #00d4ff;
        }}
        details pre {{
            background: #0a0a0a;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 0.5rem;
            overflow-x: auto;
            font-size: 0.8rem;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .empty-state {{
            text-align: center;
            padding: 3rem;
            color: #666;
        }}
        #connection-status {{
            position: fixed;
            top: 1rem;
            right: 1rem;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-size: 0.8rem;
        }}
        .connected {{ background: #27ae60; }}
        .disconnected {{ background: #e74c3c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128026; PhantomProbe Dashboard</h1>
        <p>Target: <strong>{safe_target}</strong> | Scan Time: {safe_scan_time}</p>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card" style="border-top: 4px solid #00d4ff">
                <h3>{stats['total_findings']}</h3>
                <p>TOTAL FINDINGS</p>
            </div>
            {cards_html}
        </div>

        <div class="section">
            <h2>&#128269; Findings</h2>
            {findings_table}
        </div>

        <div class="section">
            <h2>&#128027; CVE Matches</h2>
            {cve_table}
        </div>
    </div>

    <div id="connection-status" class="disconnected">&#9679; WebSocket Disconnected</div>

    <script>
        let ws;
        function connect() {{
            const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(scheme + '//' + window.location.host + '/ws');
            ws.onopen = () => {{
                document.getElementById('connection-status').className = 'connected';
                document.getElementById('connection-status').textContent = '\\u25CF Live Updates';
            }};
            ws.onclose = () => {{
                document.getElementById('connection-status').className = 'disconnected';
                document.getElementById('connection-status').textContent = '\\u25CF Reconnecting...';
                setTimeout(connect, 3000);
            }};
            ws.onmessage = (event) => {{
                const data = JSON.parse(event.data);
                console.log('Update received:', data);
                if (data.type === 'NEW_FINDING' || data.type === 'SCAN_COMPLETE') {{
                    location.reload();
                }}
            }};
        }}
        connect();
    </script>
</body>
</html>"""
        return html_page

    async def broadcast_update(self, message: Dict):
        """Broadcast update to all connected clients"""
        if not self.connected_clients:
            return

        disconnected = []
        for client in self.connected_clients:
            try:
                await client.send_text(json.dumps(message))
            except Exception:
                disconnected.append(client)
        for client in disconnected:
            if client in self.connected_clients:
                self.connected_clients.remove(client)

    def broadcast_progress_sync(self, message_type: str, data: Dict):
        """Synchronous wrapper to broadcast progress updates"""
        if not self.connected_clients:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(
                    self.broadcast_update({"type": message_type, "data": data})
                )
            else:
                loop.run_until_complete(
                    self.broadcast_update({"type": message_type, "data": data})
                )
        except RuntimeError:
            # No usable event loop in this thread; progress updates are
            # best-effort and the dashboard reloads on connect anyway.
            pass

    def run(self, open_browser: bool = True):
        """Start the dashboard server"""
        # Opening a browser only makes sense when the server is reachable from
        # this machine's desktop. In Docker (bind 0.0.0.0) there is none.
        # nosec B104 - not a bind address; this only detects the container case
        # where no local browser exists. The bind default is 127.0.0.1.
        if open_browser and self.host not in ("0.0.0.0", "::"):  # nosec B104
            try:
                webbrowser.open(f"http://{self.host}:{self.port}")
            except Exception:
                pass

        print(f"[*] Starting PhantomProbe Dashboard on http://{self.host}:{self.port}")
        print(f"[*] Press Ctrl+C to stop")

        uvicorn.run(self.app, host=self.host, port=self.port, log_level="warning")
