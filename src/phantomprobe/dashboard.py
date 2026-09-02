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
from string import Template
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

# Severity is the only chromatic language in this interface. Steps are separated
# by lightness as well as hue so the ramp survives desaturation and colour-vision
# deficiency, and every chip ships its text label: colour is never the only code.
SEVERITY_SLUGS = {
    "critical": "crit",
    "high": "high",
    "medium": "med",
    "low": "low",
    "informational": "info",
}

# Authored icons on one grid and one stroke weight, so the set reads as a system.
# Drawn rather than borrowed from a font: glyphs and emoji are not an icon system.
_ICON_BODIES = {
    "mark": (
        '<circle cx="12" cy="12" r="2.25"/>'
        '<path d="M12 3.75a8.25 8.25 0 0 1 8.25 8.25"/>'
        '<path d="M12 7.5a4.5 4.5 0 0 1 4.5 4.5"/>'
        '<path d="M4.4 16.5a8.25 8.25 0 0 1 2.2-10.3"/>'
    ),
    "findings": (
        '<path d="M4.5 6.75h9"/><path d="M4.5 12h6"/><path d="M4.5 17.25h9"/>'
        '<circle cx="17" cy="13.5" r="3.25"/><path d="M19.4 15.9 21.5 18"/>'
    ),
    "cve": (
        '<path d="M12 4.75 20.5 19.25H3.5z"/>'
        '<path d="M12 10v3.6"/><path d="M12 16.4h.01"/>'
    ),
    "chevron": '<path d="m9.5 5.75 6 6.25-6 6.25"/>',
}


def icon(name: str, size: int = 18) -> str:
    """Inline an authored icon, sized in px and coloured by currentColor."""
    return (
        f'<svg class="icon" width="{size}" height="{size}" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.5" '
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        f'{_ICON_BODIES.get(name, "")}</svg>'
    )

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


PAGE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$target findings - PhantomProbe</title>
<style>
    :root {
      color-scheme: dark;

      /* Ground: cool graphite. Not black, not navy. Elevation is carried by two
         neutral steps and a hairline, never by a shadow and a border at once. */
      --canvas:      #14161a;
      --panel:       #1b1e23;
      --panel-hi:    #22262c;
      --line:        #2c3138;
      --line-strong: #3b414a;

      --text:        #e7e9ec;
      --text-dim:    #a3abb6;
      --text-faint:  #868f9b;

      /* Interaction accent. Warm bone against the cool ground, and it appears
         only on focus, selection and the active filter: rarity gives it force. */
      --bone:        #e9dcc4;
      --bone-dim:    #bdb198;

      --crit:  #f2685c;
      --high:  #e2924a;
      --med:   #d3b551;
      --low:   #8ba5d6;
      --info:  #9aa4b0;

      --step-1: 4px;  --step-2: 8px;  --step-3: 12px;
      --step-4: 16px; --step-5: 24px; --step-6: 40px;

      --radius: 12px;
      --radius-sm: 7px;

      --ease: cubic-bezier(0.22, 0.61, 0.36, 1);
      --fast: 140ms;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    html { -webkit-text-size-adjust: 100%; }

    body {
      background: var(--canvas);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.5;
      letter-spacing: -0.006em;
      -webkit-font-smoothing: antialiased;
      caret-color: var(--bone);
    }

    /* Surfaces the browser draws that the design still owns. */
    ::selection { background: var(--bone); color: #14161a; }
    ::-webkit-scrollbar { width: 11px; height: 11px; }
    ::-webkit-scrollbar-track { background: var(--canvas); }
    ::-webkit-scrollbar-thumb {
      background: var(--line-strong);
      border-radius: 99px;
      border: 3px solid var(--canvas);
    }
    ::-webkit-scrollbar-thumb:hover { background: #4a515c; }
    * { scrollbar-color: var(--line-strong) var(--canvas); scrollbar-width: thin; }

    :focus-visible {
      outline: 2px solid var(--bone);
      outline-offset: 2px;
      border-radius: 3px;
    }

    .shell { max-width: 1280px; margin: 0 auto; padding: 0 var(--step-5); }

    .icon { flex: none; }

    /* masthead */

    .masthead { background: var(--panel); border-bottom: 1px solid var(--line); }
    .masthead-inner {
      display: flex; align-items: center; gap: var(--step-4);
      padding: var(--step-4) 0; flex-wrap: wrap;
    }
    .wordmark {
      display: flex; align-items: center; gap: var(--step-2);
      font-size: 15px; font-weight: 600; letter-spacing: -0.015em;
    }
    .wordmark .icon { color: var(--bone-dim); }
    .wordmark .name { font-weight: 600; }
    .wordmark .ver { color: var(--text-faint); font-weight: 400; font-size: 12px; }

    /* The scanned host is the page subject and carries the display step; every
       other size sits in the dense product range below it. */
    .subject { padding: var(--step-5) 0 var(--step-2); }
    .subject h1 {
      font-size: 26px; font-weight: 600; letter-spacing: -0.022em;
      line-height: 1.2;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .subject-meta {
      margin-top: 5px;
      color: var(--text-dim); font-size: 13px;
      font-variant-numeric: tabular-nums;
    }
    .subject-meta .sep { color: var(--line-strong); margin: 0 var(--step-2); }

    .link-status {
      margin-left: auto;
      display: inline-flex; align-items: center; gap: 7px;
      font-size: 12px; color: var(--text-dim);
      padding: 3px 10px 3px 8px;
      border: 1px solid var(--line); border-radius: 99px;
    }
    .link-status .pip {
      width: 6px; height: 6px; border-radius: 99px;
      background: var(--text-faint);
      transition: background var(--fast) var(--ease);
    }
    .link-status[data-state="live"] { color: var(--text); }
    .link-status[data-state="live"] .pip { background: #74c091; }

    /* filter rail */

    .rail {
      display: flex; align-items: center; gap: var(--step-2);
      padding: var(--step-4) 0 var(--step-3); flex-wrap: wrap;
    }
    .rail-label { font-size: 12px; color: var(--text-faint); margin-right: var(--step-1); }

    .chip {
      display: inline-flex; align-items: center; gap: 7px;
      padding: 5px 11px;
      font: inherit; font-size: 12px; font-weight: 550; letter-spacing: 0.02em;
      color: var(--text-dim);
      background: transparent;
      border: 1px solid var(--line);
      border-radius: 99px;
      cursor: pointer;
      transition: border-color var(--fast) var(--ease),
                  color var(--fast) var(--ease),
                  background-color var(--fast) var(--ease);
    }
    .chip:hover { border-color: var(--line-strong); color: var(--text); }
    .chip .n { font-variant-numeric: tabular-nums; color: var(--text-faint); }
    .chip[aria-pressed="true"] {
      border-color: var(--bone-dim); color: var(--text);
      background: rgba(233, 220, 196, 0.09);
    }
    .chip[aria-pressed="true"] .n { color: var(--bone); }
    .chip[disabled] { opacity: 0.45; cursor: default; }
    .chip[disabled]:hover { border-color: var(--line); color: var(--text-dim); }
    .chip .dot { width: 7px; height: 7px; border-radius: 2px; }

    .sev-crit .dot { background: var(--crit); }
    .sev-high .dot { background: var(--high); }
    .sev-med  .dot { background: var(--med); }
    .sev-low  .dot { background: var(--low); }
    .sev-info .dot { background: var(--info); }

    /* panels */

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      margin-bottom: var(--step-5);
      overflow: hidden;
    }
    .panel-head {
      display: flex; align-items: center; gap: var(--step-2);
      padding: var(--step-3) var(--step-4);
      border-bottom: 1px solid var(--line);
    }
    .panel-head h2 { font-size: 13px; font-weight: 600; letter-spacing: 0.01em; }
    .panel-head .icon { color: var(--text-faint); }
    .panel-head .count { margin-left: auto; color: var(--text-faint); font-size: 12px;
                         font-variant-numeric: tabular-nums; }

    /* table */

    .scroll-x { overflow-x: auto; }

    table { width: 100%; border-collapse: collapse; }

    th {
      text-align: left;
      font-size: 11px; font-weight: 600;
      letter-spacing: 0.06em; text-transform: uppercase;
      color: var(--text-faint);
      padding: 7px var(--step-4);
      border-bottom: 1px solid var(--line);
      white-space: nowrap;
      background: var(--panel);
    }
    td {
      padding: var(--step-1) var(--step-4);
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      line-height: 1.45;
    }
    /* First and last row keep a little more air so the table does not collide
       with the panel edges. */
    tbody tr:first-child td { padding-top: 7px; }
    tbody tr:last-child td { padding-bottom: 7px; }
    tbody tr:last-child td { border-bottom: 0; }
    tbody tr { transition: background-color var(--fast) var(--ease); }
    tbody tr:hover { background: var(--panel-hi); }
    tbody tr[hidden] { display: none; }

    .col-id {
      font-family: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
      font-variant-numeric: tabular-nums; letter-spacing: 0;
      font-size: 12px; color: var(--text-dim); white-space: nowrap;
    }
    /* width:1% collapses a column to its content; the title takes the slack. */
    .col-shrink { width: 1%; white-space: nowrap; }
    .col-title { font-weight: 500; }
    .col-cat { color: var(--text-dim); white-space: nowrap; }
    .col-score {
      font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
      font-variant-numeric: tabular-nums; text-align: right; white-space: nowrap;
    }
    .col-desc { color: var(--text-dim); max-width: 60ch; }

    /* Severity reads as a word first; the swatch only reinforces it. */
    .sev {
      display: inline-flex; align-items: center; gap: 6px;
      font-size: 11px; font-weight: 600; letter-spacing: 0.05em; white-space: nowrap;
    }
    .sev .dot { width: 7px; height: 7px; border-radius: 2px; }
    .sev-crit { color: var(--crit); }
    .sev-high { color: var(--high); }
    .sev-med  { color: var(--med); }
    .sev-low  { color: var(--low); }
    .sev-info { color: var(--info); }

    /* Exploitation badges. KEV reuses the critical hue because an actively
       exploited CVE is the most urgent thing on the page; EPSS is quiet mono. */
    .kev {
      display: inline-block; padding: 1px 6px; border-radius: 4px;
      font-size: 11px; font-weight: 700; letter-spacing: 0.03em;
      color: var(--crit); border: 1px solid var(--crit);
    }
    .epss {
      font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
      font-variant-numeric: tabular-nums; font-size: 12px;
      color: var(--text-dim); margin-left: 6px;
    }
    td[data-label="Exploit"] { white-space: nowrap; }

    /* evidence disclosure */

    details summary {
      display: inline-flex; align-items: center; gap: 5px;
      cursor: pointer; list-style: none;
      color: var(--text-dim); font-size: 12px;
      border-radius: 4px;
      min-height: 24px;
      padding: 0 6px; margin: 0 -6px;
      transition: color var(--fast) var(--ease);
    }
    details summary::-webkit-details-marker { display: none; }
    details summary:hover { color: var(--text); }
    details summary .icon { color: var(--text-faint);
                            transition: transform var(--fast) var(--ease); }
    details[open] summary .icon { transform: rotate(90deg); }
    details pre {
      margin-top: var(--step-2);
      padding: var(--step-3);
      background: var(--canvas);
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
      font-size: 12px; line-height: 1.55;
      color: var(--text-dim);
      white-space: pre-wrap; word-break: break-word;
      max-width: 90ch;
    }

    /* empty states teach the next step rather than announcing nothing */

    /* A section reporting nothing should be quiet. Centred in a tall box, the
       empty CVE panel outweighed the findings table it sat under, which is the
       wrong emphasis for the part of the page with no content in it. It still
       says what would fill it, just at the weight the absence deserves. */
    .empty {
      padding: var(--step-3) var(--step-4);
      color: var(--text-dim);
      max-width: 76ch;
    }
    .empty strong {
      color: var(--text); font-weight: 550;
    }
    .empty strong::after { content: "."; }
    .empty code {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12px; color: var(--bone-dim);
      background: var(--canvas); border: 1px solid var(--line);
      border-radius: 4px; padding: 1px 5px;
    }
    .empty[hidden] { display: none; }

    footer { padding: var(--step-5) 0 var(--step-6); color: var(--text-faint); font-size: 12px; }

    /* Below this width the table stops being a table. Scrolling it sideways
       left the visible columns beside a column of dead space, because an
       off-screen wrapped title still set the row height. Each row becomes a
       labelled block instead, so nothing is hidden and nothing is empty. */
    @media (max-width: 720px) {
      .shell { padding: 0 var(--step-4); }

      .scroll-x { overflow-x: visible; }
      table, tbody, tr, td { display: block; width: auto; }
      thead { position: absolute; width: 1px; height: 1px;
              overflow: hidden; clip-path: inset(50%); white-space: nowrap; }

      tbody tr {
        padding: var(--step-2) var(--step-4);
        border-bottom: 1px solid var(--line);
      }
      tbody tr:last-child { border-bottom: 0; }

      td {
        display: flex; align-items: baseline; gap: var(--step-3);
        padding: 1px 0; border-bottom: 0; white-space: normal;
      }
      tbody tr:first-child td, tbody tr:last-child td { padding: 1px 0; }
      td::before {
        content: attr(data-label);
        /* min-width, not width: the longest label (TECHNOLOGY) overflowed a
           fixed box and ate the gap, so labels ran into their values. */
        flex: none; min-width: 78px;
        color: var(--text-faint);
        font-size: 11px; font-weight: 600;
        letter-spacing: 0.06em; text-transform: uppercase;
      }
      .col-shrink { width: auto; white-space: normal; }
      .col-title { font-weight: 600; }
      td > details { flex: 1 1 auto; min-width: 0; }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        transition-duration: 0.01ms !important;
        animation-duration: 0.01ms !important;
      }
    }
</style>
</head>
<body>
  <header class="masthead">
    <div class="shell masthead-inner">
      <div class="wordmark">$icon_mark<span class="name">PhantomProbe</span><span class="ver">$version</span></div>
      <span class="link-status" id="link" data-state="off">
        <span class="pip"></span><span id="link-text">Offline</span>
      </span>
    </div>
  </header>

  <main class="shell">
    <!-- The page is about the scanned host, so the host is the heading. The
         tool name stays chrome in the masthead. -->
    <div class="subject">
      <h1 title="$target">$target</h1>
      <p class="subject-meta">Scanned $scan_time</p>
    </div>

    <div class="rail" role="group" aria-label="Filter findings by severity">
      <span class="rail-label">Severity</span>
      $filters
    </div>

    <section class="panel">
      <div class="panel-head">
        $icon_findings<h2>Findings</h2>
        <span class="count" id="findings-count">$findings_count</span>
      </div>
      $findings_body
    </section>

    <section class="panel">
      <div class="panel-head">
        $icon_cve<h2>CVE correlation</h2>
        <span class="count">$cve_count</span>
      </div>
      $cve_body
    </section>

    <footer>Reports are written next to the scan output. Re-run the scan to refresh this view.</footer>
  </main>

  <script>
    (function () {
      var link = document.getElementById('link');
      var linkText = document.getElementById('link-text');
      var ws;

      function setLink(state, label) {
        link.setAttribute('data-state', state);
        linkText.textContent = label;
      }

      function connect() {
        var scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(scheme + '//' + window.location.host + '/ws');
        ws.onopen = function () { setLink('live', 'Live'); };
        ws.onclose = function () {
          setLink('off', 'Reconnecting');
          setTimeout(connect, 3000);
        };
        ws.onmessage = function (event) {
          var data = JSON.parse(event.data);
          if (data.type === 'NEW_FINDING' || data.type === 'SCAN_COMPLETE') {
            location.reload();
          }
        };
      }
      connect();

      // Severity filtering. Chips are toggles, so triage can narrow to the rows
      // that matter without losing the counts.
      var chips = Array.prototype.slice.call(document.querySelectorAll('.chip[data-sev]'));
      var rows = Array.prototype.slice.call(document.querySelectorAll('tr[data-sev]'));
      var countEl = document.getElementById('findings-count');
      var emptyFiltered = document.getElementById('no-match');

      function apply() {
        var on = chips.filter(function (c) {
          return c.getAttribute('aria-pressed') === 'true';
        }).map(function (c) { return c.getAttribute('data-sev'); });

        var shown = 0;
        rows.forEach(function (row) {
          var visible = on.length === 0 || on.indexOf(row.getAttribute('data-sev')) !== -1;
          row.hidden = !visible;
          if (visible) { shown += 1; }
        });

        if (countEl) {
          countEl.textContent = shown === rows.length
            ? rows.length + ' total'
            : shown + ' of ' + rows.length;
        }
        if (emptyFiltered) { emptyFiltered.hidden = shown !== 0 || rows.length === 0; }
      }

      chips.forEach(function (chip) {
        chip.addEventListener('click', function () {
          chip.setAttribute(
            'aria-pressed',
            chip.getAttribute('aria-pressed') === 'true' ? 'false' : 'true'
          );
          apply();
        });
      });
    })();
  </script>
</body>
</html>
""")


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
        """Findings table body. Every target-controlled value is escaped."""
        rows = ""
        chevron = icon("chevron", 13)
        for severity in SEVERITY_ORDER:
            slug = SEVERITY_SLUGS.get(severity.value, "info")
            for finding in [f for f in self.findings if f.severity == severity]:
                evidence = finding.evidence or ""
                shown = evidence[:500] + ("..." if len(evidence) > 500 else "")
                rows += (
                    f'<tr data-sev="{slug}">'
                    f'<td class="col-shrink" data-label="Severity">'
                    f'<span class="sev sev-{slug}"><span class="dot"></span>'
                    f'{html.escape(severity.value.upper())}</span></td>'
                    f'<td class="col-id col-shrink" data-label="ID">{html.escape(finding.id)}</td>'
                    f'<td class="col-title" data-label="Title">{html.escape(finding.title)}</td>'
                    f'<td class="col-cat col-shrink" data-label="Category">{html.escape(finding.category)}</td>'
                    f'<td class="col-shrink" data-label="Evidence">'
                    f'<details><summary>{chevron}Evidence</summary>'
                    f'<pre>{html.escape(shown)}</pre></details></td>'
                    "</tr>"
                )
        return rows

    def _build_cve_rows(self) -> str:
        """CVE table body. Every NVD-sourced value is escaped."""
        rows = ""
        for item in self.cve_results[:20]:
            cve = item["cve"]
            slug = SEVERITY_SLUGS.get(str(cve.severity).lower(), "info")
            description = cve.description or ""
            shown = description[:180] + ("..." if len(description) > 180 else "")
            rows += (
                "<tr>"
                f'<td class="col-shrink" data-label="Severity">'
                    f'<span class="sev sev-{slug}"><span class="dot"></span>'
                f'{html.escape(str(cve.severity).upper())}</span></td>'
                f'<td class="col-id col-shrink" data-label="CVE">{html.escape(str(cve.cve_id))}</td>'
                f'<td class="col-score col-shrink" data-label="CVSS">{html.escape(str(cve.cvss_score))}</td>'
                f'<td class="col-shrink" data-label="Exploit">{self._exploit_cell(cve)}</td>'
                f'<td class="col-cat col-shrink" data-label="Technology">{html.escape(str(item["technology"]))}</td>'
                f'<td class="col-desc">{html.escape(shown)}</td>'
                "</tr>"
            )
        return rows

    @staticmethod
    def _exploit_cell(cve) -> str:
        """KEV badge and EPSS score. Empty when neither feed knew the CVE."""
        parts = []
        if getattr(cve, "in_kev", False):
            label = "KEV" + ("·RANSOM" if getattr(cve, "kev_ransomware", False) else "")
            parts.append(f'<span class="kev" title="In CISA Known Exploited '
                         f'Vulnerabilities">{label}</span>')
        epss = getattr(cve, "epss_score", None)
        if epss is not None:
            parts.append(f'<span class="epss" title="EPSS: probability of '
                         f'exploitation in 30 days">{epss:.2f}</span>')
        return "".join(parts) or '<span class="epss">n/a</span>'

    def _build_filters(self, stats: Dict) -> str:
        """
        Severity counts double as filter toggles. A count that also narrows the
        table earns its place; a count that only sits there is decoration.
        """
        chips = ""
        for severity in SEVERITY_ORDER:
            value = severity.value
            count = stats["severity_counts"].get(value, 0)
            slug = SEVERITY_SLUGS.get(value, "info")
            disabled = " disabled" if count == 0 else ""
            chips += (
                f'<button type="button" class="chip sev-{slug}" data-sev="{slug}" '
                f'aria-pressed="false"{disabled}>'
                '<span class="dot"></span>'
                f'{html.escape(value.upper())}'
                f'<span class="n">{count}</span>'
                "</button>"
            )
        return chips

    def _generate_html(self) -> str:
        """Render the dashboard page."""
        stats = self._calculate_stats()
        findings_rows = self._build_findings_rows()
        cve_rows = self._build_cve_rows()
        total = stats["total_findings"]

        if findings_rows:
            findings_body = (
                '<div class="scroll-x"><table><thead><tr>'
                '<th class="col-shrink">Severity</th><th class="col-shrink">ID</th>'
                '<th>Title</th><th class="col-shrink">Category</th>'
                '<th class="col-shrink">Evidence</th>'
                f"</tr></thead><tbody>{findings_rows}</tbody></table></div>"
                '<div class="empty" id="no-match" hidden>'
                "<strong>No findings match this filter</strong> "
                "Clear a severity chip above to widen the view.</div>"
            )
        else:
            findings_body = (
                '<div class="empty"><strong>No findings yet</strong> '
                "This view fills in when a scan completes. Run "
                "<code>phantomprobe example.com --dashboard</code> to populate it."
                "</div>"
            )

        if cve_rows:
            cve_body = (
                '<div class="scroll-x"><table><thead><tr>'
                '<th class="col-shrink">Severity</th><th class="col-shrink">CVE</th>'
                '<th class="col-shrink">CVSS</th>'
                '<th class="col-shrink">Exploit</th>'
                '<th class="col-shrink">Technology</th><th>Summary</th>'
                f"</tr></thead><tbody>{cve_rows}</tbody></table></div>"
            )
        else:
            cve_body = (
                '<div class="empty"><strong>No CVE correlation</strong> '
                "Correlation runs only with <code>--cve</code>, and needs a version "
                "string in a banner to match against NVD.</div>"
            )

        return PAGE.substitute(
            target=html.escape(self.target or "No target"),
            scan_time=html.escape(stats["scan_time"]),
            version=html.escape(__version__),
            icon_mark=icon("mark", 20),
            icon_findings=icon("findings", 16),
            icon_cve=icon("cve", 16),
            filters=self._build_filters(stats),
            findings_body=findings_body,
            cve_body=cve_body,
            findings_count=f"{total} total",
            cve_count=f"{len(self.cve_results)} matched",
        )

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
