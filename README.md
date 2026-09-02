# PhantomProbe

**Reconnaissance Scanner for Penetration Testing**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com/)

PhantomProbe is a lightweight vulnerability reconnaissance scanner for penetration testers and security researchers. It performs passive and active analysis, correlates findings with known CVEs, captures visual documentation, discovers JavaScript secrets, and provides an interactive web dashboard.

## v0.8.0 - Burp Suite Integration & Docker Support

New features:
- **Burp Suite Integration** - Burp Professional REST API support
  - Run a Burp crawl and audit from the command line
  - Import the resulting issues into the PhantomProbe report
  - Generate a starter Burp extension
- **Full Docker Support** - Multi-stage builds with compose profiles
  - Core edition (lightweight)
  - Dashboard edition (interactive)
  - Full edition (all features)
  - Development mode with hot-reload

### v0.7.0 - Interactive Web Dashboard

New features:
- **Interactive Web Dashboard** - FastAPI-based real-time visualization
- Live WebSocket updates during scans
- Severity-based filtering and statistics
- Dark theme UI optimized for security work
- CVE correlation visualization
- Finding evidence viewer with expandable details

## Features

### Phase 1 - Passive Reconnaissance
- DNS Analysis - A/AAAA records, reverse DNS, wildcard detection
- SSL/TLS Analysis - Certificate info, expiry checks, weak ciphers, deprecated TLS
- HTTP Headers - Security headers, information disclosure
- HSTS preload eligibility - Judged against hstspreload.org's current one-year
  max-age floor, not the 10886400 older guidance still quotes
- Redirect chain - Walks the hops by hand; flags plain HTTP that never reaches
  HTTPS, and redirects that leave the target host
- security.txt - RFC 9116 disclosure contact, reported as information
- WAF/CDN detection - Passive header and cookie fingerprinting of 35 WAFs,
  using the wafw00f signature set; reuses the header fetch, sends nothing extra
- Cookie security - Secure, HttpOnly and SameSite attributes, with severity set
  by what each one buys today: a session cookie readable by script outranks a
  tracking one, and a missing SameSite is hardening rather than a hole

### Phase 2 - Active Reconnaissance
- Port scanning - Common ports with service identification
- Subdomain enumeration - Common subdomain discovery
- Technology fingerprinting - Server and framework detection
- Subdomain takeover - Dangling-CNAME detection against a two-signal check,
  using fingerprints from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

### CVE Correlation
- Matches technologies to known CVEs through the NVD API, covering 74 products:
  web servers and proxies, application frameworks, client-side libraries, CMSes
  and the services a port scan turns up. Every vendor/product pair was checked
  against NVD before being added, since a wrong one returns a clean 200 with no
  results rather than an error
- Correlates only where a banner gave a version, since asking NVD for a bare
  product name returns every CVE ever filed against it, most long since fixed.
  Products seen without a version are listed as skipped rather than guessed at
- CVSS score-based filtering (>= 7.0), reading v4.0, v3.1, v3.0 or v2 scores
- Reports the first fixed release for each match where NVD records one
- Flags exploitation with CISA KEV (actively exploited in the wild, with a
  ransomware marker) and EPSS (probability of exploitation), both free and
  keyless. An exploited CVE is ranked above a higher-scored dormant one

#### Keeping the CPE table honest

A wrong vendor fails silently: NVD answers 200 with no results, so a broken
mapping is indistinguishable from a clean target. Vendors also drift, which is
why nginx is filed under `f5` today. Re-check the table with:

```bash
python scripts/audit_cpe_mapping.py                   # the whole table
python scripts/audit_cpe_mapping.py --tech nginx php  # a few entries
python scripts/audit_cpe_mapping.py --check f5:nginx  # try a candidate pair
```

It exits non-zero if any mapping matches nothing. Set `NVD_API_KEY` to run it
in under a minute instead of about nine.

### Screenshot Capture
- Full-page or viewport screenshots
- Headless Chromium via Playwright
- HTTPS bypass for testing environments

### JavaScript Analysis
- Extract API endpoints from JS files
- Detect exposed secrets (API keys, tokens, AWS keys)
- Find hidden paths and admin routes
- Identify potential vulnerabilities in client code

### Web Dashboard
- Real-time scan visualization
- Severity-based statistics cards
- Interactive findings table
- CVE correlation view
- WebSocket live updates
- Dark theme for long sessions

## Quick Start

```bash
git clone https://github.com/Ravel226/PhantomProbe.git
cd PhantomProbe
pip install -e .
phantomprobe example.com
```

## Installation

### Basic (core features, dependency-free)

The core scanner runs on the Python standard library alone.

```bash
pip install -e .
phantomprobe example.com
```

You can also run it without installing:

```bash
PYTHONPATH=src python -m phantomprobe example.com
```

### With the dashboard

```bash
pip install -e ".[dashboard]"
phantomprobe example.com --dashboard
```

### With screenshots

```bash
pip install -e ".[screenshot]"
playwright install chromium
phantomprobe example.com --screenshot
```

### Everything

```bash
pip install -e ".[all]"
```

## Usage

```bash
# Basic scan (Phase 1 - passive only)
phantomprobe example.com

# Add active reconnaissance (ports, subdomains, fingerprinting)
phantomprobe example.com --phase2

# Add CVE matching
phantomprobe example.com --phase2 --cve

# Add a screenshot
phantomprobe example.com --phase2 --cve --screenshot

# Add JavaScript analysis
phantomprobe example.com --phase2 --cve --screenshot --js

# Serve the interactive dashboard when the scan finishes
phantomprobe example.com --phase2 --cve --js --dashboard
```

Equivalent module form, if you prefer not to install the console script:

```bash
python -m phantomprobe example.com --phase2
```

### Dashboard on its own

To serve an empty dashboard (and the `/api/*` endpoints) without running a scan:

```bash
uvicorn phantomprobe.asgi:app --host 127.0.0.1 --port 8080
```

Output files (written to `--output-dir`, default `.`):
- `report-example.com.md` - Markdown report
- `report-example.com.json` - JSON report with CVE data
- `screenshot-example.com.png` - Website screenshot (with `--screenshot`)
- Dashboard at `http://127.0.0.1:8080` (with `--dashboard`)

## Docker Usage

### Quick Start

```bash
# Clone repository
git clone https://github.com/Ravel226/PhantomProbe.git
cd PhantomProbe

# Run with Docker Compose
docker-compose --profile dashboard up

# Or use Docker directly
docker build -t phantomprobe .
mkdir -p reports
docker run -p 8080:8080 -v $(pwd)/reports:/app/reports phantomprobe target.com --dashboard
```

The container runs as uid 1000. If your host directory is owned by a different
uid, the scan fails with `Permission denied` when writing its reports; run it as
yourself instead:

```bash
docker run --user "$(id -u):$(id -g)" -v $(pwd)/reports:/app/reports \
  phantomprobe target.com
```

### Docker Compose Profiles

```bash
# Core edition (lightweight, CLI only)
docker-compose --profile core up phantomprobe-core

# Dashboard edition
# Runs at http://localhost:8080
docker-compose --profile dashboard up phantomprobe-dashboard

# Full edition (all features, larger image)
docker-compose --profile full up phantomprobe-full

# Development mode: serves the dashboard and reloads on source changes
# (mounts ./src, so edits apply without rebuilding the image)
docker-compose --profile dev up phantomprobe-dev

# Dashboard API only, no scan (serves phantomprobe.asgi:app)
docker-compose --profile api up phantomprobe-api

# With Burp Suite integration
docker-compose --profile burp up phantomprobe-burp
```

The compose services bind the dashboard to `0.0.0.0` via
`PHANTOMPROBE_DASHBOARD_HOST` so it is reachable through the published port.

### Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
vim .env

# Run with environment file
docker-compose --profile dashboard --env-file .env up
```

## Burp Suite Integration

PhantomProbe can run a scan in Burp Professional and pull its issues into the
same report as the rest of the scan. Burp's REST API only scans, so results flow
one way: there is no endpoint for pushing findings back into Burp or for driving
the proxy, and PhantomProbe does not claim to do either.

### Prerequisites

1. Burp Suite Professional (this is the local REST API, not the Enterprise
   GraphQL API)
2. Settings > Suite > REST API: enable the service
3. Create an API key on that same screen and copy it, since Burp shows the value
   only once
4. `pip install "phantomprobe[burp]"`

### Configuration

```bash
export BURP_API_KEY=your-api-key
export BURP_API_URL=http://127.0.0.1:1337   # only if you moved the service
```

The key is a path prefix rather than a header: Burp serves the whole API under
`http://127.0.0.1:1337/<your-key>/v0.1/`. Opening that URL in a browser gives
you the API documentation for your exact Burp version.

### Usage

```bash
phantomprobe target.com --burp

# An audit usually needs much longer than the 300s default
phantomprobe target.com --burp --burp-timeout 1800
```

PhantomProbe queues a crawl and audit on `https://<target>`, polls until Burp
reports the scan finished, and converts each issue into a finding that lands in
the Markdown and JSON reports alongside its own. If the scan is still running
when the timeout expires, whatever Burp has found so far is still imported.

### Burp Extension

The starter extension is unrelated to the REST API: it runs inside Burp itself.

```python
from phantomprobe import BurpSuiteEngine

BurpSuiteEngine.generate_extension_template("burp_extension.py")
```

Burp runs Python extensions on Jython 2.7, so the generated file is Python 2.
Install it under Extensions > Installed > Add, with extension type Python.

## CLI Options

| Flag | Description |
|------|-------------|
| `-a`, `--phase2` | Enable active reconnaissance (ports, subdomains, fingerprinting, takeover) |
| `--no-takeover` | Skip the takeover check (it queries DoH + third-party services) |
| `-c`, `--cve` | Enable CVE matching via the NVD API |
| `-s`, `--screenshot` | Capture website screenshot (requires Playwright) |
| `-j`, `--js` | JavaScript analysis for secrets/endpoints |
| `-b`, `--burp` | Run a Burp Professional scan and import its issues |
| `--burp-timeout SECONDS` | How long to wait for the Burp scan (default: 300) |
| `-d`, `--dashboard` | Launch the interactive web dashboard |
| `-v`, `--verbose` | Show detailed output |
| `--output-dir DIR` | Where to write reports and screenshots (default: `.`) |
| `--dashboard-host HOST` | Dashboard bind address (default: `$PHANTOMPROBE_DASHBOARD_HOST` or `127.0.0.1`) |
| `--dashboard-port PORT` | Dashboard port (default: `$PHANTOMPROBE_DASHBOARD_PORT` or `8080`) |
| `--no-browser` | Do not open a browser when starting the dashboard |
| `--version` | Print the version and exit |

Run `phantomprobe --help` for the authoritative list.

## Requirements

- **Python 3.8+** (required)
- **Standard library only** for core reconnaissance - no third-party packages needed

Optional features are installed as extras:

| Extra | Enables | Install |
|-------|---------|---------|
| `dashboard` | FastAPI web dashboard | `pip install -e ".[dashboard]"` |
| `screenshot` | Playwright screenshots | `pip install -e ".[screenshot]"` then `playwright install chromium` |
| `burp` | Burp Suite REST integration | `pip install -e ".[burp]"` |
| `all` | Everything above | `pip install -e ".[all]"` |
| `dev` | Test and lint tooling | `pip install -e ".[dev]"` |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Raises the NVD rate limit from 5 to 50 requests / 30s. Without it, `--cve` throttles to ~1 query every 6.5s. [Request one here](https://nvd.nist.gov/developers/request-an-api-key). |
| `BURP_API_KEY` | Burp REST API key, used by `--burp`. Sent as a URL path prefix. |
| `BURP_API_URL` | Burp REST service URL (default: `http://127.0.0.1:1337`). |
| `PHANTOMPROBE_DASHBOARD_HOST` | Dashboard bind address (set to `0.0.0.0` in Docker). |
| `PHANTOMPROBE_DASHBOARD_PORT` | Dashboard port. |

## Dashboard Preview

```
┌─────────────────────────────────────────────────────────────┐
│  PhantomProbe Dashboard                                     │
│  Target: example.com | Scan Time: 2026-03-02T12:00:00      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                  │
│  │  12 │ │  3  │ │  5  │ │  8  │ │ 23  │  Total Findings │
│  │TOTAL│ │CRIT │ │ HIGH│ │ MED │ │ INFO│                  │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘                  │
├─────────────────────────────────────────────────────────────┤
│  Findings                                                  │
│  ├─ [CRITICAL] CVE-2024-3566 - PHP vulnerability            │
│  ├─ [HIGH]     DNS-AAAA - IPv6 DNS record                   │
│  └─ ...                                                     │
├─────────────────────────────────────────────────────────────┤
│  CVE Matches                                               │
│  ├─ CVE-2024-3566 (CVSS 9.8) - PHP/8.2.29                 │
│  └─ ...                                                     │
└─────────────────────────────────────────────────────────────┘
```

## Architecture

```
PhantomProbe/
├── src/phantomprobe/
│   ├── __init__.py       # Public API
│   ├── __main__.py       # python -m phantomprobe
│   ├── cli.py            # Argument parsing and scan orchestration
│   ├── constants.py      # Version and User-Agent (single source of truth)
│   ├── models.py         # Finding, Severity
│   ├── passive.py        # Phase 1: DNS, SSL/TLS, HTTP headers
│   ├── active.py         # Phase 2: ports, subdomains, fingerprinting
│   ├── cve.py            # NVD correlation
│   ├── js.py             # JavaScript endpoint/secret discovery
│   ├── screenshot.py     # Playwright capture
│   ├── burp.py           # Burp Suite REST integration
│   ├── report.py         # Markdown and JSON reports
│   ├── dashboard.py      # FastAPI dashboard
│   └── asgi.py           # Standalone ASGI entry point
├── tests/                # pytest suite
├── Dockerfile            # Multi-stage build
├── docker-compose.yml    # Compose profiles
└── pyproject.toml        # Packaging and tool config
```

## Development

```bash
pip install -e ".[all,dev]"

pytest tests/ -v              # run the test suite
pytest tests/ --cov=phantomprobe   # with coverage
black src/ tests/             # format
flake8 src/ tests/            # lint
bandit -r src/ -ll            # security scan
```

## Roadmap

### v0.8.0 (current)
- [x] Burp Suite integration
- [x] Docker support with compose profiles
- [x] Modular package layout

### Next
- [ ] Custom wordlists for subdomain enumeration
- [ ] CSV/Excel export
- [ ] Async I/O for the scanning engines

### v1.0.0
- [ ] Plugin system
- [ ] Multi-target scanning
- [ ] CI/CD integration
- [ ] Webhook notifications

## Security Notice

**Use only on systems you own or have explicit permission to test.**

This tool is designed for authorized penetration testing and security research only. Unauthorized scanning of systems you do not own is illegal and unethical.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

## Author

- **Ravel226**
- GitHub: [@Ravel226](https://github.com/Ravel226)

## License

MIT License - See [LICENSE](LICENSE) file

## Acknowledgments

- CVE data from [NVD](https://nvd.nist.gov/)
- Inspired by recon-ng and other reconnaissance tools
- Built with [FastAPI](https://fastapi.tiangolo.com/) for the dashboard

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

<p align="center">
  <sub>Built by Ravel226</sub>
</p>
