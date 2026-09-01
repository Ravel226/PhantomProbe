# PhantomProbe

**Reconnaissance Scanner for Penetration Testing**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com/)

PhantomProbe is a lightweight vulnerability reconnaissance scanner for penetration testers and security researchers. It performs passive and active analysis, correlates findings with known CVEs, captures visual documentation, discovers JavaScript secrets, and provides an interactive web dashboard.

## v0.8.0 - Burp Suite Integration & Docker Support

New features:
- **Burp Suite Integration** - Professional/Enterprise REST API support
  - Send requests through Burp Proxy
  - Import Burp scan results automatically
  - Export PhantomProbe findings to Burp
  - Generate Burp Extension template
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

### Phase 2 - Active Reconnaissance
- Port scanning - Common ports with service identification
- Subdomain enumeration - Common subdomain discovery
- Technology fingerprinting - Server and framework detection

### CVE Correlation
- Automatic matching of discovered technologies to known CVEs
- CVSS score-based filtering (>= 7.0)
- CPE 2.3 compatible lookups via NVD API

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

### Prerequisites

1. Burp Suite Professional or Enterprise
2. Enable REST API in Burp (User options → Misc → REST API)
3. Generate API key

### Configuration

```bash
# Set environment variables
export BURP_API_URL=http://127.0.0.1:1337
export BURP_API_KEY=your-api-key

# Or use .env file
echo "BURP_API_KEY=your-key-here" > .env
```

### Usage

```bash
# Scan target and send to Burp
phantomprobe target.com --burp

# The scanner will:
# 1. Run reconnaissance
# 2. Send target to Burp Proxy
# 3. Import Burp scan issues
# 4. Export findings back to Burp
```

### Burp Extension

Generate a custom Burp extension:

```python
from phantomprobe import BurpSuiteEngine

# Generate extension template
BurpSuiteEngine.generate_extension_template("burp_extension.py")

# Install in Burp Extensions → Installed → Add
```

## CLI Options

| Flag | Description |
|------|-------------|
| `-a`, `--phase2` | Enable active reconnaissance (ports, subdomains, fingerprinting) |
| `-c`, `--cve` | Enable CVE matching via the NVD API |
| `-s`, `--screenshot` | Capture website screenshot (requires Playwright) |
| `-j`, `--js` | JavaScript analysis for secrets/endpoints |
| `-b`, `--burp` | Burp Suite Professional integration (requires requests) |
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
| `BURP_API_KEY` | Burp Suite REST API key, used by `--burp`. |
| `PHANTOMPROBE_DASHBOARD_HOST` | Dashboard bind address (set to `0.0.0.0` in Docker). |
| `PHANTOMPROBE_DASHBOARD_PORT` | Dashboard port. |

## Dashboard Preview

```
┌─────────────────────────────────────────────────────────────┐
│  🐚 PhantomProbe Dashboard                                  │
│  Target: example.com | Scan Time: 2026-03-02T12:00:00      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                  │
│  │  12 │ │  3  │ │  5  │ │  8  │ │ 23  │  Total Findings │
│  │TOTAL│ │CRIT │ │ HIGH│ │ MED │ │ INFO│                  │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘                  │
├─────────────────────────────────────────────────────────────┤
│  🔍 Findings                                                │
│  ├─ [CRITICAL] CVE-2024-3566 - PHP vulnerability            │
│  ├─ [HIGH]     DNS-AAAA - IPv6 DNS record                   │
│  └─ ...                                                     │
├─────────────────────────────────────────────────────────────┤
│  🐛 CVE Matches                                             │
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

⚠️ **Use only on systems you own or have explicit permission to test.**

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
