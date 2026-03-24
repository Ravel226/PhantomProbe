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
python3 phantomprobe.py target.com --dashboard
```

## Installation

### Basic (Core Features)
```bash
git clone https://github.com/Ravel226/PhantomProbe.git
cd PhantomProbe
python3 phantomprobe.py target.com
```

### With Dashboard
```bash
pip install fastapi uvicorn
python3 phantomprobe.py target.com --dashboard
```

### With Screenshots
```bash
pip install playwright
playwright install chromium
python3 phantomprobe.py target.com --screenshot
```

## Usage

```bash
# Basic scan (Phase 1)
python3 phantomprobe.py example.com

# Full scan with active reconnaissance
python3 phantomprobe.py example.com --phase2

# Full scan with CVE matching
python3 phantomprobe.py example.com --phase2 --cve

# Full scan with screenshot
python3 phantomprobe.py example.com --phase2 --cve --screenshot

# Full scan with JavaScript analysis
python3 phantomprobe.py example.com --phase2 --cve --screenshot --js

# Full scan with interactive dashboard
python3 phantomprobe.py example.com --phase2 --cve --js --dashboard
```

### Dashboard Only
```bash
# Start dashboard after scan completes
python3 phantomprobe.py target.com --dashboard
```

Output files:
- `report-example.com.md` - Markdown report
- `report-example.com.json` - JSON report with CVE data
- `screenshot-example.com.png` - Website screenshot (with --screenshot)
- Dashboard at `http://127.0.0.1:8080` (with --dashboard)

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
docker run -p 8080:8080 -v $(pwd)/reports:/app/reports phantomprobe target.com --dashboard
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

# Development mode (auto-reload)
docker-compose --profile dev up phantomprobe-dev

# With Burp Suite integration
docker-compose --profile burp up phantomprobe-burp
```

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
python3 phantomprobe.py target.com --burp

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
| `--phase2` | Enable active reconnaissance |
| `--cve` | Enable CVE matching via NVD API |
| `--screenshot` | Capture website screenshot |
| `--js` | JavaScript analysis for secrets/endpoints |
| `--dashboard` | Launch interactive web dashboard |
| `--verbose` | Show detailed output |

## Requirements

- **Python 3.8+** (required)
- **Standard library** - Core functionality (dependency-free)
- **FastAPI + Uvicorn** - For web dashboard
  ```bash
  pip install fastapi uvicorn
  ```
- **Playwright** - For screenshots
  ```bash
  pip install playwright
  playwright install chromium
  ```

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
├── phantomprobe.py       # Main scanner
├── README.md             # Documentation
├── requirements.txt      # Python dependencies
├── .claude/              # Ruflo agent configs
├── .claude-flow/         # Claude Flow settings
└── reports/              # Generated reports
```

## Roadmap

### v0.8.0 (Next)
- [ ] Burp Suite integration
- [ ] Custom wordlists for subdomain enumeration
- [ ] CSV/Excel export

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
