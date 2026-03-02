# PhantomProbe

**Reconnaissance Scanner for Penetration Testing**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

PhantomProbe is a lightweight vulnerability reconnaissance scanner for penetration testers and security researchers. It performs passive and active analysis, correlates findings with known CVEs, captures visual documentation, and discovers JavaScript secrets.

## v0.6.0 - JavaScript Discovery

New features:
- JavaScript file analysis
- API endpoint extraction
- Secret/key detection in client-side code
- Hidden path discovery

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

## Quick Start

```bash
git clone https://github.com/Ravel226/phantomprobe.git
cd phantomprobe
python3 phantomprobe.py target.com
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
```

Output files:
- `report-example.com.md` - Markdown report
- `report-example.com.json` - JSON report with CVE data
- `screenshot-example.com.png` - Website screenshot (with --screenshot)

## Requirements

- Python 3.8+
- Standard library (core functionality)
- Optional: Playwright for screenshots
  ```bash
  pip install playwright
  playwright install chromium
  ```

## Roadmap

### v0.7.0 (Next)
- [ ] Web dashboard
- [ ] Burp Suite integration
- [ ] Custom wordlists for subdomain enumeration

### v1.0.0
- [ ] Plugin system
- [ ] Multi-target scanning
- [ ] CI/CD integration

## Disclaimer

For authorized testing only. Only use on systems you own or have explicit permission to test.

## Credits

- Inspired by [web-check](https://github.com/Lissy93/web-check)
- Architecture influenced by [PentAGI](https://github.com/vxcontrol/pentagi)

## License

MIT License
