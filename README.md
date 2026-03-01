# PhantomProbe

**Reconnaissance Scanner for Penetration Testing**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

PhantomProbe is a lightweight vulnerability reconnaissance scanner for penetration testers and security researchers. It performs passive and active analysis to identify security misconfigurations and correlates findings with known CVEs.

## v0.4.0 - CVE Matching

New features:
- CVE correlation via NVD API
- Automatic technology-to-CVE matching
- CVSS score filtering (high/critical only)
- CPE-based vulnerability lookup

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
```

Output files:
- `report-example.com.md` - Markdown report
- `report-example.com.json` - JSON report with CVE data

## What PhantomProbe Detects

### Security Headers
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options (Clickjacking)
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

### Information Disclosure
- X-Powered-By header
- Server banner leaks
- Technology fingerprints
- Framework version hints

### SSL/TLS Issues
- Expired certificates
- Weak ciphers
- Deprecated TLS versions (1.0, 1.1)

### CVE Correlation
- Matches discovered software versions to known vulnerabilities
- Filters by CVSS score (>= 7.0)
- Provides links to vulnerability details

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

## Roadmap

### v0.5.0 (Next)
- [ ] Screenshot capture
- [ ] JavaScript/endpoint discovery
- [ ] Secret detection (API keys in JS)

### v0.6.0
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
