# PhantomProbe 🔍

**AI-Powered Reconnaissance for Bug Bounty Hunters**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![HackerOne](https://img.shields.io/badge/Bug%20Bounty-Ready-green.svg)](https://hackerone.com)

PhantomProbe is a lightweight vulnerability reconnaissance scanner designed for ethical hackers and bug bounty hunters. It performs passive analysis to identify security misconfigurations without exploitation.

> *"A ghost in the machine, hunting for truth in the shadows."*

## 🆕 v0.2.0 - Phase A Complete

New passive reconnaissance modules:
- **DNS Analysis** - A/AAAA records, reverse DNS, wildcard detection
- **SSL/TLS Analysis** - Certificate info, expiry checks, weak ciphers, deprecated TLS versions
- **HTTP Headers** - Security headers, information disclosure detection

## ✨ Features

- **🔍 Passive Reconnaissance** — Safe for production environments
- **🛡️ Security Header Analysis** — Detects 10+ security misconfigurations  
- **🕵️ Information Disclosure Detection** — Finds leaked technology fingerprints
- **📊 HackerOne-Compatible Reports** — Markdown + JSON output formats
- **⚡ Zero Dependencies** — Standard library only (Python 3.8+)
- **🎨 Terminal Colors** — Easy-to-read scan results

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Ravel226/phantomprobe.git
cd phantomprobe

# Run a scan
python3 phantomprobe.py target.com
```

## 📋 Usage

```bash
# Basic scan
python3 phantomprobe.py example.com

# Scan with verbose output
python3 phantomprobe.py example.com --verbose

# Output files generated:
# - report-example.com.md    (HackerOne format)
# - report-example.com.json  (Machine readable)
```

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════╗
║  PhantomProbe v0.1.0                                     ║
║  Ghost in the Machine                                    ║
╚══════════════════════════════════════════════════════════╝

Target: laurellewourougou.com
Scan Date: 2026-02-23T23:21:18

[Phase 1] Reconnaissance ──────────────────────────────────
  ✓ HTTP Headers        ... 4 findings
  ✓ Information Disclosure ... 2 findings
  ✓ Security Analysis     ... 2 findings

Scan Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total Findings:        8

  [!] CRITICAL:          0
  [!!] HIGH:             0
  [!] MEDIUM:            0
  [⚠] LOW:               1
  [ℹ] INFORMATIONAL:     7

Findings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[LOW]     SESSION-Cache: PHP Session Configuration
[INFO]    INFO-XPoweredBy: Technology Stack Disclosure
[INFO]    INFO-Server: Server Banner Disclosure
[INFO]    HEADER-Good: Security Headers Well Configured

[✓] Reports saved:
    • report-laurellewourougou.com.md
    • report-laurellewourougou.com.json
```

## 🔧 What PhantomProbe Detects

### Security Headers
- ✅ Strict-Transport-Security (HSTS)
- ✅ Content-Security-Policy (CSP)
- ✅ X-Frame-Options (Clickjacking)
- ✅ X-Content-Type-Options
- ✅ Referrer-Policy
- ✅ Permissions-Policy

### Information Disclosure
- 🤫 X-Powered-By header
- 🤫 Server banner leaks
- 🤫 Technology fingerprints
- 🤫 Framework version hints

### Session Management
- 🔒 Secure cookie flags
- 🔒 HttpOnly attributes
- 🔒 SameSite configuration
- 🔒 Cache control headers

## 🐍 Installation

### From Source
```bash
git clone https://github.com/Ravel226/phantomprobe.git
cd phantomprobe
chmod +x phantomprobe.py

# Optional: create symlink
ln -s $(pwd)/phantomprobe.py ~/.local/bin/phantomprobe
```

### Requirements
- Python 3.8+
- No external dependencies (standard library only!)

## 📖 HackerOne Integration

PhantomProbe generates reports compatible with HackerOne submission format:

```markdown
## Summary
[Brief vulnerability description]

## Steps to Reproduce
1. Visit target.com
2. Observe response headers
3. ...

## Impact
[Security impact assessment]

## Evidence
```
[X-Powered-By: PHP/8.2.29]
```

## Remediation
[Fix recommendation]

## References
- https://owasp.org/...
```

## 🗺️ Roadmap

### v0.2.0 (Next)
- [ ] Active reconnaissance (nmap-style port scanning)
- [ ] Subdomain enumeration
- [ ] SSL/TLS certificate analysis
- [ ] Technology fingerprinting (Wappalyzer-style)

### v0.3.0  
- [ ] AI integration (Kimi/Qwen for analysis)
- [ ] CVE matching and correlation
- [ ] Screenshot capture (Puppeteer integration)
- [ ] API endpoint discovery

### v1.0.0
- [ ] Web dashboard
- [ ] HackerOne API bridge (auto-import targets)
- [ ] CI/CD integration (GitHub Actions)
- [ ] Burp Suite extension

## 🤝 Contributing

Contributions welcome! Areas we need help:

- [ ] Additional security checks
- [ ] Report templates (other platforms)
- [ ] Documentation translations
- [ ] Test cases

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## ⚠️ Disclaimer

**For authorized testing only.** 

PhantomProbe is designed for:
- ✅ Your own systems
- ✅ Bug bounty programs (with explicit scope)
- ✅ Vulnerability disclosure programs
- ✅ Authorized penetration testing

**Never use on systems you don't own or have permission to test.**

## 🙏 Credits

- Inspired by [web-check](https://github.com/Lissy93/web-check) — Comprehensive website analyzer
- Architecture influenced by [PentAGI](https://github.com/vxcontrol/pentagi) — Autonomous AI pentesting
- Built with ❤️ by Ravel226 and Nylah 🐚

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built for bug bounty hunters, by a bug bounty hunter.</sub>
</div>
