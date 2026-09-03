# PhantomProbe

**Passive-first reconnaissance scanner for penetration testers and bug bounty hunters.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-264%20passing-brightgreen.svg)](tests/)

PhantomProbe maps a target's attack surface and reports what is actually wrong
with it. The core runs on the Python standard library alone, so a default
install has no dependencies and starts in one command. Optional features (a web
dashboard, screenshots, a Burp bridge) each pull in their own packages and
nothing else.

Two ideas run through it:

- **Observe before you touch.** Everything except the opt-in `--aggressive`
  phase either reads what the target already sends or resolves DNS. Records that
  the standard library cannot reach, such as TXT, MX and DNSKEY, are fetched
  over DNS-over-HTTPS rather than by adding a DNS dependency.
- **Say something only when it means something.** Severities are set by what a
  finding buys an attacker today, not by dated checklists. A missing `SameSite`
  is hardening; a session cookie readable by script is not. A CVE that CISA
  lists as exploited outranks a higher-scored one nobody uses. On a
  well-configured target, PhantomProbe stays quiet.

## Quick start

```bash
git clone https://github.com/Ravel226/PhantomProbe.git
cd PhantomProbe
pip install -e .
phantomprobe example.com
```

That first scan is entirely passive. Add phases as you need them:

```bash
phantomprobe example.com --phase2                 # active recon (ports, subdomains, takeover)
phantomprobe example.com --phase2 --cve           # correlate versions to CVEs (KEV/EPSS ranked)
phantomprobe example.com --phase2 --cve --js      # add JavaScript endpoint/secret discovery
phantomprobe example.com --phase2 --aggressive    # opt-in active probes (authorized targets only)
phantomprobe example.com --phase2 --cve --dashboard   # serve results in the web UI
```

Every scan writes `report-<target>.md` and `report-<target>.json` to the
`--output-dir` (default: the current directory).

## Installation

The core scanner is dependency-free. Install extras only for the features you
want; `pip install -e .` is enough for a full passive and active scan.

| Command | Adds |
|---------|------|
| `pip install -e .` | Core scanner (no dependencies) |
| `pip install -e ".[dashboard]"` | Interactive web dashboard (FastAPI, uvicorn) |
| `pip install -e ".[screenshot]"` | Full-page screenshots (Playwright) |
| `pip install -e ".[burp]"` | Burp Professional REST integration (requests) |
| `pip install -e ".[all]"` | Every feature above |

Screenshots need the browser as well as the package:

```bash
pip install -e ".[screenshot]"
playwright install chromium
```

Run it without installing at all, straight from a checkout:

```bash
PYTHONPATH=src python -m phantomprobe example.com
```

## What it checks

### Phase 1: passive (always on)

Reads what the target already sends and resolves DNS. No probing.

- **DNS** - A/AAAA records, reverse DNS, wildcard detection
- **SSL/TLS** - certificate details and expiry, weak ciphers, deprecated TLS versions
- **Security headers** - the six response headers that harden a browser session (CSP, HSTS, X-Frame-Options and the rest)
- **Cookies** - `Secure`, `HttpOnly` and `SameSite`, weighted by whether a
  cookie looks like a session or a tracker
- **Email security** - SPF, DMARC and DKIM over DoH. Missing SPF or DMARC lets
  anyone forge mail from the domain, the cheapest phishing route into an org
- **CAA and DNSSEC** - certificate-issuance restrictions and zone signing,
  reported as hardening
- **HSTS preload eligibility** - judged against hstspreload.org's current
  one-year `max-age` floor
- **Redirect chain** - flags plain HTTP that never reaches HTTPS, and redirects
  that leave the target host
- **security.txt** - the RFC 9116 disclosure contact

### Phase 2: active reconnaissance (`--phase2`)

- **Port scan** - common service ports, concurrently
- **Subdomain enumeration** - common-name discovery
- **Technology fingerprinting** - server and framework detection
- **Subdomain takeover** - dangling-CNAME detection against a two-signal check
  (the CNAME must point at a known service *and* the service must report the
  resource unclaimed), using the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
  fingerprints. Disable with `--no-takeover`.
- **WAF / CDN** - passive fingerprinting of 35 WAFs from the wafw00f signature set

### CVE correlation (`--cve`)

Matches fingerprinted technology versions to NVD, across 74 products whose CPE
vendor/product pairs were each verified against the live API before being added
(a wrong vendor returns a clean empty result, so it fails silently). It only
correlates where a banner gave a version, reads CVSS v4.0/v3.1/v3.0/v2 scores,
and enriches every match with:

- **CISA KEV** - whether the CVE is exploited in the wild, with a ransomware marker
- **EPSS** - the probability of exploitation in the next 30 days

An exploited CVE is ranked above a higher-scored dormant one. Keep the CPE table
honest as vendors change hands:

```bash
python scripts/audit_cpe_mapping.py            # re-check every mapping against NVD
```

### Phase 3: active vulnerability probing (`--aggressive`, opt-in)

Off by default, and it prints an authorization notice when it runs, because
these checks send crafted requests to the target rather than observing it. All
four are non-destructive.

- **CORS** - a reflected origin with credentials is high; a bare `*`, which
  browsers already block from credentialed use, is not reported
- **Open redirect** - common redirect parameters on the root path
- **HTTP parameter pollution** - flags a status-code change on a duplicated
  parameter, filed as an informational hint
- **S3 buckets** - guesses bucket names from the domain; a public listing is high

Request smuggling is deliberately excluded: a faithful probe desyncs the
connection and can affect other users of a shared server, which belongs in a
dedicated tool under a scoped engagement.

### Other features

- **JavaScript analysis** (`--js`) - extracts API endpoints, exposed secrets
  (API keys, tokens, AWS keys) and hidden paths from linked scripts
- **Screenshot** (`--screenshot`) - a full-page capture via headless Chromium
- **Burp Professional** (`--burp`) - runs a Burp scan and imports its issues; see below

## CLI options

| Flag | Description |
|------|-------------|
| `-a`, `--phase2` | Active recon: ports, subdomains, fingerprinting, takeover |
| `--no-takeover` | Skip the takeover check (it queries DoH and third-party services) |
| `--aggressive` | Phase 3 active probes. Sends crafted requests; authorized targets only |
| `-c`, `--cve` | CVE correlation via NVD, ranked by KEV and EPSS |
| `-s`, `--screenshot` | Full-page screenshot (needs `[screenshot]`) |
| `-j`, `--js` | JavaScript endpoint and secret discovery |
| `-b`, `--burp` | Run a Burp Professional scan and import its issues (needs `[burp]`) |
| `--burp-timeout SECONDS` | How long to wait for the Burp scan (default: 300) |
| `-d`, `--dashboard` | Serve the interactive web dashboard (needs `[dashboard]`) |
| `--output-dir DIR` | Where to write reports and screenshots (default: `.`) |
| `-v`, `--verbose` | Verbose output |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Raises the NVD rate limit from 5 to 50 requests / 30s. Without it, `--cve` throttles to ~1 query every 6.5s. [Request one](https://nvd.nist.gov/developers/request-an-api-key). |
| `BURP_API_KEY` | Burp REST API key, used by `--burp`. Sent as a URL path prefix. |
| `BURP_API_URL` | Burp REST service URL (default: `http://127.0.0.1:1337`). |
| `PHANTOMPROBE_DASHBOARD_HOST` | Dashboard bind address (default: `127.0.0.1`). |
| `PHANTOMPROBE_DASHBOARD_PORT` | Dashboard port (default: `8080`). |

## Reports and dashboard

Each scan writes two reports next to the output directory:

- `report-<target>.md` - a HackerOne-style Markdown report
- `report-<target>.json` - the same findings as structured JSON, including the
  CVE matches with their KEV and EPSS fields

The `--dashboard` flag serves the findings in a dark, dense web UI with
severity filtering, live WebSocket updates, and a CVE table that surfaces which
matches are actively exploited. Serve an empty dashboard, without running a
scan, straight from the ASGI app:

```bash
pip install -e ".[dashboard]"
uvicorn phantomprobe.asgi:app --host 127.0.0.1 --port 8080
```

## Docker

```bash
git clone https://github.com/Ravel226/PhantomProbe.git
cd PhantomProbe
mkdir -p reports

# One-off scan (results land in ./reports)
docker build -t phantomprobe .
docker run -v "$(pwd)/reports:/app/reports" phantomprobe example.com --output-dir /app/reports
```

The container runs as uid 1000. If your host `reports/` directory is owned by a
different user, the scan fails with `Permission denied`; run it as yourself with
`--user "$(id -u):$(id -g)"`.

Compose ships a profile per edition:

```bash
docker compose --profile core up phantomprobe-core            # CLI only, smallest image
docker compose --profile dashboard up phantomprobe-dashboard  # dashboard at http://localhost:8080
docker compose --profile full up phantomprobe-full            # every feature, includes Chromium
docker compose --profile dev up phantomprobe-dev              # dashboard with source reload
docker compose --profile api up phantomprobe-api              # dashboard API only, no scan
docker compose --profile burp up phantomprobe-burp            # with a Burp REST endpoint
```

## Burp Suite integration

PhantomProbe can run a scan in Burp Professional and pull its issues into the
same report. Burp's REST API only scans, so results flow one way: there is no
endpoint for pushing findings back or driving the proxy, and PhantomProbe does
not pretend to offer either.

1. Burp Professional: enable the REST API under Settings → Suite → REST API
2. Create an API key on that screen (Burp shows the value only once)
3. `pip install -e ".[burp]"`

```bash
export BURP_API_KEY=your-api-key
phantomprobe target.com --burp --burp-timeout 1800
```

The key is a URL path prefix, not a header: Burp serves the API under
`http://127.0.0.1:1337/<your-key>/v0.1/`. Opening that URL in a browser shows
the API documentation for your exact Burp version.

## Architecture

```
src/phantomprobe/
├── cli.py            Argument parsing and scan orchestration
├── constants.py      Version and User-Agent (single source of truth)
├── models.py         Finding, Severity
├── http_client.py    Fetch helper with a URL-scheme allowlist
├── doh.py            DNS-over-HTTPS resolver (shared)
│
├── passive.py        Phase 1: DNS, SSL/TLS, HTTP headers
├── cookies.py        Cookie security attributes
├── dns_security.py   SPF, DMARC, DKIM, CAA, DNSSEC
├── http_checks.py    HSTS preload, redirect chain, security.txt
│
├── active.py         Phase 2: ports, subdomains, fingerprinting
├── takeover.py       Subdomain takeover (two-signal)
├── waf.py            WAF/CDN fingerprinting
│
├── aggressive.py     Phase 3: CORS, open redirect, HPP, S3 (opt-in)
│
├── cve.py            NVD correlation + KEV/EPSS enrichment
├── js.py             JavaScript endpoint/secret discovery
├── screenshot.py     Playwright capture            (extra: screenshot)
├── burp.py           Burp REST integration         (extra: burp)
├── report.py         Markdown and JSON reports
├── dashboard.py      FastAPI dashboard             (extra: dashboard)
└── asgi.py           Standalone ASGI entry point   (extra: dashboard)

scripts/audit_cpe_mapping.py   Re-check the CVE table against live NVD
tests/                         264 tests, network stubbed
```

## Development

```bash
pip install -r requirements-dev.txt   # editable install with all extras + tooling

pytest                    # run the suite (network is stubbed; no target needed)
pytest --cov=phantomprobe # with coverage
black src tests           # format
flake8 src tests          # lint
bandit -r src -ll         # security scan
```

The test suite stubs every network call, so it runs offline and touches no real
host. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## Security notice

**Use PhantomProbe only against systems you own or are explicitly authorized to
test.** Passive checks read what a target already exposes, but active
reconnaissance (`--phase2`) and vulnerability probing (`--aggressive`) send
traffic to it. Unauthorized scanning is illegal in most jurisdictions.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

## Credits

- CVE data from [NVD](https://nvd.nist.gov/); exploitation data from
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
  [FIRST EPSS](https://www.first.org/epss/)
- Takeover fingerprints from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- WAF signatures derived from [wafw00f](https://github.com/EnableSecurity/wafw00f)

## License

MIT - see [LICENSE](LICENSE). Author: [@Ravel226](https://github.com/Ravel226).

## Changelog

Release history and unreleased changes are in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are welcome. Fork, branch, add tests, and open a pull request.
See [CONTRIBUTING.md](CONTRIBUTING.md).
