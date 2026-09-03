# Changelog

All notable changes to PhantomProbe are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A large body of work turning the single-file scanner into a modular,
passive-first package. Every data table and calibration below was checked
against its live source before shipping. Suggested release: 0.9.0.

### Added

- **Subdomain takeover detection** (`--phase2`). A two-signal check: the CNAME
  must point at a known service *and* the service must report the resource
  unclaimed, using the can-i-take-over-xyz fingerprints. Resolves CNAMEs over
  DNS-over-HTTPS so the core stays dependency-free.
- **Email security** over DoH: SPF, DMARC and DKIM, with `+all` treated as
  worse than a missing record, and DKIM reporting only the selectors it finds.
- **CAA and DNSSEC** checks, reported as hardening.
- **Cookie security** analysis (`Secure`, `HttpOnly`, `SameSite`), weighted by
  whether a cookie looks like a session or a tracker.
- **WAF / CDN fingerprinting** of 35 WAFs from the wafw00f signature set.
- **HSTS preload eligibility**, judged against hstspreload.org's current
  one-year `max-age` floor; **redirect-chain** analysis; and **security.txt**
  discovery.
- **CVE exploitation intelligence**: every match is enriched with CISA KEV
  (exploited in the wild, with a ransomware marker) and EPSS (probability of
  exploitation), and an exploited CVE now ranks above a higher-scored dormant one.
- **Phase 3 active vulnerability probing** (`--aggressive`, opt-in): CORS, open
  redirect, HTTP parameter pollution and S3 bucket exposure. Non-destructive;
  request smuggling deliberately excluded.
- **CPE audit script** (`scripts/audit_cpe_mapping.py`) to re-check the CVE
  table against live NVD, and a **CI job** that builds and exercises every
  Docker stage.
- **`requirements-dev.txt`** and a `--no-takeover` flag.

### Changed

- **Restructured** the 2270-line `packages/core/scanner.py` into a proper
  `src/phantomprobe/` package of focused modules, each under 500 lines.
- **Redesigned the dashboard**: a dense, calibrated dark theme that scores zero
  on the impeccable design detector, down from 41 anti-patterns.
- **Expanded the CVE CPE table** from 21 to 74 products, each vendor/product
  pair verified against NVD before being added (nginx corrected to `f5`, express
  to `openjsf`).
- **Version is now single-sourced** from `constants.py` via hatchling, so
  distribution metadata cannot drift from the running code.
- Trimmed the `burp` extra to `requests` alone, and rewrote the README.

### Fixed

- **Packaging and tests were broken**: the wheel shipped only a shim reaching
  the real code through a `sys.path` hack, and all five tests failed on imports.
- **Docker**: the dashboard bound to loopback inside the container (unreachable
  via the published port), the `full` image could not take a screenshot
  (browsers installed as root), and several compose profiles were misconfigured.
- **Console encoding** could abort a whole scan: an unencodable byte in output
  raised on a legacy code page, discarding every finding.
- **Burp integration** was rewritten against the API Burp actually exposes; the
  old code sent the key as a header instead of a path prefix and read fields
  that do not exist.
- **CVE correlation returned nothing**: a padded CPE matched zero results in
  NVD, two vendor mappings were wrong, and CVSS v4.0 scores were unread.

### Security

- Fixed **stored XSS** in the dashboard: target- and finding-derived fields are
  now HTML-escaped before rendering.
- All outbound fetches go through a helper enforcing an **http/https scheme
  allowlist**, so a hostile page cannot point the scanner at `file://`.

## [0.8.1] - 2026-03-11

### Added
- WebSocket live scanning with an improved dashboard UI.

## [0.8.0] - 2026-03-10

### Added
- Burp Suite integration and multi-stage Docker support with compose profiles.

## [0.7.2] - 2026-03-08

### Added
- CI/CD workflows, a test suite, and contributing guidelines.

## [0.7.0] - 2026-03-02

### Added
- Interactive FastAPI web dashboard.

## [0.6.0] - 2026-03-02

### Added
- JavaScript endpoint and secret discovery.

## [0.5.0] - 2026-03-02

### Added
- Full-page screenshot capture via Playwright.

## [0.4.0] - 2026-03-01

### Added
- CVE matching via the NVD API.

## [0.3.0] - 2026-02-28

### Added
- Phase 2 active reconnaissance: port scanning, subdomain enumeration, and
  technology fingerprinting.

## [0.2.0] - 2026-02-28

### Added
- Phase 1 passive reconnaissance: DNS and SSL/TLS analysis.

## [0.1.0]

### Added
- Initial release.

[Unreleased]: https://github.com/Ravel226/PhantomProbe/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.8.1
[0.8.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.8.0
[0.7.2]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.7.2
[0.7.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.7.0
[0.6.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.6.0
[0.5.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.5.0
[0.4.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.4.0
[0.3.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.3.0
[0.2.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.2.0
[0.1.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.1.0
