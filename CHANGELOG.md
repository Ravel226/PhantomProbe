# Changelog

All notable changes to PhantomProbe are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.4] - 2026-11-17

### Fixed

- **CVE correlation still missed CVEs filed under other identifiers, for nine
  products.** A search of NVD's whole product dictionary and every CVE record
  (`docs/research/nvd-identifier-study-2026-11-17`) found 9 more identifiers
  for software in the table, and checking those turned up 4 more that its
  rules missed. 11 are now queried, each checked against live NVD at a real
  version. Java 1.6.0 had 459 CVEs under `oracle:jdk` and 196 more under
  `sun:jdk`, 123 of them scored 7.0 or higher. Exim 4.20 had 56 under
  `exim:exim` and 4 more under `university_of_cambridge:exim`, three of them
  7.0 or higher. The others are `oracle:jre` and `oracle:java_se` (Java),
  `django_project:django`, `cloudbees:jenkins`,
  `atlassian:jira_software_data_center`, `magentocommerce:magento`,
  `jetty:jetty`, `beasts:vsftpd` and `nuxtjs:nuxt.js`. Three of them appear
  only in CVE records and not in the product dictionary, so no search of the
  dictionary finds them. Java is now asked about under four identifiers,
  which makes its lookup slower without an NVD API key.
- **Two of the identifiers the study proposed are left out, because what
  they add is not a flaw in the product.** `joyent:node.js` holds two npm
  packages filed against Node.js versions, and would have reported Node.js
  0.8.3 with a 7.5 and a 10.0 it does not have. `samba:samba_server` holds
  one CVE, which is Apple's Samba on Mac OS X. The table now states this as
  a rule, and a test keeps both out. The checks behind both entries are in
  `docs/research/nvd-identifier-study-2026-11-17/followup/`.
- **The CPE audit could pass a dead identifier.** It kept each verdict under a
  label made of the technology and the product name, so where NVD files one
  product under two vendors with the same product name (Spring, and now Jetty
  and Magento), the second verdict overwrote the first. The label now names
  the vendor too. Run against live NVD after this change, all 110 identifiers
  in the table returned CVEs.
- **A gateway error from NVD made a product look clean.** NVD's 502 and 504
  answers were not retried, unlike 503, 429 and timeouts, so the identifier
  asked about returned nothing for that scan. One of 27 requests got a 502
  while the identifiers above were being checked. Both are now retried with
  the same pauses, and the CPE audit retries them too instead of leaving the
  pair unchecked.

### Changed

- **Playwright is bounded, and the Docker image pins it.** The dependency had
  no upper limit, which is how a new release stopped the full image from
  building. The `screenshot` and `all` extras now require `playwright<2`, and
  the full image installs one tested release (`PLAYWRIGHT_VERSION` in the
  Dockerfile, 1.65.2). Raising that pin is deliberate and is checked by the
  Docker job in CI. It should be raised regularly, because it also carries the
  browser's security fixes.

## [0.9.3] - 2026-11-17

Each entry below was found by checking the scanner against a known answer, and
confirmed afterwards against live NVD, CISA KEV and real DNS.

### Added

- **Service banners in phase 2.** Where a service speaks first (FTP, SSH,
  SMTP, POP3, IMAP and the MySQL handshake), the port scan now records what it
  sends on connect, and `--cve` correlates the version in it. Nothing is sent
  to draw the banner out. The CPE table already listed OpenSSH, ProFTPD,
  vsftpd, Exim, MySQL and MariaDB, but a scan only recorded that their ports
  were open, so those entries could never match. A port number alone still
  names no product: "Port 3306/MySQL" without a banner is not looked up.
- **A caution on distribution builds.** A distribution fixes a vulnerability
  in the release it ships and keeps the upstream version number, so a version
  match can be a patched system. When the banner a version was read from names
  a distribution, every CVE matched on it says so in the Markdown and JSON
  reports, the console summary and the dashboard, and the CVE section of the
  report opens by stating that a version match is a lead to confirm.

### Fixed

- **A lettered version lost its letter.** OpenSSL 1.1.1w and ProFTPD 1.3.5e
  were looked up as 1.1.1 and 1.3.5, the oldest release of each line. NVD
  compares the letter: it returned 63 CVEs for OpenSSL 1.1.1 and 33 for
  1.1.1w, so fixed vulnerabilities were reported as open. A single trailing
  letter is now kept; the `p1` of `OpenSSH_8.9p1` is still left out.

- **Wildcard DNS filled the report with subdomains that do not exist.** Behind
  a wildcard every name resolves, so one real scan reported all 198 wordlist
  names, nine tenths of its findings, although phase 1 had flagged the
  wildcard. Enumeration now learns the wildcard's answer first and lists only
  names that answer differently, with one note accounting for the rest.
- **CVE correlation missed most current nginx CVEs.** `f5:nginx` returns 41
  results and passed the audit, but NVD files the newer nginx CVEs under
  `f5:nginx_open_source`. For nginx 1.24.0 the scanner saw 2 CVEs of 17, and
  showed 1 of the 10 scored 7.0 or higher. A technology can now carry further
  identifiers (`CPE_SIBLINGS`), queried together and merged.
- **The same gap affected 18 more products.** 42 candidate second identifiers
  were looked up in NVD and 36 exist. 32 of those were asked about a real
  version alongside the identifier in the table, and 25 returned CVEs the
  table's identifier did not; they are now queried too, across 19 products.
  For five products the table's identifier returned nothing at all, which
  looks exactly like a clean target: Joomla 3.9.0 (125 CVEs under
  `joomla:joomla\!`), Docker 20.10.5 (16), Confluence 7.13.0 (14), RabbitMQ
  3.8.9 (8) and IIS 7.5 (3). MySQL 8.0.30 had 147 CVEs under `oracle:mysql`
  and a further 155 under `oracle:mysql_server`, and Magento 2.4.3 had 8
  against 126 under `adobe:magento`. Each addition carries its measurement in
  `cpe_tables.py`, with the identifiers that were measured and left out listed
  beside them. The measurements themselves, with the scripts that produced
  them, are in `docs/research/nvd-identifier-audit-2026-11-16/`.
- **An exploited CVE scoring under 7.0 was dropped before KEV was consulted.**
  The severity cut ran first, so the promise that an exploited CVE outranks a
  dormant one could not hold for CVE-2020-11023 (jQuery, scored 6.1 to 6.9, in
  KEV since 2025). Exploitation data is now fetched before the cut, and a CVE in
  KEV is kept at any score.
- **NVD results were read as one short page.** The client took the first 20 and
  stopped, and NVD sorts oldest first: for `f5:nginx` that page ran from 2009
  to 2014. Pages are now followed to the end, and a cut at the cap is announced.
- **Client-side library versions never reached CVE matching.** Script URLs were
  not recorded as findings, and JavaScript analysis ran after correlation.
  Versioned script assets are now reported and analysis runs first. A script URL
  is read for client-side libraries only, so `spring-1.2.0.js` is not taken for
  the Spring Framework.
- **A busy NVD made a product look clean.** A 503, a 429 or a timeout returned
  nothing for that product. They are now retried, and a timeout while reading
  the response body no longer ends the scan.
- **Technology fingerprinting reported words, not technologies.** Signatures
  were substrings searched across the headers and the page text together, so
  "java" matched any page containing "javascript", ".net" any link to a .net
  domain, and "passenger" a travel site. One real scan credited a WordPress
  site with Java and Node.js. Each signature now names the header, cookie or
  markup it may be found in and matches whole words, and each finding states
  the signal that identified it. Cookie values and request ids are kept out of
  the evidence.
- **The full Docker image stopped building.** The `playwright` dependency has
  no upper bound and resolved to 1.65, whose bundled Node driver needs
  `libatomic`. The slim base image does not ship it, so `playwright install`
  could not start. The full image now installs `libatomic1`.
- **CI could not run Python 3.8 or 3.9.** `ubuntu-latest` moved to Ubuntu
  26.04, which has no build of either version, so both jobs failed before any
  test ran. The test job is pinned to `ubuntu-24.04`.

### Changed

- The CPE audit checks sibling identifiers alongside their technology, and its
  documentation states what a passing count does and does not prove.
- `cve.py` is split by responsibility into `cve.py` (correlation), `nvd.py`
  (the NVD client) and `cpe_tables.py` (the identifier tables), each under 500
  lines. `CVEMatcher` keeps its interface.
- IIS is reported as `iis` rather than folded into `asp.net`, and a WordPress
  generator tag carries its version through to CVE correlation.

## [0.9.2] - 2026-09-11

### Fixed

- **A skipped dashboard was silent.** On a plain `pip install phantomprobe`
  without the `[dashboard]` extra, `--dashboard` correctly skipped the web UI,
  but the only notice printed once at the start and scrolled away during the
  scan, so the run looked like it did nothing. The scan always wrote its reports
  to the current directory, where a user expecting a dashboard would not look.
  The end-of-run summary now always states where the reports were written, and
  says plainly when `--dashboard` was requested without its dependencies, with
  the one command that installs them.

## [0.9.1] - 2026-09-04

### Fixed

- **The CI was red on every run since the 0.9.0 dashboard redesign.** The docker
  job's reachability check grepped the served page for a string the redesign
  removed; it now matches a stable section heading. Local pytest stayed green,
  which is why it went unnoticed.
- **The release workflow could swallow itself**: PyPI publish ran first and was
  mandatory, so a missing token failed the whole run and no GitHub Release was
  created. The Release is now created first and always; the PyPI publish is last
  and runs only when a token is configured.

### Changed

- The README leads with `pip install phantomprobe` now that the package is on
  PyPI, and carries a PyPI version badge.

## [0.9.0] - 2026-09-03

The first packaged release. It consolidates the earlier single-file prototypes
into a modular, passive-first scanner, so several entries below read as fixes
against that prototype. Every data table and severity calibration was checked
against its live source before shipping.

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
  exploitation), and an exploited CVE ranks above a higher-scored dormant one.
- **Phase 3 active vulnerability probing** (`--aggressive`, opt-in): CORS, open
  redirect, HTTP parameter pollution and S3 bucket exposure. Non-destructive;
  request smuggling deliberately excluded.
- **CPE audit script** (`scripts/audit_cpe_mapping.py`) to re-check the CVE
  table against live NVD, and a **CI job** that builds and exercises every
  Docker stage.
- **`requirements-dev.txt`** and a `--no-takeover` flag.

### Changed

- **Restructured** the 2270-line single scanner file into a proper
  `src/phantomprobe/` package of focused modules, each under 500 lines.
- **Redesigned the dashboard**: a dense, calibrated dark theme that scores zero
  on the impeccable design detector, down from 41 anti-patterns.
- **Expanded the CVE CPE table** from 21 to 74 products, each vendor/product
  pair verified against NVD before being added (nginx corrected to `f5`, express
  to `openjsf`).
- **Version is single-sourced** from `constants.py` via hatchling, so
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

[Unreleased]: https://github.com/Ravel226/PhantomProbe/compare/v0.9.4...HEAD
[0.9.4]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.9.4
[0.9.3]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.9.3
[0.9.2]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.9.2
[0.9.1]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.9.1
[0.9.0]: https://github.com/Ravel226/PhantomProbe/releases/tag/v0.9.0
