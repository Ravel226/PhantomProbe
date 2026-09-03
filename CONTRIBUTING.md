# Contributing to PhantomProbe

Thanks for your interest. This document covers the setup and the conventions
that keep the scanner trustworthy.

## Development setup

```bash
git clone https://github.com/Ravel226/PhantomProbe.git
cd PhantomProbe

python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate

pip install -r requirements-dev.txt  # editable install + all extras + tooling
```

## Running the checks

```bash
pytest                       # the suite runs offline; no target is needed
pytest --cov=phantomprobe    # with coverage
black src tests              # format
flake8 src tests             # lint
bandit -r src -ll            # security scan (CI fails on medium+ findings)
```

## Project conventions

These are the habits that make the difference between a scanner people trust and
one they learn to ignore.

### Verify data against its source, don't transcribe it

Every lookup table here (the CVE CPE map, the takeover fingerprints, the WAF
signatures) was checked against the authority before landing, and the
verification is repeatable. A wrong CPE vendor, for instance, returns a clean
empty result from NVD, so a broken mapping looks exactly like a clean target.

- CVE mappings: `python scripts/audit_cpe_mapping.py --check vendor:product`
  before adding one, and re-run the whole script periodically as vendors change
  hands.
- Fingerprint tables: generate them from the upstream source rather than typing
  them out, and add a test that guards their shape.

### Calibrate severity to real impact

Severity is what a finding buys an attacker today, not what a checklist said
years ago. A missing `SameSite` is hardening (browsers already default to Lax);
a session cookie readable by script is a genuine risk. When you are unsure, look
up the current behavior at the source (MDN, the relevant RFC, the vendor) and
put the reasoning in a comment.

A scanner that cries wolf gets muted. On a well-configured target, a check
should produce nothing.

### Tests touch no network

Every test stubs its I/O. Reach for a real host only to develop against, never
in the committed suite: it must pass offline and deterministically. Cover the
paths a healthy target never takes (a missing SPF, a public bucket), since those
are the ones a live run cannot show you.

### Keep the core dependency-free

The default install has no runtime dependencies. Anything a feature needs goes
in an optional extra in `pyproject.toml` and is imported lazily inside the
module that uses it, so importing the package never fails for a missing extra.

### Active behavior is opt-in

Passive checks read what the target exposes. Anything that sends crafted
requests belongs behind `--aggressive` and must be non-destructive: no request
rewriting, no writes, nothing that can disrupt other users of a shared host.

## Pull requests

1. Fork and branch (`git checkout -b feature/thing`)
2. Add tests for the new behavior, including the negative cases
3. Run the full check list above; it must be green
4. Update the README if you added a check or a flag
5. Open a PR with a description of what changed and why

Commit messages: present tense, imperative mood, first line under 72 characters,
with the reasoning in the body.

## Security

- Never commit secrets, credentials, or `.env` files
- Report vulnerabilities in PhantomProbe itself privately, not in a public issue
