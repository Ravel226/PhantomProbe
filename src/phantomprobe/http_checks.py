#!/usr/bin/env python3
"""
HTTP posture checks beyond the security headers.

Three passive checks that share a theme: how the site presents itself over
HTTP, rather than what a single header says.

  HSTS preload    Evaluated from the header already fetched, so it costs
                  nothing. Thresholds come from hstspreload.org, not from
                  older write-ups: the current floor is a one-year max-age.
  Redirect chain  Walks the hops from http:// and https:// by hand, which
                  urlopen otherwise follows invisibly. The question worth
                  answering is whether plain HTTP reaches HTTPS at all.
  security.txt    Fetches the RFC 9116 locations. Its absence is not a
                  vulnerability, so it is reported as information.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .constants import USER_AGENT
from .http_client import unverified_context, validate_url
from .models import Finding, Severity

# hstspreload.org: max-age must be at least one year, and both directives are
# required. Older guidance used 10886400 (18 weeks), which no longer qualifies.
HSTS_PRELOAD_MIN_AGE = 31536000

# RFC 9116 puts the file under .well-known and keeps the root path as legacy.
SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")

MAX_REDIRECTS = 10


class _NoRedirect(HTTPRedirectHandler):
    """Stop urllib following redirects so each hop can be recorded."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_no_redirect(url: str, timeout: int = 10):
    """
    Fetch a URL without following redirects.

    Returns (status, headers) or None when the request could not be made. A 3xx
    surfaces as HTTPError once redirection is disabled, which is the case this
    exists to capture, so it is a result rather than an error.
    """
    validate_url(url)
    opener = build_opener(_NoRedirect)
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.headers
    except HTTPError as exc:
        return exc.code, exc.headers
    except (URLError, OSError, ValueError):
        return None


def evaluate_hsts_preload(header: Optional[str]) -> Tuple[bool, List[str]]:
    """
    Judge an HSTS header against the preload list's requirements.

    Returns (eligible, reasons_it_is_not). An absent header returns no reasons:
    the missing-header case is already reported by the security-header check
    and repeating it here would double-count the same gap.
    """
    if not header:
        return False, []

    lowered = header.lower()
    reasons = []

    match = re.search(r"max-age\s*=\s*(\d+)", lowered)
    max_age = int(match.group(1)) if match else 0
    if max_age < HSTS_PRELOAD_MIN_AGE:
        reasons.append(
            f"max-age is {max_age}, below the {HSTS_PRELOAD_MIN_AGE} "
            f"(one year) the preload list requires"
        )
    if "includesubdomains" not in lowered:
        reasons.append("includeSubDomains is not set, so subdomains are unprotected")
    if "preload" not in lowered:
        reasons.append("the preload directive is not present")

    return not reasons, reasons


class HstsPreloadScanner:
    """Report how far the HSTS header is from preload eligibility."""

    def __init__(self, target: str):
        self.target = target

    def analyze(self, headers) -> List[Finding]:
        header = headers.get("Strict-Transport-Security")
        eligible, reasons = evaluate_hsts_preload(header)
        if not header or eligible:
            # Nothing to add: either the header is absent, which the header
            # check already covers, or it already qualifies.
            return []

        # A short max-age leaves a real stripping window; the rest is hardening.
        short_age = any("max-age" in r for r in reasons)
        return [Finding(
            id="HSTS-NotPreloadEligible",
            title="HSTS Not Eligible for Preloading",
            description=(
                "The site sends HSTS but does not meet the preload list's "
                "requirements: " + "; ".join(reasons) + "."
            ),
            severity=Severity.LOW if short_age else Severity.INFORMATIONAL,
            category="Security Headers",
            evidence=f"Strict-Transport-Security: {header}",
            remediation=(
                "To qualify, serve "
                "'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload' and submit at hstspreload.org."
            ),
            references=["https://hstspreload.org/"],
            discovered_at=datetime.now().isoformat(),
            target=self.target,
        )]


class RedirectScanner:
    """Walk the redirect chain from plain HTTP and from HTTPS."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout

    def trace(self, url: str) -> List[Dict[str, object]]:
        """Follow Location headers by hand, returning one entry per hop."""
        chain: List[Dict[str, object]] = []
        current = url
        for _ in range(MAX_REDIRECTS):
            result = _fetch_no_redirect(current, self.timeout)
            if result is None:
                break
            status, headers = result
            location = headers.get("Location") if headers else None
            chain.append({"url": current, "status": status, "location": location})
            if not (300 <= status < 400) or not location:
                break
            # Location may be relative.
            current = urljoin(current, location)
        return chain

    def run(self) -> List[Finding]:
        findings = []
        http_chain = self.trace(f"http://{self.target}")

        if http_chain:
            reached_https = any(
                str(hop["url"]).startswith("https://") for hop in http_chain[1:]
            ) or any(
                str(hop.get("location") or "").startswith("https://")
                for hop in http_chain
            )
            path = " -> ".join(
                f"{hop['url']} [{hop['status']}]" for hop in http_chain
            )

            if not reached_https:
                findings.append(Finding(
                    id="REDIRECT-NoHttpsUpgrade",
                    title="Plain HTTP Is Not Redirected to HTTPS",
                    description=(
                        "A request to http:// never arrives at https://. Traffic "
                        "sent to the plain-HTTP endpoint stays readable in "
                        "transit, and the site cannot qualify for HSTS preloading."
                    ),
                    severity=Severity.MEDIUM,
                    category="Transport",
                    evidence=path,
                    remediation="Redirect all HTTP traffic to HTTPS on the same host.",
                    references=["https://hstspreload.org/"],
                    discovered_at=datetime.now().isoformat(),
                    target=self.target,
                ))
            else:
                findings.append(Finding(
                    id="REDIRECT-Chain",
                    title="HTTP to HTTPS Redirect Chain",
                    description=f"Plain HTTP reaches HTTPS in {len(http_chain)} hop(s).",
                    severity=Severity.INFORMATIONAL,
                    category="Transport",
                    evidence=path,
                    remediation="N/A - information gathering",
                    references=[],
                    discovered_at=datetime.now().isoformat(),
                    target=self.target,
                ))

            # A hop onto another registrable host is worth stating plainly.
            offsite = [
                str(hop["url"]) for hop in http_chain[1:]
                if urlparse(str(hop["url"])).hostname
                and self.target not in str(urlparse(str(hop["url"])).hostname)
            ]
            if offsite:
                findings.append(Finding(
                    id="REDIRECT-Offsite",
                    title="Redirect Leaves the Target Host",
                    description="The chain sends the client to a different host.",
                    severity=Severity.INFORMATIONAL,
                    category="Transport",
                    evidence="\n".join(offsite),
                    remediation="Confirm the destination host is expected.",
                    references=[],
                    discovered_at=datetime.now().isoformat(),
                    target=self.target,
                ))

        return findings


class SecurityTxtScanner:
    """Look for the RFC 9116 security.txt disclosure file."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout

    def run(self) -> List[Finding]:
        from .http_client import safe_urlopen

        for path in SECURITY_TXT_PATHS:
            url = f"https://{self.target}{path}"
            try:
                request = Request(url, headers={"User-Agent": USER_AGENT})
                with safe_urlopen(request, timeout=self.timeout,
                                  context=unverified_context()) as response:
                    if response.status != 200:
                        continue
                    body = response.read(16384).decode("utf-8", errors="ignore")
            except Exception:
                continue

            fields = self.parse(body)
            if not fields:
                continue
            summary = "; ".join(f"{k}: {v}" for k, v in list(fields.items())[:6])
            return [Finding(
                id="SECURITYTXT-Found",
                title="security.txt Published",
                description=(
                    f"The target publishes {path}, naming how to report "
                    f"vulnerabilities."
                ),
                severity=Severity.INFORMATIONAL,
                category="Information Disclosure",
                evidence=f"{url}\n{summary}",
                remediation="N/A - information gathering",
                references=["https://www.rfc-editor.org/rfc/rfc9116"],
                discovered_at=datetime.now().isoformat(),
                target=self.target,
            )]

        return [Finding(
            id="SECURITYTXT-Missing",
            title="No security.txt Published",
            description=(
                "Neither RFC 9116 location serves a security.txt. Researchers "
                "have no documented channel for reporting a vulnerability. This "
                "is a missing convenience rather than a weakness."
            ),
            severity=Severity.INFORMATIONAL,
            category="Information Disclosure",
            evidence="Checked: " + ", ".join(SECURITY_TXT_PATHS),
            remediation="Publish /.well-known/security.txt with a Contact field.",
            references=["https://www.rfc-editor.org/rfc/rfc9116"],
            discovered_at=datetime.now().isoformat(),
            target=self.target,
        )]

    @staticmethod
    def parse(body: str) -> Dict[str, str]:
        """
        Pull the field/value pairs out of a security.txt.

        Comments and the PGP signature envelope are skipped, and a repeated
        field (Contact appears more than once by design) keeps every value.
        """
        fields: Dict[str, str] = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-----"):
                continue
            match = re.match(r"^([A-Za-z-]+):\s*(.+)$", line)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip()
            if key in fields:
                fields[key] += f", {value}"
            else:
                fields[key] = value
        return fields
