#!/usr/bin/env python3
"""
Phase 3: active vulnerability probing (opt-in).

Unlike the rest of the scanner, these checks send crafted requests to the
target: a hostile Origin, redirect payloads, duplicated parameters, guessed
bucket names. They are non-destructive (no request rewriting, no writes, no
flooding), but they are unmistakably active, so they run only behind
--aggressive and only against a target you are authorized to test.

Request smuggling is deliberately absent. A faithful smuggling probe sends
ambiguous Transfer-Encoding/Content-Length requests whose purpose is to
desync the connection, which can affect other users of a shared server. That
belongs in a dedicated tool under a scoped engagement, not in a recon sweep.
"""

from datetime import datetime
from typing import Dict, List, Optional

from .constants import USER_AGENT
from .http_client import safe_urlopen, unverified_context
from .models import Finding, Severity

# A syntactically valid origin that the target can have no reason to trust.
HOSTILE_ORIGIN = "https://phantomprobe-cors-probe.example"

# Parameters commonly used for redirection, and payloads that leave the site.
REDIRECT_PARAMS = (
    "redirect", "url", "next", "return", "returnurl", "return_url", "dest",
    "destination", "redir", "redirect_uri", "continue", "r", "u", "go", "to",
)
REDIRECT_PAYLOADS = (
    "https://phantomprobe.example",
    "//phantomprobe.example",
)
REDIRECT_MARK = "phantomprobe.example"

# Parameters worth duplicating for a parameter-pollution hint.
HPP_PARAMS = ("id", "page", "q", "search", "user", "lang", "category")

# Suffixes appended to the base name when guessing bucket names.
BUCKET_SUFFIXES = (
    "", "-assets", "-static", "-media", "-backup", "-backups", "-dev",
    "-staging", "-prod", "-data", "-uploads", "-files", "-public", "-www",
    "-cdn", "-images", "-logs",
)


def _import_fetch_no_redirect():
    # Imported lazily to avoid a module-load cycle with http_checks.
    from .http_checks import _fetch_no_redirect
    return _fetch_no_redirect


class AggressiveScanner:
    """Active, non-destructive vulnerability probes."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.findings: List[Finding] = []

    def _add(self, finding_id, title, description, severity, category,
             evidence, remediation, references):
        self.findings.append(Finding(
            id=finding_id, title=title, description=description,
            severity=severity, category=category, evidence=evidence,
            remediation=remediation, references=references,
            discovered_at=datetime.now().isoformat(), target=self.target,
        ))

    def _get(self, url: str, headers: Optional[Dict[str, str]] = None):
        """A single GET, returning (status, headers, body) or None."""
        from urllib.error import HTTPError, URLError
        from urllib.request import Request

        request = Request(url, headers=headers or {"User-Agent": USER_AGENT})
        try:
            with safe_urlopen(request, timeout=self.timeout,
                              context=unverified_context()) as response:
                return response.status, response.headers, response.read(4096)
        except HTTPError as exc:
            return exc.code, exc.headers, b""
        except (URLError, OSError, ValueError):
            return None

    # -- CORS -----------------------------------------------------------------

    def check_cors(self) -> None:
        """
        Send a hostile Origin and read the ACAO/ACAC response.

        The distinction that matters: reflecting the specific origin together
        with credentials lets a hostile site read authenticated responses,
        which is the real hole. A bare "*" cannot be used with credentials, so
        browsers already block the dangerous case; it is reported low.
        """
        result = self._get(
            f"https://{self.target}",
            headers={"User-Agent": USER_AGENT, "Origin": HOSTILE_ORIGIN},
        )
        if result is None:
            return
        _, headers, _ = result
        acao = headers.get("Access-Control-Allow-Origin")
        acac = str(headers.get("Access-Control-Allow-Credentials", "")).lower()
        if not acao:
            return

        if acao == HOSTILE_ORIGIN and acac == "true":
            self._add(
                "CORS-ReflectedWithCredentials",
                "CORS Reflects Any Origin With Credentials",
                "The server echoes the request's Origin into "
                "Access-Control-Allow-Origin and sets "
                "Access-Control-Allow-Credentials: true. A hostile site can "
                "therefore read authenticated responses from this domain.",
                Severity.HIGH, "CORS",
                f"Origin: {HOSTILE_ORIGIN}\nAccess-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}",
                "Reflect only an allowlist of trusted origins, and never combine "
                "a reflected origin with credentials.",
                ["https://portswigger.net/web-security/cors"],
            )
        elif acao == HOSTILE_ORIGIN:
            self._add(
                "CORS-ReflectedOrigin", "CORS Reflects Any Origin",
                "The server echoes the request's Origin into "
                "Access-Control-Allow-Origin. Without credentials the exposure "
                "is limited to whatever an unauthenticated request can read, "
                "but the reflection itself is rarely intended.",
                Severity.LOW, "CORS",
                f"Origin: {HOSTILE_ORIGIN}\nAccess-Control-Allow-Origin: {acao}",
                "Reflect only an allowlist of trusted origins.",
                ["https://portswigger.net/web-security/cors"],
            )
        elif acao == "null":
            self._add(
                "CORS-NullOrigin", "CORS Allows the null Origin",
                "Access-Control-Allow-Origin is 'null', which several sandboxed "
                "contexts can present, so it is not a safe allowlist entry.",
                Severity.MEDIUM if acac == "true" else Severity.LOW, "CORS",
                f"Access-Control-Allow-Origin: null\n"
                f"Access-Control-Allow-Credentials: {acac}",
                "Remove 'null' from the allowed origins.",
                ["https://portswigger.net/web-security/cors"],
            )
        # A bare "*" is deliberately not reported: it is the correct setting for
        # a public, non-credentialed API and browsers block its dangerous use.

    # -- open redirect --------------------------------------------------------

    def check_open_redirect(self) -> None:
        """
        Probe common redirect parameters on the root path.

        This is a surface check: it exercises the root, not every app route, so
        a clean result is not proof the site has no open redirect anywhere. A
        hit, though, is real: the Location header points off-site.
        """
        fetch = _import_fetch_no_redirect()
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS:
                from urllib.parse import quote
                url = f"https://{self.target}/?{param}={quote(payload, safe='')}"
                result = fetch(url, self.timeout)
                if not result:
                    continue
                status, headers = result
                location = headers.get("Location", "") if headers else ""
                host = self._location_host(location)
                if 300 <= status < 400 and host and REDIRECT_MARK in host:
                    self._add(
                        "REDIRECT-Open", "Open Redirect",
                        f"The '{param}' parameter controls the redirect target, "
                        f"and a request for an external URL is honoured. This is "
                        f"used in phishing to lend the target's name to an "
                        f"attacker's link.",
                        Severity.MEDIUM, "Open Redirect",
                        f"{url}\n-> Location: {location}",
                        "Redirect only to a validated allowlist of paths or "
                        "hosts, never to a raw request parameter.",
                        ["https://cwe.mitre.org/data/definitions/601.html"],
                    )
                    return

    @staticmethod
    def _location_host(location: str) -> str:
        """
        The host a Location value would send the browser to.

        Protocol-relative values (//host/...) and absolute URLs both need to be
        read, since either can carry the redirect off-site.
        """
        from urllib.parse import urlparse
        if location.startswith("//"):
            location = "https:" + location
        return (urlparse(location).hostname or "").lower()

    # -- HTTP parameter pollution --------------------------------------------

    def check_hpp(self) -> None:
        """
        Compare one parameter value against the same parameter given twice.

        Reported only when the duplicate changes the HTTP status, which is a
        far steadier signal than a response-length delta: a dynamic page's
        length wobbles on its own, so length-based HPP detection is mostly
        noise. Even so this is a hint, filed as informational.
        """
        for param in HPP_PARAMS:
            single = self._get(f"https://{self.target}/?{param}=1")
            double = self._get(f"https://{self.target}/?{param}=1&{param}=2")
            if not single or not double:
                continue
            if single[0] is not None and single[0] != double[0]:
                self._add(
                    "HPP-StatusChange", "Parameter Pollution Changes the Response",
                    f"Sending '{param}' twice produced a different HTTP status "
                    f"than sending it once ({single[0]} vs {double[0]}), which "
                    f"suggests the backend handles duplicate parameters "
                    f"inconsistently. A hint worth manual follow-up, not a "
                    f"confirmed flaw.",
                    Severity.INFORMATIONAL, "Parameter Pollution",
                    f"{param}=1 -> HTTP {single[0]}\n"
                    f"{param}=1&{param}=2 -> HTTP {double[0]}",
                    "Decide explicitly how duplicate parameters are handled, and "
                    "apply it consistently across the stack.",
                    ["https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution"],
                )
                return

    # -- S3 bucket exposure ---------------------------------------------------

    def _bucket_names(self) -> List[str]:
        """Candidate bucket names derived from the target domain."""
        base = self.target
        labels = base.split(".")
        stem = labels[0] if labels else base
        roots = {base, base.replace(".", "-"), stem}
        names = []
        for root in roots:
            for suffix in BUCKET_SUFFIXES:
                names.append(f"{root}{suffix}")
        # Dedupe while preserving order.
        seen = set()
        return [n for n in names if not (n in seen or seen.add(n))]

    def check_s3_buckets(self) -> None:
        """
        Look for S3 buckets named after the target.

        Read-only: a GET on the bucket root tells us, from the body, whether it
        does not exist, exists but is private, or is publicly listable. Only a
        public listing is a real exposure.
        """
        for name in self._bucket_names():
            result = self._get(f"https://{name}.s3.amazonaws.com/")
            if result is None:
                continue
            _, _, body = result
            text = body.decode("utf-8", errors="ignore")

            if "<ListBucketResult" in text:
                self._add(
                    f"S3-Public-{name}", "Public S3 Bucket",
                    f"The bucket '{name}' is publicly listable, exposing its "
                    f"contents to anyone.",
                    Severity.HIGH, "Cloud Storage",
                    f"https://{name}.s3.amazonaws.com/ returns a bucket listing",
                    "Remove public list permissions; review the objects that "
                    "were exposed.",
                    ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html"],
                )
            elif "AccessDenied" in text:
                self._add(
                    f"S3-Exists-{name}", "S3 Bucket Exists (Access Denied)",
                    f"A bucket named '{name}' exists but denies listing. Its "
                    f"name is confirmed, which is useful for further testing.",
                    Severity.INFORMATIONAL, "Cloud Storage",
                    f"https://{name}.s3.amazonaws.com/ returns AccessDenied",
                    "N/A - information gathering",
                    [],
                )

    def run(self) -> List[Finding]:
        print("[!] Aggressive checks send crafted requests to the target.")
        print("[*] Running active vulnerability probes (CORS, redirect, HPP, S3)...")
        self.check_cors()
        self.check_open_redirect()
        self.check_hpp()
        self.check_s3_buckets()
        print(f"[+] Aggressive probes: {len(self.findings)} findings")
        return self.findings
