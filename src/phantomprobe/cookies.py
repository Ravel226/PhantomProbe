#!/usr/bin/env python3
"""
Cookie security attribute analysis.

Passive: it reads the Set-Cookie headers already received during header
analysis, so it adds no request and no traffic to the target.

Severity is calibrated to what each attribute actually buys today, not to what
the advice used to be:

  Secure      Missing on an HTTPS site means the cookie is also sent over plain
              HTTP, where it can be read in transit. A real finding.
  HttpOnly    Missing means JavaScript can read the cookie, so any XSS becomes
              session theft. Weighted higher for session and auth cookies,
              since a tracking cookie readable by script is often deliberate.
  SameSite    Absent is a hardening gap rather than a hole: most current
              browsers already treat an unspecified cookie as Lax. Reported low.
              SameSite=None without Secure is different, and worse: browsers
              reject that cookie outright, so it is both insecure and broken.
"""

from datetime import datetime
from typing import Dict, List, Tuple

from .models import Finding, Severity

# Substrings that mark a cookie as carrying a session or credential, where a
# missing HttpOnly matters much more than it does on an analytics cookie.
SESSION_HINTS = (
    "sess", "sid", "auth", "token", "login", "logged", "jwt", "user", "account",
)


def parse_set_cookie(raw: str) -> Tuple[str, Dict[str, object]]:
    """
    Split one Set-Cookie value into its name and its attributes.

    Attribute names are lowercased because servers spell them inconsistently:
    GitHub sends "secure" and "HttpOnly" in the same response. The cookie value
    is left alone, and only the first "=" splits name from value, since values
    legitimately contain "=" and even JSON.
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return "", {}

    name = parts[0].split("=", 1)[0].strip()
    attrs: Dict[str, object] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            # Valueless flags: Secure, HttpOnly.
            attrs[part.lower()] = True
    return name, attrs


def is_session_cookie(name: str) -> bool:
    """Whether the name suggests the cookie carries a session or credential."""
    lowered = name.lower()
    return any(hint in lowered for hint in SESSION_HINTS)


def _cookie_values(headers) -> List[str]:
    """Every Set-Cookie value. get_all is required; a dict keeps only the last."""
    get_all = getattr(headers, "get_all", None)
    if get_all is not None:
        return [v for v in get_all("Set-Cookie", []) if v]
    value = headers.get("Set-Cookie") if hasattr(headers, "get") else None
    return [value] if value else []


class CookieScanner:
    """Report missing or contradictory cookie security attributes."""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []

    def analyze(self, headers) -> List[Finding]:
        """Analyze the Set-Cookie headers on an already-fetched response."""
        cookies = [parse_set_cookie(raw) for raw in _cookie_values(headers)]
        cookies = [(name, attrs) for name, attrs in cookies if name]
        if not cookies:
            return self.findings

        no_secure, no_httponly, no_samesite, none_without_secure = [], [], [], []
        for name, attrs in cookies:
            secure = "secure" in attrs
            samesite = str(attrs.get("samesite", "")).lower()

            if not secure:
                no_secure.append(name)
            if "httponly" not in attrs:
                no_httponly.append(name)
            if not samesite:
                no_samesite.append(name)
            elif samesite == "none" and not secure:
                none_without_secure.append(name)

        session_at_risk = [n for n in no_httponly if is_session_cookie(n)]

        if no_secure:
            self._add(
                "COOKIE-NoSecure", "Cookies Without the Secure Attribute",
                "Sent over plain HTTP as well as HTTPS, so they can be read in "
                "transit by anyone on the path.",
                Severity.MEDIUM, no_secure, len(cookies),
                "Add the Secure attribute to every cookie set over HTTPS.",
            )

        if no_httponly:
            self._add(
                "COOKIE-NoHttpOnly", "Cookies Readable by JavaScript",
                "Without HttpOnly a cookie is exposed to document.cookie, so any "
                "cross-site scripting flaw can read it."
                + (f" {len(session_at_risk)} of these look like session or auth "
                   f"cookies: {', '.join(session_at_risk)}." if session_at_risk else ""),
                # A session cookie readable by script turns any XSS into account
                # takeover; on a tracking cookie it is often deliberate.
                Severity.MEDIUM if session_at_risk else Severity.LOW,
                no_httponly, len(cookies),
                "Add HttpOnly to any cookie that client-side code does not need "
                "to read, session and authentication cookies above all.",
            )

        if none_without_secure:
            self._add(
                "COOKIE-SameSiteNoneInsecure", "SameSite=None Without Secure",
                "A cookie declaring SameSite=None must also set Secure. Browsers "
                "reject this combination, so the cookie is both insecure and "
                "silently dropped.",
                Severity.MEDIUM, none_without_secure, len(cookies),
                "Add Secure alongside SameSite=None, or pick Lax or Strict.",
            )

        if no_samesite:
            self._add(
                "COOKIE-NoSameSite", "Cookies Without an Explicit SameSite",
                "No SameSite attribute. Most current browsers already default "
                "these to Lax, so this is hardening rather than an open door, "
                "but the behaviour is left to the browser rather than stated.",
                Severity.LOW, no_samesite, len(cookies),
                "Set SameSite explicitly: Lax for most cookies, Strict where "
                "cross-site use is never needed.",
            )

        return self.findings

    def _add(self, finding_id: str, title: str, description: str,
             severity: Severity, names: List[str], total: int,
             remediation: str) -> None:
        self.findings.append(Finding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity,
            category="Cookie Security",
            evidence=f"{len(names)} of {total} cookies: {', '.join(names)}",
            remediation=remediation,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
                "https://owasp.org/www-community/controls/SecureCookieAttribute",
            ],
            discovered_at=datetime.now().isoformat(),
            target=self.target,
        ))
