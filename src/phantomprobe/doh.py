#!/usr/bin/env python3
"""
DNS over HTTPS resolver.

The standard library resolves names but not record types: socket returns
addresses and nothing else, so TXT, MX, CAA and DNSKEY are out of reach without
a DNS library. Asking a public resolver over HTTPS keeps the core
dependency-free, which is why every DNS-derived check here uses it.

Both endpoints speak Google's DNS-JSON shape, so one parser covers them and the
second is a fallback for when the first is blocked.
"""

import json
from typing import List, Optional
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request

from .constants import USER_AGENT
from .http_client import safe_urlopen

DOH_ENDPOINTS = (
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
)

# DNS response codes (RFC 1035).
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

# Record types this scanner asks for.
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_MX = 15
TYPE_TXT = 16
TYPE_DS = 43
TYPE_DNSKEY = 48
TYPE_CAA = 257


def query(name: str, rtype: str, timeout: int = 10) -> Optional[dict]:
    """
    Resolve name/type, returning the raw DNS-JSON, or None if unreachable.

    None means "could not ask", which callers must not confuse with an
    authoritative "does not exist": a blocked resolver is not a missing record.
    """
    params = urlencode({"name": name, "type": rtype})
    for endpoint in DOH_ENDPOINTS:
        request = Request(
            f"{endpoint}?{params}",
            headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT},
        )
        try:
            with safe_urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode())
        except (URLError, json.JSONDecodeError, OSError):
            continue
    return None


def _clean_txt(value: str) -> str:
    """
    Normalise one TXT answer.

    DNS-JSON returns TXT data quoted, and a record longer than 255 bytes comes
    back as several quoted strings that the publisher intended as one value, so
    the chunks are joined with nothing between them.
    """
    if '"' not in value:
        return value.strip()
    return "".join(part for part in value.split('"') if part.strip())


def records(name: str, rtype: str, timeout: int = 10) -> List[str]:
    """
    Answer data for a name and type, as strings.

    Only answers of the requested type are returned: a CNAME in the chain
    appears in the same Answer list and would otherwise be mistaken for data.
    """
    data = query(name, rtype, timeout)
    if not data or data.get("Status") != RCODE_NOERROR:
        return []

    wanted = {
        "A": TYPE_A, "NS": TYPE_NS, "CNAME": TYPE_CNAME, "MX": TYPE_MX,
        "TXT": TYPE_TXT, "DS": TYPE_DS, "DNSKEY": TYPE_DNSKEY, "CAA": TYPE_CAA,
    }.get(rtype.upper())

    out = []
    for answer in data.get("Answer", []):
        if wanted is not None and answer.get("type") != wanted:
            continue
        value = answer.get("data", "")
        out.append(_clean_txt(value) if rtype.upper() == "TXT" else value.strip())
    return out


def resolves(name: str, timeout: int = 10) -> bool:
    """
    Whether the name exists.

    NXDOMAIN is the only answer treated as "gone". A resolver failure returns
    True, so a network blip is never reported as a missing name.
    """
    data = query(name, "A", timeout)
    if data is None:
        return True
    return data.get("Status") != RCODE_NXDOMAIN


def is_dnssec_validated(name: str, timeout: int = 10) -> Optional[bool]:
    """
    Whether the resolver validated the answer (the AD flag).

    None when the lookup failed, so "unknown" stays distinct from "unsigned".
    """
    data = query(name, "A", timeout)
    if data is None:
        return None
    return bool(data.get("AD"))
