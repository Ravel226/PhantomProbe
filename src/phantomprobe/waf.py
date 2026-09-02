#!/usr/bin/env python3
"""
Web Application Firewall / CDN fingerprinting.

Passive: it reads the response headers and cookies already fetched during
header analysis and matches them against known WAF signatures. Nothing extra is
sent to the target, so this adds no requests and no attack traffic.

A match is worth knowing before anything active: it tells the tester what sits
in front of the application, which shapes both what a scan will see and what an
attacker would have to get past.

Signatures are the passive header/cookie subset of wafw00f
(https://github.com/EnableSecurity/wafw00f), by way of the port maintained in
web-check, plus the current Cloudflare cookies that the older port predates.
Active-probe-only WAFs are intentionally excluded: confirming them means sending
a payload and reading the block page, which this passive check does not do.
"""

from datetime import datetime
from typing import List

from .models import Finding, Severity

# (header, needle, waf). needle None means the header's presence is the signal;
# otherwise the header value must contain needle (case-insensitive).
_WAF_SIGNATURES = [
    ('server', 'cloudflare', 'Cloudflare'),
    ('cf-ray', None, 'Cloudflare'),
    ('set-cookie', '__cfduid', 'Cloudflare'),
    ('set-cookie', '__cf_bm', 'Cloudflare'),
    ('set-cookie', 'cf_clearance', 'Cloudflare'),
    ('server', 'sucuri', 'Sucuri CloudProxy WAF'),
    ('x-sucuri-id', None, 'Sucuri CloudProxy WAF'),
    ('x-sucuri-cache', None, 'Sucuri CloudProxy WAF'),
    ('server', 'imperva', 'Imperva SecureSphere WAF'),
    ('x-iinfo', None, 'Imperva Incapsula'),
    ('x-cdn', 'incapsula', 'Imperva Incapsula'),
    ('set-cookie', 'incap_ses', 'Imperva Incapsula'),
    ('set-cookie', 'visid_incap', 'Imperva Incapsula'),
    ('server', 'akamaighost', 'Akamai'),
    ('x-powered-by', 'aws lambda', 'AWS WAF'),
    ('server', 'big-ip', 'F5 BIG-IP'),
    ('set-cookie', 'bigipserver', 'F5 BIG-IP'),
    ('server', 'barracudawaf', 'Barracuda WAF'),
    ('set-cookie', 'barra_counter_session', 'Barracuda WAF'),
    ('set-cookie', 'bni_persistence', 'Barracuda WAF'),
    ('set-cookie', 'bni__barracuda_lb_cookie', 'Barracuda WAF'),
    ('server', 'fortiweb', 'Fortinet FortiWeb WAF'),
    ('set-cookie', 'fortiwafsid', 'Fortinet FortiWeb WAF'),
    ('via', 'ns-cache', 'Citrix NetScaler'),
    ('set-cookie', 'citrix_ns_id', 'Citrix NetScaler'),
    ('set-cookie', 'ns_af=', 'Citrix NetScaler'),
    ('server', 'reblaze secure web gateway', 'Reblaze WAF'),
    ('x-waf-event-info', None, 'Reblaze WAF'),
    ('set-cookie', 'rbzid', 'Reblaze WAF'),
    ('x-sl-compstate', None, 'Radware AppWall'),
    ('server', 'wallarm', 'Wallarm WAF'),
    ('server', 'mod_security', 'ModSecurity'),
    ('x-protected-by', 'sqreen', 'Sqreen'),
    ('server', 'ddos-guard', 'DDoS-Guard WAF'),
    ('set-cookie', '__ddg', 'DDoS-Guard WAF'),
    ('server', 'qrator', 'QRATOR WAF'),
    ('server', 'protected by comodo waf', 'Comodo cWatch WAF'),
    ('server', 'zscaler', 'Zscaler'),
    ('server', 'imunify360', 'Imunify360 WAF'),
    ('server', 'arvancloud', 'ArvanCloud WAF'),
    ('server', 'sonicwall', 'SonicWall'),
    ('x-datapower-transactionid', None, 'IBM WebSphere DataPower'),
    ('server', 'naxsi', 'NAXSI WAF'),
    ('server', 'safe3waf', 'Safe3 Web Application Firewall'),
    ('x-webcoment', None, 'Webcoment Firewall'),
    ('server', 'yundun', 'Yundun WAF'),
    ('x-yd-waf-info', None, 'Yundun WAF'),
    ('x-yd-info', None, 'Yundun WAF'),
    ('server', 'qianxin-waf', '360 WangZhanBao WAF'),
    ('wzws-ray', None, '360 WangZhanBao WAF'),
    ('x-powered-by-360wzb', None, '360 WangZhanBao WAF'),
    ('x-denied-reason', None, 'WangZhanBao WAF'),
    ('x-wzws-requested-method', None, 'WangZhanBao WAF'),
    ('x-powered-by-anquanbao', None, 'Anquanbao WAF'),
    ('server', 'yunjiasu', 'Baidu Yunjiasu WAF'),
    ('server', 'nsfocus', 'NSFocus WAF'),
    ('server', 'jiasule-waf', 'Jiasule WAF'),
    ('set-cookie', '__jsluid', 'Jiasule WAF'),
    ('set-cookie', 'jsl_tracking', 'Jiasule WAF'),
    ('server', 'safedog', 'SafeDog WAF'),
    ('set-cookie', 'safedog-flow-item', 'SafeDog WAF'),
    ('set-cookie', 'yunsuo_session', 'Yunsuo WAF'),
]

def _header_values(headers, name: str) -> List[str]:
    """
    All values for a header, case-insensitively.

    Set-Cookie legitimately repeats, and http.client keeps the copies only via
    get_all; a plain dict lookup would see just the last one and miss a cookie
    signature. Falls back to a mapping for callers that pass a plain dict.
    """
    get_all = getattr(headers, "get_all", None)
    if get_all is not None:
        return [v for v in get_all(name, []) if v]
    value = headers.get(name)
    return [value] if value else []


def detect_waf(headers) -> List[str]:
    """
    Return the WAFs whose signatures match these response headers.

    headers is an http.client.HTTPMessage or any case-insensitive mapping; the
    result is de-duplicated and ordered by first match.
    """
    found: List[str] = []
    for header, needle, name in _WAF_SIGNATURES:
        if name in found:
            continue
        values = _header_values(headers, header)
        if not values:
            continue
        if needle is None or any(needle.lower() in v.lower() for v in values):
            found.append(name)
    return found


class WafScanner:
    """Turn a WAF match into a finding, from headers fetched elsewhere."""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []

    def analyze(self, headers) -> List[Finding]:
        """Match the given response headers and record a finding per WAF."""
        for name in detect_waf(headers):
            self.findings.append(Finding(
                id=f"WAF-{name.split()[0].replace('/', '-')}",
                title=f"WAF/CDN Detected: {name}",
                description=(
                    f"Response headers match {name}. A WAF or CDN sits in front "
                    f"of {self.target}, which affects what later checks observe."
                ),
                # Recon context, not a weakness in itself.
                severity=Severity.INFORMATIONAL,
                category="WAF Detection",
                evidence=f"Signature match for {name} in response headers",
                remediation="N/A - informational. Note it when interpreting later results.",
                references=["https://github.com/EnableSecurity/wafw00f"],
                discovered_at=datetime.now().isoformat(),
                target=self.target,
            ))
        return self.findings
