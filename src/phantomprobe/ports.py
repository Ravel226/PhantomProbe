#!/usr/bin/env python3
"""
Port scan and service banners (phase 2).

A connect scan of common service ports. Some services speak first: FTP, SSH,
SMTP, POP3 and IMAP greet a client in text, and MySQL opens with a handshake
packet that carries its version. Where a port belongs to one of those, the
greeting is read and recorded. Nothing is sent to draw it out: these are the
bytes the service gives to anyone who connects, which the scan already did.

A banner is hostile input like everything else a target sends. It is cut down
to printable ASCII, loses its backticks so it cannot close the code block a
report prints it in, and is capped in length.

A version in a banner is what the service says about itself. Distributions fix
vulnerabilities without changing it, which is why the CVE matcher marks a
banner that names a distribution (see cve.py).
"""

import concurrent.futures
import re
import socket
from datetime import datetime
from typing import List, Optional, Tuple

from .models import Finding, Severity

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
]

SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

# Services that greet the client in text as soon as it connects.
TEXT_GREETING_PORTS = frozenset({21, 22, 25, 110, 143})
# MySQL and MariaDB open with a binary handshake that names the version.
MYSQL_PORTS = frozenset({3306})

BANNER_LIMIT = 200


def clean_banner(raw: bytes) -> str:
    """
    Reduce what a service sent to one printable line.

    Up to three lines are kept, because an FTP server often puts a welcome on
    the first and its name on the next.
    """
    text = raw.decode("ascii", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()][:3]
    joined = " / ".join(lines)
    printable = "".join(
        ch if " " <= ch <= "~" and ch != "`" else " " for ch in joined
    )
    return " ".join(printable.split())[:BANNER_LIMIT]


def mysql_version(raw: bytes) -> str:
    """
    The server version from a MySQL protocol 10 handshake, or "" otherwise.

    The packet is a 3-byte length, a sequence byte, the protocol version
    (0x0a) and then the version as a null-terminated string. A server that
    refuses the client by address sends an error packet instead (0xff), which
    carries no version.
    """
    if len(raw) < 6 or raw[4] != 0x0a:
        return ""
    end = raw.find(b"\x00", 5)
    if end == -1:
        return ""
    return clean_banner(raw[5:end])


def describe_mysql(version: str) -> str:
    """
    Name the product in front of its version, so the two read as a banner.

    The handshake holds a bare version string. MariaDB writes its own version
    after a compatibility prefix ("5.5.5-10.6.12-MariaDB"), and distributions
    append their package revision; the full string is kept beside the parsed
    version because that revision is the sign of a patched build.
    """
    if not version:
        return ""
    maria = re.search(r"(\d+\.\d+\.\d+)-MariaDB", version, re.IGNORECASE)
    if maria:
        return f"MariaDB {maria.group(1)} (server version string: {version})"
    plain = re.match(r"\d+\.\d+\.\d+", version)
    if plain:
        return f"MySQL {plain.group(0)} (server version string: {version})"
    return version


class PortScanner:
    """Connect scan that also records what greeting-type services say."""

    def __init__(self, target: str, timeout: float = 2, banner_timeout: float = 3):
        self.target = target
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.text_ports = TEXT_GREETING_PORTS
        self.mysql_ports = MYSQL_PORTS

    def _greeting(self, sock, port: int) -> str:
        """What the service volunteered on connect, or "" if it stayed silent."""
        if port not in self.text_ports and port not in self.mysql_ports:
            return ""
        try:
            sock.settimeout(self.banner_timeout)
            raw = sock.recv(512)
        except OSError:
            # A timeout or a reset: the port is open, it just said nothing.
            return ""
        if port in self.mysql_ports:
            return describe_mysql(mysql_version(raw))
        return clean_banner(raw)

    def check(self, port: int) -> Optional[Tuple[int, str]]:
        """(port, banner) for an open port, None for a closed one."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.target, port)) != 0:
                    return None
                return port, self._greeting(sock, port)
        except OSError:
            # Unreachable host, refused connection or exhausted sockets:
            # treat as closed rather than aborting the whole sweep.
            return None

    def run(self, ports: Optional[List[int]] = None) -> List[Finding]:
        """Scan the ports and return one finding per open one."""
        ports = ports or COMMON_PORTS
        print(f"[*] Scanning {len(ports)} common ports...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            open_ports = [hit for hit in executor.map(self.check, ports) if hit]

        findings = []
        for port, banner in open_ports:
            service = SERVICES.get(port, 'Unknown')
            evidence = f"Port {port}/{service} is accepting connections"
            if banner:
                evidence += f"\nBanner: {banner}"
            findings.append(Finding(
                id=f"PORT-{port}",
                title=f"Open Port: {port}",
                description=f"Port {port} is open ({service})",
                severity=Severity.INFORMATIONAL,
                category="Port Scan",
                evidence=evidence,
                remediation="N/A - Information gathering",
                references=["https://en.wikipedia.org/wiki/Port_scanner"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        with_banner = sum(1 for _, banner in open_ports if banner)
        print(f"[+] Port scan: {len(open_ports)} open ports"
              + (f", {with_banner} with a banner" if with_banner else ""))
        return findings
