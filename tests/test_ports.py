"""
Tests for the port scan and the banners it records.

The scanner is pointed at loopback sockets opened by the test itself, so the
real connect and read paths run without touching any other host.
"""
import socket
import threading

import pytest

from phantomprobe.active import ActiveReconEngine
from phantomprobe.cve import CVEMatcher
from phantomprobe.nvd import CVE
from phantomprobe.ports import (
    COMMON_PORTS,
    SERVICES,
    PortScanner,
    clean_banner,
    describe_mysql,
    mysql_version,
)


@pytest.fixture
def service():
    """
    Start a loopback service that sends a greeting, returning its port.

    Call it with the bytes to send on connect (None to stay silent).
    """
    servers = []

    def start(greeting):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        servers.append(server)

        def serve():
            while True:
                try:
                    client, _ = server.accept()
                except OSError:
                    return
                with client:
                    if greeting is not None:
                        client.sendall(greeting)
                    # Hold the connection open until the scanner hangs up.
                    try:
                        client.recv(1)
                    except OSError:
                        pass

        threading.Thread(target=serve, daemon=True).start()
        return server.getsockname()[1]

    yield start
    for server in servers:
        server.close()


def scanner_for(port, mysql=False):
    scanner = PortScanner("127.0.0.1", timeout=2, banner_timeout=0.5)
    scanner.text_ports = frozenset() if mysql else frozenset({port})
    scanner.mysql_ports = frozenset({port}) if mysql else frozenset()
    return scanner


def mysql_handshake(version: bytes) -> bytes:
    payload = b"\x0a" + version + b"\x00" + b"\x08\x00\x00\x00filler-bytes"
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


class TestCleanBanner:
    def test_a_plain_greeting_is_kept(self):
        assert clean_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n") == (
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")

    def test_control_and_non_ascii_bytes_are_removed(self):
        assert clean_banner(b"220 \x1b[31mFTP\x07 \xff\xfe ready\r\n") == "220 [31mFTP ready"

    def test_backticks_cannot_close_a_report_code_block(self):
        """The Markdown report prints evidence inside a fenced block."""
        assert "`" not in clean_banner(b"220 ```\n# injected heading\n")

    def test_a_server_name_on_the_second_line_is_kept(self):
        """FTP servers often greet first and name themselves on the next line."""
        raw = b"220-Welcome to the archive\r\n220 ProFTPD 1.3.5e Server ready\r\n"
        assert "ProFTPD 1.3.5e" in clean_banner(raw)

    def test_length_is_capped(self):
        assert len(clean_banner(b"A" * 5000)) == 200

    def test_nothing_sent_is_an_empty_banner(self):
        assert clean_banner(b"") == ""


class TestMysqlHandshake:
    def test_version_is_read_from_a_protocol_10_handshake(self):
        assert mysql_version(mysql_handshake(b"8.0.36")) == "8.0.36"

    def test_an_error_packet_carries_no_version(self):
        """A server that refuses the client by address answers with 0xff."""
        payload = b"\xff\x6a\x04Host '10.0.0.5' is not allowed to connect"
        raw = len(payload).to_bytes(3, "little") + b"\x00" + payload
        assert mysql_version(raw) == ""

    @pytest.mark.parametrize("raw", [b"", b"\x00\x01", b"SSH-2.0-OpenSSH_8.9\r\n",
                                     b"\x05\x00\x00\x00\x0a8.0"])
    def test_anything_else_is_not_a_version(self, raw):
        assert mysql_version(raw) == ""

    @pytest.mark.parametrize("version,expected", [
        ("8.0.36", "MySQL 8.0.36 (server version string: 8.0.36)"),
        ("8.0.36-0ubuntu0.22.04.1",
         "MySQL 8.0.36 (server version string: 8.0.36-0ubuntu0.22.04.1)"),
        # MariaDB puts a compatibility prefix in front of its own version.
        ("5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1",
         "MariaDB 10.6.12 (server version string: "
         "5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1)"),
        ("10.11.6-MariaDB-0+deb12u1",
         "MariaDB 10.11.6 (server version string: 10.11.6-MariaDB-0+deb12u1)"),
        ("", ""),
    ])
    def test_the_product_is_named_in_front_of_its_version(self, version, expected):
        assert describe_mysql(version) == expected

    def test_the_matcher_reads_the_described_version(self):
        matcher = CVEMatcher()
        assert matcher.extract_tech_version(describe_mysql("8.0.36")) == [
            ("mysql", "8.0.36")]
        assert matcher.extract_tech_version(
            describe_mysql("5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1")) == [
            ("mariadb", "10.6.12")]


class TestPortScanner:
    def test_a_greeting_is_recorded_as_a_banner(self, service):
        port = service(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
        findings = scanner_for(port).run([port])

        assert len(findings) == 1
        assert findings[0].category == "Port Scan"
        assert "Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" in findings[0].evidence

    def test_a_silent_service_is_still_an_open_port(self, service):
        port = service(None)
        findings = scanner_for(port).run([port])

        assert len(findings) == 1
        assert "accepting connections" in findings[0].evidence
        assert "Banner:" not in findings[0].evidence

    def test_a_closed_port_is_not_reported(self):
        # Bind and release a port so that nothing is listening on it.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        assert scanner_for(port).run([port]) == []

    def test_only_services_that_speak_first_are_read(self, service):
        """An HTTP port says nothing until asked, so no read is attempted."""
        port = service(b"this would be read if the port were listened to\r\n")
        scanner = PortScanner("127.0.0.1", banner_timeout=0.5)

        findings = scanner.run([port])

        assert len(findings) == 1
        assert "Banner:" not in findings[0].evidence

    def test_a_mysql_handshake_becomes_a_readable_banner(self, service):
        port = service(mysql_handshake(b"8.0.36-0ubuntu0.22.04.1"))
        findings = scanner_for(port, mysql=True).run([port])

        assert "Banner: MySQL 8.0.36 (server version string: 8.0.36-0ubuntu0.22.04.1)" \
            in findings[0].evidence

    def test_the_engine_delegates_to_the_scanner(self, service, monkeypatch):
        port = service(b"220 ProFTPD 1.3.5e Server ready\r\n")
        monkeypatch.setattr("phantomprobe.ports.TEXT_GREETING_PORTS", frozenset({port}))

        findings = ActiveReconEngine("127.0.0.1").scan_ports([port])

        assert "Banner: 220 ProFTPD 1.3.5e Server ready" in findings[0].evidence


class TestTables:
    def test_every_scanned_port_has_a_service_name(self):
        assert all(port in SERVICES for port in COMMON_PORTS)

    def test_the_engine_exposes_the_same_port_list(self):
        assert ActiveReconEngine.COMMON_PORTS is COMMON_PORTS


class TestBannersReachCveMatching:
    """
    The CPE table lists OpenSSH, ProFTPD, vsftpd, Exim, MySQL and MariaDB,
    but the scan only recorded that their ports were open, so none of those
    entries could ever match.
    """

    @staticmethod
    def _queried(findings):
        matcher = CVEMatcher()
        queried = []
        matcher.query_nvd = lambda cpe, tech, version=None: (
            queried.append((tech, version)) or [])
        matcher.match_findings(findings)
        return queried

    def test_an_ssh_banner_is_correlated(self, service):
        port = service(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
        findings = scanner_for(port).run([port])

        assert ("openssh", "8.9") in self._queried(findings)

    def test_a_port_number_alone_names_no_product(self, capsys):
        """
        "Port 3306/MySQL" is a guess from the port number. Without a banner
        it must not be looked up, nor reported as seen without a version.
        """
        from phantomprobe.models import Finding, Severity

        silent = Finding(
            id="PORT-3306", title="Open Port: 3306", description="",
            severity=Severity.INFORMATIONAL, category="Port Scan",
            evidence="Port 3306/MySQL is accepting connections",
            remediation="", references=[], discovered_at="", target="example.com",
        )

        assert self._queried([silent]) == []
        assert "mysql" not in capsys.readouterr().out.lower()

    def test_a_distribution_in_the_banner_travels_with_the_match(self, service):
        """
        Ubuntu patches OpenSSH without changing "8.9", so every CVE matched on
        this banner has to say where the version came from.
        """
        port = service(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
        findings = scanner_for(port).run([port])

        matcher = CVEMatcher()
        matcher.query_nvd = lambda cpe, tech, version=None: [
            CVE("CVE-2024-6387", "HIGH", 8.1, "d", [], [], [], "", "")]
        matcher._load_kev = lambda: {}
        matcher._load_epss = lambda ids: {}
        matched = matcher.match_findings(findings)

        assert matched[0]["technology"] == "openssh"
        assert matched[0]["distribution"] == "Ubuntu"
