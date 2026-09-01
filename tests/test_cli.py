"""
Unit tests for the PhantomProbe command-line interface.
"""
import io
from unittest import mock

import pytest

from phantomprobe import cli
from phantomprobe.cli import build_parser, normalize_target


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com", "example.com"),
        ("https://example.com/path/to?q=1", "example.com"),
        ("example.com:8443", "example.com"),
        ("https://example.com:8443/x", "example.com"),
        ("http://user:pass@example.com/x", "example.com"),
        ("  example.com  ", "example.com"),
        ("sub.example.co.uk", "sub.example.co.uk"),
    ],
)
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


def test_normalize_target_keeps_ipv6_literal():
    """IPv6 literals are bracketed; the port-stripping must not mangle them."""
    assert normalize_target("[2001:db8::1]") == "[2001:db8::1]"


def test_parser_requires_a_target():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_defaults_are_all_off():
    args = build_parser().parse_args(["example.com"])

    assert args.target == "example.com"
    assert args.phase2 is False
    assert args.cve is False
    assert args.screenshot is False
    assert args.js is False
    assert args.burp is False
    assert args.dashboard is False
    assert args.output_dir == "."


def test_parser_accepts_long_flags():
    args = build_parser().parse_args(
        ["example.com", "--phase2", "--cve", "--js", "--dashboard"]
    )

    assert args.phase2 and args.cve and args.js and args.dashboard


def test_parser_accepts_short_flags():
    """The pre-argparse CLI advertised these; keep them working."""
    args = build_parser().parse_args(["example.com", "-a", "-c", "-s", "-j", "-b", "-d"])

    assert args.phase2 and args.cve and args.screenshot
    assert args.js and args.burp and args.dashboard


def test_parser_dashboard_overrides():
    args = build_parser().parse_args(
        ["example.com", "--dashboard-host", "0.0.0.0", "--dashboard-port", "9000",
         "--no-browser"]
    )

    assert args.dashboard_host == "0.0.0.0"
    assert args.dashboard_port == 9000
    assert args.no_browser is True


def test_parser_rejects_non_numeric_port():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["example.com", "--dashboard-port", "abc"])


class TestConsoleEncoding:
    """
    A scan must survive output it cannot encode. Printing a dependency's error
    message or a hostile server's header used to raise UnicodeEncodeError on a
    cp1252 console, aborting the run before any report was written.
    """

    def test_configure_console_encoding_sets_replacement(self):
        import io

        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
        with mock.patch.object(cli.sys, "stdout", stream), \
                mock.patch.object(cli.sys, "stderr", stream):
            cli.configure_console_encoding()
            # The box-drawing characters Playwright uses in its error banner.
            stream.write("boom \u2554\u2550\u2557 \u4f60\u597d")
        assert stream.errors == "replace"

    def test_configure_console_encoding_tolerates_plain_streams(self):
        # A stream without reconfigure (a plain StringIO, or a redirect) must
        # not blow up the entry point.
        with mock.patch.object(cli.sys, "stdout", io.StringIO()), \
                mock.patch.object(cli.sys, "stderr", io.StringIO()):
            cli.configure_console_encoding()

    def test_console_supports_detects_legacy_code_page(self):
        cp1252 = mock.Mock(encoding="cp1252")
        utf8 = mock.Mock(encoding="utf-8")
        with mock.patch.object(cli.sys, "stdout", cp1252):
            assert cli.console_supports("plain ascii") is True
            assert cli.console_supports("\u2554\u2550\u2557") is False
        with mock.patch.object(cli.sys, "stdout", utf8):
            assert cli.console_supports("\u2554\u2550\u2557") is True

    def test_banner_falls_back_to_ascii_on_legacy_console(self, capsys):
        with mock.patch.object(cli, "console_supports", return_value=False):
            cli.print_banner()
        assert "PhantomProbe" in capsys.readouterr().out

    def test_screenshot_failure_is_swallowed_on_a_legacy_console(self):
        """
        The regression itself. Playwright's failure message contains box-drawing
        characters; printing it on a cp1252 console used to raise out of
        capture() and kill the scan before any report was written.
        """
        message = "Executable doesn't exist ╔═╗"
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")

        fake_playwright = mock.MagicMock()
        fake_playwright.return_value.__enter__.return_value.chromium.launch.side_effect = (
            RuntimeError(message)
        )

        with mock.patch.object(cli.sys, "stdout", stream),                 mock.patch.object(cli.sys, "stderr", stream):
            cli.configure_console_encoding()
            with mock.patch.dict(
                "sys.modules",
                {"playwright": mock.MagicMock(),
                 "playwright.sync_api": mock.MagicMock(
                     sync_playwright=fake_playwright)},
            ), mock.patch("sys.stdout", stream):
                capturer = cli.ScreenshotCapture(output_dir=".")
                capturer.playwright_available = True
                # Must return None rather than propagating the encode error.
                assert capturer.capture("example.com") is None
