"""
Unit tests for the PhantomProbe command-line interface.
"""
import pytest

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
