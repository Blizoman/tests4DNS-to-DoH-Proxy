"""Command-line interface: -h, validation, exit codes.

Spec: "A repeated single-valued option, a value out of range, or a -u that
is not an http(s) URL MUST exit non-zero (EX_USAGE 64) with a message on
stderr. -h / --help wins over all validation." Also EX_UNAVAILABLE (69)
for a socket bind failure and EX_CONFIG (78) for zone/blocklist errors
are covered in test_startup_shutdown.py and test_zones.py/test_blocklists.py.
"""
import subprocess

import pytest

EX_USAGE = 64


def run(proxy_bin, args, timeout=5):
    return subprocess.run([proxy_bin, *args], capture_output=True, text=True, timeout=timeout)


def test_help_short_flag(proxy_bin):
    r = run(proxy_bin, ["-h"])
    assert r.returncode == 0
    assert r.stdout.strip() != ""


def test_help_long_flag(proxy_bin):
    r = run(proxy_bin, ["--help"])
    assert r.returncode == 0
    assert r.stdout.strip() != ""


def test_help_wins_over_missing_mandatory_u(proxy_bin):
    r = run(proxy_bin, ["-h"])
    assert r.returncode == 0


def test_help_wins_over_invalid_option_value(proxy_bin):
    # -p is out of range AND -h is present: -h must still win.
    r = run(proxy_bin, ["-p", "0", "-h"])
    assert r.returncode == 0


def test_missing_mandatory_u_is_usage_error(proxy_bin):
    r = run(proxy_bin, [])
    assert r.returncode == EX_USAGE
    assert r.stderr.strip() != ""
    assert r.stdout == ""


@pytest.mark.parametrize("url", ["ftp://example.com/dns-query", "example.com/dns-query", "not-a-url"])
def test_u_must_be_http_or_https(proxy_bin, url):
    r = run(proxy_bin, ["-u", url])
    assert r.returncode == EX_USAGE
    assert r.stdout == ""


@pytest.mark.parametrize("port", ["0", "65536", "-1", "abc", ""])
def test_p_out_of_range_or_non_numeric(proxy_bin, port):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-p", port])
    assert r.returncode == EX_USAGE


@pytest.mark.parametrize("timeout", ["0", "3601", "-1", "abc"])
def test_w_out_of_range(proxy_bin, timeout):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-w", timeout])
    assert r.returncode == EX_USAGE


def test_repeated_single_valued_option_p(proxy_bin):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-p", "5300", "-p", "5301"])
    assert r.returncode == EX_USAGE


def test_repeated_single_valued_option_u(proxy_bin):
    r = run(
        proxy_bin,
        ["-u", "https://example.test/dns-query", "-u", "https://other.test/dns-query"],
    )
    assert r.returncode == EX_USAGE


def test_repeated_single_valued_option_a(proxy_bin):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-a", "127.0.0.1", "-a", "127.0.0.2"])
    assert r.returncode == EX_USAGE


def test_repeated_single_valued_option_w(proxy_bin):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-w", "2", "-w", "3"])
    assert r.returncode == EX_USAGE


def test_invalid_a_hostname_not_literal(proxy_bin):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-a", "localhost"])
    assert r.returncode == EX_USAGE


def test_invalid_a_with_brackets(proxy_bin):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-a", "[::1]"])
    assert r.returncode == EX_USAGE


def test_invalid_a_with_zone_index(proxy_bin):
    r = run(proxy_bin, ["-u", "https://example.test/dns-query", "-a", "fe80::1%eth0"])
    assert r.returncode == EX_USAGE
