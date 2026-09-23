"""Blocklist matching semantics, independent of any loaded zone."""
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from conftest import blocklist
from isa_tests import netio, ports
from isa_tests.dnsutil import make_query
from isa_tests.proxy import ProxyHandle


def _query(proxy, qname, qtype="A"):
    _h, host, port = proxy
    q = make_query(qname, qtype)
    wire = netio.udp_roundtrip(host, port, q.to_wire())
    return dns.message.from_wire(wire, raise_on_truncation=False)


@pytest.fixture(scope="module")
def block_proxy(proxy_bin, blocklists_dir):
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        [
            "-u", "https://example.test/dns-query",
            "-p", str(port), "-a", "127.0.0.1",
            "-b", blocklist("ads.txt"),
        ],
    )
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
    yield h, "127.0.0.1", port
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


def test_exact_match_blocked(block_proxy):
    r = _query(block_proxy, "ads.example.com.", "A")
    assert r.rcode() == dns.rcode.NXDOMAIN
    assert not (r.flags & dns.flags.AA)
    assert len(r.answer) == 0
    assert len(r.authority) == 0


def test_subdomain_blocked(block_proxy):
    r = _query(block_proxy, "www.ads.example.com.", "AAAA")
    assert r.rcode() == dns.rcode.NXDOMAIN
    assert len(r.answer) == 0
    assert len(r.authority) == 0


def test_label_boundary_not_substring(block_proxy):
    # "bads.example.com" must NOT be blocked by an "ads.example.com" entry
    # (matching is on label boundaries, not substrings). block_proxy has no
    # working upstream (bogus -u), so a name that escapes the blocklist gets
    # *forwarded* and eventually SERVFAIL's on the unreachable upstream --
    # a different, distinguishable outcome from the NXDOMAIN a blocked verdict
    # always produces. See test_forwarding.py for the same case against a
    # real mock upstream that returns a normal answer.
    _h, host, port = block_proxy
    q = make_query("bads.example.com.", "A")
    wire = netio.udp_roundtrip(host, port, q.to_wire(), timeout=5.0)
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.rcode() == dns.rcode.SERVFAIL, "must have been forwarded (and failed), not blocked"


def test_multiple_names_on_one_hosts_style_line(block_proxy):
    for name in ["tracker.example.net.", "telemetry.example.net."]:
        r = _query(block_proxy, name, "A")
        assert r.rcode() == dns.rcode.NXDOMAIN, name


def test_case_insensitive_and_trailing_dot_ignored(block_proxy):
    r1 = _query(block_proxy, "ADS.EXAMPLE.COM.", "A")
    assert r1.rcode() == dns.rcode.NXDOMAIN
    r2 = _query(block_proxy, "ads.example.com", "A")  # dnspython adds trailing dot; kept for clarity
    assert r2.rcode() == dns.rcode.NXDOMAIN


def test_blocked_regardless_of_qtype(block_proxy):
    for qtype in ["A", "AAAA", "MX", "TXT", "ANY"]:
        r = _query(block_proxy, "ads.example.com.", qtype)
        assert r.rcode() == dns.rcode.NXDOMAIN, qtype
        assert len(r.answer) == 0


@pytest.fixture(scope="module")
def hosts_format_proxy(proxy_bin, blocklists_dir):
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        [
            "-u", "https://example.test/dns-query",
            "-p", str(port), "-a", "127.0.0.1",
            "-b", blocklist("hosts-format.txt"),
        ],
    )
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start (hosts-format.txt should load cleanly): {h.stderr_extra}"
    yield h, "127.0.0.1", port
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


def test_hosts_format_crlf_and_headers_load_cleanly(hosts_format_proxy):
    assert hosts_format_proxy[0].is_running()


@pytest.mark.parametrize("name", ["doubleclick.example.", "ads1.example.org.", "ads2.example.org."])
def test_hosts_format_real_entries_blocked(hosts_format_proxy, name):
    r = _query(hosts_format_proxy, name, "A")
    assert r.rcode() == dns.rcode.NXDOMAIN, name
