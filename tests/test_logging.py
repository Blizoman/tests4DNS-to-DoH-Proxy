"""The stdout query log: one flushed line per message, exact format, content
correctness per verdict, and multiset (not positional) matching.
"""
import time

import dns.message
import pytest

from conftest import blocklist, zone
from isa_tests import dnswire, netio, ports
from isa_tests.dnsutil import make_query
from isa_tests.logqueries import LOG_LINE_RE, find
from isa_tests.proxy import ProxyHandle
from isa_tests.upstream import MockDoHUpstream


@pytest.fixture(scope="module")
def log_env(proxy_bin, zones_dir, blocklists_dir):
    up = MockDoHUpstream()
    up.start()
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        [
            "-u", up.url, "-p", str(port), "-a", "127.0.0.1",
            "-z", zone("home.lan.zone"), "-b", blocklist("ads.txt"), "-w", "3",
        ],
    )
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
    yield h, "127.0.0.1", port, up
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()
    up.stop()


def _udp_with_client_port(host, port, wire, timeout=3.0):
    s = netio.udp_socket(timeout=timeout)
    s.bind(("127.0.0.1", 0))
    lport = s.getsockname()[1]
    try:
        s.sendto(wire, (host, port))
        data, _ = s.recvfrom(65535)
    finally:
        s.close()
    return data, lport


def test_local_verdict_log_line(log_env):
    h, host, port, up = log_env
    q = make_query("router.home.lan.", "A")
    _resp, lport = _udp_with_client_port(host, port, q.to_wire())
    lines = h.pop_log_lines(count=1, timeout=2.0)
    assert len(lines) == 1
    LOG_LINE_RE.match(lines[0])
    rec = find(lines, client=f"127.0.0.1:{lport}", qname="router.home.lan.", qtype="A")
    assert rec is not None, lines
    assert rec["verdict"] == "local"
    assert rec["rcode"] == "NOERROR"


def test_local_nxdomain_verdict_log_line(log_env):
    h, host, port, up = log_env
    q = make_query("printer.home.lan.", "A")
    _resp, lport = _udp_with_client_port(host, port, q.to_wire())
    lines = h.pop_log_lines(count=1, timeout=2.0)
    rec = find(lines, client=f"127.0.0.1:{lport}", qname="printer.home.lan.", qtype="A")
    assert rec is not None, lines
    assert rec["verdict"] == "local"
    assert rec["rcode"] == "NXDOMAIN"


def test_blocked_verdict_log_line(log_env):
    h, host, port, up = log_env
    q = make_query("www.ads.example.com.", "AAAA")
    _resp, lport = _udp_with_client_port(host, port, q.to_wire())
    lines = h.pop_log_lines(count=1, timeout=2.0)
    rec = find(lines, client=f"127.0.0.1:{lport}", qname="www.ads.example.com.", qtype="AAAA")
    assert rec is not None, lines
    assert rec["verdict"] == "blocked"
    assert rec["rcode"] == "NXDOMAIN"


def test_forwarded_verdict_log_line(log_env):
    h, host, port, up = log_env
    q = make_query("www.fit.vut.cz.", "A")
    _resp, lport = _udp_with_client_port(host, port, q.to_wire())
    lines = h.pop_log_lines(count=1, timeout=2.0)
    rec = find(lines, client=f"127.0.0.1:{lport}", qname="www.fit.vut.cz.", qtype="A")
    assert rec is not None, lines
    assert rec["verdict"] == "forwarded"
    assert rec["rcode"] == "NOERROR"


def test_invalid_verdict_qname_dash_when_question_unparsed(log_env):
    """OPCODE is checked (step 3) before the question is ever parsed (step
    5), so a bad OPCODE must log qname/qtype as '-' even though valid
    question bytes follow in the message."""
    h, host, port, up = log_env
    payload = dnswire.header(id_=0x9001, opcode=1, qdcount=1) + dnswire.question(dnswire.encode_name("x.test."))
    _resp, lport = _udp_with_client_port(host, port, payload)
    lines = h.pop_log_lines(count=1, timeout=2.0)
    rec = find(lines, client=f"127.0.0.1:{lport}")
    assert rec is not None, lines
    assert rec["qname"] == "-"
    assert rec["qtype"] == "-"
    assert rec["verdict"] == "invalid"
    assert rec["rcode"] == "NOTIMP"


def test_invalid_verdict_qname_present_when_question_parsed(log_env):
    """QCLASS != IN fails in step 7, after the question parsed successfully
    in step 5 -- qname/qtype must be logged."""
    h, host, port, up = log_env
    q = dnswire.question(dnswire.encode_name("chquery.test."), qclass=dnswire.QCLASS_CH)
    payload = dnswire.header(id_=0x9002, qdcount=1) + q
    _resp, lport = _udp_with_client_port(host, port, payload)
    lines = h.pop_log_lines(count=1, timeout=2.0)
    rec = find(lines, client=f"127.0.0.1:{lport}")
    assert rec is not None, lines
    assert rec["qname"] == "chquery.test."
    assert rec["qtype"] == "A"  # QTYPE for the CH query was A (type 1); mnemonic is type-based, not class-based
    assert rec["verdict"] == "invalid"
    assert rec["rcode"] == "NOTIMP"


def test_dropped_verdict_short_message_dash_fields(log_env):
    h, host, port, up = log_env
    s = netio.udp_socket(timeout=0.5)
    s.bind(("127.0.0.1", 0))
    lport = s.getsockname()[1]
    try:
        s.sendto(b"\x00\x01\x02", (host, port))
        try:
            s.recvfrom(65535)
            pytest.fail("a dropped message must not produce any response")
        except TimeoutError:
            pass
        except OSError:
            pass
    finally:
        s.close()
    lines = h.pop_log_lines(count=1, timeout=2.0)
    rec = find(lines, client=f"127.0.0.1:{lport}")
    assert rec is not None, lines
    assert rec["qname"] == "-"
    assert rec["qtype"] == "-"
    assert rec["verdict"] == "dropped"
    assert rec["rcode"] == "-"


def test_ipv4_client_logged_as_plain_ipv4_even_on_dual_stack_default(proxy_bin, zones_dir):
    """Regardless of whether the implementation uses one dual-stack IPv6
    socket or two separate sockets for the default (no -a) case, an IPv4
    client MUST be logged in plain IPv4 form, never as an IPv4-mapped IPv6
    address."""
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(proxy_bin, ["-u", "https://example.test/dns-query", "-p", str(port), "-a", "0.0.0.0"])
    try:
        lines = h.wait_listening(expected=2, timeout=5)
        assert len(lines) == 2
        q = make_query("plain-v4.test.", "A")
        _resp, lport = _udp_with_client_port("127.0.0.1", port, q.to_wire(), timeout=5.0)
        log_lines = h.pop_log_lines(count=1, timeout=2.0)
        assert len(log_lines) == 1
        assert log_lines[0].split(" ")[1] == f"127.0.0.1:{lport}"
    finally:
        if h.is_running():
            h.send_signal()
            if h.wait_exit(timeout=2.0) is None:
                h.kill()


def test_exactly_one_log_line_per_message(log_env):
    h, host, port, up = log_env
    q = make_query("nas.home.lan.", "A")
    _udp_with_client_port(host, port, q.to_wire())
    lines = h.pop_log_lines(count=1, timeout=2.0)
    assert len(lines) == 1
    assert h.expect_no_log_line(timeout=0.3), "exactly one line per message, no extras"


def test_multiset_matching_independent_of_arrival_order(log_env):
    h, host, port, up = log_env
    queries = [
        ("router.home.lan.", "A"),
        ("nas.home.lan.", "A"),
        ("www.ads.example.com.", "A"),
    ]
    expected_clients = []
    for name, qtype in queries:
        q = make_query(name, qtype)
        _resp, lport = _udp_with_client_port(host, port, q.to_wire())
        expected_clients.append((f"127.0.0.1:{lport}", name, qtype))

    lines = h.pop_log_lines(count=3, timeout=3.0)
    assert len(lines) == 3
    for client, name, qtype in expected_clients:
        rec = find(lines, client=client, qname=name, qtype=qtype)
        assert rec is not None, f"missing log line for {client} {name} {qtype} in {lines}"
