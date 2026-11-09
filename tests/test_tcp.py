"""TCP framing: RFC 1035 length prefix, pipelining, idle timeout, and the
"a slow client MUST NOT delay other messages" requirement.
"""
import socket
import struct
import time

import dns.message
import dns.rcode
import pytest

from conftest import zone
from isa_tests import netio, ports
from isa_tests.dnsutil import make_query
from isa_tests.proxy import ProxyHandle


@pytest.fixture(scope="module")
def tcp_proxy(proxy_bin, zones_dir):
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        ["-u", "https://example.test/dns-query", "-p", str(port), "-a", "127.0.0.1", "-z", zone("home.lan.zone")],
    )
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
    yield h, "127.0.0.1", port
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


def test_single_query_over_tcp(tcp_proxy):
    _h, host, port = tcp_proxy
    q = make_query("router.home.lan.", "A")
    sock = netio.tcp_connect(host, port, timeout=5.0)
    try:
        netio.send_tcp_message(sock, q.to_wire())
        wire = netio.recv_tcp_message(sock)
    finally:
        sock.close()
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.answer) == 1


def test_several_queries_on_one_connection(tcp_proxy):
    _h, host, port = tcp_proxy
    names = ["router.home.lan.", "nas.home.lan.", "mail.home.lan.", "printer.home.lan."]
    sock = netio.tcp_connect(host, port, timeout=5.0)
    try:
        for name in names:
            netio.send_tcp_message(sock, make_query(name, "A").to_wire())
        got = {}
        for _ in names:
            wire = netio.recv_tcp_message(sock)
            r = dns.message.from_wire(wire, raise_on_truncation=False)
            got[r.question[0].name.to_text().lower()] = r
    finally:
        sock.close()
    assert set(got) == {n.lower() for n in names}
    assert got["printer.home.lan."].rcode() == dns.rcode.NXDOMAIN
    assert got["router.home.lan."].rcode() == dns.rcode.NOERROR


def test_message_split_across_segments(tcp_proxy):
    _h, host, port = tcp_proxy
    q = make_query("router.home.lan.", "A")
    sock = netio.tcp_connect(host, port, timeout=5.0)
    try:
        netio.send_tcp_message(sock, q.to_wire(), chunk_size=3, inter_chunk_delay=0.02)
        wire = netio.recv_tcp_message(sock)
    finally:
        sock.close()
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.rcode() == dns.rcode.NOERROR


@pytest.mark.slow
def test_idle_connection_closed_after_10s(tcp_proxy):
    _h, host, port = tcp_proxy
    sock = netio.tcp_connect(host, port, timeout=20.0)
    try:
        q = make_query("router.home.lan.", "A")
        netio.send_tcp_message(sock, q.to_wire())
        netio.recv_tcp_message(sock)

        t0 = time.monotonic()
        sock.settimeout(20.0)
        closed = False
        try:
            data = sock.recv(1)
            closed = data == b""
        except socket.timeout:
            closed = False
        elapsed = time.monotonic() - t0
        assert closed, f"connection was not closed by the proxy within {elapsed:.1f}s of idleness"
        assert 10.0 <= elapsed <= 15.0, f"idle timeout MUST be 10s (+5s tolerance), took {elapsed:.1f}s"
    finally:
        sock.close()


def test_client_closing_mid_message_produces_no_log_line(tcp_proxy):
    h, host, port = tcp_proxy
    time.sleep(0.3)
    h.drain_stdout()  # log lines of earlier tests sharing this proxy
    sock = netio.tcp_connect(host, port, timeout=5.0)
    # Send only the two-byte length prefix (claiming a large body), then close.
    sock.sendall(struct.pack("!H", 100))
    sock.close()
    time.sleep(0.3)
    assert h.expect_no_log_line(timeout=0.5), (
        "a client closing mid-message must not produce a stdout log line: "
        f"got {getattr(h, '_unexpected_line', None)!r}"
    )


def test_dropped_tcp_message_closes_connection(tcp_proxy):
    """A message that is dropped per steps 1-2 (e.g. QR=1) closes the TCP
    connection (spec: 'after a dropped TCP message it closes the
    connection')."""
    from isa_tests import dnswire

    _h, host, port = tcp_proxy
    payload = dnswire.header(qr=1, qdcount=1) + dnswire.question(dnswire.encode_name("x.test."))
    sock = netio.tcp_connect(host, port, timeout=5.0)
    try:
        netio.send_tcp_message(sock, payload)
        assert netio.tcp_expect_closed(sock, timeout=2.0)
    finally:
        sock.close()


def test_slow_client_does_not_stall_other_clients(tcp_proxy):
    """One TCP client trickles a length prefix in and never finishes; a
    second, well-behaved UDP client must still get prompt answers."""
    _h, host, port = tcp_proxy
    slow_sock = netio.tcp_connect(host, port, timeout=20.0)
    try:
        slow_sock.sendall(b"\x00")  # half of a length prefix, then silence

        t0 = time.monotonic()
        q = make_query("router.home.lan.", "A")
        wire = netio.udp_roundtrip(host, port, q.to_wire(), timeout=2.0)
        elapsed = time.monotonic() - t0
        r = dns.message.from_wire(wire, raise_on_truncation=False)
        assert r.rcode() == dns.rcode.NOERROR
        assert elapsed <= 0.5, f"a stalled TCP client delayed an unrelated UDP query by {elapsed:.2f}s"
    finally:
        slow_sock.close()
