"""OPT echoing and UDP truncation rules from the "Responses" section."""
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from conftest import blocklist, zone
from isa_tests import dnswire, netio, ports
from isa_tests.dnsutil import make_query
from isa_tests.proxy import ProxyHandle


@pytest.fixture(scope="module")
def edns_proxy(proxy_bin, zones_dir, blocklists_dir):
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        [
            "-u", "https://example.test/dns-query",
            "-p", str(port), "-a", "127.0.0.1",
            "-z", zone("home.lan.zone"),
            "-z", zone("big-answer.test.zone"),
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


def _raw(edns_proxy, payload, timeout=2.0):
    _h, host, port = edns_proxy
    return netio.udp_roundtrip(host, port, payload, timeout=timeout)


# --- OPT echoing --------------------------------------------------------------

def test_local_answer_with_opt_gets_opt_echoed(edns_proxy):
    q = make_query("router.home.lan.", "A", use_edns=True, payload=1232)
    wire = _raw(edns_proxy, q.to_wire())
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.edns == 0
    assert r.payload >= 1232
    assert not r.options


def test_local_answer_without_opt_gets_no_opt(edns_proxy):
    q = make_query("router.home.lan.", "A", use_edns=False)
    wire = _raw(edns_proxy, q.to_wire())
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.edns == -1


def test_blocked_answer_with_opt_gets_opt_echoed(edns_proxy):
    q = make_query("ads.example.com.", "A", use_edns=True, payload=2000)
    wire = _raw(edns_proxy, q.to_wire())
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.rcode() == dns.rcode.NXDOMAIN
    assert r.edns == 0
    assert r.payload >= 1232


def test_invalid_answer_with_opt_gets_opt_echoed(edns_proxy):
    q = dnswire.header(id_=0x3001, opcode=1, qdcount=1, arcount=1)
    q += dnswire.question(dnswire.encode_name("x.test."))
    q += dnswire.opt_record(payload_size=1500)
    wire = _raw(edns_proxy, q)
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.rcode() == dns.rcode.NOTIMP
    assert r.edns == 0
    assert r.payload >= 1232


def test_rejected_in_early_steps_never_carries_opt(edns_proxy):
    # QDCOUNT != 1 is rejected in step 4, well before the OPT rules (step 6)
    # are ever reached. Spec: "Responses to messages rejected in steps 1-6
    # carry no OPT" -- true regardless of what bytes happen to follow.
    q = dnswire.header(id_=0x3002, qdcount=0)
    wire = _raw(edns_proxy, q)
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.edns == -1


# --- UDP truncation ------------------------------------------------------------

def test_oversized_zone_answer_truncated_without_opt(edns_proxy):
    q = make_query("big.big-answer.test.", "A", use_edns=False)
    wire = _raw(edns_proxy, q.to_wire())
    assert len(wire) <= 512
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.flags & dns.flags.TC
    assert len(r.answer) == 0
    assert len(r.authority) == 0
    assert len(r.question) == 1
    assert r.edns == -1


def test_oversized_zone_answer_truncated_at_bufsize_512_with_opt(edns_proxy):
    q = make_query("big.big-answer.test.", "A", use_edns=True, payload=512)
    wire = _raw(edns_proxy, q.to_wire())
    assert len(wire) <= 512
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert r.flags & dns.flags.TC
    assert len(r.answer) == 0
    assert r.edns == 0
    assert len(r.question) == 1


def test_oversized_zone_answer_not_truncated_under_default_edns_payload(edns_proxy):
    q = make_query("big.big-answer.test.", "A", use_edns=True, payload=1232)
    wire = _raw(edns_proxy, q.to_wire())
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert not (r.flags & dns.flags.TC)
    assert len(r.answer) == 40


def test_small_answer_not_truncated_without_opt(edns_proxy):
    q = make_query("router.home.lan.", "A", use_edns=False)
    wire = _raw(edns_proxy, q.to_wire())
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert not (r.flags & dns.flags.TC)
    assert len(r.answer) == 1


def test_forwarded_oversized_response_truncated_without_opt(proxy_bin, mock_upstream):
    big_rrset_names = [f"198.51.100.{i}" for i in range(1, 41)]

    def responder(body, q):
        resp = dns.message.make_response(q)
        rr = dns.rrset.from_text(q.question[0].name, 60, "IN", "A", *big_rrset_names)
        resp.answer.append(rr)
        return resp.to_wire()

    mock_upstream.responder = responder
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(proxy_bin, ["-u", mock_upstream.url, "-p", str(port), "-a", "127.0.0.1", "-w", "3"])
    try:
        lines = h.wait_listening(expected=2, timeout=5)
        assert len(lines) == 2

        q = make_query("huge.example.test.", "A", use_edns=False)
        wire = netio.udp_roundtrip("127.0.0.1", port, q.to_wire(), timeout=5.0)
        assert len(wire) <= 512
        r = dns.message.from_wire(wire, raise_on_truncation=False)
        assert r.flags & dns.flags.TC
        assert len(r.answer) == 0
        assert len(r.question) == 1
    finally:
        if h.is_running():
            h.send_signal()
            if h.wait_exit(timeout=2.0) is None:
                h.kill()


def test_tcp_response_never_truncated(edns_proxy):
    _h, host, port = edns_proxy
    q = make_query("big.big-answer.test.", "A", use_edns=False)
    sock = netio.tcp_connect(host, port, timeout=5.0)
    try:
        netio.send_tcp_message(sock, q.to_wire())
        wire = netio.recv_tcp_message(sock)
    finally:
        sock.close()
    r = dns.message.from_wire(wire, raise_on_truncation=False)
    assert not (r.flags & dns.flags.TC)
    assert len(r.answer) == 40
