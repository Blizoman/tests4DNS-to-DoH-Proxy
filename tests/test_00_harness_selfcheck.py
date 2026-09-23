"""Self-checks for the test harness itself -- no isa-dnsproxy binary needed.

These run today, with no student implementation in the picture, and stay
green regardless of which language (C, Go, ...) the proxy ends up written
in. They exist so a red result elsewhere in the suite means "your proxy
does something the spec forbids", not "the test helper is broken".
"""
import http.client
import socket
import ssl

import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from isa_tests import dnswire, ports
from isa_tests.logqueries import LOG_LINE_RE, find, parse_log_line

pytestmark = pytest.mark.harness


# --- log line format -------------------------------------------------------

SPEC_EXAMPLE_LOG_LINES = [
    "2026-09-15T09:57:29+02:00 127.0.0.1:50417 router.home.lan. A local NOERROR",
    "2026-09-15T09:57:29+02:00 127.0.0.1:44669 media.home.lan. A local NOERROR",
    "2026-09-15T09:57:29+02:00 127.0.0.1:37223 printer.home.lan. A local NXDOMAIN",
    "2026-09-15T09:57:29+02:00 127.0.0.1:51555 www.ads.example.com. AAAA blocked NXDOMAIN",
    "2026-09-15T09:57:29+02:00 127.0.0.1:35694 www.fit.vut.cz. A forwarded NOERROR",
]


@pytest.mark.parametrize("line", SPEC_EXAMPLE_LOG_LINES)
def test_log_regex_accepts_spec_examples(line):
    assert LOG_LINE_RE.match(line), line


@pytest.mark.parametrize(
    "line",
    [
        "2026-09-15 09:57:29+02:00 127.0.0.1:50417 router.home.lan. A local NOERROR",  # missing T
        "2026-09-15T09:57:29+02:00 127.0.0.1 router.home.lan. A local NOERROR",  # missing port
        "2026-09-15T09:57:29+02:00 127.0.0.1:50417 router.home.lan A local NOERROR",  # no trailing dot
        "2026-09-15T09:57:29+02:00 127.0.0.1:50417 router.home.lan. a local NOERROR",  # lowercase qtype
        "2026-09-15T09:57:29+02:00 127.0.0.1:50417 router.home.lan. A weird NOERROR",  # bad verdict
        "2026-09-15T09:57:29+02:00 127.0.0.1:50417 router.home.lan. A local noerror",  # lowercase rcode
    ],
)
def test_log_regex_rejects_malformed(line):
    assert LOG_LINE_RE.match(line) is None


def test_log_parse_and_multiset_find():
    lines = list(SPEC_EXAMPLE_LOG_LINES)
    rec = find(lines, qname="media.home.lan.", qtype="A")
    assert rec is not None
    assert rec["verdict"] == "local"
    assert rec["rcode"] == "NOERROR"
    assert find(lines, qname="nonexistent.") is None


def test_log_parse_ipv6_client():
    line = "2026-09-15T09:57:29Z [fd00::10]:51555 www.ads.example.com. AAAA blocked NXDOMAIN"
    assert LOG_LINE_RE.match(line)
    rec = parse_log_line(line)
    assert rec["client"] == "[fd00::10]:51555"


# --- raw DNS wire helpers ---------------------------------------------------

def test_dnswire_simple_query_parses_with_dnspython():
    wire = dnswire.simple_query("www.example.test.", qtype=dnswire.QTYPE_A, id_=0xABCD, with_opt=True)
    msg = dns.message.from_wire(wire)
    assert msg.id == 0xABCD
    assert msg.question[0].name.to_text() == "www.example.test."
    assert msg.question[0].rdtype == dns.rdatatype.A
    assert msg.edns == 0


def test_dnswire_header_flags_roundtrip():
    wire = dnswire.header(id_=1, qr=1, opcode=0, aa=1, tc=0, rd=1, ra=1, rcode=3, qdcount=1)
    wire += dnswire.question(dnswire.encode_name("x.test."))
    msg = dns.message.from_wire(wire)
    assert msg.flags & dns.flags.QR
    assert msg.flags & dns.flags.AA
    assert msg.rcode() == dns.rcode.NXDOMAIN


def test_dnswire_short_message_is_really_short():
    wire = dnswire.header(qdcount=0)[:11]
    assert len(wire) < 12


# --- mock DoH upstream -------------------------------------------------------

def test_mock_upstream_plain_http_roundtrip(mock_upstream):
    q = dns.message.make_query("example.test.", "A")
    q.id = 0
    conn = http.client.HTTPConnection(mock_upstream.host, mock_upstream.port, timeout=5)
    conn.request(
        "POST",
        "/dns-query",
        body=q.to_wire(),
        headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
    )
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    assert resp.status == 200
    assert resp.getheader("Content-Type") == "application/dns-message"
    answer = dns.message.from_wire(body)
    assert answer.question[0].name.to_text() == "example.test."
    assert answer.rcode() == dns.rcode.NOERROR
    assert len(answer.answer) == 1

    recorded = mock_upstream.last_request()
    assert recorded.method == "POST"
    assert recorded.headers.get("Content-Type") == "application/dns-message"


def test_mock_upstream_records_are_isolated_per_test(mock_upstream):
    # a fresh `mock_upstream` fixture instance per test => no leftover requests
    assert mock_upstream.requests == []


def test_mock_upstream_tls_requires_verification_by_default(mock_upstream_tls):
    ctx = ssl.create_default_context()
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection((mock_upstream_tls.host, mock_upstream_tls.port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=mock_upstream_tls.host):
                pass


def test_mock_upstream_tls_reachable_when_verification_disabled(mock_upstream_tls):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((mock_upstream_tls.host, mock_upstream_tls.port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=mock_upstream_tls.host) as tls_sock:
            assert tls_sock.version() is not None


# --- misc --------------------------------------------------------------------

def test_free_port_is_bindable_udp_and_tcp():
    port = ports.free_udp_tcp_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
        t.bind(("127.0.0.1", port))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.bind(("127.0.0.1", port))
