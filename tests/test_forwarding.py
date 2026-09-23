"""DoH forwarding: RFC 8484 request shape, response relay, and every
documented SERVFAIL condition. Forwarding is worth about half the
automated grade, so this file is the largest in the suite.
"""
import socket
import threading
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from isa_tests import netio, ports
from isa_tests.dnsutil import make_query
from isa_tests.proxy import ProxyHandle


def _proxy_for(proxy_bin, upstream_url, extra_args=None, w=None, insecure=False, wait_for=2):
    port = ports.free_udp_tcp_port()
    args = ["-u", upstream_url, "-p", str(port), "-a", "127.0.0.1"]
    if w is not None:
        args += ["-w", str(w)]
    if insecure:
        args.append("--insecure")
    if extra_args:
        args += extra_args
    h = ProxyHandle(proxy_bin, args)
    lines = h.wait_listening(expected=wait_for, timeout=5)
    assert len(lines) == wait_for, f"proxy did not start against {upstream_url}: {h.stderr_extra}"
    return h, "127.0.0.1", port


def _teardown(h):
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


def _query(host, port, qname, qtype="A", id=0xBEEF, timeout=5.0):
    q = make_query(qname, qtype, id=id)
    wire = netio.udp_roundtrip(host, port, q.to_wire(), timeout=timeout)
    return dns.message.from_wire(wire, raise_on_truncation=False)


@pytest.fixture
def fwd_proxy(proxy_bin, mock_upstream):
    h, host, port = _proxy_for(proxy_bin, mock_upstream.url, w=3)
    yield h, host, port, mock_upstream
    _teardown(h)


# --- basic relay -------------------------------------------------------------

def test_basic_forward_uses_post_with_dns_message_content_type(fwd_proxy):
    h, host, port, up = fwd_proxy
    r = _query(host, port, "www.example.test.", "A", id=0x1234)
    assert r.rcode() == dns.rcode.NOERROR
    assert r.id == 0x1234
    assert len(r.answer) == 1
    assert str(r.answer[0][0]) == "203.0.113.10"

    assert len(up.requests) == 1, "caching off => exactly one upstream request per forwarded query"
    req = up.requests[0]
    assert req.method == "POST"
    assert req.headers.get("Content-Type") == "application/dns-message"
    assert req.headers.get("Accept") == "application/dns-message"


def test_forwarded_query_id_should_be_zero(fwd_proxy):
    """RFC 8484 SHOULD, not MUST: relax/remove this one test if your design
    deliberately keeps a nonzero ID (e.g. to match responses without relying
    on the HTTP exchange -- though the spec says matching MUST be by
    exchange, not ID, so zero is the expected choice)."""
    h, host, port, up = fwd_proxy
    _query(host, port, "id-check.example.test.", "A", id=0x7777)
    q = dns.message.from_wire(up.requests[-1].body)
    assert q.id == 0


def test_client_id_restored_on_response(fwd_proxy):
    h, host, port, up = fwd_proxy
    r = _query(host, port, "id2.example.test.", "A", id=0x55AA)
    assert r.id == 0x55AA


def test_question_relayed_unchanged(fwd_proxy):
    h, host, port, up = fwd_proxy
    _query(host, port, "Www.Example.Test.", "A")
    q = dns.message.from_wire(up.requests[-1].body)
    assert q.question[0].name.to_text().lower() == "www.example.test."


def test_non_noerror_rcode_relayed_unchanged(fwd_proxy):
    h, host, port, up = fwd_proxy

    def responder(body, q):
        resp = dns.message.make_response(q)
        resp.set_rcode(dns.rcode.REFUSED)
        return resp.to_wire()

    up.responder = responder
    r = _query(host, port, "refused.example.test.", "A")
    assert r.rcode() == dns.rcode.REFUSED


def test_upstream_opt_relayed_unchanged(fwd_proxy):
    h, host, port, up = fwd_proxy

    def responder(body, q):
        resp = dns.message.make_response(q)
        resp.use_edns(edns=1, payload=4096)  # deliberately non-default version/size
        return resp.to_wire()

    up.responder = responder
    r = _query(host, port, "opt-passthrough.example.test.", "A")
    assert r.edns == 1
    assert r.payload == 4096


def test_two_clients_same_query_id_get_own_responses(fwd_proxy):
    h, host, port, up = fwd_proxy
    results = {}
    barrier = threading.Barrier(2)

    def worker(name, key):
        barrier.wait(timeout=5)
        r = _query(host, port, name, "A", id=0x9999)
        results[key] = r

    t1 = threading.Thread(target=worker, args=("client-one.example.test.", "one"))
    t2 = threading.Thread(target=worker, args=("client-two.example.test.", "two"))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert results["one"].id == 0x9999
    assert results["two"].id == 0x9999
    assert len(up.requests) == 2


# --- SERVFAIL conditions ------------------------------------------------------

def test_servfail_when_upstream_hostname_does_not_resolve(proxy_bin):
    # .invalid is reserved by RFC 2606 to never resolve.
    h, host, port = _proxy_for(proxy_bin, "https://this-name-must-not-resolve.invalid/dns-query", w=3)
    try:
        r = _query(host, port, "x.example.test.", "A", timeout=5.0)
        assert r.rcode() == dns.rcode.SERVFAIL
    finally:
        _teardown(h)


def test_servfail_when_connection_refused(proxy_bin):
    dead_port = ports.free_udp_tcp_port()  # free => nothing listening there
    h, host, port = _proxy_for(proxy_bin, f"http://127.0.0.1:{dead_port}/dns-query", w=3)
    try:
        r = _query(host, port, "x.example.test.", "A", timeout=5.0)
        assert r.rcode() == dns.rcode.SERVFAIL
    finally:
        _teardown(h)


def test_servfail_on_non_2xx_http_response(fwd_proxy):
    h, host, port, up = fwd_proxy
    up.mode = "http_error"
    up.http_status = 500
    r = _query(host, port, "http-error.example.test.", "A")
    assert r.rcode() == dns.rcode.SERVFAIL


def test_redirect_not_followed_and_results_in_servfail(fwd_proxy):
    h, host, port, up = fwd_proxy
    up.mode = "redirect"
    r = _query(host, port, "redirect-me.example.test.", "A")
    assert r.rcode() == dns.rcode.SERVFAIL
    assert len(up.requests) == 1, "the proxy must not follow the redirect and issue a second request"


def test_servfail_on_invalid_response_body(fwd_proxy):
    h, host, port, up = fwd_proxy
    up.mode = "invalid_body"
    up.invalid_body = b"this is not a dns message"
    r = _query(host, port, "garbage-body.example.test.", "A")
    assert r.rcode() == dns.rcode.SERVFAIL


def test_servfail_when_response_question_mismatches(fwd_proxy):
    h, host, port, up = fwd_proxy

    def responder(body, q):
        other = make_query("someone-else.example.test.", "A")
        resp = dns.message.make_response(other)
        return resp.to_wire()

    up.responder = responder
    r = _query(host, port, "mismatch.example.test.", "A")
    assert r.rcode() == dns.rcode.SERVFAIL


def test_servfail_when_response_qr_not_set(fwd_proxy):
    h, host, port, up = fwd_proxy

    def responder(body, q):
        resp = dns.message.make_response(q)
        wire = bytearray(resp.to_wire())
        wire[2] &= 0x7F  # clear QR
        return bytes(wire)

    up.responder = responder
    r = _query(host, port, "no-qr.example.test.", "A")
    assert r.rcode() == dns.rcode.SERVFAIL


def test_timeout_elapses_then_servfail(proxy_bin, mock_upstream):
    mock_upstream.delay = 2.0
    h, host, port = _proxy_for(proxy_bin, mock_upstream.url, w=1)
    try:
        t0 = time.monotonic()
        r = _query(host, port, "slow.example.test.", "A", timeout=5.0)
        elapsed = time.monotonic() - t0
        assert r.rcode() == dns.rcode.SERVFAIL
        assert elapsed >= 1.0, "must not answer before the -w timeout elapses"
        assert elapsed <= 2.0, "forwarded (incl. SERVFAIL on timeout) budget is TIMEOUT + 1s"
    finally:
        _teardown(h)


def test_shutdown_in_flight_forwarded_query_gets_servfail(proxy_bin, mock_upstream):
    mock_upstream.delay = 5.0
    h, host, port = _proxy_for(proxy_bin, mock_upstream.url, w=10)
    try:
        result = {}

        def worker():
            result["r"] = _query(host, port, "in-flight.example.test.", "A", timeout=4.0)

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.3)  # let the query reach the proxy and start forwarding
        t0 = time.monotonic()
        h.send_signal()
        code = h.wait_exit(timeout=2.5)
        elapsed = time.monotonic() - t0
        t.join(timeout=4.0)

        assert code == 0, f"expected exit 0 within 2s of SIGTERM, got {code} after {elapsed:.2f}s"
        assert elapsed <= 2.5
        assert "r" in result, "client never got a response to the in-flight query"
        assert result["r"].rcode() == dns.rcode.SERVFAIL
    finally:
        if h.is_running():
            h.kill()


# --- TLS certificate verification --------------------------------------------

def test_default_rejects_self_signed_cert(proxy_bin, mock_upstream_tls):
    h, host, port = _proxy_for(proxy_bin, mock_upstream_tls.url, w=3, insecure=False)
    try:
        r = _query(host, port, "tls-default.example.test.", "A", timeout=5.0)
        assert r.rcode() == dns.rcode.SERVFAIL
    finally:
        _teardown(h)


def test_insecure_flag_accepts_self_signed_cert(proxy_bin, mock_upstream_tls):
    h, host, port = _proxy_for(proxy_bin, mock_upstream_tls.url, w=3, insecure=True)
    try:
        r = _query(host, port, "tls-insecure.example.test.", "A", timeout=5.0)
        assert r.rcode() == dns.rcode.NOERROR
        assert len(r.answer) == 1
    finally:
        _teardown(h)


def test_ssl_cert_file_env_can_trust_our_self_signed_cert(proxy_bin, mock_upstream_tls, self_signed_cert):
    """When SSL_CERT_FILE points at a bundle containing our self-signed cert,
    the proxy MUST trust it without --insecure (this is how the course's
    isa devShell CA bundle is meant to be used)."""
    cert_path, _key_path = self_signed_cert
    port = ports.free_udp_tcp_port()
    import os
    env = dict(os.environ)
    env["SSL_CERT_FILE"] = cert_path
    h = ProxyHandle(
        proxy_bin,
        ["-u", mock_upstream_tls.url, "-p", str(port), "-a", "127.0.0.1", "-w", "3"],
        env=env,
    )
    try:
        lines = h.wait_listening(expected=2, timeout=5)
        assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
        r = _query(host="127.0.0.1", port=port, qname="ssl-cert-file.example.test.", qtype="A", timeout=5.0)
        assert r.rcode() == dns.rcode.NOERROR
    finally:
        _teardown(h)


# --- HTTP/1.1-only upstream compatibility ------------------------------------

def test_works_against_http1_1_only_upstream(fwd_proxy):
    # Python's http.server speaks HTTP/1.1 only; a passing basic-forward test
    # already proves this, but we also confirm several sequential queries
    # over the same upstream all succeed (no protocol-version assumption).
    h, host, port, up = fwd_proxy
    for i in range(5):
        r = _query(host, port, f"seq{i}.example.test.", "A")
        assert r.rcode() == dns.rcode.NOERROR
    assert len(up.requests) == 5
