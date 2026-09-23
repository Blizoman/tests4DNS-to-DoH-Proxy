"""The eight ordered checks in "Message processing" (spec order matters:
first failing check decides the verdict), plus the response-shape rules
that follow from it.
"""
import dns.flags
import dns.message
import dns.rcode
import pytest

from isa_tests import dnswire, netio, ports
from isa_tests.proxy import ProxyHandle


@pytest.fixture(scope="module")
def running_proxy(proxy_bin):
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(proxy_bin, ["-u", "https://example.test/dns-query", "-p", str(port), "-a", "127.0.0.1"])
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
    yield h, "127.0.0.1", port
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


def _send(running_proxy, payload, timeout=2.0):
    _h, host, port = running_proxy
    return netio.udp_roundtrip(host, port, payload, timeout=timeout)


def _expect_dropped(running_proxy, payload, timeout=0.5):
    _h, host, port = running_proxy
    assert netio.udp_expect_no_response(host, port, payload, timeout=timeout)


# --- step 1: shorter than 12 octets -> dropped ------------------------------

@pytest.mark.parametrize("length", [0, 1, 6, 11])
def test_step1_short_message_dropped(running_proxy, length):
    _expect_dropped(running_proxy, b"\x00" * length)


# --- step 2: QR = 1 -> dropped ----------------------------------------------

def test_step2_qr_set_dropped(running_proxy):
    payload = dnswire.header(qr=1, qdcount=1) + dnswire.question(dnswire.encode_name("x.test."))
    _expect_dropped(running_proxy, payload)


# --- step 3: OPCODE != QUERY -> invalid, NOTIMP -----------------------------

@pytest.mark.parametrize("opcode", [1, 2, 4, 5])
def test_step3_bad_opcode_notimp(running_proxy, opcode):
    payload = dnswire.header(id_=0x4242, opcode=opcode, rd=1, qdcount=1) + dnswire.question(dnswire.encode_name("x.test."))
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.id == 0x4242
    assert resp.flags & dns.flags.QR
    assert resp.opcode() == opcode, "OPCODE MUST be copied from the query even on NOTIMP"
    assert resp.rcode() == dns.rcode.NOTIMP
    assert len(resp.question) == 0


# --- step 4: QDCOUNT != 1 -> invalid, FORMERR -------------------------------

def test_step4_qdcount_zero_formerr(running_proxy):
    payload = dnswire.header(id_=0x1001, qdcount=0)
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 0


def test_step4_qdcount_two_formerr(running_proxy):
    q = dnswire.question(dnswire.encode_name("x.test."))
    payload = dnswire.header(id_=0x1002, qdcount=2) + q + q
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 0


# --- step 5: question does not parse -> invalid, FORMERR --------------------

def test_step5_bad_label_length_formerr(running_proxy):
    name = dnswire.label(70, b"x" * 20) + b"\x00"
    payload = dnswire.header(id_=0x1003, qdcount=1) + dnswire.question(name)
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 0


def test_step5_compression_pointer_in_question_formerr(running_proxy):
    # A label followed by a pointer instead of a root terminator: valid,
    # ordinary DNS name compression -- and explicitly disallowed here.
    name = bytes([1]) + b"s" + dnswire.compression_pointer(0)
    payload = dnswire.header(id_=0x1004, qdcount=1) + dnswire.question(name)
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 0


def test_step5_name_too_long_formerr(running_proxy):
    # > 255 octets total: sixty-three 4-byte labels ("aaa.") is 252 bytes of
    # labels alone before the root, comfortably over the limit.
    labels = "aaa." * 70
    name = dnswire.encode_name(labels.rstrip("."))
    assert len(name) > 255
    payload = dnswire.header(id_=0x1005, qdcount=1) + dnswire.question(name)
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 0


def test_step5_question_runs_past_message_formerr(running_proxy):
    full = dnswire.header(id_=0x1006, qdcount=1) + dnswire.question(dnswire.encode_name("x.test."))
    truncated = full[:-3]  # cut into QTYPE/QCLASS
    wire = _send(running_proxy, truncated)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 0


# --- step 6: other sections / OPT rules -> invalid, FORMERR -----------------

def test_step6_ancount_claims_record_that_is_absent_formerr(running_proxy):
    payload = dnswire.header(id_=0x1007, qdcount=1, ancount=1) + dnswire.question(dnswire.encode_name("x.test."))
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    # question parsed successfully (step 5 passed) so it must be echoed back
    assert len(resp.question) == 1
    assert resp.question[0].name.to_text() == "x.test."


def test_step6_two_opt_records_formerr(running_proxy):
    q = dnswire.question(dnswire.encode_name("x.test."))
    payload = dnswire.header(id_=0x1008, qdcount=1, arcount=2) + q + dnswire.opt_record() + dnswire.opt_record()
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 1


def test_step6_opt_outside_additional_formerr(running_proxy):
    q = dnswire.question(dnswire.encode_name("x.test."))
    # OPT bytes placed where the answer section is expected (ancount=1, arcount=0)
    payload = dnswire.header(id_=0x1009, qdcount=1, ancount=1, arcount=0) + q + dnswire.opt_record()
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 1


def test_step6_opt_non_root_owner_formerr(running_proxy):
    q = dnswire.question(dnswire.encode_name("x.test."))
    bad_opt = dnswire.opt_record(owner=dnswire.encode_name("not-root.test."))
    payload = dnswire.header(id_=0x100A, qdcount=1, arcount=1) + q + bad_opt
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.FORMERR
    assert len(resp.question) == 1


def test_step6_ordinary_records_in_other_sections_not_an_error(running_proxy):
    """A query carrying an OPT (as dig always sends) plus arbitrary but
    well-formed extra flags (TC, AA, RA, AD) MUST NOT be rejected."""
    q = dnswire.question(dnswire.encode_name("plain.test."))
    payload = dnswire.header(id_=0x100B, qdcount=1, rd=1, tc=1, aa=1, ra=1, ad=1, arcount=1) + q + dnswire.opt_record()
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() != dns.rcode.FORMERR
    assert resp.rcode() != dns.rcode.NOTIMP


def test_step6_opt_version_not_checked(running_proxy):
    q = dnswire.question(dnswire.encode_name("plain.test."))
    payload = dnswire.header(id_=0x100C, qdcount=1, arcount=1) + q + dnswire.opt_record(version=200)
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() != dns.rcode.FORMERR


# --- step 7: QCLASS != IN -> invalid, NOTIMP --------------------------------

@pytest.mark.parametrize("qclass", [dnswire.QCLASS_CH, 255])
def test_step7_qclass_not_in_notimp(running_proxy, qclass):
    q = dnswire.question(dnswire.encode_name("x.test."), qclass=qclass)
    payload = dnswire.header(id_=0x100D, qdcount=1) + q
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.NOTIMP
    assert len(resp.question) == 1
    assert resp.question[0].rdclass == qclass


# --- step 8: QTYPE = AXFR/IXFR -> invalid, REFUSED --------------------------

@pytest.mark.parametrize("qtype", [252, 251])
def test_step8_axfr_ixfr_refused(running_proxy, qtype):
    q = dnswire.question(dnswire.encode_name("x.test."), qtype=qtype)
    payload = dnswire.header(id_=0x100E, qdcount=1) + q
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.rcode() == dns.rcode.REFUSED
    assert len(resp.question) == 1
    assert resp.question[0].rdtype == qtype


# --- response header shape --------------------------------------------------

def test_response_copies_rd_and_cd_and_client_id(running_proxy):
    q = dnswire.question(dnswire.encode_name("x.test."), qclass=dnswire.QCLASS_CH)
    payload = dnswire.header(id_=0x2001, rd=1, cd=1, qdcount=1) + q
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert resp.id == 0x2001
    assert resp.flags & dns.flags.RD
    assert resp.flags & dns.flags.CD
    assert resp.flags & dns.flags.RA
    assert not (resp.flags & dns.flags.AD)


def test_response_rd_0_and_cd_0_copied_too(running_proxy):
    q = dnswire.question(dnswire.encode_name("x.test."), qclass=dnswire.QCLASS_CH)
    payload = dnswire.header(id_=0x2002, rd=0, cd=0, qdcount=1) + q
    wire = _send(running_proxy, payload)
    resp = dns.message.from_wire(wire, raise_on_truncation=False)
    assert not (resp.flags & dns.flags.RD)
    assert not (resp.flags & dns.flags.CD)
