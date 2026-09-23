"""Zone loading, lookup, CNAME chains, negative responses, precedence over
blocklists. Mirrors the assignment's own worked examples where possible."""
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from conftest import blocklist, zone
from isa_tests import netio, ports
from isa_tests.proxy import ProxyHandle


def _query(proxy, qname, qtype="A", **kw):
    from isa_tests.dnsutil import make_query
    _h, host, port = proxy
    q = make_query(qname, qtype, **kw)
    wire = netio.udp_roundtrip(host, port, q.to_wire())
    return dns.message.from_wire(wire, raise_on_truncation=False)


@pytest.fixture(scope="module")
def zone_proxy(proxy_bin, zones_dir, blocklists_dir):
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        [
            "-u", "https://example.test/dns-query",
            "-p", str(port), "-a", "127.0.0.1",
            "-z", zone("home.lan.zone"),
            "-z", zone("cname-chain.test.zone"),
            "-z", zone("nested-parent.test.zone"),
            "-z", zone("nested-child.test.zone"),
            "-z", zone("unsupported-type.test.zone"),
            "-b", blocklist("covers-home-lan.txt"),
        ],
    )
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
    yield h, "127.0.0.1", port
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


# --- basic answers, matching the spec's own dig examples --------------------

def test_a_record_in_zone(zone_proxy):
    r = _query(zone_proxy, "router.home.lan.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert r.flags & dns.flags.AA, "aa MUST be set for a local answer"
    assert len(r.answer) == 1
    assert str(r.answer[0][0]) == "192.168.1.1"
    assert r.answer[0].ttl == 3600


def test_any_returns_every_rrset(zone_proxy):
    r = _query(zone_proxy, "router.home.lan.", "ANY")
    assert r.rcode() == dns.rcode.NOERROR
    types = {rrset.rdtype for rrset in r.answer}
    assert dns.rdatatype.A in types
    assert dns.rdatatype.AAAA in types


def test_cname_chain_within_zone(zone_proxy):
    r = _query(zone_proxy, "media.home.lan.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert r.flags & dns.flags.AA
    assert len(r.answer) == 2
    assert r.answer[0].rdtype == dns.rdatatype.CNAME
    assert str(r.answer[0][0]).rstrip(".") == "nas.home.lan"
    assert r.answer[1].rdtype == dns.rdatatype.A
    assert str(r.answer[1][0]) == "192.168.1.20"


def test_cname_query_type_returns_only_cname(zone_proxy):
    r = _query(zone_proxy, "media.home.lan.", "CNAME")
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.answer) == 1
    assert r.answer[0].rdtype == dns.rdatatype.CNAME


def test_nxdomain_below_apex_carries_soa(zone_proxy):
    r = _query(zone_proxy, "printer.home.lan.", "A")
    assert r.rcode() == dns.rcode.NXDOMAIN
    assert r.flags & dns.flags.AA
    assert len(r.answer) == 0
    assert len(r.authority) == 1
    assert r.authority[0].rdtype == dns.rdatatype.SOA
    # TTL MUST be min(SOA TTL, SOA MINIMUM); this zone's $TTL is 3600 and
    # MINIMUM is also 3600.
    assert r.authority[0].ttl == 3600


def test_nodata_name_exists_without_queried_type(zone_proxy):
    r = _query(zone_proxy, "router.home.lan.", "MX")
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.answer) == 0
    assert len(r.authority) == 1
    assert r.authority[0].rdtype == dns.rdatatype.SOA


def test_case_insensitive_lookup(zone_proxy):
    r = _query(zone_proxy, "RoUtEr.HOME.lan.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.answer) == 1


# --- CNAME chain edge cases --------------------------------------------------

def test_cname_chain_multi_hop(zone_proxy):
    r = _query(zone_proxy, "a.cname-chain.test.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    names = [str(rr.name).rstrip(".").lower() for rr in r.answer]
    assert names[0] == "a.cname-chain.test"
    assert r.answer[-1].rdtype == dns.rdatatype.A
    assert str(r.answer[-1][0]) == "192.0.2.42"


def test_cname_loop_ends_noerror_no_soa(zone_proxy):
    r = _query(zone_proxy, "loop1.cname-chain.test.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.authority) == 0, "a CNAME loop MUST NOT carry a SOA"
    cnames = [rr for rr in r.answer if rr.rdtype == dns.rdatatype.CNAME]
    assert len(cnames) >= 1


def test_cname_target_outside_zones_noerror_no_soa(zone_proxy):
    r = _query(zone_proxy, "outside.cname-chain.test.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.authority) == 0
    assert len(r.answer) == 1
    assert r.answer[0].rdtype == dns.rdatatype.CNAME


# --- nested zones: longest apex wins ----------------------------------------

def test_nested_zone_longest_apex_wins(zone_proxy):
    r = _query(zone_proxy, "host.sub.nested.test.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert str(r.answer[0][0]) == "192.0.2.21"


def test_parent_zone_still_answers_outside_child(zone_proxy):
    r = _query(zone_proxy, "www.nested.test.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert str(r.answer[0][0]) == "192.0.2.11"


# --- unsupported-but-registered type: skipped, owner still exists -----------

def test_unsupported_type_record_skipped_owner_still_exists(zone_proxy):
    r = _query(zone_proxy, "weird.unsupported.test.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.answer) == 0
    assert len(r.authority) == 1  # NODATA with SOA: owner exists, no A record


# --- zone precedence over blocklist ------------------------------------------

def test_zone_wins_over_overlapping_blocklist_entry(zone_proxy):
    # covers-home-lan.txt blocks the entire home.lan tree; the zone MUST win.
    r = _query(zone_proxy, "router.home.lan.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert r.flags & dns.flags.AA
    assert len(r.answer) == 1


@pytest.fixture
def above_apex_proxy(proxy_bin, zones_dir, blocklists_dir):
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        [
            "-u", "https://example.test/dns-query",
            "-p", str(port), "-a", "127.0.0.1",
            "-z", zone("home.lan.zone"),
            "-b", blocklist("above-zone-apex.txt"),
        ],
    )
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
    yield h, "127.0.0.1", port
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


def test_zone_wins_even_when_blocklist_entry_is_above_apex(above_apex_proxy):
    r = _query(above_apex_proxy, "router.home.lan.", "A")
    assert r.rcode() == dns.rcode.NOERROR
    assert len(r.answer) == 1


def test_name_outside_zone_still_blocked_by_entry_above_apex(above_apex_proxy):
    r = _query(above_apex_proxy, "other.lan.", "A")
    assert r.rcode() == dns.rcode.NXDOMAIN
    assert not (r.flags & dns.flags.AA), "a blocked answer is not authoritative"
    assert len(r.answer) == 0
    assert len(r.authority) == 0
