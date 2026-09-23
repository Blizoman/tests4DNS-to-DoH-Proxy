"""Well-formed DNS message helpers, built on dnspython.

For malformed / rule-breaking messages, use dnswire.py instead.
"""
from __future__ import annotations

import dns.edns
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype


def make_query(qname: str, qtype="A", *, id=0x1234, rd=True, use_edns=True, payload=1232) -> dns.message.QueryMessage:
    q = dns.message.make_query(
        qname,
        qtype,
        rdclass="IN",
        use_edns=0 if use_edns else None,
        payload=payload,
        want_dnssec=False,
    )
    q.id = id
    q.flags = dns.flags.RD if rd else dns.flags.Flag(0)
    return q


def flag_set(message: dns.message.Message, flag_name: str) -> bool:
    return bool(message.flags & getattr(dns.flags, flag_name))


def rcode_name(message: dns.message.Message) -> str:
    return dns.rcode.to_text(message.rcode())


def has_opt(message: dns.message.Message) -> bool:
    return message.edns != -1


def parse(wire: bytes) -> dns.message.Message:
    return dns.message.from_wire(wire, raise_on_truncation=False)
