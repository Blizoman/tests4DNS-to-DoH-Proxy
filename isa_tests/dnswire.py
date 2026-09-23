"""Low-level, deliberately unsafe DNS message byte-crafting.

dnspython refuses to build most of the malformed messages the assignment's
"Message processing" section requires the proxy to reject in specific ways
(bad label lengths, compression pointers, truncated sections, stray OPT
records, ...). This module builds raw wire bytes by hand so tests can
construct exactly the malformed input the spec describes, byte for byte.

Only use dnsutil.py (which wraps dnspython) for well-formed messages;
use this module when a test needs to break a specific rule on purpose.
"""
import struct

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_OPT = 41
QTYPE_AXFR = 252
QTYPE_ANY = 255

QCLASS_IN = 1
QCLASS_CH = 3

OPCODE_QUERY = 0
OPCODE_IQUERY = 1
OPCODE_STATUS = 2


def header(
    id_=0x1234,
    qr=0, opcode=OPCODE_QUERY, aa=0, tc=0, rd=1, ra=0, z=0, ad=0, cd=0, rcode=0,
    qdcount=1, ancount=0, nscount=0, arcount=0,
) -> bytes:
    flags = (qr & 1) << 15
    flags |= (opcode & 0xF) << 11
    flags |= (aa & 1) << 10
    flags |= (tc & 1) << 9
    flags |= (rd & 1) << 8
    flags |= (ra & 1) << 7
    flags |= (z & 1) << 6
    flags |= (ad & 1) << 5
    flags |= (cd & 1) << 4
    flags |= (rcode & 0xF)
    return struct.pack("!HHHHHH", id_ & 0xFFFF, flags, qdcount, ancount, nscount, arcount)


def encode_name(name: str) -> bytes:
    """Encode a presentation-format name (no escaping support) to wire bytes."""
    if name in (".", ""):
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not (0 <= len(raw) <= 63):
            raise ValueError(f"label {label!r} out of 0..63 range")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def label(length_octet: int, content: bytes = b"") -> bytes:
    """A single raw label: an arbitrary length octet plus raw content bytes.

    Used to build labels the encoder above would refuse, e.g. a length
    octet in the reserved 64..191 range.
    """
    return bytes([length_octet & 0xFF]) + content


def question(name_bytes: bytes, qtype=QTYPE_A, qclass=QCLASS_IN) -> bytes:
    return name_bytes + struct.pack("!HH", qtype, qclass)


def compression_pointer(offset: int) -> bytes:
    return struct.pack("!H", 0xC000 | (offset & 0x3FFF))


def opt_record(payload_size=1232, version=0, flags=0, extended_rcode=0, options=b"", owner=b"\x00", rrclass=None) -> bytes:
    """A full OPT resource record (root owner, TYPE=41, CLASS=UDP payload size)."""
    cls = rrclass if rrclass is not None else payload_size
    ttl = ((extended_rcode & 0xFF) << 24) | ((version & 0xFF) << 16) | (flags & 0xFFFF)
    return owner + struct.pack("!HHIH", QTYPE_OPT, cls, ttl, len(options)) + options


def simple_query(name="example.test.", qtype=QTYPE_A, qclass=QCLASS_IN, id_=0x1234, rd=1, with_opt=False, payload_size=1232) -> bytes:
    arcount = 1 if with_opt else 0
    msg = header(id_=id_, rd=rd, qdcount=1, arcount=arcount)
    msg += question(encode_name(name), qtype, qclass)
    if with_opt:
        msg += opt_record(payload_size=payload_size)
    return msg


def truncate(message: bytes, length: int) -> bytes:
    return message[:length]
