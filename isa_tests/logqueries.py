"""Validation and lookup helpers for the stdout query log format.

The regex below is copied verbatim from the assignment ("Query log"
section) -- do not "improve" it, it is the grading oracle.
"""
import re

LOG_LINE_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) '
    r'((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]):\d{1,5} '
    r'(-|\.|(?:(?:[^\sA-Z\\.;()@$"]|\\[0-9]{3}|\\[.;()@$"\\])+\.)+) '
    r'(-|[A-Z][A-Z0-9-]*|TYPE\d+) '
    r'(local|blocked|forwarded|invalid|dropped) '
    r'(-|[A-Z]+|RCODE\d+)$'
)


def assert_valid_log_line(line: str) -> None:
    assert LOG_LINE_RE.match(line), f"log line violates the required format: {line!r}"


def parse_log_line(line: str):
    m = LOG_LINE_RE.match(line)
    if not m:
        return None
    fields = line.split(" ")
    return {
        "raw": line,
        "timestamp": fields[0],
        "client": fields[1],
        "qname": m.group(3),
        "qtype": m.group(4),
        "verdict": m.group(5),
        "rcode": m.group(6),
    }


def find(lines, **want):
    """Find a parsed record matching all given keyword fields (multiset lookup,
    per the spec: 'match lines as a multiset keyed by client, name, and type,
    never by position')."""
    for line in lines:
        rec = parse_log_line(line)
        if rec is None:
            continue
        if all(rec.get(k) == v for k, v in want.items()):
            return rec
    return None
