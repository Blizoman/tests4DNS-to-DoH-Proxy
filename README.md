# isa-tests

Black-box automated tests for the NES@FIT ISA "filtering DNS-to-DoH proxy"
assignment (`isa-dnsproxy`). Everything here talks to the built executable
over the network and reads its stdout/stderr/exit code — nothing links
against your code — so it works the same whether your proxy is written in
C, Go, Rust, whatever. One person can add tests, others can just run them.

Written in Python + pytest. That's just this repo's implementation language;
it says nothing about what you write your proxy in.

## Quick start

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run only the tests that don't need your binary yet (harness self-checks):
pytest -m harness -v

# Once you have a built isa-dnsproxy:
export ISA_DNSPROXY_BIN=/path/to/isa-dnsproxy
pytest -v

# Skip the slower timing-budget tests during quick iteration:
pytest -m "not slow"
```

`ISA_DNSPROXY_BIN` (or `--proxy-bin /path/to/isa-dnsproxy`) must point at
the built executable. Every test that needs a running proxy is **skipped**
(not failed) when it's unset, so `pytest` is always safe to run, even with
nothing built yet.

Run it inside the course environment so `openssl` (used to mint a
throw-away self-signed cert for the TLS/`--insecure` tests) and Python 3.10+
are available:

```sh
nix develop dev-envs#isa -c pytest
```

## Layout

- `isa_tests/` — the test harness itself:
  - `proxy.py` — spawns the binary, waits for `listening on ...` lines,
    captures stdout (query log) and stderr, handles signals/teardown.
  - `upstream.py` — a configurable mock DoH (RFC 8484) server: records every
    request, can inject delays, non-2xx statuses, redirects, garbage
    bodies, or a custom responder callback.
  - `dnsutil.py` — well-formed query builders (wraps `dnspython`).
  - `dnswire.py` — hand-rolled wire-format bytes for the malformed messages
    the spec requires rejecting (bad label lengths, compression pointers,
    stray OPT records, ...) — `dnspython` refuses to build these on purpose.
  - `netio.py` — raw UDP/TCP send/receive with explicit control over TCP
    framing (partial sends, multiple messages per connection, etc).
  - `logqueries.py` — the stdout query-log regex (copied verbatim from the
    assignment) plus multiset lookup helpers.
  - `certs.py`, `ports.py` — self-signed cert generation, free-port lookup.
- `fixtures/zones/`, `fixtures/blocklists/` — zone files and blocklists used
  by the tests, including `fixtures/zones/errors/` (one grammar violation
  per file, for the start-up error tests) and the assignment's own
  `home.lan.zone` / `ads.txt` examples verbatim.
- `tests/` — one file per spec section: `test_cli.py`,
  `test_startup_shutdown.py`, `test_message_processing.py`, `test_zones.py`,
  `test_blocklists.py`, `test_forwarding.py`, `test_responses_edns.py`,
  `test_tcp.py`, `test_logging.py`, `test_concurrency.py`.
- `tests/test_00_harness_selfcheck.py` — tests of the harness itself (the
  mock DoH server, the log regex, the raw wire-format builders). These need
  no proxy binary and pass today; if something here goes red, the bug is in
  this repo, not in your proxy.

## What's covered

Every test tries to cite the exact spec sentence it checks. Broad strokes:

- CLI validation and exit codes (`EX_USAGE`/64, `EX_CONFIG`/78,
  `EX_UNAVAILABLE`/69), `-h`/`--help` precedence.
- Startup: `listening on` lines (default dual-stack vs. `-a`), port-in-use,
  zone/blocklist load errors (one fixture file per grammar rule), the
  10-zones/200k-entries/5s startup budget, SIGINT/SIGTERM timing and exit
  codes.
- The eight ordered "Message processing" checks, each isolated, plus the
  response-header rules that follow (flags copied, ID, OPT-echoing rules,
  question copied vs. `QDCOUNT=0`).
- Zones: basic lookup, `ANY`, CNAME chains (multi-hop, loop, external
  target), NXDOMAIN/NODATA with SOA + correct TTL, case-insensitivity,
  nested zones (longest apex wins), unsupported-but-registered types
  skipped with the owner still existing, zone-over-blocklist precedence.
- Blocklists: exact/subtree matching on label boundaries, case/trailing-dot
  insensitivity, CRLF + hosts(5)-header + multi-name-per-line tolerance.
- Forwarding (about half the assignment's automated grade): POST shape,
  ID handling, unchanged relay of RCODE/OPT, two clients sharing a query ID,
  every documented SERVFAIL trigger (DNS resolution failure, connection
  refused, non-2xx, redirects not followed, garbage body, mismatched
  question, timeout budget, mid-shutdown), default cert verification vs.
  `--insecure`, `SSL_CERT_FILE` trust.
- EDNS/response shape: OPT echoing (version 0, no options, floor 1232),
  UDP truncation at 512/clamped-payload, `+bufsize=512`/`+noedns` cases,
  TCP never truncated.
- TCP: pipelining, split segments, 10s(+5s) idle timeout, a dropped TCP
  message closing the connection, a slow/stalled client not blocking others.
- The stdout query log: the assignment's own regex, exact field content per
  verdict (including the `-`/parsed-question distinction for invalid and
  dropped messages), multiset (not positional) matching, exactly one line
  per message.
- The spec's own concurrency scenario (3s-delayed upstream, 10 forwarded +
  1 local query, 200ms/5s budgets).

## What's intentionally not (fully) covered

- The outstanding-request cap: it's a MAY, and its exact value is
  implementation-chosen, so there's no fixed behavior to assert against.
- A genuine publicly-trusted upstream certificate / real public DoH
  resolver: nothing here depends on network access or a specific resolver,
  per the assignment ("the proxy MUST NOT depend on a particular one").
  `test_forwarding.py` covers cert verification with a local self-signed
  cert instead (default rejects it, `--insecure` and a matching
  `SSL_CERT_FILE` both accept it).
- HTTP/2 upstream behavior — the mock upstream is HTTP/1.1 only (matching
  the assignment's explicit "MUST work with an upstream offering HTTP/1.1
  only" requirement), so HTTP/2-specific behavior isn't exercised.
- Wire-level DNS name escaping in the query log (`\DDD`, `\c`) beyond the
  regex accepting it — no fixture currently forces a name with bytes
  outside `0x21..0x7E`.

If you find a spec requirement this suite doesn't touch, that's a real gap,
not a deliberate one unless listed above — please add a test or open an
issue.

## Notes for a Go (or any other language) implementation

Nothing here imports or assumes any C-specific behavior. The only contract
is: an executable named as `ISA_DNSPROXY_BIN`/`--proxy-bin` accepts the CLI
described in the assignment, listens on the given UDP/TCP ports, and prints
`listening on ...` / the query log exactly as specified. Point the env var
at your binary and run `pytest`.

## Contributing

- Keep tests black-box: no importing or shelling into proxy internals, only
  sockets/subprocess/stdout/stderr/exit-code.
- New fixtures go in `fixtures/zones/` or `fixtures/blocklists/`; one clear
  violation per file for the start-up-error fixtures under
  `fixtures/zones/errors/`, so a failure points at a single cause.
- Prefer extending `isa_tests/` helpers over reaching for raw
  sockets/subprocess in a test file directly.
