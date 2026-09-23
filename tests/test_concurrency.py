"""The spec's own concurrency scenario: a slow upstream must not delay
local/blocked/invalid answers, and many forwarded queries must be handled
in parallel rather than serialized behind the slow upstream.
"""
import threading
import time

import dns.message
import dns.rcode
import pytest

from conftest import zone
from isa_tests import netio, ports
from isa_tests.dnsutil import make_query
from isa_tests.proxy import ProxyHandle


@pytest.fixture
def concurrency_env(proxy_bin, mock_upstream, zones_dir):
    mock_upstream.delay = 3.0
    port = ports.free_udp_tcp_port()
    h = ProxyHandle(
        proxy_bin,
        [
            "-u", mock_upstream.url, "-p", str(port), "-a", "127.0.0.1",
            "-z", zone("home.lan.zone"), "-w", "10",
        ],
    )
    lines = h.wait_listening(expected=2, timeout=5)
    assert len(lines) == 2, f"proxy did not start: {h.stderr_extra}"
    yield h, "127.0.0.1", port, mock_upstream
    if h.is_running():
        h.send_signal()
        if h.wait_exit(timeout=2.0) is None:
            h.kill()


def _timed_query(host, port, qname, qtype, timeout):
    t0 = time.monotonic()
    q = make_query(qname, qtype)
    wire = netio.udp_roundtrip(host, port, q.to_wire(), timeout=timeout)
    elapsed = time.monotonic() - t0
    return dns.message.from_wire(wire, raise_on_truncation=False), elapsed


@pytest.mark.slow
def test_slow_upstream_does_not_delay_local_answer_and_forwards_stay_parallel(concurrency_env):
    h, host, port, up = concurrency_env

    # One warm-up query, per spec's own timing caveat for the 200ms budget.
    _timed_query(host, port, "router.home.lan.", "A", timeout=5.0)

    results = {}
    lock = threading.Lock()

    def fwd_worker(i):
        r, elapsed = _timed_query(host, port, f"fwd{i}.example.test.", "A", timeout=8.0)
        with lock:
            results[f"fwd{i}"] = (r, elapsed)

    def local_worker():
        # Give the ten forwarded queries a head start so they are genuinely
        # in flight against the (slow) upstream when the local query lands.
        time.sleep(0.05)
        r, elapsed = _timed_query(host, port, "nas.home.lan.", "A", timeout=2.0)
        with lock:
            results["local"] = (r, elapsed)

    threads = [threading.Thread(target=fwd_worker, args=(i,)) for i in range(10)]
    threads.append(threading.Thread(target=local_worker))
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
    total = time.monotonic() - t0

    assert "local" in results, "local query never answered"
    local_resp, local_elapsed = results["local"]
    assert local_resp.rcode() == dns.rcode.NOERROR
    assert local_elapsed <= 0.2, f"local answer took {local_elapsed:.3f}s, budget is 200ms"

    for i in range(10):
        key = f"fwd{i}"
        assert key in results, f"{key} never answered (total wall time {total:.2f}s)"
        r, elapsed = results[key]
        assert r.rcode() == dns.rcode.NOERROR
        assert elapsed <= 5.0, f"{key} took {elapsed:.2f}s, budget is 5s"

    assert len(up.requests) == 10
