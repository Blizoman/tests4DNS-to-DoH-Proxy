import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from isa_tests import certs, ports  # noqa: E402
from isa_tests.proxy import ProxyHandle  # noqa: E402
from isa_tests.upstream import MockDoHUpstream  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
ZONES_DIR = os.path.join(FIXTURES, "zones")
ZONE_ERRORS_DIR = os.path.join(FIXTURES, "zones", "errors")
BLOCKLISTS_DIR = os.path.join(FIXTURES, "blocklists")


def pytest_addoption(parser):
    parser.addoption(
        "--proxy-bin",
        action="store",
        default=os.environ.get("ISA_DNSPROXY_BIN"),
        help="Path to the isa-dnsproxy executable under test "
        "(defaults to $ISA_DNSPROXY_BIN). Without it, every test that "
        "needs a running proxy is skipped.",
    )


@pytest.fixture(scope="session")
def proxy_bin(request):
    path = request.config.getoption("--proxy-bin")
    if not path:
        pytest.skip("no proxy binary configured: set ISA_DNSPROXY_BIN=/path/to/isa-dnsproxy or pass --proxy-bin")
    path = os.path.abspath(path)
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        pytest.fail(f"--proxy-bin/{path} is not an executable file")
    return path


@pytest.fixture
def free_port():
    return ports.free_udp_tcp_port()


@pytest.fixture(scope="session")
def zones_dir():
    return ZONES_DIR


@pytest.fixture(scope="session")
def zone_errors_dir():
    return ZONE_ERRORS_DIR


@pytest.fixture(scope="session")
def blocklists_dir():
    return BLOCKLISTS_DIR


def zone(name: str) -> str:
    return os.path.join(ZONES_DIR, name)


def zone_error(name: str) -> str:
    return os.path.join(ZONE_ERRORS_DIR, name)


def blocklist(name: str) -> str:
    return os.path.join(BLOCKLISTS_DIR, name)


@pytest.fixture
def mock_upstream():
    u = MockDoHUpstream()
    u.start()
    yield u
    u.stop()


@pytest.fixture(scope="session")
def self_signed_cert(tmp_path_factory):
    d = tmp_path_factory.mktemp("cert")
    return certs.generate_self_signed(cn="127.0.0.1", out_dir=str(d))


@pytest.fixture
def mock_upstream_tls(self_signed_cert):
    cert, key = self_signed_cert
    u = MockDoHUpstream(tls=True, cert=cert, key=key)
    u.start()
    yield u
    u.stop()


@pytest.fixture
def start_proxy(proxy_bin):
    """Factory fixture: start_proxy(args, wait_for=4, timeout=5.0) -> (handle, listening_lines).

    Tears every spawned proxy down (TERM, then KILL if needed) at test end.
    """
    handles = []

    def _start(args, wait_for=4, timeout=5.0, expect_listen=True):
        h = ProxyHandle(proxy_bin, args)
        handles.append(h)
        lines = h.wait_listening(expected=wait_for, timeout=timeout) if expect_listen else []
        return h, lines

    yield _start

    for h in handles:
        if h.is_running():
            h.send_signal()
            if h.wait_exit(timeout=2.0) is None:
                h.kill()
