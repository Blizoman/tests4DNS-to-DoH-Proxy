"""Free-port allocation helpers.

We need a single port number that is simultaneously free on UDP and TCP
(isa-dnsproxy listens on both for the same -p). Binding-then-closing is
racy in theory but good enough for a local test run.
"""
import socket


def free_udp_tcp_port(host: str = "127.0.0.1", attempts: int = 100) -> int:
    for _ in range(attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
            t.bind((host, 0))
            port = t.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            try:
                u.bind((host, port))
            except OSError:
                continue
        return port
    raise RuntimeError("could not find a port free on both udp and tcp")
