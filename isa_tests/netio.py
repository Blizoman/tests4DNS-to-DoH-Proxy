"""Raw UDP/TCP send/receive helpers with explicit control over framing.

Deliberately does not hide TCP length-prefix framing behind a
request/response call: several tests need to split a message across
segments, send several messages on one connection, or send a message and
then assert that nothing comes back (dropped).
"""
from __future__ import annotations

import socket
import struct
import time


class Timeout(Exception):
    pass


def udp_socket(family=socket.AF_INET, bind=None, timeout=2.0) -> socket.socket:
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    if bind:
        s.bind(bind)
    return s


def udp_roundtrip(host, port, payload: bytes, family=socket.AF_INET, timeout=2.0):
    s = udp_socket(family=family, timeout=timeout)
    try:
        s.sendto(payload, (host, port))
        try:
            data, _from = s.recvfrom(65535)
        except socket.timeout:
            raise Timeout(f"no UDP response within {timeout}s")
        return data
    finally:
        s.close()


def udp_expect_no_response(host, port, payload: bytes, family=socket.AF_INET, timeout=0.5) -> bool:
    """Sends payload and returns True if nothing came back within timeout."""
    s = udp_socket(family=family, timeout=timeout)
    try:
        s.sendto(payload, (host, port))
        try:
            s.recvfrom(65535)
            return False
        except socket.timeout:
            return True
    finally:
        s.close()


def tcp_connect(host, port, family=socket.AF_INET, timeout=5.0) -> socket.socket:
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def frame(payload: bytes) -> bytes:
    return struct.pack("!H", len(payload)) + payload


def send_tcp_message(sock: socket.socket, payload: bytes, chunk_size: int | None = None, inter_chunk_delay: float = 0.0):
    data = frame(payload)
    if chunk_size is None:
        sock.sendall(data)
        return
    for i in range(0, len(data), chunk_size):
        sock.sendall(data[i:i + chunk_size])
        if inter_chunk_delay:
            time.sleep(inter_chunk_delay)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return buf


def recv_tcp_message(sock: socket.socket) -> bytes:
    length_bytes = recv_exact(sock, 2)
    (length,) = struct.unpack("!H", length_bytes)
    return recv_exact(sock, length)


def tcp_expect_closed(sock: socket.socket, timeout=1.0) -> bool:
    """Returns True if the peer closed the connection (recv returns b'')."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(1)
        return data == b""
    except socket.timeout:
        return False
    except ConnectionError:
        return True
