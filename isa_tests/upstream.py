"""A configurable mock DoH (RFC 8484) upstream for forwarding tests.

Records every request it receives (method, path, headers, raw body) so
tests can assert the proxy sent exactly one well-formed POST per forwarded
query, and can be switched between several response modes to exercise the
proxy's SERVFAIL conditions.
"""
from __future__ import annotations

import http.server
import ssl
import threading
import time
from dataclasses import dataclass, field

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset


@dataclass
class RecordedRequest:
    method: str
    path: str
    headers: dict
    body: bytes
    ts: float


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _record(self, body: bytes) -> None:
        self.server.upstream.requests.append(
            RecordedRequest(self.command, self.path, dict(self.headers), body, time.time())
        )

    def _handle(self):
        body = self._read_body()
        self._record(body)
        up = self.server.upstream

        if up.delay:
            time.sleep(up.delay)

        mode = up.mode
        if mode == "hang":
            time.sleep(up.hang_seconds or 3600)
            return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", up.redirect_to or (self.path + "-elsewhere"))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "http_error":
            self.send_response(up.http_status or 500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "invalid_body":
            payload = up.invalid_body if up.invalid_body is not None else b"\x00not-a-dns-message"
            self.send_response(200)
            self.send_header("Content-Type", "application/dns-message")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if mode == "close_abruptly":
            self.close_connection = True
            return

        try:
            q = dns.message.from_wire(body) if body else None
        except Exception:
            q = None

        if up.responder is not None:
            resp_bytes = up.responder(body, q)
        else:
            resp_bytes = up.default_response(body, q)

        self.send_response(up.http_status or 200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()


class MockDoHUpstream:
    def __init__(self, host: str = "127.0.0.1", tls: bool = False, cert: str | None = None, key: str | None = None):
        self.host = host
        self.requests: list[RecordedRequest] = []
        self.delay = 0.0
        self.mode = "normal"
        self.http_status: int | None = None
        self.invalid_body: bytes | None = None
        self.redirect_to: str | None = None
        self.hang_seconds: float | None = None
        self.responder = None  # callable(body: bytes, q: dns.message.Message|None) -> bytes

        self.httpd = http.server.ThreadingHTTPServer((host, 0), _Handler)
        self.httpd.upstream = self
        self.httpd.daemon_threads = True

        self._tls = tls
        if tls:
            if not (cert and key):
                raise ValueError("tls=True requires cert and key paths")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)

        self.port = self.httpd.server_address[1]
        scheme = "https" if tls else "http"
        self.url = f"{scheme}://{host}:{self.port}/dns-query"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def default_response(self, body: bytes, q) -> bytes:
        if q is None or not q.question:
            return b""
        r = dns.message.make_response(q)
        r.set_rcode(dns.rcode.NOERROR)
        qname = q.question[0].name
        qtype = q.question[0].rdtype
        if qtype == dns.rdatatype.A:
            rrset = dns.rrset.from_text(qname, 60, "IN", "A", "203.0.113.10")
            r.answer.append(rrset)
        elif qtype == dns.rdatatype.AAAA:
            rrset = dns.rrset.from_text(qname, 60, "IN", "AAAA", "2001:db8::10")
            r.answer.append(rrset)
        return r.to_wire()

    def last_request(self) -> RecordedRequest | None:
        return self.requests[-1] if self.requests else None

    def clear(self):
        self.requests.clear()
