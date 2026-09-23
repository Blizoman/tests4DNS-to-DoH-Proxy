"""Subprocess lifecycle management for the isa-dnsproxy binary under test."""
from __future__ import annotations

import queue
import re
import signal
import subprocess
import threading
import time

LISTENING_RE = re.compile(r"^listening on (?:\[(?P<ipv6>[0-9a-fA-F:]+)\]|(?P<ipv4>[0-9.]+)):(?P<port>\d+)$")


class ProxyHandle:
    def __init__(self, binary: str, args: list[str], cwd: str | None = None, env: dict | None = None):
        self.argv = [binary, *args]
        self.proc = subprocess.Popen(
            self.argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.stdout_q: queue.Queue[str] = queue.Queue()
        self.stderr_q: queue.Queue[str] = queue.Queue()
        self._threads = [
            threading.Thread(target=self._pump, args=(self.proc.stdout, self.stdout_q), daemon=True),
            threading.Thread(target=self._pump, args=(self.proc.stderr, self.stderr_q), daemon=True),
        ]
        for t in self._threads:
            t.start()

    @staticmethod
    def _pump(pipe, q: queue.Queue):
        try:
            for line in pipe:
                q.put(line.rstrip("\n"))
        except Exception:
            pass
        finally:
            try:
                pipe.close()
            except Exception:
                pass

    def wait_listening(self, expected: int = 4, timeout: float = 5.0) -> list[str]:
        """Collects 'listening on ...' lines from stderr until `expected` have
        arrived or `timeout` elapses. Non-matching stderr lines are kept in
        stderr_extra for inspection (e.g. skip-record warnings)."""
        deadline = time.monotonic() + timeout
        lines = []
        self.stderr_extra = []
        while time.monotonic() < deadline and len(lines) < expected:
            remaining = deadline - time.monotonic()
            try:
                line = self.stderr_q.get(timeout=max(0.0, remaining))
            except queue.Empty:
                break
            if LISTENING_RE.match(line):
                lines.append(line)
            else:
                self.stderr_extra.append(line)
        return lines

    def drain_stderr(self, timeout: float = 0.3) -> list[str]:
        lines = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                lines.append(self.stderr_q.get(timeout=remaining))
            except queue.Empty:
                break
        return lines

    def pop_log_lines(self, count: int = 1, timeout: float = 2.0) -> list[str]:
        lines = []
        deadline = time.monotonic() + timeout
        while len(lines) < count and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                lines.append(self.stdout_q.get(timeout=max(0.0, remaining)))
            except queue.Empty:
                break
        return lines

    def expect_no_log_line(self, timeout: float = 0.5) -> bool:
        try:
            line = self.stdout_q.get(timeout=timeout)
        except queue.Empty:
            return True
        # put it back for the caller to inspect if desired
        self._unexpected_line = line
        return False

    def send_signal(self, sig=signal.SIGTERM):
        self.proc.send_signal(sig)

    def wait_exit(self, timeout: float = 2.0):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        try:
            self.proc.kill()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=2)
        except Exception:
            pass

    def is_running(self) -> bool:
        return self.proc.poll() is None

    def returncode(self):
        return self.proc.poll()
