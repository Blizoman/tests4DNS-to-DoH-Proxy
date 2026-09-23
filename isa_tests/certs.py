"""Self-signed certificate generation for the local HTTPS mock upstream.

isa-dnsproxy must verify the upstream's certificate chain and hostname
unless --insecure is given. We cannot obtain a publicly-trusted certificate
for a local test server, so tests that exercise the default (verifying)
path expect the connection to fail against this self-signed cert, and
tests of --insecure expect it to succeed. Uses the system `openssl` binary
(present in the course devShell, and used elsewhere in this suite already).
"""
import os
import subprocess


def generate_self_signed(cn: str, out_dir: str, days: int = 2):
    key_path = os.path.join(out_dir, "key.pem")
    cert_path = os.path.join(out_dir, "cert.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", str(days), "-nodes",
            "-subj", f"/CN={cn}",
            "-addext", f"subjectAltName=IP:{cn}" if _looks_like_ip(cn) else f"subjectAltName=DNS:{cn}",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
