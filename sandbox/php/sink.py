#!/usr/bin/env python3
"""Fake HTTP/HTTPS sink: 200 OK, SNI certs from the sandbox CA, JSONL request log."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LOGS = Path("/logs")
CA_DIR = Path("/tmp/ca")
_cert_cache: dict[str, ssl.SSLContext] = {}
_ca_cert = None
_ca_key = None
_lock = threading.Lock()


def _now() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def init_ca(ca_dir: Path) -> None:
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / "ca.key"
    crt_path = ca_dir / "ca.crt"
    if key_path.exists() and crt_path.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evilbox Sandbox"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Evilbox Sandbox CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _load_ca(ca_dir: Path):
    global _ca_cert, _ca_key
    _ca_key = serialization.load_pem_private_key((ca_dir / "ca.key").read_bytes(), password=None)
    _ca_cert = x509.load_pem_x509_certificate((ca_dir / "ca.crt").read_bytes())


def _subject_alt_name(hostname: str) -> x509.SubjectAlternativeName:
    host = hostname.strip() or "localhost"
    try:
        return x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))])
    except ValueError:
        return x509.SubjectAlternativeName([x509.DNSName(host)])


def _leaf_for_host(hostname: str) -> ssl.SSLContext:
    host = (hostname or "localhost").split(":")[0] or "localhost"
    with _lock:
        if host in _cert_cache:
            return _cert_cache[host]
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evilbox Sink"),
                x509.NameAttribute(NameOID.COMMON_NAME, host),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(_ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
            .add_extension(_subject_alt_name(host), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(_ca_key, hashes.SHA256())
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        cert_file = CA_DIR / f"leaf-{host.replace('/', '_')}.pem"
        key_file = CA_DIR / f"leaf-{host.replace('/', '_')}.key"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        ctx.load_cert_chain(str(cert_file), str(key_file))
        _cert_cache[host] = ctx
        return ctx


def _sni_callback(sock, server_name, _ctx):
    name = server_name.decode("utf-8", "replace") if isinstance(server_name, bytes) else (server_name or "localhost")
    sock.context = _leaf_for_host(name)


def _log_domain(host: str) -> None:
    host = (host or "").strip().lower().split(":")[0]
    if not host:
        return
    path = LOGS / "domains.txt"
    existing = set()
    if path.exists():
        existing = {line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()}
    if host not in existing:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(host + "\n")


class SinkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    scheme = "http"

    def log_message(self, fmt, *args):
        return

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 65536)) if length else b""
        host = self.headers.get("Host", "")
        record = {
            "ts": _now(),
            "scheme": getattr(self, "scheme", "http"),
            "method": self.command,
            "host": host,
            "path": self.path,
            "client": self.client_address[0],
            "headers": {k: v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace")[:8192],
        }
        LOGS.mkdir(parents=True, exist_ok=True)
        with (LOGS / "http.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        with (LOGS / "http.log").open("a", encoding="utf-8") as fh:
            fh.write(
                f"{record['ts']} {record['scheme'].upper()} {record['method']} "
                f"http{'s' if record['scheme']=='https' else ''}://{host}{self.path}\n"
            )
        _log_domain(host.split("@")[-1] if host else "")
        stage = Path("/opt/sandbox/stage.bin")
        if stage.is_file():
            payload = stage.read_bytes()[:65536]
        else:
            payload = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    def do_PATCH(self):
        self._handle()


class HTTPSHandler(SinkHandler):
    scheme = "https"


def serve(ca_dir: Path) -> None:
    _load_ca(ca_dir)
    httpd = ThreadingHTTPServer(("0.0.0.0", 80), SinkHandler)
    httpsd = ThreadingHTTPServer(("0.0.0.0", 443), HTTPSHandler)
    ctx = _leaf_for_host("localhost")
    ctx.sni_callback = _sni_callback
    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    httpsd.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-ca", action="store_true")
    parser.add_argument("--ca-dir", default=str(CA_DIR))
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    ca_dir = Path(args.ca_dir)
    if args.init_ca or args.serve:
        init_ca(ca_dir)
    if args.serve:
        serve(ca_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
