#!/usr/bin/env python3
"""Fake HTTP/HTTPS sink: 200 OK, SNI certs from the sandbox CA, JSONL request log.

Certificates are minted with the OpenSSL CLI so the image does not need
python3-cryptography (or a network fetch of that wheel).
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOGS = Path("/logs")
CA_DIR = Path("/tmp/ca")
_cert_cache: dict[str, ssl.SSLContext] = {}
_lock = threading.Lock()


def _now() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise RuntimeError("openssl is not installed in the sandbox image")
    return path


def _run_openssl(args: list[str]) -> None:
    proc = subprocess.run(
        [_openssl(), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "openssl failed").strip()
        raise RuntimeError(detail)


def init_ca(ca_dir: Path) -> None:
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / "ca.key"
    crt_path = ca_dir / "ca.crt"
    if key_path.exists() and crt_path.exists():
        return
    _run_openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-keyout",
            str(key_path),
            "-out",
            str(crt_path),
            "-days",
            "3650",
            "-subj",
            "/C=US/O=Evilbox Sandbox/CN=Evilbox Sandbox CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )


def _san_for_host(hostname: str) -> str:
    host = hostname.strip() or "localhost"
    try:
        ipaddress.ip_address(host)
        return f"IP:{host}"
    except ValueError:
        return f"DNS:{host}"


def _leaf_for_host(hostname: str) -> ssl.SSLContext:
    host = (hostname or "localhost").split(":")[0] or "localhost"
    with _lock:
        if host in _cert_cache:
            return _cert_cache[host]
        safe = host.replace("/", "_")
        key_file = CA_DIR / f"leaf-{safe}.key"
        crt_file = CA_DIR / f"leaf-{safe}.crt"
        csr_file = CA_DIR / f"leaf-{safe}.csr"
        ext_file = CA_DIR / f"leaf-{safe}.ext"
        ext_file.write_text(
            "basicConstraints=CA:FALSE\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName={_san_for_host(host)}\n",
            encoding="utf-8",
        )
        _run_openssl(
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_file),
                "-out",
                str(csr_file),
                "-subj",
                f"/O=Evilbox Sink/CN={host}",
            ]
        )
        _run_openssl(
            [
                "x509",
                "-req",
                "-in",
                str(csr_file),
                "-CA",
                str(CA_DIR / "ca.crt"),
                "-CAkey",
                str(CA_DIR / "ca.key"),
                "-CAcreateserial",
                "-out",
                str(crt_file),
                "-days",
                "365",
                "-sha256",
                "-extfile",
                str(ext_file),
            ]
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(crt_file), str(key_file))
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
    httpd = ThreadingHTTPServer(("0.0.0.0", 80), SinkHandler)
    httpsd = ThreadingHTTPServer(("0.0.0.0", 443), HTTPSHandler)
    ctx = _leaf_for_host("localhost")
    ctx.sni_callback = _sni_callback
    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    httpsd.serve_forever()


def main() -> int:
    global CA_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-ca", action="store_true")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--ca-dir", default=str(CA_DIR))
    args = parser.parse_args()
    CA_DIR = Path(args.ca_dir)
    if args.init_ca or args.serve:
        init_ca(CA_DIR)
    if args.serve:
        serve(CA_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
