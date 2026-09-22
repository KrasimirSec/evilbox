#!/usr/bin/env python3
"""HTTPS front: spoofed shop origin + Google SERP + C2 sink on the same ports."""

from __future__ import annotations

import os
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

sys.path.insert(0, "/opt/sandbox")
import sink  # noqa: E402
import wrap  # noqa: E402

LOGS = Path("/logs")
SAMPLE = Path(os.environ.get("SANDBOX_SAMPLE") or "/samples/sample.js")
ORIGIN_HOST = (os.environ.get("SANDBOX_HOST") or "www.shop-assets.net").split(":")[0].lower()
SCRIPT_PATH = os.environ.get("SANDBOX_SCRIPT_PATH") or "/assets/app.min.js"


def _host_only(value: str) -> str:
    host = (value or "").split("@")[-1].split(":")[0].strip().lower()
    return host


def _origin_hosts() -> set[str]:
    hosts = {ORIGIN_HOST}
    if not ORIGIN_HOST.startswith("www."):
        hosts.add("www." + ORIGIN_HOST)
    else:
        hosts.add(ORIGIN_HOST[4:])
    return hosts


def _google_hosts() -> set[str]:
    return {"google.com", "www.google.com", "google.co.uk", "www.google.co.uk"}


class FrontHandler(sink.SinkHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        sink.apply_cors(self)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _record(self, role: str, body: bytes) -> None:
        host = self.headers.get("Host", "")
        record = {
            "ts": sink._now(),
            "scheme": getattr(self, "scheme", "http"),
            "method": self.command,
            "host": host,
            "path": self.path,
            "role": role,
            "client": self.client_address[0],
            "headers": {k: v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace")[:8192],
        }
        LOGS.mkdir(parents=True, exist_ok=True)
        with (LOGS / "http.jsonl").open("a", encoding="utf-8") as fh:
            import json

            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        sink._log_domain(_host_only(host))

    def _serve_eval_beacon(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(min(length, 2_000_000)) if length else b""
        dump_dir = LOGS / "php"
        dump_dir.mkdir(parents=True, exist_ok=True)
        n = len(list(dump_dir.glob("eval-*.js"))) + len(list(LOGS.glob("eval-*.js"))) + 1
        path = dump_dir / f"eval-{n:04d}.js"
        text = payload.decode("utf-8", "replace")
        path.write_text(text, encoding="utf-8")
        with (dump_dir / "eval.log").open("a", encoding="utf-8") as fh:
            fh.write(f"--- eval #{n} ---\n{text}\n\n")
        self._record("eval-hook", payload[:4096])
        self._send(204, b"", "text/plain")

    def _serve_origin(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path or "/")
        if self.command == "POST" and path in {"/cdn/l.gif", "/cdn/l"}:
            self._serve_eval_beacon()
            return
        if path in {SCRIPT_PATH, "/assets/app.min.js", "/assets/app.js"}:
            data = SAMPLE.read_bytes() if SAMPLE.is_file() else b""
            self._record("origin", b"")
            self._send(200, data, "application/javascript; charset=utf-8")
            return
        if path == "/assets/site.css":
            css = Path("/opt/sandbox/site.css").read_bytes()
            self._record("origin", b"")
            self._send(200, css, "text/css; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._record("origin", b"")
            self._send(200, _FAVICON, "image/x-icon")
            return
        if path == "/robots.txt":
            self._record("origin", b"")
            self._send(200, b"User-agent: *\nAllow: /\n", "text/plain")
            return
        html = wrap.wrap_html(host=ORIGIN_HOST, script_src=SCRIPT_PATH).encode("utf-8")
        self._record("origin", b"")
        self._send(200, html, "text/html; charset=utf-8")

    def _serve_google(self) -> None:
        brand = wrap.brand_from_host(ORIGIN_HOST)
        html = wrap.google_serp_html(target_url=f"https://{ORIGIN_HOST}/", brand=brand).encode("utf-8")
        self._record("referrer", b"")
        self._send(200, html, "text/html; charset=utf-8")

    def _handle(self) -> None:
        host = _host_only(self.headers.get("Host", ""))
        if host in _origin_hosts() or host == "localhost":
            self._serve_origin()
            return
        if host in _google_hosts():
            self._serve_google()
            return
        super()._handle()


class HTTPSFront(FrontHandler):
    scheme = "https"


# 1x1 PNG as a tiny favicon stand-in.
_FAVICON = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n\x2d\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


def serve(ca_dir: Path) -> None:
    sink.CA_DIR = ca_dir
    httpd = ThreadingHTTPServer(("0.0.0.0", 80), FrontHandler)
    httpsd = ThreadingHTTPServer(("0.0.0.0", 443), HTTPSFront)
    ctx = sink._leaf_for_host(ORIGIN_HOST)
    ctx.sni_callback = sink._sni_callback
    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
    import threading

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    httpsd.serve_forever()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--init-ca", action="store_true")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--ca-dir", default=str(sink.CA_DIR))
    args = parser.parse_args()
    ca_dir = Path(args.ca_dir)
    sink.CA_DIR = ca_dir
    if args.init_ca or args.serve:
        sink.init_ca(ca_dir)
    if args.serve:
        serve(ca_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
