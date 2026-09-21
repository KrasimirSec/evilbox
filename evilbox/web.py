"""In-memory web UI and JSON API for static JS/PHP decoding.

Samples are never written to disk and are not executed. The PHP Docker
sandbox is not available over HTTP.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from email.parser import BytesParser
from email.policy import HTTP as HTTP_POLICY
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from evilbox.pipeline import deobfuscate
from evilbox.report import build_report, dump_json

MAX_BYTES = int(os.environ.get("EVILBOX_WEB_MAX_BYTES", str(2 * 1024 * 1024)))
DECODE_TIMEOUT = float(os.environ.get("EVILBOX_WEB_TIMEOUT", "20"))
MAX_PASSES = 24
DEFAULT_PASSES = 16
MAX_CONCURRENT = 4
INDEX_PATH = Path(__file__).with_name("web_index.html")

_SLOT = threading.BoundedSemaphore(MAX_CONCURRENT)
_WORKER = (
    "import json,sys; from evilbox.web import decode_payload, WebError;\n"
    "payload=json.load(sys.stdin)\n"
    "try:\n"
    "    json.dump(decode_payload(**payload), sys.stdout)\n"
    "except WebError as exc:\n"
    "    json.dump({'__web_error': True, 'message': exc.message, 'status': exc.status}, sys.stdout)\n"
    "    sys.exit(2)\n"
)

EXAMPLES: list[dict[str, str]] = [
    {
        "id": "php-eval-b64",
        "name": "PHP eval + base64",
        "lang": "php",
        "filename": "eval-base64.php",
        "source": "<?php eval(base64_decode('ZWNobyAiaGkiOw=='));\n",
    },
    {
        "id": "js-fromcharcode",
        "name": "JS fromCharCode",
        "lang": "js",
        "filename": "fromcharcode.js",
        "source": 'var x = String.fromCharCode(72,101,108,108,111) + " " + "world";\n',
    },
    {
        "id": "php-webshell",
        "name": "PHP webshell (eval + POST)",
        "lang": "php",
        "filename": "webshell.php",
        "source": "<?php eval($_POST['x']);\n",
    },
]


class WebError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def decode_payload(
    source: str,
    *,
    lang: str = "auto",
    filename: str | None = None,
    max_passes: int = DEFAULT_PASSES,
) -> dict[str, Any]:
    if lang not in {"auto", "js", "php"}:
        raise WebError("lang must be auto, js, or php")
    if not isinstance(source, str):
        raise WebError("source must be a string")
    if not source.strip():
        raise WebError("paste or upload a JavaScript or PHP sample")
    size = len(source.encode("utf-8"))
    if size > MAX_BYTES:
        raise WebError(f"sample is too large (max {MAX_BYTES} bytes)", 413)
    try:
        passes = int(max_passes)
    except (TypeError, ValueError) as exc:
        raise WebError("max_passes must be an integer") from exc
    if passes < 1 or passes > MAX_PASSES:
        raise WebError(f"max_passes must be between 1 and {MAX_PASSES}")

    path = _safe_filename(filename)
    result = deobfuscate(source, language=lang, path=path, max_passes=passes)
    report = build_report(result=result, path=path)
    layers = []
    for layer in result.layers:
        item = layer.to_dict()
        item["text"] = layer.text
        layers.append(item)
    return {
        "ok": True,
        "decoded": result.text,
        "report": report,
        "layers": layers,
    }


def _safe_filename(name: str | None) -> str | None:
    if not name:
        return None
    base = Path(str(name)).name.strip()
    if not base or base in {".", ".."}:
        return None
    return base[:200]


def _decode_with_timeout(kwargs: dict[str, Any]) -> dict[str, Any]:
    if not _SLOT.acquire(timeout=DECODE_TIMEOUT):
        raise WebError("decoder is busy; try again shortly", 503)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", _WORKER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            out, err = proc.communicate(json.dumps(kwargs).encode("utf-8"), timeout=DECODE_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.wait()
            raise WebError("decode timed out", 504) from exc
        if not out:
            detail = (err or b"").decode("utf-8", errors="replace")[:200]
            raise WebError(f"decode worker failed{': ' + detail if detail else ''}", 500)
        payload = json.loads(out.decode("utf-8"))
        if isinstance(payload, dict) and payload.get("__web_error"):
            raise WebError(str(payload.get("message") or "decode failed"), int(payload.get("status") or 400))
        return payload
    finally:
        _SLOT.release()


def _parse_request(content_type: str, body: bytes, query: dict[str, list[str]]) -> dict[str, Any]:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    lang = (query.get("lang") or ["auto"])[0] or "auto"
    filename = (query.get("filename") or [None])[0]
    max_passes = (query.get("max_passes") or [DEFAULT_PASSES])[0]

    if ctype in {"application/json", "text/json"}:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WebError("request body is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise WebError("JSON body must be an object")
        return {
            "source": payload.get("source", ""),
            "lang": payload.get("lang", lang),
            "filename": payload.get("filename", filename),
            "max_passes": payload.get("max_passes", max_passes),
        }

    if ctype.startswith("multipart/"):
        fields = _parse_multipart(content_type, body)
        source = ""
        file_name = filename
        if "source" in fields:
            source = fields["source"][1]
        if "file" in fields:
            fname, text = fields["file"]
            if not source:
                source = text
            file_name = file_name or fname
        if "lang" in fields and fields["lang"][1]:
            lang = fields["lang"][1]
        if "filename" in fields and fields["filename"][1]:
            file_name = fields["filename"][1]
        if "max_passes" in fields and fields["max_passes"][1]:
            max_passes = fields["max_passes"][1]
        return {"source": source, "lang": lang, "filename": file_name, "max_passes": max_passes}

    source = body.decode("utf-8", errors="replace")
    return {"source": source, "lang": lang, "filename": filename, "max_passes": max_passes}


def _parse_multipart(content_type: str, body: bytes) -> dict[str, tuple[str | None, str]]:
    header = f"Content-Type: {content_type}\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=HTTP_POLICY).parsebytes(header + body)
    out: dict[str, tuple[str | None, str]] = {}
    if not msg.is_multipart():
        return out
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            text = payload.decode("utf-8", errors="replace")
        else:
            text = str(part.get_content())
        out[str(name)] = (filename, text)
    return out


def make_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    return Server((host, port), Handler)


def serve_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evilbox serve",
        description="Open a local web UI where anyone can paste or upload a JS/PHP sample for static decoding. The PHP sandbox is not exposed.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--open", action="store_true", help="Open the UI in a browser")
    args = parser.parse_args(argv)
    if args.port < 1 or args.port > 65535:
        parser.error("port must be between 1 and 65535")
    try:
        server = make_server(args.host, args.port)
    except OSError as exc:
        print(f"error: cannot bind {args.host}:{args.port} ({exc})", file=sys.stderr)
        return 2
    host, port = server.server_address[:2]
    shown = "127.0.0.1" if str(host) in {"0.0.0.0", "::", "::0"} else str(host)
    url = f"http://{shown}:{port}/"
    print(f"Evilbox web decoder: {url}", flush=True)
    print("Static analysis only. Samples stay in memory and are not executed.", flush=True)
    if args.open:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nerror: interrupted", file=sys.stderr)
        return 130
    finally:
        server.server_close()
    return 0


class Handler(BaseHTTPRequestHandler):
    server_version = "EvilboxWeb/0.1"
    protocol_version = "HTTP/1.1"

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, b"", "text/plain")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/":
            self._send_html()
            return
        if path == "/health":
            self._send_json(200, {"ok": True, "service": "evilbox", "sandbox": False})
            return
        if path == "/api/examples":
            self._send_json(200, {"examples": EXAMPLES})
            return
        if path == "/api/decode":
            self._send_json(405, {"ok": False, "error": "POST a sample to /api/decode"}, allow=["GET, POST, OPTIONS"])
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path != "/api/decode":
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        try:
            body = self._read_body()
            query = parse_qs(parsed.query)
            payload = _parse_request(self.headers.get("Content-Type", ""), body, query)
            started = time.monotonic()
            result = _decode_with_timeout(payload)
            result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            self._send_json(200, result)
        except WebError as exc:
            self._send_json(exc.status, {"ok": False, "error": exc.message})
        except BrokenPipeError:
            return
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": f"unexpected failure ({type(exc).__name__})"})

    def _read_body(self) -> bytes:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            raise WebError("Content-Length is required", 411)
        try:
            length = int(length_header)
        except ValueError as exc:
            raise WebError("invalid Content-Length") from exc
        if length < 0:
            raise WebError("invalid Content-Length")
        if length > MAX_BYTES:
            self.close_connection = True
            raise WebError(f"sample is too large (max {MAX_BYTES} bytes)", 413)
        data = self.rfile.read(length)
        if len(data) != length:
            raise WebError("incomplete request body", 400)
        return data

    def _send_html(self) -> None:
        try:
            html = INDEX_PATH.read_bytes()
        except OSError:
            self._send_json(500, {"ok": False, "error": "web UI file is missing"})
            return
        self._send(200, html, "text/html; charset=utf-8")

    def _send_json(self, status: int, payload: dict[str, Any], allow: str | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        extra = {"Allow": allow} if allow else None
        self._send(status, body, "application/json; charset=utf-8", extra)

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        print("%s - %s" % (self.address_string(), format % args), file=sys.stderr, flush=True)
