#!/usr/bin/env python3
"""Drive Chromium over CDP: spoofed origin, referrer click-through, network log."""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

LOGS = Path("/logs")
HOST = (os.environ.get("SANDBOX_HOST") or "www.shop-assets.net").split(":")[0]
MODE = os.environ.get("SANDBOX_MODE") or "observe"
PROFILE = os.environ.get("SANDBOX_PROFILE") or "default"
TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT") or "20")
UA_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def _chrome_bin() -> str:
    for name in (os.environ.get("CHROME_BIN"), "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if name and Path(name).is_file():
            return name
    raise RuntimeError("chromium is not installed")


def _wait_port(host: str, port: int, seconds: float) -> None:
    deadline = time.time() + seconds
    last: Exception | None = None
    while time.time() < deadline:
        try:
            sock = socket.create_connection((host, port), 0.4)
            sock.close()
            return
        except OSError as exc:
            last = exc
            time.sleep(0.1)
    raise RuntimeError(f"chrome debug port {host}:{port} did not open ({last})")


class WebSocket:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)
        self.sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=20)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port or 80}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(req.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("chrome closed during websocket handshake")
            buf += chunk
        if b"101" not in buf.split(b"\r\n", 1)[0]:
            raise RuntimeError("chrome websocket upgrade failed: " + buf[:200].decode("latin-1", "replace"))
        self._lock = threading.Lock()

    def send_text(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray()
        header.append(0x81)
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", n))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._lock:
            self.sock.sendall(header + masked)

    def recv_text(self) -> str:
        def recvn(n: int) -> bytes:
            out = b""
            while len(out) < n:
                chunk = self.sock.recv(n - len(out))
                if not chunk:
                    raise RuntimeError("chrome websocket closed")
                out += chunk
            return out

        b1, b2 = recvn(2)
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack("!H", recvn(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", recvn(8))[0]
        if b2 & 0x80:
            mask = recvn(4)
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(recvn(length)))
        else:
            payload = recvn(length)
        if opcode == 0x8:
            raise RuntimeError("chrome websocket closed")
        if opcode == 0x9:
            # ping
            return self.recv_text()
        return payload.decode("utf-8")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class CDP:
    def __init__(self, url: str) -> None:
        self.ws = WebSocket(url)
        self._id = 0
        self._pending: dict[int, dict] = {}
        self._events: list[dict] = []
        self._err: BaseException | None = None
        self._cv = threading.Condition()
        t = threading.Thread(target=self._read_loop, daemon=True)
        t.start()

    def _read_loop(self) -> None:
        try:
            while True:
                msg = json.loads(self.ws.recv_text())
                with self._cv:
                    if "id" in msg:
                        self._pending[int(msg["id"])] = msg
                    else:
                        self._events.append(msg)
                    self._cv.notify_all()
        except Exception as exc:
            self._err = exc
            with self._cv:
                self._cv.notify_all()

    def send(self, method: str, params: dict | None = None, timeout: float = 20, session_id: str | None = None) -> dict:
        self._id += 1
        msg_id = self._id
        payload: dict = {"id": msg_id, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        self.ws.send_text(json.dumps(payload))
        deadline = time.time() + timeout
        with self._cv:
            while msg_id not in self._pending:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(method)
                if self._err:
                    raise RuntimeError(self._err)
                self._cv.wait(remaining)
            return self._pending.pop(msg_id)

    def drain_events(self) -> list[dict]:
        with self._cv:
            events = self._events
            self._events = []
            return events

    def wait_event(self, method: str, timeout: float) -> dict | None:
        deadline = time.time() + timeout
        with self._cv:
            while True:
                for i, ev in enumerate(self._events):
                    if ev.get("method") == method:
                        return self._events.pop(i)
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                if self._err:
                    raise RuntimeError(self._err)
                self._cv.wait(min(remaining, 0.2))


def _http_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ua() -> str:
    if PROFILE == "googlebot":
        return UA_GOOGLEBOT
    return UA_CHROME


def _use_google_referrer() -> bool:
    return PROFILE in {"default", "google-referrer"}


def _load_scripts() -> str:
    stealth = Path("/opt/sandbox/stealth.js").read_text(encoding="utf-8")
    hook = Path("/opt/sandbox/hook.js").read_text(encoding="utf-8").replace("__MODE__", MODE)
    return stealth + "\n" + hook


def _log_cdp(events: list[dict]) -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    net = LOGS / "cdp-network.jsonl"
    console = LOGS / "console.jsonl"
    with net.open("a", encoding="utf-8") as fh, console.open("a", encoding="utf-8") as ch:
        for ev in events:
            method = ev.get("method") or ""
            params = ev.get("params") or {}
            if method.startswith("Network."):
                rec = {"method": method, "ts": time.time()}
                req = params.get("request") or {}
                if req:
                    rec["url"] = req.get("url")
                    rec["req_method"] = req.get("method")
                    rec["headers"] = req.get("headers")
                    if req.get("postData"):
                        rec["post"] = str(req.get("postData"))[:8192]
                if "response" in params:
                    rec["status"] = (params.get("response") or {}).get("status")
                    rec["mime"] = (params.get("response") or {}).get("mimeType")
                    rec["url"] = rec.get("url") or (params.get("response") or {}).get("url")
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            elif method in {"Runtime.consoleAPICalled", "Log.entryAdded"}:
                ch.write(json.dumps({"method": method, "ts": time.time(), "params": params}, ensure_ascii=False) + "\n")


def main() -> int:
    LOGS.mkdir(parents=True, exist_ok=True)
    (LOGS / "downloads").mkdir(exist_ok=True)
    chrome = _chrome_bin()
    args = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=Translate,MediaRouter,OptimizationHints",
        "--disable-component-update",
        "--disable-sync",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-client-side-phishing-detection",
        "--disable-hang-monitor",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--metrics-recording-only",
        "--password-store=basic",
        "--use-mock-keychain",
        "--hide-scrollbars",
        "--mute-audio",
        "--window-size=1920,1080",
        f"--user-agent={_ua()}",
        "--lang=en-US",
        "--accept-lang=en-US,en",
        "--ignore-certificate-errors",
        "--allow-running-insecure-content",
        "--remote-debugging-port=9222",
        "--remote-debugging-address=127.0.0.1",
        "--user-data-dir=/tmp/chrome",
        "about:blank",
    ]
    proc = subprocess.Popen(args, stdout=(LOGS / "chromium.stdout.log").open("w"), stderr=(LOGS / "chromium.stderr.log").open("w"))
    try:
        _wait_port("127.0.0.1", 9222, 25)
        version = _http_json("http://127.0.0.1:9222/json/version")
        cdp = CDP(version["webSocketDebuggerUrl"])
        created = cdp.send("Target.createTarget", {"url": "about:blank"})
        target_id = (created.get("result") or {}).get("targetId")
        attached = cdp.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        session = (attached.get("result") or {}).get("sessionId")
        if not session:
            raise RuntimeError("failed to attach to chrome target")

        def s(method: str, params: dict | None = None, timeout: float = 20) -> dict:
            return cdp.send(method, params, timeout=timeout, session_id=session)

        s("Page.enable")
        s("Network.enable")
        s("Runtime.enable")
        s("Log.enable")
        s("Page.addScriptToEvaluateOnNewDocument", {"source": _load_scripts()})
        s("Emulation.setDeviceMetricsOverride", {
            "width": 1920,
            "height": 1080,
            "deviceScaleFactor": 1,
            "mobile": False,
        })
        s("Emulation.setTimezoneOverride", {"timezoneId": "America/New_York"})
        s("Emulation.setLocaleOverride", {"locale": "en-US"})
        ua_params: dict = {"userAgent": _ua(), "acceptLanguage": "en-US,en", "platform": "Win32"}
        if PROFILE != "googlebot":
            ua_params["userAgentMetadata"] = {
                "brands": [
                    {"brand": "Not_A Brand", "version": "8"},
                    {"brand": "Chromium", "version": "131"},
                    {"brand": "Google Chrome", "version": "131"},
                ],
                "fullVersionList": [
                    {"brand": "Not_A Brand", "version": "8.0.0.0"},
                    {"brand": "Chromium", "version": "131.0.6778.86"},
                    {"brand": "Google Chrome", "version": "131.0.6778.86"},
                ],
                "fullVersion": "131.0.6778.86",
                "platform": "Windows",
                "platformVersion": "10.0.0",
                "architecture": "x86",
                "model": "",
                "mobile": False,
                "bitness": "64",
                "wow64": False,
            }
        s("Network.setUserAgentOverride", ua_params)
        try:
            cdp.send(
                "Browser.setDownloadBehavior",
                {"behavior": "allow", "downloadPath": "/logs/downloads", "eventsEnabled": True},
            )
        except Exception:
            try:
                s("Page.setDownloadBehavior", {"behavior": "allow", "downloadPath": "/logs/downloads"})
            except Exception:
                pass
        if PROFILE == "wp-cookie":
            for name, value in (
                ("wordpress_logged_in_3c9e1a7b8f2d4e6a", "admin|1730000000|1730000000|a1b2c3d4e5f6"),
                ("wordpress_test_cookie", "WP Cookie check"),
            ):
                s(
                    "Network.setCookie",
                    {
                        "name": name,
                        "value": value,
                        "domain": HOST,
                        "path": "/",
                        "secure": True,
                    },
                )

        _log_cdp(cdp.drain_events())
        origin = f"https://{HOST}/"
        if _use_google_referrer():
            s("Page.navigate", {"url": f"https://www.google.com/search?q={HOST}"})
            cdp.wait_event("Page.loadEventFired", min(8.0, max(2.0, TIMEOUT / 4)))
            _log_cdp(cdp.drain_events())
            s(
                "Runtime.evaluate",
                {
                    "expression": "const a=document.getElementById('result'); if(a){a.click();} else {location.href=%s;}"
                    % json.dumps(origin),
                    "userGesture": True,
                },
            )
            cdp.wait_event("Page.loadEventFired", min(8.0, max(2.0, TIMEOUT / 4)))
        else:
            referrer = "https://www.google.com/" if PROFILE == "googlebot" else ""
            nav = {"url": origin}
            if referrer:
                nav["referrer"] = referrer
            s("Page.navigate", nav)
            cdp.wait_event("Page.loadEventFired", min(8.0, max(2.0, TIMEOUT / 4)))

        deadline = time.time() + max(3, TIMEOUT)
        while time.time() < deadline:
            _log_cdp(cdp.drain_events())
            time.sleep(0.25)
        _log_cdp(cdp.drain_events())
        shot = s("Page.captureScreenshot", {"format": "png", "fromSurface": True}, timeout=10)
        data = (shot.get("result") or {}).get("data")
        if data:
            (LOGS / "screenshot.png").write_bytes(base64.b64decode(data))
        info = s(
            "Runtime.evaluate",
            {
                "expression": "({href: location.href, referrer: document.referrer, origin: location.origin, ua: navigator.userAgent, webdriver: navigator.webdriver, hidden: document.hidden})",
                "returnByValue": True,
            },
        )
        value = ((info.get("result") or {}).get("result") or {}).get("value") or {}
        (LOGS / "location.txt").write_text(str(value.get("href") or "") + "\n", encoding="utf-8")
        (LOGS / "location.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
