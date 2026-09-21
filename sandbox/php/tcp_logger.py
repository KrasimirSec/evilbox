#!/usr/bin/env python3
"""Catch-all TCP logger. iptables redirects non-80/443/53 traffic here."""

from __future__ import annotations

import json
import socket
import datetime as dt
from pathlib import Path

LOGS = Path("/logs")
PORT = 9999


def main() -> int:
    LOGS.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    sock.listen(128)
    sock.settimeout(1.0)
    while True:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.settimeout(2.0)
            data = conn.recv(4096)
            record = {
                "ts": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "client": addr[0],
                "port": addr[1],
                "banner": data[:512].decode("latin-1", "replace"),
            }
            with (LOGS / "tcp.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            conn.sendall(b"OK\n")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
