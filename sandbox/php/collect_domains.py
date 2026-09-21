#!/usr/bin/env python3
"""Merge DNS + HTTP hosts into domains.txt and write summary.json."""

from __future__ import annotations

import json
import re
from pathlib import Path

LOGS = Path("/logs")
QUERY_RE = re.compile(r"query\[[^\]]+\]\s+(\S+)", re.I)


def main() -> int:
    domains: set[str] = set()
    domains_file = LOGS / "domains.txt"
    if domains_file.exists():
        domains.update(
            line.strip().lower()
            for line in domains_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        )
    dns_log = LOGS / "dns.log"
    if dns_log.exists():
        for line in dns_log.read_text(encoding="utf-8", errors="replace").splitlines():
            match = QUERY_RE.search(line)
            if match:
                host = match.group(1).rstrip(".").lower()
                if host and host not in {".", "localhost"}:
                    domains.add(host)
    http_jsonl = LOGS / "http.jsonl"
    requests = 0
    if http_jsonl.exists():
        for line in http_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            requests += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(rec.get("host") or "").split(":")[0].lower()
            if host:
                domains.add(host)
    evals = sorted(list(LOGS.glob("eval-*.php")) + list(LOGS.glob("php/eval-*.php")))
    summary = {
        "domains": sorted(domains),
        "http_requests": requests,
        "eval_dumps": [p.name for p in evals],
    }
    (LOGS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    domains_file.write_text("".join(d + "\n" for d in sorted(domains)), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
