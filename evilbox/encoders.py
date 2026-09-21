"""Commercial PHP encoders: detect headers, do not attempt to decode bytecode."""

from __future__ import annotations

import re
from dataclasses import dataclass

_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "ioncube-encoded",
        re.compile(
            r"ionCube\s+Loader|extension_loaded\s*\(\s*['\"]ionCube\s+Loader['\"]|"
            r"ioncube_loader|HR\+cP|/ioncube/",
            re.I,
        ),
        "encoded, not analyzable",
    ),
    (
        "zend-guard-encoded",
        re.compile(r"@Zend;|Zend\s+Guard|zend_loader|ZG\?|This file was encoded by.*Zend", re.I),
        "encoded, not analyzable",
    ),
    (
        "sourceguardian-encoded",
        re.compile(
            r"sourceguardian|sg_load\s*\(|sourceguardian\.com|"
            r"if\s*\(\s*!?\s*function_exists\s*\(\s*['\"]sg_load['\"]",
            re.I,
        ),
        "encoded, not analyzable",
    ),
)

_BINARY_MARKERS: tuple[tuple[str, bytes], ...] = (
    ("ioncube-encoded", b"ionCube"),
    ("ioncube-encoded", b"HR+cP"),
    ("zend-guard-encoded", b"Zend\x00"),
    ("sourceguardian-encoded", b"sg_load"),
)


@dataclass(frozen=True)
class EncoderHit:
    name: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "detail": self.detail}


def detect_commercial_encoders(source: str | bytes) -> list[EncoderHit]:
    if isinstance(source, bytes):
        raw = source
        text = source.decode("latin-1", errors="replace")
    else:
        text = source
        raw = source.encode("latin-1", errors="replace")
    found: list[EncoderHit] = []
    seen: set[str] = set()
    for name, pattern, detail in _RULES:
        if name in seen:
            continue
        if pattern.search(text):
            found.append(EncoderHit(name, detail))
            seen.add(name)
    for name, marker in _BINARY_MARKERS:
        if name in seen:
            continue
        if marker in raw:
            found.append(EncoderHit(name, "encoded, not analyzable"))
            seen.add(name)
    return found
