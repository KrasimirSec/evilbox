from __future__ import annotations

import re

_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("eval+base64", re.compile(r"eval\s*\(\s*base64_decode\s*\(", re.I)),
    ("eval+gzinflate", re.compile(r"eval\s*\(\s*gzinflate\s*\(", re.I)),
    ("eval+gzuncompress", re.compile(r"eval\s*\(\s*gzuncompress\s*\(", re.I)),
    ("eval+gzdecode", re.compile(r"eval\s*\(\s*gzdecode\s*\(", re.I)),
    ("eval+str_rot13", re.compile(r"eval\s*\(\s*str_rot13\s*\(", re.I)),
    ("eval+strrev", re.compile(r"eval\s*\(\s*strrev\s*\(", re.I)),
    ("eval+urldecode", re.compile(r"eval\s*\(\s*(?:raw)?urldecode\s*\(", re.I)),
    ("eval+bitwise-not", re.compile(r"eval\s*\(\s*~", re.I)),
    ("js-string-array", re.compile(r"\b(?:push|shift)\s*\([^;]{0,40}\b(?:push|shift)\s*\(")),
    ("function-constructor", re.compile(r"\b(?:new\s+)?Function\s*\(")),
    ("computed-fromCharCode", re.compile(r"""String\s*\[\s*['\"]fromCharCode['\"]\s*\]""")),
    ("fromCharCode", re.compile(r"fromCharCode\s*\(")),
    ("preg_replace/e", re.compile(r"preg_replace\s*\([^;]{0,120}e['\"]\s*,", re.I)),
    ("create_function", re.compile(r"create_function\s*\(", re.I)),
    ("assert+decode", re.compile(r"assert\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)", re.I)),
    ("include+decode", re.compile(r"(?:include|require)(?:_once)?\s*\(\s*(?:base64_decode|gzinflate)", re.I)),
    ("pack-H*", re.compile(r"pack\s*\(\s*['\"]H\*", re.I)),
    ("string-xor", re.compile(r"""['"][^'"]{4,}['"]\s*\^\s*['"]""")),
    ("goto-labels", re.compile(r"\bgoto\s+\w+", re.I)),
)


def packer_hints(source: str) -> list[str]:
    found: list[str] = []
    for label, pattern in _HINTS:
        if pattern.search(source):
            found.append(label)
    return found
