"""Language-agnostic codecs. Never executes JS or PHP."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import quopri
import re
import zlib
from dataclasses import dataclass

_HEX_RE = re.compile(r"^[0-9a-fA-F\s]+$")

# Cap decompressor output so a tiny gzinflate blob cannot fill memory.
MAX_CODEC_OUTPUT = 2 * 1024 * 1024
PHP_TRIM_DEFAULT = " \t\n\r\0\x0b"


def b64decode(text: str) -> bytes | None:
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned:
        return None
    pad = (-len(cleaned)) % 4
    cleaned += "=" * pad
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(cleaned)
        except Exception:
            continue
    return None


def hex_decode(text: str) -> bytes | None:
    cleaned = text.strip()
    if re.search(r"\\x[0-9a-fA-F]{2}", cleaned, re.I):
        cleaned = re.sub(r"\\x", "", cleaned, flags=re.I)
    cleaned = re.sub(r"0x", "", cleaned, flags=re.I)
    cleaned = re.sub(r"[\s:_,\-]", "", cleaned)
    if len(cleaned) < 2 or len(cleaned) % 2 or not _HEX_RE.match(cleaned):
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def hex_payload_to_text(text: str, *, min_bytes: int = 2) -> str | None:
    data = hex_decode(text)
    if data is None or len(data) < min_bytes:
        return None
    decoded = bytes_to_text(data)
    if decoded is None:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\r\t")
    if printable / max(len(decoded), 1) < 0.85:
        return None
    return decoded


def parse_js_quoted_string(literal: str) -> str | None:
    """JS single and double quotes both honour \\x / \\u / octal escapes."""
    if len(literal) < 2:
        return None
    quote = literal[0]
    if quote not in "'\"" or literal[-1] != quote:
        return None
    return unescape_js_string_body(literal[1:-1])


def js_unescape(text: str) -> str:
    """JS unescape(): %uXXXX and %HH."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "%" and i + 5 < n and text[i + 1] in "uU":
            hexpart = text[i + 2 : i + 6]
            if re.fullmatch(r"[0-9a-fA-F]{4}", hexpart):
                out.append(chr(int(hexpart, 16)))
                i += 6
                continue
        if text[i] == "%" and i + 2 < n:
            hexpart = text[i + 1 : i + 3]
            if re.fullmatch(r"[0-9a-fA-F]{2}", hexpart):
                out.append(chr(int(hexpart, 16)))
                i += 3
                continue
        out.append(text[i])
        i += 1
    return "".join(out)


def rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def _decompress_limited(data: bytes, wbits: int, max_out: int = MAX_CODEC_OUTPUT) -> bytes | None:
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(data, max_out)
    except zlib.error:
        return None
    if not obj.eof:
        return None
    if len(out) > max_out:
        return None
    return out


def gzip_bytes(data: bytes) -> bytes | None:
    return _decompress_limited(data, 16 + zlib.MAX_WBITS)


def bzip_bytes(data: bytes) -> bytes | None:
    try:
        import bz2

        obj = bz2.BZ2Decompressor()
        out = obj.decompress(data, max_length=MAX_CODEC_OUTPUT)
        if not obj.eof:
            return None
        if len(out) > MAX_CODEC_OUTPUT:
            return None
        return out
    except Exception:
        return None


def zlib_bytes(data: bytes) -> bytes | None:
    return _decompress_limited(data, zlib.MAX_WBITS)


# Stored inflate window (raw deflate+zlib header) for codec self-checks.
_ZRAW = bytes(
    (120, 218, 243, 46, 74, 44, 206, 204, 205, 44, 82, 240, 206, 207, 203, 47, 3, 0, 40, 85, 5, 112)
)


def raw_inflate(data: bytes) -> bytes | None:
    return _decompress_limited(data, -15)


def gzip_zlib_or_inflate(data: bytes) -> bytes | None:
    for fn in (gzip_bytes, zlib_bytes, raw_inflate):
        out = fn(data)
        if out is not None:
            return out
    return _decompress_limited(data, 32 + zlib.MAX_WBITS)


# Common cookie/POST passwords used by PAS-family PHP webshells.
PAS_COMMON_KEYS: tuple[str, ...] = (
    "root",
    "admin",
    "1",
    "12",
    "123",
    "1234",
    "12345",
    "123456",
    "12345678",
    "password",
    "pass",
    "passwd",
    "pwd",
    "qwerty",
    "abc123",
    "admin123",
    "letmein",
    "secret",
    "shell",
    "cmd",
    "ok",
    "p@ssw0rd",
    "predator",
    "wso",
    "c99",
    "r57",
    "b374k",
    "pas",
    "php",
    "test",
    "default",
    "changeme",
    "111111",
    "000000",
    "666666",
    "888888",
    "password1",
    "pass123",
    "root123",
    "toor",
    "god",
    "love",
    "china",
    "india",
    "xxx",
    "hack",
    "hacker",
    "webshell",
    "backdoor",
)


def pas_key_schedule(password: bytes) -> bytes:
    """md5(pw) + substr(md5(strrev(pw)), 0, strlen(pw)) as used by PAS shells."""
    forward = hashlib.md5(password).hexdigest().encode("ascii")
    reverse = hashlib.md5(password[::-1]).hexdigest().encode("ascii")
    return forward + reverse[: len(password)]


def pas_autokey_decrypt(data: bytes, password: str | bytes) -> bytes | None:
    """Subtractive autokey: out[i]=(ct[i]-key[i])%256; key.=out[i]."""
    if not data:
        return None
    pw = password.encode("latin-1") if isinstance(password, str) else password
    key = bytearray(pas_key_schedule(pw))
    if not key:
        return None
    out = bytearray(len(data))
    for i, cipher in enumerate(data):
        if i >= len(key):
            return None
        plain = (cipher - key[i]) % 256
        out[i] = plain
        key.append(plain)
    return bytes(out)


def looks_like_php_payload(data: bytes) -> bool:
    if len(data) < 48:
        return False
    text = data.decode("latin-1", "replace")
    stripped = text.lstrip()
    if stripped.startswith(("<?", "@ini_set", "@error", "@set_time", "@ignore_user", "goto ", "eval(", "$")):
        if len(data) >= 64 or "$_" in text or "function" in text or "@ini_set" in text:
            return True
    markers = (
        "<?php",
        "<?=",
        "$_GET",
        "$_POST",
        "$_COOKIE",
        "$_REQUEST",
        "function ",
        "@ini_set",
        "eval(",
        "create_function",
        "base64_decode",
        "gzinflate",
    )
    return sum(1 for marker in markers if marker in text) >= 2


def pas_recover_payload(data: bytes, extra_keys: list[str] | None = None) -> tuple[bytes, str] | None:
    """Try extra keys then the common PAS password list; keep the longest PHP-like inflate."""
    seen: set[str] = set()
    best: tuple[bytes, str] | None = None
    for raw in list(extra_keys or []) + list(PAS_COMMON_KEYS):
        if raw in seen:
            continue
        seen.add(raw)
        decrypted = pas_autokey_decrypt(data, raw)
        if decrypted is None:
            continue
        inflated = gzip_zlib_or_inflate(decrypted)
        if inflated is None or not looks_like_php_payload(inflated):
            continue
        if best is None or len(inflated) > len(best[0]):
            best = (inflated, raw)
    return best


def bytes_to_text(data: bytes) -> str | None:
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def unescape_js_string_body(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        simple = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "b": "\b",
            "f": "\f",
            "v": "\v",
            "0": "\0",
            "\\": "\\",
            "'": "'",
            '"': '"',
            "/": "/",
        }
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
            continue
        if nxt == "x" and i + 3 < len(body):
            hexpart = body[i + 2 : i + 4]
            if re.fullmatch(r"[0-9a-fA-F]{2}", hexpart):
                out.append(chr(int(hexpart, 16)))
                i += 4
                continue
        if nxt == "u":
            if i + 2 < len(body) and body[i + 2] == "{":
                end = body.find("}", i + 3)
                if end != -1:
                    hexpart = body[i + 3 : end]
                    if re.fullmatch(r"[0-9a-fA-F]+", hexpart):
                        out.append(chr(int(hexpart, 16)))
                        i = end + 1
                        continue
            elif i + 5 < len(body):
                hexpart = body[i + 2 : i + 6]
                if re.fullmatch(r"[0-9a-fA-F]{4}", hexpart):
                    out.append(chr(int(hexpart, 16)))
                    i += 6
                    continue
        if nxt in "01234567":
            j = i + 1
            while j < len(body) and j < i + 4 and body[j] in "01234567":
                j += 1
            out.append(chr(int(body[i + 1 : j], 8)))
            i = j
            continue
        out.append(nxt)
        i += 2
    return "".join(out)


def parse_quoted_string(literal: str) -> str | None:
    if len(literal) < 2:
        return None
    quote = literal[0]
    if quote not in "'\"" or literal[-1] != quote:
        return None
    body = literal[1:-1]
    if quote == "'":
        return body.replace("\\'", "'").replace("\\\\", "\\")
    return unescape_js_string_body(body)


def unescape_html_entities(text: str) -> str:
    if "&#" not in text and "&" not in text:
        return text
    out = html.unescape(text)
    if any(ord(ch) > 255 for ch in out):
        return text
    return out


def looks_like_php_source(text: str) -> bool:
    sample = text.lstrip()
    if sample.startswith("<?") or sample.startswith("?>"):
        return True
    lowered = text.lower()
    return any(
        token in lowered
        for token in (
            "<?php",
            "$_get",
            "$_post",
            "$_cookie",
            "eval(",
            "echo ",
            "print ",
            "function ",
            "system(",
            "$auth_pass",
            "filesman",
            "gzinflate",
            "base64_decode",
            "create_function",
        )
    )


def percent_decode(text: str) -> str | None:
    try:
        return _percent_decode(text)
    except Exception:
        return None


def php_urldecode(text: str) -> str:
    return _percent_decode(text.replace("+", " "))


def parse_php_version(version: str | tuple[int, int] | None) -> tuple[int, int]:
    if version is None:
        return (8, 3)
    if isinstance(version, tuple):
        major = int(version[0])
        minor = int(version[1]) if len(version) > 1 else 0
        return (major, minor)
    text = str(version).strip()
    if text.startswith("php"):
        text = text[3:].lstrip()
    parts = text.split(".")
    try:
        major = int(parts[0])
    except (TypeError, ValueError):
        return (8, 3)
    try:
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        minor = 0
    return (major, minor)


def php_string_bytes(text: str) -> bytes:
    """PHP strings are byte arrays. Characters above U+00FF are not representable."""
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("PHP strings are bytes; character is outside latin-1") from exc


def php_bitwise_not(text: str) -> str:
    data = php_string_bytes(text)
    return bytes((~b) & 0xFF for b in data).decode("latin-1")


def quoted_printable_decode(text: str) -> str | None:
    try:
        return quopri.decodestring(text, header=False).decode("latin-1")
    except Exception:
        return None


@dataclass(frozen=True)
class UudecodeResult:
    data: bytes
    recovered: bool = False


def uudecode(text: str) -> bytes | None:
    result = uudecode_ex(text)
    return None if result is None else result.data


def _uu_line_short(line: str) -> bool:
    """True when the length byte claims more payload than the line encodes."""
    body = line.replace("\r", "").replace("\n", "")
    if not body:
        return False
    nbytes = (ord(body[0]) - 32) & 63
    encoded_needed = ((nbytes + 2) // 3) * 4
    return len(body) < 1 + encoded_needed


def uudecode_ex(text: str) -> UudecodeResult | None:
    """PHP convert_uudecode. Short/padded lines are marked recovered, not clean."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = bytearray()
    recovered = False
    for line in lines:
        if not line or line.startswith("begin ") or line.strip() == "end":
            continue
        if _uu_line_short(line):
            recovered = True
        try:
            out.extend(binascii.a2b_uu(line))
            continue
        except binascii.Error:
            pass
        try:
            out.extend(binascii.a2b_uu(line + " " * 36))
            recovered = True
        except Exception:
            return None
    if not out:
        return None
    return UudecodeResult(bytes(out), recovered=recovered)


def stripslashes(text: str) -> str:
    """PHP stripslashes: `\\0` is NUL, a trailing lone backslash is dropped."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 1
            if i >= n:
                break
            nxt = text[i]
            out.append("\0" if nxt == "0" else nxt)
            i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def php_substr(
    text: str,
    start: int,
    length: int | None = None,
    *,
    php_version: str | tuple[int, int] | None = "8.3",
) -> str | bool:
    """PHP substr. PHP 8 returns '' when the start is past the string; PHP 5/7 return false."""
    n = len(text)
    major, _minor = parse_php_version(php_version)
    oob: str | bool = "" if major >= 8 else False
    if start >= n:
        return oob
    if start < 0:
        start = n + start
        if start < 0:
            start = 0
    if length is None:
        return text[start:]
    if length < 0:
        end = n + length
        if end <= start:
            return oob
        return text[start:end]
    return text[start : start + length]


def _percent_decode(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "%" and i + 2 < len(text) and re.fullmatch(r"[0-9a-fA-F]{2}", text[i + 1 : i + 3]):
            out.append(chr(int(text[i + 1 : i + 3], 16)))
            i += 3
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def js_quote(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def php_quote(value: str) -> str:
    """PHP literal for a byte string.

    Single quotes cannot spell NUL or other controls without embedding the raw
    byte, and tree-sitter rejects a raw NUL inside quotes. Those values use
    double quotes and `\\xHH`, so a later fold still parses.
    """
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return _php_double_quote(value)
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _php_double_quote(value: str) -> str:
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "$":
            out.append("\\$")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        elif code > 255:
            out.append(f"\\u{{{code:x}}}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def format_js_number(value: float | int) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def xor_bytes(data: bytes, key: bytes) -> bytes | None:
    if not data or not key:
        return None
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_strings(left: str, right: str) -> str:
    a = php_string_bytes(left)
    b = php_string_bytes(right)
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n])).decode("latin-1")


def rc4_crypt(data: bytes, key: bytes) -> bytes | None:
    if not data or not key:
        return None
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = 0
    j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def php_strtoupper(text: str) -> str:
    return "".join(chr(ord(ch) - 32) if "a" <= ch <= "z" else ch for ch in text)


def php_strtolower(text: str) -> str:
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in text)


def expand_php_charlist(mask: str) -> str:
    """PHP trim/chop charlist: `a..z` is a range of bytes."""
    out: list[str] = []
    i = 0
    n = len(mask)
    while i < n:
        if i + 3 < n and mask[i + 1] == "." and mask[i + 2] == ".":
            start, end = ord(mask[i]), ord(mask[i + 3])
            step = 1 if end >= start else -1
            out.extend(chr(code) for code in range(start, end + step, step))
            i += 4
            continue
        out.append(mask[i])
        i += 1
    return "".join(out)


def php_str_pad(text: str, width: int, pad: str = " ", style: int = 1) -> str | None:
    if width < 0 or width > 1_000_000:
        return None
    if len(text) >= width:
        return text
    if not pad:
        pad = " "
    need = width - len(text)
    fill = (pad * (need // len(pad) + 1))[:need]
    if style == 0:  # STR_PAD_LEFT
        return fill + text
    if style == 2:  # STR_PAD_BOTH
        left = need // 2
        return fill[:left] + text + fill[left:]
    return text + fill


def format_php_number(value: float | int) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and value.bit_length() > 256:
        raise ValueError("integer too large to fold")
    try:
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        return str(value)
    except ValueError:
        raise ValueError("integer too large to fold") from None
