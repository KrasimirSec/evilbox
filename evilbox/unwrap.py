"""Source-level unwraps for known packers. Never executes JS or PHP."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from evilbox.decode import hex_payload_to_text, unescape_js_string_body

_PACKER_HEAD = re.compile(
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,",
    re.I,
)
_PACKER_RETURN = re.compile(r"return\s+p\s*\}\s*\(", re.I)
_PACKER_TAIL = re.compile(r"\s*(?:,\s*\d+\s*,\s*\{[^{}]*\}\s*)?\)\s*\)", re.S)

_ALPHABET_62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_ALPHABET_95 = (
    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

_JSFUCK_CHARS = set("[]()!+")
_ARRAY_METHODS = {
    "concat",
    "constructor",
    "entries",
    "every",
    "fill",
    "filter",
    "find",
    "findIndex",
    "flat",
    "flatMap",
    "forEach",
    "includes",
    "indexOf",
    "join",
    "keys",
    "map",
    "pop",
    "push",
    "reduce",
    "reverse",
    "shift",
    "slice",
    "some",
    "sort",
    "splice",
    "toString",
    "unshift",
    "values",
}


def unwrap_source(source: str, language: str = "js") -> tuple[str, list[str]]:
    """Apply packer-specific static unwraps. Language selects extra JS-only steps."""
    warnings: list[str] = []
    text = source
    text, notes = unwrap_dean_edwards(text)
    warnings.extend(notes)
    text, notes = unwrap_halt_compiler(text)
    warnings.extend(notes)
    text, notes = unwrap_percent_script(text)
    warnings.extend(notes)
    text, notes = unwrap_hex(text)
    warnings.extend(notes)
    text, notes = unwrap_layout(text)
    warnings.extend(notes)
    if language == "js" or _mostly_jsfuck(text):
        text, notes = unwrap_jsfuck(text)
        warnings.extend(notes)
        text, notes = unwrap_jjencode(text)
        warnings.extend(notes)
        text, notes = unwrap_aaencode(text)
        warnings.extend(notes)
    return text, warnings


def unwrap_dean_edwards(source: str) -> tuple[str, list[str]]:
    """Dictionary unpack for Dean Edwards p.a.c.k.e.r. / tholu php-packer JS output."""
    text = source
    unpacked = 0
    for _ in range(8):
        nxt = _unpack_dean_once(text)
        if nxt is None or nxt == text:
            break
        text = nxt
        unpacked += 1
    if not unpacked:
        return source, []
    return text, [f"Unpacked Dean Edwards / p.a.c.k.e.r. dictionary encoding ({unpacked} layer(s))."]


def _unpack_dean_once(source: str) -> str | None:
    head = _PACKER_HEAD.search(source)
    if not head:
        return None
    invoke = _PACKER_RETURN.search(source, head.start())
    if not invoke:
        return None
    parsed = _parse_packer_args(source, invoke.end())
    if parsed is None:
        return None
    payload, radix, count, symtab, args_end = parsed
    unbase = _unbaser(radix)
    if unbase is None:
        return None

    def lookup(match: re.Match[str]) -> str:
        word = match.group(0)
        try:
            idx = unbase(word)
        except Exception:
            return word
        if 0 <= idx < len(symtab) and symtab[idx]:
            return symtab[idx]
        return word

    body = re.sub(r"\b\w+\b", lookup, payload, flags=re.ASCII)
    tail = _PACKER_TAIL.match(source, args_end)
    end = tail.end() if tail else args_end
    _ = count
    return source[: head.start()] + body + source[end:]


def _parse_packer_args(source: str, start: int) -> tuple[str, int, int, list[str], int] | None:
    i = _skip_ws(source, start)
    payload, i = _read_js_string(source, i)
    if payload is None:
        return None
    i = _skip_ws(source, i)
    if i >= len(source) or source[i] != ",":
        return None
    i = _skip_ws(source, i + 1)
    if source.startswith("[]", i):
        radix = 62
        i += 2
    else:
        m = re.match(r"\d+", source[i:])
        if not m:
            return None
        radix = int(m.group(0))
        i += m.end()
    i = _skip_ws(source, i)
    if i >= len(source) or source[i] != ",":
        return None
    i = _skip_ws(source, i + 1)
    m = re.match(r"\d+", source[i:])
    if not m:
        return None
    count = int(m.group(0))
    i += m.end()
    i = _skip_ws(source, i)
    if i >= len(source) or source[i] != ",":
        return None
    i = _skip_ws(source, i + 1)
    table, i = _read_js_string(source, i)
    if table is None:
        return None
    split = re.match(r"\s*\.split\s*\(\s*(['\"])\|\1\s*\)", source[i:])
    if not split:
        return None
    i += split.end()
    return payload, radix, count, table.split("|"), i


def _skip_ws(source: str, i: int) -> int:
    n = len(source)
    while i < n and source[i] in " \t\r\n":
        i += 1
    return i


def _read_js_string(source: str, i: int) -> tuple[str | None, int]:
    if i >= len(source) or source[i] not in "'\"":
        return None, i
    quote = source[i]
    i += 1
    chars: list[str] = []
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "\\":
            if i + 1 >= n:
                break
            chars.append("\\")
            chars.append(source[i + 1])
            i += 2
            continue
        if ch == quote:
            return unescape_js_string_body("".join(chars)), i + 1
        chars.append(ch)
        i += 1
    return None, i


def _unbaser(radix: int):
    if 2 <= radix <= 36:
        return lambda token: int(token, radix)
    alphabet = None
    if 36 < radix <= 62:
        alphabet = _ALPHABET_62[:radix]
    elif radix == 95:
        alphabet = _ALPHABET_95
    if not alphabet:
        return None
    table = {ch: i for i, ch in enumerate(alphabet)}

    def convert(token: str) -> int:
        value = 0
        for ch in token:
            value = value * radix + table[ch]
        return value

    return convert


def unwrap_percent_script(source: str) -> tuple[str, list[str]]:
    """Whole-file percent-encoding used by some bookmarklets and droppers."""
    stripped = source.strip()
    if stripped.count("%") < 12:
        return source, []
    sample = re.sub(r"\s+", "", stripped[:400])
    if not sample or sample.count("%") * 3 < len(sample) * 0.6:
        return source, []
    from evilbox.decode import percent_decode

    decoded = percent_decode(stripped)
    if not decoded or decoded == stripped:
        return source, []
    if decoded.count("%") >= stripped.count("%"):
        return source, []
    return decoded, ["Unpacked percent-encoded script."]


_HEX_STREAM_RE = re.compile(r"^(?:\\x[0-9a-fA-F]{2}|\s)+$", re.I)
_UNICODE_STREAM_RE = re.compile(r"^(?:\\u[0-9a-fA-F]{4}|\s)+$", re.I)
_HEX_DUMP_RE = re.compile(r"^(?:0x[0-9a-fA-F]{2}[\s,;]*){8,}$", re.I)


def unwrap_hex(source: str) -> tuple[str, list[str]]:
    """Decode whole-file hex / \\xHH / \\u00HH streams used as a packer layer."""
    stripped = source.strip()
    if len(stripped) < 16:
        return source, []
    if _HEX_STREAM_RE.match(stripped) and stripped.lower().count("\\x") >= 8:
        body = re.sub(r"\s+", "", stripped)
        decoded = unescape_js_string_body(body)
        if decoded and decoded != stripped:
            return decoded, ["Unpacked hex \\xHH byte stream."]
    if _UNICODE_STREAM_RE.match(stripped) and stripped.lower().count("\\u") >= 8:
        body = re.sub(r"\s+", "", stripped)
        decoded = unescape_js_string_body(body)
        if decoded and decoded != stripped:
            return decoded, ["Unpacked \\uHHHH unicode stream."]
    if _HEX_DUMP_RE.match(stripped):
        decoded = hex_payload_to_text(stripped, min_bytes=8)
        if decoded:
            return decoded, ["Unpacked 0xHH hex dump."]
    hexish = re.sub(r"[\s:_,\-]", "", stripped)
    if re.fullmatch(r"[0-9a-fA-F]+", hexish) and len(hexish) >= 16 and len(hexish) % 2 == 0:
        decoded = hex_payload_to_text(stripped, min_bytes=8)
        if decoded:
            return decoded, ["Unpacked hex-encoded payload."]
    return source, []


def _mostly_jsfuck(source: str) -> bool:
    compact = re.sub(r"\s+", "", source)
    if len(compact) < 24:
        return False
    other = sum(1 for ch in compact if ch not in _JSFUCK_CHARS)
    return other / len(compact) <= 0.02


def unwrap_jsfuck(source: str) -> tuple[str, list[str]]:
    compact = re.sub(r"\s+", "", source)
    if not _mostly_jsfuck(source):
        return source, []
    try:
        result = _eval_jsfuck(compact)
    except Exception:
        return source, []
    if result is None:
        return source, []
    if result.kind == "code" and isinstance(result.value, str) and result.value:
        return result.value, ["Unpacked JSFuck / []()!+ encoding."]
    if result.kind == "str" and result.is_program and isinstance(result.value, str) and result.value:
        return result.value, ["Unpacked JSFuck / []()!+ encoding."]
    return source, []


@dataclass
class _J:
    kind: str
    value: Any = None
    name: str = ""
    is_program: bool = False


def _eval_jsfuck(source: str) -> _J | None:
    tokens = _tokenize_jsfuck(source)
    parser = _JSFuckParser(tokens)
    value = parser.parse_expr()
    if parser.i != len(tokens):
        return None
    return value


def _tokenize_jsfuck(source: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch in " \t\n\r":
            i += 1
            continue
        if ch not in "[]()!+":
            raise ValueError("not jsfuck")
        if ch == "[" and i + 1 < n and source[i + 1] == "]":
            tokens.append("[]")
            i += 2
            continue
        tokens.append(ch)
        i += 1
    return tokens


class _JSFuckParser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> str | None:
        if self.i >= len(self.tokens):
            return None
        return self.tokens[self.i]

    def take(self, expected: str | None = None) -> str:
        if self.i >= len(self.tokens):
            raise ValueError("eof")
        tok = self.tokens[self.i]
        if expected is not None and tok != expected:
            raise ValueError("token")
        self.i += 1
        return tok

    def parse_expr(self) -> _J:
        left = self.parse_unary()
        while self.peek() == "+":
            self.take("+")
            right = self.parse_unary()
            left = _js_add(left, right)
        return left

    def parse_unary(self) -> _J:
        tok = self.peek()
        if tok == "!":
            self.take("!")
            return _js_not(self.parse_unary())
        if tok == "+":
            self.take("+")
            return _js_to_number(self.parse_unary())
        return self.parse_postfix()

    def parse_postfix(self) -> _J:
        value = self.parse_atom()
        while True:
            tok = self.peek()
            if tok == "[":
                self.take("[")
                index = self.parse_expr()
                self.take("]")
                value = _js_index(value, index)
                continue
            if tok == "(":
                self.take("(")
                arg = None
                if self.peek() != ")":
                    arg = self.parse_expr()
                self.take(")")
                value = _js_call(value, arg)
                continue
            return value

    def parse_atom(self) -> _J:
        tok = self.peek()
        if tok == "[]":
            self.take("[]")
            return _J("arr", [])
        if tok == "(":
            self.take("(")
            value = self.parse_expr()
            self.take(")")
            return value
        if tok == "[":
            self.take("[")
            inner = self.parse_expr()
            self.take("]")
            return _J("arr", [inner])
        raise ValueError("atom")


def _js_truthy(val: _J) -> bool:
    if val.kind == "arr":
        return True
    if val.kind == "str":
        return bool(val.value)
    if val.kind == "num":
        return val.value != 0 and val.value == val.value
    if val.kind == "bool":
        return bool(val.value)
    if val.kind in {"undef", "nan", "null"}:
        return False
    if val.kind == "inf":
        return True
    return True


def _js_not(val: _J) -> _J:
    return _J("bool", not _js_truthy(val))


def _js_to_primitive(val: _J) -> _J:
    if val.kind == "arr":
        if not val.value:
            return _J("str", "")
        parts = [_js_to_string(item).value for item in val.value]
        return _J("str", ",".join(parts))
    if val.kind == "native":
        return _J("str", f"function {val.name}() {{ [native code] }}")
    if val.kind == "ctor":
        return _J("str", f"function {val.name}() {{ [native code] }}")
    return val


def _js_to_string(val: _J) -> _J:
    prim = _js_to_primitive(val)
    if prim.kind == "str":
        return prim
    if prim.kind == "bool":
        return _J("str", "true" if prim.value else "false")
    if prim.kind == "undef":
        return _J("str", "undefined")
    if prim.kind == "nan":
        return _J("str", "NaN")
    if prim.kind == "null":
        return _J("str", "null")
    if prim.kind == "inf":
        return _J("str", "Infinity" if prim.value >= 0 else "-Infinity")
    if prim.kind == "num":
        n = prim.value
        if isinstance(n, float) and n.is_integer():
            n = int(n)
        return _J("str", str(n))
    if prim.kind == "code":
        return _J("str", str(prim.value))
    return _J("str", "")


def _js_to_number(val: _J) -> _J:
    if val.kind == "num":
        return val
    if val.kind == "bool":
        return _J("num", 1 if val.value else 0)
    if val.kind in {"undef", "nan"}:
        return _J("nan")
    if val.kind == "null":
        return _J("num", 0)
    if val.kind == "inf":
        return val
    if val.kind == "arr":
        return _js_to_number(_js_to_primitive(val))
    if val.kind == "str":
        text = val.value.strip()
        if not text:
            return _J("num", 0)
        try:
            if "." in text or "e" in text.lower():
                return _J("num", float(text))
            return _J("num", int(text, 10))
        except ValueError:
            return _J("nan")
    prim = _js_to_primitive(val)
    if prim.kind != val.kind:
        return _js_to_number(prim)
    return _J("nan")


def _js_add(left: _J, right: _J) -> _J:
    lp = _js_to_primitive(left)
    rp = _js_to_primitive(right)
    if lp.kind == "str" or rp.kind == "str":
        return _J("str", _js_to_string(lp).value + _js_to_string(rp).value)
    ln = _js_to_number(lp)
    rn = _js_to_number(rp)
    if ln.kind == "nan" or rn.kind == "nan":
        return _J("nan")
    if ln.kind == "inf" or rn.kind == "inf":
        return _J("inf", 1)
    return _J("num", ln.value + rn.value)


def _js_index(obj: _J, index: _J) -> _J:
    key = _js_to_string(index).value
    if obj.kind == "arr":
        if key == "length":
            return _J("num", len(obj.value))
        if key == "constructor":
            return _J("ctor", name="Array")
        if key in _ARRAY_METHODS:
            return _J("native", name=key)
        if key.isdigit():
            idx = int(key)
            if 0 <= idx < len(obj.value):
                return obj.value[idx]
        return _J("undef")
    if obj.kind == "str":
        if key == "length":
            return _J("num", len(obj.value))
        if key == "constructor":
            return _J("ctor", name="String")
        if key == "toString":
            return _J("native", name="toString")
        if key.isdigit() or (key.startswith("-") and key[1:].isdigit()):
            idx = int(key)
            if 0 <= idx < len(obj.value):
                return _J("str", obj.value[idx])
        return _J("undef")
    if obj.kind == "bool":
        if key == "constructor":
            return _J("ctor", name="Boolean")
        return _J("undef")
    if obj.kind == "num":
        if key == "constructor":
            return _J("ctor", name="Number")
        return _J("undef")
    if obj.kind in {"native", "ctor"}:
        if key == "constructor":
            return _J("ctor", name="Function")
        if key == "toString":
            return _J("native", name="toString")
        return _J("undef")
    return _J("undef")


def _js_call(fn: _J, arg: _J | None) -> _J:
    if fn.kind == "ctor" and fn.name == "Function":
        code = _js_to_string(arg).value if arg is not None else ""
        return _J("code", code, is_program=True)
    if fn.kind == "code":
        return _J("code", fn.value, is_program=True)
    if fn.kind == "native" and fn.name == "toString":
        return _js_to_string(arg) if arg is not None else _J("str", "")
    if fn.kind == "ctor" and fn.name == "String":
        return _js_to_string(arg) if arg is not None else _J("str", "")
    if fn.kind == "ctor" and fn.name == "Number":
        return _js_to_number(arg) if arg is not None else _J("num", 0)
    if fn.kind == "ctor" and fn.name == "Boolean":
        return _J("bool", _js_truthy(arg) if arg is not None else False)
    if fn.kind == "ctor" and fn.name == "Array":
        return _J("arr", [arg] if arg is not None else [])
    return _J("undef")


_JJ_START = re.compile(r"""(?:^|[;\s])([$\w]+)\s*=\s*~\s*\[\s*\]""")


def unwrap_jjencode(source: str) -> tuple[str, list[str]]:
    """Best-effort static decode of Yosuke Hasegawa jjencode."""
    if not _looks_like_jjencode(source):
        return source, []
    decoded = _jjdecode(source)
    if not decoded or decoded == source:
        return source, []
    return decoded, ["Unpacked jjencode ($=~[] / constructor) encoding."]


def _looks_like_jjencode(source: str) -> bool:
    compact = re.sub(r"\s+", "", source)
    if "=~[]" not in compact and "=~ []" not in source:
        return False
    if "___:" not in compact and "$$$" not in compact:
        return False
    return True


def _jjdecode(source: str) -> str | None:
    """
    jjencode builds Function from $=~[] then evaluates a quoted payload.
    Recover the payload string after the constructor preamble.
    """
    # Common trailer: gv.$ ( gv.$ ( gv.$$ + "\"" + PAYLOAD + "\"" ) () ) ()
    # PAYLOAD is JS string content, often with octal/hex escapes.
    match = re.search(
        r"""\+["']["']\+["']((?:\\.|[^"'\\])*)["']["']\+["']["']""",
        source,
        re.S,
    )
    if not match:
        match = re.search(
            r"""\$\$\s*\+\s*["']\\?["']["']\s*\+\s*["']((?:\\.|[^"'\\])+?)["']\s*\+\s*["']\\?["']["']""",
            source,
            re.S,
        )
    if not match:
        match = re.search(
            r"""["']((?:\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\u[0-9a-fA-F]{4}|[^"'\\]){8,})["']""",
            source,
        )
    if not match:
        return None
    payload = unescape_js_string_body(match.group(1))
    if "function" in payload or "return" in payload or ";" in payload:
        return payload
    # Some encodings wrap return "..." 
    inner = re.match(r"""^return\s+["'](.*)["']\s*;?\s*$""", payload, re.S)
    if inner:
        return unescape_js_string_body(inner.group(1))
    if re.search(r"[A-Za-z_$][\w$]*\s*\(", payload):
        return payload
    return None


_HALT_RE = re.compile(r"__halt_compiler\s*\(\s*\)\s*;", re.I)


def unwrap_halt_compiler(source: str) -> tuple[str, list[str]]:
    match = _HALT_RE.search(source)
    if not match:
        return source, []
    prefix = source[: match.start()].rstrip()
    trailer = source[match.end() :]
    if not trailer.strip():
        return source, []
    from evilbox.decode import b64decode, bytes_to_text, gzip_zlib_or_inflate, hex_payload_to_text

    blob = trailer.strip()
    decoded = hex_payload_to_text(blob, min_bytes=8)
    if decoded is None:
        raw = b64decode(re.sub(r"\s+", "", blob))
        if raw is not None:
            inflated = gzip_zlib_or_inflate(raw)
            decoded = bytes_to_text(inflated if inflated is not None else raw)
    if decoded:
        joined = prefix + "\n" + decoded if prefix else decoded
        return joined, ["Extracted and decoded __halt_compiler() trailer."]
    joined = prefix + "\n" + trailer if prefix else trailer
    return joined, ["Extracted raw __halt_compiler() trailer."]


def unwrap_layout(source: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    text = source
    if re.search(r"\n{12,}", text):
        text = re.sub(r"\n{3,}", "\n\n", text)
        notes.append("Collapsed excessive blank lines.")
    if re.search(r"[^\S\n]{120,}", text):
        text = re.sub(r"[^\S\n]{120,}", " ", text)
        notes.append("Collapsed huge whitespace runs.")
    return text, notes


def unwrap_aaencode(source: str) -> tuple[str, list[str]]:
    if "ﾟωﾟ" not in source and "ﾟДﾟ" not in source and "aaencode" not in source.lower():
        return source, []
    decoded = _aadecode(source)
    if not decoded or decoded == source:
        return source, ["Detected AAEncode; character-table payload could not be fully recovered statically."]
    return decoded, ["Unpacked AAEncode emoticon encoding."]


def _aadecode(source: str) -> str | None:
    """Map AAEncode's 3-bit glyphs to octal character codes without a JS engine."""
    text = re.sub(r"/\*.*?\*/", "", source)
    digits = (
        (r"\(c\^_\^o\)", "0"),
        (r"\(ﾟΘﾟ\)", "1"),
        (r"\(\(o\^_\^o\)-\(ﾟΘﾟ\)\)", "2"),
        (r"\(o\^_\^o\)", "3"),
        (r"\(ﾟｰﾟ\)", "4"),
        (r"\(\(ﾟｰﾟ\)\+\(ﾟΘﾟ\)\)", "5"),
        (r"\(\(o\^_\^o\)\+\(o\^_\^o\)\)", "6"),
        (r"\(\(ﾟｰﾟ\)\+\(o\^_\^o\)\)", "7"),
    )
    for pat, digit in digits:
        text = re.sub(pat, digit, text)
    text = text.replace("+", "")
    chunks = re.findall(r"(\d{2,3})", text)
    if len(chunks) < 8:
        return None
    out: list[str] = []
    for chunk in chunks:
        try:
            code = int(chunk, 8)
        except ValueError:
            continue
        if 9 <= code <= 0x10FFFF:
            out.append(chr(code))
    payload = "".join(out)
    if len(payload) < 6:
        return None
    printable = sum(1 for ch in payload if ch.isprintable() or ch in "\n\r\t")
    if printable / len(payload) < 0.8:
        return None
    return payload
