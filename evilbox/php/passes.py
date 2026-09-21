from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from evilbox.decode import (
    b64decode,
    bytes_to_text,
    bzip_bytes,
    format_php_number,
    gzip_bytes,
    hex_decode,
    hex_payload_to_text,
    parse_quoted_string,
    php_bitwise_not,
    php_quote,
    php_string_bytes,
    php_substr,
    php_urldecode,
    quoted_printable_decode,
    raw_inflate,
    rc4_crypt,
    rot13,
    stripslashes,
    unescape_html_entities,
    unescape_js_string_body,
    uudecode_ex,
    xor_bytes,
    xor_strings,
    zlib_bytes,
)
from evilbox.parsers import parse_php
from evilbox.rewrite import apply_replacements, node_text, stmt_span, walk

PHP_JUNK_RE = re.compile(r"^_0x[0-9a-fA-F]+$")
PHP_HEX_VAR_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)
PHP_LOOKALIKE_RE = re.compile(r"^[O0Il]{4,}$")
PHP_UNDERSCORES_RE = re.compile(r"^_{2,}$")

PHP_SUPERGLOBALS = {
    "this",
    "GLOBALS",
    "_GET",
    "_POST",
    "_REQUEST",
    "_COOKIE",
    "_SERVER",
    "_FILES",
    "_ENV",
    "_SESSION",
}


@dataclass
class Value:
    py: Any
    splice_raw: bool = False


@dataclass
class FoldEnv:
    arrays: dict[str, list[Value]] = field(default_factory=dict)
    keyed_arrays: dict[str, dict[Any, Value]] = field(default_factory=dict)
    scalars: dict[str, Value] = field(default_factory=dict)
    concat_rhs: dict[str, object] = field(default_factory=dict)
    concat_extra: dict[str, list] = field(default_factory=dict)
    php_version: str = "8.3"
    path: str | None = None
    original: str | None = None
    warnings: list[str] = field(default_factory=list)


def transform_php(
    source: str,
    *,
    php_version: str = "8.3",
    path: str | None = None,
    original: str | None = None,
) -> tuple[str, list[str]]:
    warnings: list[str] = []
    tree = parse_php(source)
    env = collect_env(tree, source)
    env.php_version = php_version
    env.path = path
    env.original = original if original is not None else source
    replacements: list[tuple[int, int, str]] = list(_concat_collapse_replacements(source, env, php_quote))
    for node in walk(tree.root_node):
        rendered = _render_if_simplified(node, source, env)
        if rendered is None:
            continue
        original = node_text(source, node)
        if rendered != original:
            replacements.append((node.start_byte, node.end_byte, rendered))
    text = apply_replacements(source, replacements)
    text = _rename_junk(text)
    warnings.extend(env.warnings)
    return text, warnings


def collect_const_arrays(tree, source: str) -> dict[str, list[Value]]:
    return collect_env(tree, source).arrays


def collect_env(tree, source: str) -> FoldEnv:
    env = FoldEnv()
    for node in walk(tree.root_node):
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or left.type != "variable_name":
                continue
            name = node_text(source, left).lstrip("$")
            if right.type == "array_creation_expression":
                elems, keyed = _php_array_parts(right, source, env)
                if elems is not None:
                    env.arrays[name] = elems
                else:
                    env.arrays.pop(name, None)
                if keyed:
                    env.keyed_arrays[name] = keyed
                else:
                    env.keyed_arrays.pop(name, None)
                env.scalars.pop(name, None)
                env.concat_rhs.pop(name, None)
                env.concat_extra.pop(name, None)
                continue
            item = const_eval(right, source, env)
            if item is not None and not item.splice_raw:
                env.scalars[name] = item
                env.concat_rhs[name] = right
                env.concat_extra[name] = []
            else:
                env.scalars.pop(name, None)
                env.arrays.pop(name, None)
                env.concat_rhs.pop(name, None)
                env.concat_extra.pop(name, None)
            continue
        if node.type == "augmented_assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")
            op = op_node.type if op_node is not None else node_text(source, node)
            if left is None or right is None or left.type != "variable_name":
                continue
            name = node_text(source, left).lstrip("$")
            if op != ".=":
                env.scalars.pop(name, None)
                continue
            prev = env.scalars.get(name)
            item = const_eval(right, source, env)
            if (
                prev is not None
                and item is not None
                and isinstance(prev.py, str)
                and isinstance(item.py, (str, bytes, int, float))
                and not item.splice_raw
            ):
                env.scalars[name] = Value(prev.py + _as_php_string(item.py))
                env.concat_extra.setdefault(name, []).append(node)
            else:
                env.scalars.pop(name, None)
                env.concat_rhs.pop(name, None)
                env.concat_extra.pop(name, None)
    return env


def _concat_collapse_replacements(source: str, env: FoldEnv, quote_fn) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for name, extras in env.concat_extra.items():
        if not extras:
            continue
        val = env.scalars.get(name)
        if val is None or not isinstance(val.py, str):
            continue
        rhs = env.concat_rhs.get(name)
        if rhs is not None:
            out.append((rhs.start_byte, rhs.end_byte, quote_fn(val.py)))
        for extra in extras:
            start, end = stmt_span(source, extra)
            out.append((start, end, ""))
    return out


def _php_array_parts(
    node, source: str, env: FoldEnv | None
) -> tuple[list[Value] | None, dict[Any, Value] | None]:
    elems: list[Value] = []
    keyed: dict[Any, Value] = {}
    saw_list = False
    for el in node.named_children:
        if el.type != "array_element_initializer":
            continue
        named = [c for c in el.named_children]
        if len(named) == 2:
            key_v = const_eval(named[0], source, env)
            val_v = const_eval(named[1], source, env)
            if key_v is None or val_v is None:
                return None, None
            if not isinstance(key_v.py, (str, int)) or isinstance(key_v.py, bool):
                return None, None
            keyed[key_v.py] = val_v
            continue
        inner = named[0] if named else el
        item = const_eval(inner, source, env)
        if item is None:
            return None, None
        elems.append(item)
        saw_list = True
    list_out = elems if saw_list or not keyed else None
    return list_out, (keyed or None)


def _php_array_elements(node, source: str, env: FoldEnv | None) -> list[Value] | None:
    elems, _keyed = _php_array_parts(node, source, env)
    return elems


def _render_if_simplified(node, source: str, env: FoldEnv | None = None) -> str | None:
    if node.type == "string":
        return _simplified_string(node, source)
    if node.type in {
        "unary_op_expression",
        "unary_expression",
        "binary_expression",
        "encapsed_string",
        "parenthesized_expression",
        "function_call_expression",
        "eval_expression",
        "subscript_expression",
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
    }:
        val = const_eval(node, source, env)
        if val is None:
            return None
        text = _format_value(val)
        if val.splice_raw:
            text = _strip_php_tags(text)
        return text
    return None


def _strip_php_tags(code: str) -> str:
    stripped = code.strip()
    if stripped.startswith("?>"):
        stripped = stripped[2:].lstrip()
    if stripped.startswith("<?php"):
        stripped = stripped[5:]
    elif stripped.startswith("<?="):
        stripped = "echo " + stripped[3:]
    elif stripped.startswith("<?"):
        stripped = stripped[2:]
    if stripped.endswith("?>"):
        stripped = stripped[:-2]
    return stripped.strip()


def _simplified_string(node, source: str) -> str | None:
    raw = node_text(source, node)
    parsed = _php_string_value(node, source)
    if parsed is None:
        return None
    unescaped = unescape_html_entities(parsed)
    quoted = php_quote(unescaped)
    if quoted == raw:
        return None
    if unescaped == parsed and "\\" not in raw and "&#" not in raw:
        return None
    return quoted


def _php_string_value(node, source: str) -> str | None:
    raw = node_text(source, node)
    if raw.startswith("b'") or raw.startswith('b"'):
        raw = raw[1:]
    parsed = parse_quoted_string(raw)
    if parsed is not None:
        if raw.startswith('"'):
            return parsed
        return parsed
    contents = []
    for child in node.children:
        if child.type in {"string_content", "encapsed_string_content"}:
            contents.append(node_text(source, child))
    if contents:
        return "".join(contents)
    return None


def _format_value(val: Value) -> str:
    if val.splice_raw and isinstance(val.py, str):
        return val.py
    if isinstance(val.py, bytes):
        text = bytes_to_text(val.py)
        if text is None:
            return php_quote(val.py.decode("latin-1"))
        return php_quote(text)
    if isinstance(val.py, list):
        inner = ", ".join(
            _format_value(item if isinstance(item, Value) else Value(item)) for item in val.py
        )
        return f"array({inner})"
    if isinstance(val.py, str):
        return php_quote(val.py)
    if isinstance(val.py, bool):
        return "true" if val.py else "false"
    if val.py is None:
        return "null"
    if isinstance(val.py, (int, float)):
        return format_php_number(val.py)
    return php_quote(str(val.py))


def const_eval(node, source: str, env: FoldEnv | None = None) -> Value | None:
    t = node.type
    if t == "string":
        parsed = _php_string_value(node, source)
        if parsed is None:
            return None
        return Value(unescape_html_entities(parsed))
    if t in {"integer", "float"}:
        return _parse_php_number(node_text(source, node))
    if t == "name" and node_text(source, node).lower() in {"true", "false", "null"}:
        word = node_text(source, node).lower()
        if word == "true":
            return Value(True)
        if word == "false":
            return Value(False)
        return Value(None)
    if t in {"name", "magic_constant", "constant"}:
        raw = node_text(source, node)
        if raw in {"__FILE__", "__DIR__"} and env is not None and env.path:
            from pathlib import Path

            sample = Path(env.path)
            if raw == "__FILE__":
                return Value(str(sample))
            return Value(str(sample.parent))
    if t == "boolean":
        return Value(node_text(source, node).lower() == "true")
    if t == "null":
        return Value(None)
    if t == "variable_name" and env is not None:
        name = node_text(source, node).lstrip("$")
        if name in env.scalars:
            return env.scalars[name]
        return None
    if t == "dynamic_variable_name" and env is not None:
        inner = next((c for c in node.named_children if c.type == "variable_name"), None)
        if inner is None:
            return None
        name = node_text(source, inner).lstrip("$")
        val = env.scalars.get(name)
        if val is None or not isinstance(val.py, str):
            return None
        return env.scalars.get(val.py)
    if t == "array_creation_expression":
        elems, keyed = _php_array_parts(node, source, env)
        if keyed and elems is None:
            return Value(keyed)
        return Value(elems) if elems is not None else None
    if t == "parenthesized_expression":
        inner = node.named_children[0] if node.named_children else None
        return const_eval(inner, source, env) if inner is not None else None
    if t in {"unary_op_expression", "unary_expression"}:
        return _eval_unary(node, source, env)
    if t == "binary_expression":
        return _eval_binary(node, source, env)
    if t == "encapsed_string":
        parts: list[str] = []
        for child in node.named_children:
            if child.type in {"string_content", "encapsed_string_content"}:
                parts.append(node_text(source, child))
            elif child.type == "escape_sequence":
                parts.append(unescape_js_string_body(node_text(source, child)))
            else:
                val = const_eval(child, source, env)
                if val is None or not isinstance(val.py, (str, int, float)) or isinstance(val.py, bool):
                    if val is not None and isinstance(val.py, str):
                        parts.append(val.py)
                    else:
                        return None
                else:
                    parts.append(str(val.py))
        if parts:
            return Value("".join(parts))
        raw = node_text(source, node)
        parsed = parse_quoted_string(raw)
        return Value(parsed) if parsed is not None else None
    if t == "argument":
        inner = node.named_children[0] if node.named_children else None
        return const_eval(inner, source, env) if inner is not None else None
    if t == "function_call_expression":
        return _eval_call(node, source, env)
    if t == "eval_expression":
        return _eval_eval(node, source, env)
    if t == "subscript_expression":
        return _eval_subscript(node, source, env)
    if t in {
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
    }:
        return _eval_include(node, source, env)
    return None


def _parse_php_number(text: str) -> Value | None:
    text = text.replace("_", "").strip()
    try:
        if text.lower().startswith("0x"):
            return Value(int(text, 16))
        if "." in text or "e" in text.lower():
            return Value(float(text))
        if text.startswith("0") and len(text) > 1 and text[1] not in "xX.":
            try:
                return Value(int(text, 8))
            except ValueError:
                pass
        return Value(int(text, 10))
    except ValueError:
        try:
            return Value(float(text))
        except ValueError:
            return None


def _eval_unary(node, source: str, env: FoldEnv | None = None) -> Value | None:
    op = None
    arg = None
    for child in node.children:
        if not child.is_named and child.type in {"!", "+", "-", "~"}:
            op = child.type
        elif child.is_named:
            arg = child
    if arg is None and node.named_children:
        arg = node.named_children[0]
        text = node_text(source, node).strip()
        if text.startswith("!"):
            op = "!"
        elif text.startswith("-"):
            op = "-"
        elif text.startswith("+"):
            op = "+"
        elif text.startswith("~"):
            op = "~"
    if arg is None or op is None:
        return None
    val = const_eval(arg, source, env)
    if val is None:
        return None
    if op == "!":
        return Value(not bool(val.py))
    if op in {"+", "-"} and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(val.py if op == "+" else -val.py)
    if op == "~":
        if isinstance(val.py, str):
            try:
                return Value(php_bitwise_not(val.py))
            except ValueError:
                return None
        if isinstance(val.py, bytes):
            return Value(bytes((~b) & 0xFF for b in val.py))
        if _is_num(val.py):
            return Value(~int(val.py))
    return None


def _eval_binary(node, source: str, env: FoldEnv | None = None) -> Value | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    op_node = node.child_by_field_name("operator")
    op = op_node.type if op_node is not None else None
    if op is None:
        for child in node.children:
            if not child.is_named:
                op = child.type
                break
    if left is None or right is None or op is None:
        return None
    lv = const_eval(left, source, env)
    rv = const_eval(right, source, env)
    if lv is None or rv is None:
        return None
    if op == "^" and isinstance(lv.py, str) and isinstance(rv.py, str):
        try:
            return Value(xor_strings(lv.py, rv.py))
        except ValueError:
            return None
    if op == "^" and _is_num(lv.py) and _is_num(rv.py):
        return Value(int(lv.py) ^ int(rv.py))
    if op in {"&", "|", "<<", ">>"} and _is_num(lv.py) and _is_num(rv.py):
        a, b = int(lv.py), int(rv.py)
        if op == "&":
            return Value(a & b)
        if op == "|":
            return Value(a | b)
        if op == "<<":
            return Value(a << b)
        return Value(a >> b)
    if op == ".":
        return Value(_as_php_string(lv.py) + _as_php_string(rv.py))
    if op in {"+", "-", "*", "/", "%"} and _is_num(lv.py) and _is_num(rv.py):
        try:
            if op == "+":
                return Value(lv.py + rv.py)
            if op == "-":
                return Value(lv.py - rv.py)
            if op == "*":
                return Value(lv.py * rv.py)
            if op == "/":
                if rv.py == 0:
                    return None
                result = lv.py / rv.py
                if isinstance(lv.py, int) and isinstance(rv.py, int) and lv.py % rv.py == 0:
                    return Value(lv.py // rv.py)
                return Value(result)
            if op == "%":
                return Value(lv.py % rv.py)
        except Exception:
            return None
    return None


def _as_php_string(value: Any) -> str:
    if isinstance(value, bytes):
        return bytes_to_text(value) or value.decode("latin-1")
    if value is True:
        return "1"
    if value is False or value is None:
        return ""
    return str(value)


def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _call_name(node, source: str, env: FoldEnv | None = None) -> str | None:
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    if fn is None:
        return None
    if fn.type == "variable_name":
        if env is None:
            return None
        val = env.scalars.get(node_text(source, fn).lstrip("$"))
        if val is not None and isinstance(val.py, str):
            return val.py.lstrip("\\").lower()
        return None
    if fn.type == "subscript_expression":
        item = _eval_subscript(fn, source, env)
        if item is not None and isinstance(item.py, str) and item.py:
            return item.py.lstrip("\\").lower()
        return None
    if fn.type == "name":
        return node_text(source, fn).lstrip("\\").lower()
    val = const_eval(fn, source, env)
    if val is not None and isinstance(val.py, str) and val.py:
        return val.py.lstrip("\\").lower()
    return node_text(source, fn).lstrip("\\").lower()


def _call_args(node):
    args = node.child_by_field_name("arguments")
    if args is None:
        for child in node.children:
            if child.type in {"arguments", "argument_list"}:
                args = child
                break
    if args is None:
        return []
    out = []
    for child in args.named_children:
        if child.type == "argument" and child.named_children:
            out.append(child.named_children[0])
        else:
            out.append(child)
    return out


def _eval_call(node, source: str, env: FoldEnv | None = None) -> Value | None:
    name = _call_name(node, source, env)
    if not name:
        return None
    args = _call_args(node)
    values: list[Value] = []
    for arg in args:
        val = const_eval(arg, source, env)
        if val is None:
            return None
        values.append(val)

    def as_bytes(val: Value) -> bytes | None:
        if isinstance(val.py, bytes):
            return val.py
        if isinstance(val.py, str):
            try:
                return php_string_bytes(val.py)
            except ValueError:
                return None
        return None

    def as_str(val: Value) -> str | None:
        if isinstance(val.py, str):
            return val.py
        if isinstance(val.py, bytes):
            return bytes_to_text(val.py) or val.py.decode("latin-1")
        return None

    if name in {"call_user_func", "register_shutdown_function", "register_tick_function"} and values:
        cb = as_str(values[0])
        if not cb:
            return None
        name = cb.lstrip("\\").lower()
        values = values[1:]
    elif name == "call_user_func_array" and len(values) >= 2:
        cb = as_str(values[0])
        items = values[1].py if isinstance(values[1].py, list) else None
        if not cb or items is None:
            return None
        name = cb.lstrip("\\").lower()
        values = [item if isinstance(item, Value) else Value(item) for item in items]
    elif name == "ob_start" and values:
        cb = as_str(values[0])
        if cb:
            name = cb.lstrip("\\").lower()
            values = values[1:]

    if name == "base64_decode" and values:
        raw = as_str(values[0])
        if raw is None:
            return None
        data = b64decode(raw)
        return Value(data) if data is not None else None

    if name == "gzinflate" and values:
        data = as_bytes(values[0])
        if data is None:
            return None
        out = raw_inflate(data)
        return Value(out) if out is not None else None

    if name == "gzuncompress" and values:
        data = as_bytes(values[0])
        if data is None:
            return None
        out = zlib_bytes(data)
        return Value(out) if out is not None else None

    if name == "gzdecode" and values:
        data = as_bytes(values[0])
        if data is None:
            return None
        out = gzip_bytes(data)
        return Value(out) if out is not None else None

    if name in {"bzdecompress", "bzinflate"} and values:
        data = as_bytes(values[0])
        if data is None:
            return None
        out = bzip_bytes(data)
        return Value(out) if out is not None else None

    if name == "str_rot13" and values:
        s = as_str(values[0])
        return Value(rot13(s)) if s is not None else None

    if name == "hex2bin" and values:
        s = as_str(values[0])
        if s is None:
            return None
        data = hex_decode(s)
        return Value(data) if data is not None else None

    if name == "hexdec" and values:
        s = as_str(values[0]) if not _is_num(values[0].py) else None
        if _is_num(values[0].py):
            return Value(int(values[0].py))
        if s is None:
            return None
        try:
            return Value(int(s, 16))
        except ValueError:
            return None

    if name == "pack" and len(values) >= 2:
        fmt = as_str(values[0])
        payload = as_str(values[1])
        if fmt is None or payload is None:
            return None
        if fmt.replace("'", "") in {"H*", "H"}:
            data = hex_decode(payload)
            return Value(data) if data is not None else None

    if name == "unpack" and len(values) >= 2:
        fmt = as_str(values[0])
        data = as_bytes(values[1])
        if fmt is None or data is None:
            return None
        kind = fmt.replace("'", "").rstrip("0123456789*")
        if kind in {"H", "h"}:
            return Value(data.hex())
        if kind == "a":
            text = bytes_to_text(data)
            return Value(text if text is not None else data.decode("latin-1"))

    if name == "chr" and values and _is_num(values[0].py):
        return Value(chr(int(values[0].py) & 0xFF))

    if name == "strtr" and len(values) >= 3:
        hay = as_str(values[0])
        frm = as_str(values[1])
        to = as_str(values[2])
        if hay is None or frm is None or to is None:
            return None
        table = str.maketrans(frm[: len(to)], to[: len(frm)])
        return Value(hay.translate(table))

    if name == "str_repeat" and len(values) >= 2:
        s = as_str(values[0])
        if s is None or not _is_num(values[1].py):
            return None
        n = int(values[1].py)
        if n < 0 or n > 1_000_000 or len(s) * n > 2_000_000:
            return None
        return Value(s * n)

    if name == "strrev" and values:
        s = as_str(values[0])
        return Value(s[::-1]) if s is not None else None

    if name == "urldecode" and values:
        s = as_str(values[0])
        return Value(php_urldecode(s)) if s is not None else None

    if name == "rawurldecode" and values:
        s = as_str(values[0])
        if s is None:
            return None
        from evilbox.decode import percent_decode

        decoded = percent_decode(s)
        return Value(decoded if decoded is not None else s)

    if name in {"str_replace", "str_ireplace"} and len(values) >= 3:
        search = as_str(values[0])
        repl = as_str(values[1])
        subject = as_str(values[2])
        if search is None or repl is None or subject is None:
            return None
        if name == "str_ireplace":
            pattern = re.compile(re.escape(search), re.I)
            return Value(pattern.sub(lambda _m: repl, subject))
        return Value(subject.replace(search, repl))

    if name == "substr" and len(values) >= 2 and isinstance(values[0].py, (str, bytes)) and _is_num(values[1].py):
        s = as_str(values[0])
        if s is None:
            return None
        length = int(values[2].py) if len(values) > 2 and _is_num(values[2].py) else None
        version = env.php_version if env is not None else "8.3"
        return Value(php_substr(s, int(values[1].py), length, php_version=version))

    if name in {"strtolower", "mb_strtolower"} and values:
        s = as_str(values[0])
        return Value(s.lower()) if s is not None else None
    if name in {"strtoupper", "mb_strtoupper"} and values:
        s = as_str(values[0])
        return Value(s.upper()) if s is not None else None

    if name in {"implode", "join"} and values:
        glue = ""
        pieces: list[Any] | None = None
        first = values[0].py
        if isinstance(first, list):
            pieces = first
            if len(values) > 1:
                glue = as_str(values[1]) or ""
        elif len(values) >= 2 and isinstance(values[1].py, list):
            glue = as_str(values[0]) or ""
            pieces = values[1].py
        if pieces is None:
            return None
        parts = [_as_php_string(p.py if isinstance(p, Value) else p) for p in pieces]
        return Value(glue.join(parts))

    if name == "sprintf" and values:
        fmt = as_str(values[0])
        if fmt is None or "%$" in fmt or "*" in fmt:
            return None
        try:
            args = tuple(_as_php_string(v.py) if not _is_num(v.py) else v.py for v in values[1:])
            return Value(fmt % args)
        except Exception:
            return None

    if name in {"html_entity_decode", "htmlspecialchars_decode"} and values:
        s = as_str(values[0])
        return Value(unescape_html_entities(s)) if s is not None else None

    if name == "stripslashes" and values:
        s = as_str(values[0])
        return Value(stripslashes(s)) if s is not None else None

    if name == "quoted_printable_decode" and values:
        s = as_str(values[0])
        if s is None:
            return None
        out = quoted_printable_decode(s)
        return Value(out) if out is not None else None

    if name == "convert_uudecode" and values:
        s = as_str(values[0])
        if s is None:
            return None
        decoded = uudecode_ex(s)
        if decoded is None:
            return None
        if decoded.recovered and env is not None:
            env.warnings.append("convert_uudecode used line padding; output marked recovered")
        return Value(decoded.data)

    if name == "ord" and values:
        s = as_str(values[0])
        if not s:
            return None
        return Value(ord(s[0]))

    if name in {"intval", "int"} and values:
        s = as_str(values[0]) if not _is_num(values[0].py) else None
        if _is_num(values[0].py):
            return Value(int(values[0].py))
        if s is None:
            return None
        try:
            return Value(int(s, 10))
        except ValueError:
            return None

    if name in {"trim", "ltrim", "rtrim"} and values:
        s = as_str(values[0])
        if s is None:
            return None
        chars = as_str(values[1]) if len(values) > 1 else None
        if name == "trim":
            return Value(s.strip() if chars is None else s.strip(chars))
        if name == "ltrim":
            return Value(s.lstrip() if chars is None else s.lstrip(chars))
        return Value(s.rstrip() if chars is None else s.rstrip(chars))

    if name == "str_pad" and len(values) >= 2 and _is_num(values[1].py):
        s = as_str(values[0])
        if s is None:
            return None
        width = int(values[1].py)
        if width < 0 or width > 1_000_000:
            return None
        pad = as_str(values[2]) if len(values) > 2 else " "
        pad = pad or " "
        return Value(s.ljust(width, pad[0]))

    if name == "bin2hex" and values:
        data = as_bytes(values[0])
        return Value(data.hex()) if data is not None else None

    if name in {"xor", "str_xor"} and len(values) >= 2:
        data = as_bytes(values[0])
        key = as_bytes(values[1])
        if data is None or key is None:
            return None
        out = xor_bytes(data, key)
        return Value(out) if out is not None else None

    if name in {"rc4", "rc4crypt"} and len(values) >= 2:
        data = as_bytes(values[0])
        key = as_bytes(values[1])
        if data is None or key is None:
            return None
        out = rc4_crypt(data, key)
        return Value(out) if out is not None else None

    if name in {"eval", "assert"} and values:
        s = as_str(values[0])
        if s is None:
            return None
        return Value(s, splice_raw=True)

    if name == "create_function" and len(values) >= 2:
        body = as_str(values[1])
        if body is None:
            return None
        return Value(body, splice_raw=True)

    if name == "preg_replace" and len(values) >= 2:
        pattern = as_str(values[0])
        replacement = as_str(values[1])
        if pattern and replacement and _preg_eval_modifier(pattern):
            return Value(replacement, splice_raw=True)

    if name == "array_map" and len(values) >= 2:
        cb = (as_str(values[0]) or "").lstrip("\\").lower()
        items = values[1].py if isinstance(values[1].py, list) else None
        if cb and items is not None:
            mapped: list[Value] = []
            for item in items:
                applied = _eval_named(cb, [item if isinstance(item, Value) else Value(item)], source, env)
                if applied is None:
                    mapped = []
                    break
                mapped.append(applied)
            if mapped:
                return Value(mapped)

    if name in {"array_filter", "array_walk", "usort", "uasort", "uksort"} and len(values) >= 2:
        cb = (as_str(values[1]) or "").lstrip("\\").lower()
        items = values[0].py if isinstance(values[0].py, list) else None
        if cb in {"assert", "eval"} and items:
            for item in items:
                raw = as_str(item if isinstance(item, Value) else Value(item))
                if raw:
                    return Value(raw, splice_raw=True)

    if name in {"file_get_contents", "readfile"} and values:
        target = as_str(values[0])
        if target:
            data = _read_local_file(target, env)
            if data is not None:
                return Value(data)

    if name == "dirname" and values:
        s = as_str(values[0])
        if s:
            from pathlib import Path

            return Value(str(Path(s).parent))

    return None


def _eval_named(name: str, values: list[Value], source: str, env: FoldEnv | None) -> Value | None:
    """Apply a known decoder by name to already-evaluated arguments."""
    def as_str(val: Value) -> str | None:
        if isinstance(val.py, str):
            return val.py
        if isinstance(val.py, bytes):
            return bytes_to_text(val.py) or val.py.decode("latin-1")
        return None

    if name == "base64_decode" and values:
        raw = as_str(values[0])
        if raw is None:
            return None
        data = b64decode(raw)
        return Value(data) if data is not None else None
    if name == "str_rot13" and values:
        s = as_str(values[0])
        return Value(rot13(s)) if s is not None else None
    if name == "strrev" and values:
        s = as_str(values[0])
        return Value(s[::-1]) if s is not None else None
    if name == "gzinflate" and values:
        data = values[0].py if isinstance(values[0].py, bytes) else None
        if data is None and isinstance(values[0].py, str):
            try:
                data = php_string_bytes(values[0].py)
            except ValueError:
                data = None
        if data is None:
            return None
        out = raw_inflate(data)
        return Value(out) if out is not None else None
    if name in {"urldecode"} and values:
        s = as_str(values[0])
        return Value(php_urldecode(s)) if s is not None else None
    if name == "stripslashes" and values:
        s = as_str(values[0])
        return Value(stripslashes(s)) if s is not None else None
    if name in {"eval", "assert"} and values:
        s = as_str(values[0])
        if s is None:
            return None
        return Value(s, splice_raw=True)
    return None


def _preg_eval_modifier(pattern: str) -> bool:
    if len(pattern) < 3:
        return False
    delim = pattern[0]
    end = pattern.rfind(delim)
    if end <= 0:
        return False
    return "e" in pattern[end + 1 :].lower()


def _looks_like_php_source(text: str) -> bool:
    sample = text.lstrip()
    if sample.startswith("<?"):
        return True
    lowered = text.lower()
    return any(token in lowered for token in ("$_get", "$_post", "$_cookie", "eval(", "function ", "system("))


def _eval_include(node, source: str, env: FoldEnv | None) -> Value | None:
    inner = node.named_children[0] if node.named_children else None
    if inner is None:
        return None
    val = const_eval(inner, source, env)
    if val is None:
        return None
    text = val.py
    if isinstance(text, bytes):
        text = bytes_to_text(text) or text.decode("latin-1")
    if not isinstance(text, str) or not _looks_like_php_source(text):
        return None
    return Value(text, splice_raw=True)


def _eval_subscript(node, source: str, env: FoldEnv | None) -> Value | None:
    named = node.named_children
    if len(named) < 2:
        return None
    obj, index = named[0], named[1]
    idx_val = const_eval(index, source, env)
    if idx_val is None:
        return None
    name = node_text(source, obj).lstrip("$") if obj.type == "variable_name" else None
    if isinstance(idx_val.py, str) and env is not None and name:
        keyed = env.keyed_arrays.get(name) or {}
        item = keyed.get(idx_val.py)
        return item
    if not _is_num(idx_val.py):
        return None
    idx = int(idx_val.py)
    elems = None
    if obj.type == "variable_name" and env is not None:
        elems = env.arrays.get(name or "")
        if elems is None:
            keyed = env.keyed_arrays.get(name or "") or {}
            item = keyed.get(idx)
            if item is not None:
                return item
    elif obj.type == "array_creation_expression":
        elems = _php_array_elements(obj, source, env)
    if elems is None or idx < 0 or idx >= len(elems):
        return None
    return elems[idx]


def _read_local_file(target: str, env: FoldEnv | None) -> str | None:
    if env is None:
        return None
    from pathlib import Path

    if env.path:
        sample = Path(env.path).resolve()
        raw = Path(target)
        if str(raw) == str(sample) or target.replace("\\", "/") == str(sample).replace("\\", "/"):
            return env.original
        try:
            if not raw.is_absolute():
                raw = (sample.parent / target).resolve()
            raw.relative_to(sample.parent)
        except (OSError, ValueError):
            return None
        if raw.is_file() and raw.stat().st_size <= 2 * 1024 * 1024:
            return raw.read_text(encoding="utf-8", errors="replace")
    return None


def _eval_eval(node, source: str, env: FoldEnv | None = None) -> Value | None:
    inner = node.named_children[0] if node.named_children else None
    if inner is None:
        return None
    val = const_eval(inner, source, env)
    if val is None:
        return None
    if isinstance(val.py, bytes):
        text = bytes_to_text(val.py)
        if text is None:
            return None
        return Value(text, splice_raw=True)
    if isinstance(val.py, str):
        decoded = hex_payload_to_text(val.py, min_bytes=8)
        if decoded:
            return Value(decoded, splice_raw=True)
        return Value(val.py, splice_raw=True)
    return None


def _rename_junk(source: str) -> str:
    tree = parse_php(source)
    mapping: dict[str, str] = {}
    order = 0
    replacements: list[tuple[int, int, str]] = []
    for node in walk(tree.root_node):
        if node.type != "variable_name":
            continue
        raw = node_text(source, node)
        name = raw[1:] if raw.startswith("$") else raw
        if name in PHP_SUPERGLOBALS:
            continue
        if not (
            PHP_JUNK_RE.match(name)
            or PHP_HEX_VAR_RE.match(name)
            or PHP_LOOKALIKE_RE.match(name)
            or PHP_UNDERSCORES_RE.match(name)
            or any(ord(ch) > 127 for ch in name)
        ):
            continue
        if name not in mapping:
            mapping[name] = f"v{order}"
            order += 1
        replacements.append((node.start_byte, node.end_byte, "$" + mapping[name]))
    return apply_replacements(source, replacements)
