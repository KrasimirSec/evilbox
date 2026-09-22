from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from evilbox.decode import (
    PHP_TRIM_DEFAULT,
    b64decode,
    bytes_to_text,
    bzip_bytes,
    expand_php_charlist,
    format_php_number,
    gzip_bytes,
    hex_decode,
    hex_payload_to_text,
    looks_like_php_source,
    parse_quoted_string,
    php_bitwise_not,
    php_quote,
    php_string_bytes,
    php_str_pad,
    php_strtolower,
    php_strtoupper,
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
from evilbox.rewrite import (
    apply_replacements,
    enclosing_function_id,
    inside_branch,
    inside_loop,
    node_text,
    reset_source_encoding,
    stmt_span,
    use_source_encoding,
    walk,
)

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


ScopeKey = tuple[int, str]


@dataclass
class FoldEnv:
    arrays: dict[ScopeKey, list[Value]] = field(default_factory=dict)
    keyed_arrays: dict[ScopeKey, dict[Any, Value]] = field(default_factory=dict)
    scalars: dict[ScopeKey, Value] = field(default_factory=dict)
    concat_rhs: dict[ScopeKey, object] = field(default_factory=dict)
    concat_extra: dict[ScopeKey, list] = field(default_factory=dict)
    history: dict[ScopeKey, list[tuple[int, Value | None, bool]]] = field(default_factory=dict)
    php_version: str = "8.3"
    path: str | None = None
    original: str | None = None
    warnings: list[str] = field(default_factory=list)

    def key(self, node, name: str) -> ScopeKey:
        return (enclosing_function_id(node), name)

    def drop(self, node, name: str) -> None:
        key = self.key(node, name)
        self.scalars.pop(key, None)
        self.arrays.pop(key, None)
        self.keyed_arrays.pop(key, None)
        self.concat_rhs.pop(key, None)
        self.concat_extra.pop(key, None)

    def record(self, node, name: str, value: Value | None, unsound: bool) -> None:
        key = self.key(node, name)
        self.history.setdefault(key, []).append((node.start_byte, value, unsound))

    def reaching(self, node, name: str) -> Value | None:
        key = self.key(node, name)
        pos = node.start_byte
        prior = [item for item in self.history.get(key, []) if item[0] < pos]
        if not prior:
            return None
        last = prior[-1]
        if last[2] or last[1] is None:
            return None
        return last[1]


def transform_php(
    source: str,
    *,
    php_version: str = "8.3",
    path: str | None = None,
    original: str | None = None,
) -> tuple[str, list[str]]:
    warnings: list[str] = []
    token = use_source_encoding(source)
    try:
        tree = parse_php(source)
        env = collect_env(tree, source)
        env.php_version = php_version
        env.path = path
        env.original = original if original is not None else source
        replacements: list[tuple[int, int, str]] = list(_concat_collapse_replacements(source, env, php_quote))
        replacements.extend(_xor_loop_replacements(tree, source, env))
        for node in walk(tree.root_node):
            rendered = _render_if_simplified(node, source, env)
            if rendered is None:
                continue
            original_text = node_text(source, node)
            if rendered != original_text:
                replacements.append((node.start_byte, node.end_byte, rendered))
        text = apply_replacements(source, replacements)
        text = _rename_junk(text)
        warnings.extend(env.warnings)
        return text, warnings
    finally:
        reset_source_encoding(token)


def collect_const_arrays(tree, source: str) -> dict[str, list[Value]]:
    env = collect_env(tree, source)
    return {name: items for (_scope, name), items in env.arrays.items()}


def collect_env(tree, source: str) -> FoldEnv:
    env = FoldEnv()
    tainted = _tainted_php_names(tree, source)
    nodes = [
        node
        for node in walk(tree.root_node)
        if node.type in {"assignment_expression", "augmented_assignment_expression"}
    ]
    nodes.sort(key=lambda node: node.start_byte)

    for node in nodes:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "variable_name":
            continue
        name = node_text(source, left).lstrip("$")
        key = env.key(left, name)
        unsound = "*" in tainted or key in tainted or inside_loop(node) or inside_branch(node)
        if node.type == "assignment_expression":
            if any((not child.is_named and child.type == "&") or child.type == "&" for child in node.children):
                unsound = True
            if unsound:
                env.record(node, name, None, True)
                env.drop(left, name)
                continue
            if right.type == "array_creation_expression":
                elems, keyed = _php_array_parts(right, source, env)
                value: Value | None = None
                if keyed and elems is None:
                    value = Value(keyed)
                    env.keyed_arrays[key] = keyed
                    env.arrays.pop(key, None)
                elif elems is not None:
                    value = Value(elems)
                    env.arrays[key] = elems
                    if keyed:
                        env.keyed_arrays[key] = keyed
                    else:
                        env.keyed_arrays.pop(key, None)
                env.record(node, name, value, False)
                env.scalars.pop(key, None)
                env.concat_rhs.pop(key, None)
                env.concat_extra.pop(key, None)
                continue
            item = const_eval(right, source, env)
            if item is not None and not item.splice_raw:
                env.record(node, name, item, False)
                env.scalars[key] = item
                env.concat_rhs[key] = right
                env.concat_extra[key] = []
            else:
                env.record(node, name, None, False if item is None else True)
                env.drop(left, name)
            continue
        op_node = node.child_by_field_name("operator")
        op = op_node.type if op_node is not None else node_text(source, node)
        if op != ".=" or unsound:
            env.record(node, name, None, True)
            env.drop(left, name)
            continue
        prev = env.reaching(node, name)
        item = const_eval(right, source, env)
        if (
            prev is not None
            and item is not None
            and isinstance(prev.py, str)
            and isinstance(item.py, (str, bytes, int, float))
            and not item.splice_raw
        ):
            combined = Value(prev.py + _as_php_string(item.py))
            env.record(node, name, combined, False)
            env.scalars[key] = combined
            env.concat_extra.setdefault(key, []).append(node)
        else:
            env.record(node, name, None, True)
            env.drop(left, name)
    return env


def _php_var_name(node, source: str) -> str | None:
    if node is None:
        return None
    if node.type == "variable_name":
        return node_text(source, node).lstrip("$")
    return None


def _ord_index_var(node, source: str) -> tuple[str, str, int | None] | None:
    """ord($data[$i]) or ord($key[$i % N]) → (array, index, modulo)."""
    if node.type != "function_call_expression":
        return None
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "name" or node_text(source, fn).lower() != "ord":
        return None
    args = _call_args(node)
    if len(args) != 1 or args[0].type != "subscript_expression":
        return None
    named = args[0].named_children
    if len(named) < 2:
        return None
    arr = _php_var_name(named[0], source)
    index_node = named[1]
    if arr is None:
        return None
    if index_node.type == "variable_name":
        return arr, node_text(source, index_node).lstrip("$"), None
    if index_node.type == "binary_expression" and _binary_op(index_node, source) == "%":
        left = index_node.child_by_field_name("left")
        right = index_node.child_by_field_name("right")
        if left is None or right is None:
            return None
        idx = _php_var_name(left, source)
        if idx is None:
            return None
        mod = None
        if right.type == "integer":
            try:
                mod = int(node_text(source, right), 0)
            except ValueError:
                return None
        elif right.type == "function_call_expression":
            rfn = right.child_by_field_name("function")
            if rfn is None or node_text(source, rfn).lower() != "strlen":
                return None
        return arr, idx, mod
    return None


def _parse_xor_for(node, source: str) -> tuple[str, str, str, int | None] | None:
    if node.type != "for_statement":
        return None
    cond = node.child_by_field_name("condition")
    body = node.child_by_field_name("body")
    if cond is None or body is None:
        return None
    count: int | None = None
    if cond.type == "binary_expression" and _binary_op(cond, source) in {"<", "<="}:
        right = cond.child_by_field_name("right")
        if right is not None and right.type == "integer":
            try:
                count = int(node_text(source, right), 0)
            except ValueError:
                count = None
    stmt = body
    if body.type == "compound_statement" and len(body.named_children) == 1:
        stmt = body.named_children[0]
    expr = stmt.named_children[0] if stmt.type == "expression_statement" and stmt.named_children else stmt
    if expr.type != "augmented_assignment_expression":
        return None
    op_node = expr.child_by_field_name("operator")
    op = op_node.type if op_node is not None else node_text(source, expr)
    if op != ".=":
        return None
    out_name = _php_var_name(expr.child_by_field_name("left"), source)
    right = expr.child_by_field_name("right")
    if out_name is None or right is None or right.type != "function_call_expression":
        return None
    rfn = right.child_by_field_name("function")
    if rfn is None or node_text(source, rfn).lower() != "chr":
        return None
    chr_args = _call_args(right)
    if len(chr_args) != 1 or chr_args[0].type != "binary_expression" or _binary_op(chr_args[0], source) != "^":
        return None
    xor = chr_args[0]
    left_ord = _ord_index_var(xor.child_by_field_name("left"), source)
    right_ord = _ord_index_var(xor.child_by_field_name("right"), source)
    if left_ord is None or right_ord is None:
        return None
    data_name, _, _ = left_ord
    key_name, _, _ = right_ord
    return data_name, key_name, out_name, count


def _peel_php_expr(node):
    expr = node
    if node is not None and node.type == "expression_statement" and node.named_children:
        expr = node.named_children[0]
    while expr is not None and expr.type in {
        "error_suppression_expression",
        "parenthesized_expression",
        "unary_op_expression",
        "unary_expression",
    }:
        inner = expr.child_by_field_name("body")
        if inner is None and expr.named_children:
            inner = expr.named_children[0]
        if inner is None:
            break
        expr = inner
    return expr


def _decoder_of_var(node, source: str, env: FoldEnv, out_name: str) -> str | None:
    expr = _peel_php_expr(node)
    arg = None
    if expr is None:
        return None
    if expr.type == "eval_expression":
        arg = expr.named_children[0] if expr.named_children else None
    elif expr.type == "function_call_expression":
        name = _call_name(expr, source, env)
        if name not in {"eval", "assert", "print", "echo"}:
            return None
        args = _call_args(expr)
        arg = args[0] if args else None
    elif expr.type in {"echo_statement", "print_intrinsic_expression", "print_expression"}:
        named = [child for child in expr.named_children if child.type != "echo"]
        arg = named[0] if named else None
    if arg is None:
        return None
    arg = _peel_php_expr(arg)
    if arg is None or arg.type != "function_call_expression":
        return None
    args = _call_args(arg)
    if len(args) != 1 or _php_var_name(args[0], source) != out_name:
        return None
    return _call_name(arg, source, env)


def _value_bytes(val: Value | None) -> bytes | None:
    if val is None:
        return None
    if isinstance(val.py, bytes):
        return val.py
    if isinstance(val.py, str):
        try:
            return php_string_bytes(val.py)
        except ValueError:
            return None
    return None


def _apply_known_decoder(name: str | None, data: bytes) -> bytes | None:
    if not name or not data:
        return None
    key = name.lstrip("\\").lower()
    if key == "gzinflate":
        return raw_inflate(data)
    if key == "gzuncompress":
        return zlib_bytes(data)
    if key == "gzdecode":
        return gzip_bytes(data)
    if key in {"bzdecompress", "bzinflate"}:
        return bzip_bytes(data)
    if key == "base64_decode":
        text = data.decode("latin-1")
        return b64decode(text)
    if key in {"hex2bin", "hex2ascii", "hextobin", "unhex"}:
        return hex_decode(data.decode("latin-1"))
    return None


def _xor_loop_replacements(tree, source: str, env: FoldEnv) -> list[tuple[int, int, str]]:
    """for ($i=0;$i<N;$i++) $out.=chr(ord($data[$i])^ord($key[$i%K])); eval($decoder($out));"""
    out: list[tuple[int, int, str]] = []
    for node in walk(tree.root_node):
        if node.type != "for_statement":
            continue
        parsed = _parse_xor_for(node, source)
        if parsed is None:
            continue
        data_name, key_name, out_name, count = parsed
        data = _value_bytes(env.reaching(node, data_name))
        key = _value_bytes(env.reaching(node, key_name))
        if data is None or key is None:
            continue
        if count is not None:
            data = data[:count]
        xored = xor_bytes(data, key)
        if xored is None:
            continue
        parent = node.parent
        if parent is None:
            continue
        siblings = list(parent.named_children)
        try:
            index = siblings.index(node)
        except ValueError:
            continue
        if index + 1 >= len(siblings):
            continue
        nxt = siblings[index + 1]
        decoder = _decoder_of_var(nxt, source, env, out_name)
        payload = _apply_known_decoder(decoder, xored)
        if payload is None:
            payload = xored
        try:
            text = payload.decode("latin-1")
        except Exception:
            continue
        if not looks_like_php_source(text) and "echo" not in text.lower():
            continue
        start = node.start_byte
        _, end = stmt_span(source, nxt)
        out.append((start, end, _strip_php_tags(text)))
        env.warnings.append(f"Unwrapped repeating-XOR loop ({decoder or 'bytes'}).")
    return out


def _tainted_php_names(tree, source: str) -> set[str | ScopeKey]:
    names: set[str | ScopeKey] = set()
    for node in walk(tree.root_node):
        t = node.type
        if t in {"global_declaration", "global_statement"}:
            for child in node.named_children:
                if child.type == "variable_name":
                    names.add((enclosing_function_id(child), node_text(source, child).lstrip("$")))
        if t == "foreach_statement":
            for child in node.named_children:
                if child.type == "variable_name":
                    names.add((enclosing_function_id(child), node_text(source, child).lstrip("$")))
        if t == "simple_parameter":
            raw = node_text(source, node)
            if "&" in raw:
                for child in node.named_children:
                    if child.type == "variable_name":
                        names.add((enclosing_function_id(child), node_text(source, child).lstrip("$")))
        if t == "function_call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "name":
                callee = node_text(source, fn).lstrip("\\").lower()
                if callee in {"extract", "compact", "parse_str", "mb_parse_str", "get_defined_vars"}:
                    return {"*"}
        if t == "dynamic_variable_name":
            names.add("*")
        if t == "assignment_expression":
            raw = node_text(source, node)
            if "=&" in raw.replace(" ", "") or " = &" in raw:
                left = node.child_by_field_name("left")
                if left is not None and left.type == "variable_name":
                    names.add((enclosing_function_id(left), node_text(source, left).lstrip("$")))
    if "*" in names:
        return {"*"}
    return names


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
        if node.type == "binary_expression" and _binary_op(node, source) == ".":
            parent = node.parent
            if parent is not None and parent.type == "binary_expression" and _binary_op(parent, source) == ".":
                return None
        val = const_eval(node, source, env)
        if val is None:
            return None
        text = _format_value(val)
        if text is None:
            return None
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


def _looks_printable_text(text: str) -> bool:
    if not text or "\0" in text[:200]:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text) >= 0.85


def _format_value(val: Value) -> str | None:
    if val.splice_raw and isinstance(val.py, str):
        return val.py
    if isinstance(val.py, bytes):
        text = val.py.decode("latin-1")
        if not val.splice_raw and not looks_like_php_source(text) and not _looks_printable_text(text):
            return None
        return php_quote(text)
    if isinstance(val.py, list):
        parts: list[str] = []
        for item in val.py:
            rendered = _format_value(item if isinstance(item, Value) else Value(item))
            if rendered is None:
                return None
            parts.append(rendered)
        return f"array({', '.join(parts)})"
    if isinstance(val.py, str):
        try:
            php_string_bytes(val.py)
        except ValueError:
            return php_quote(val.py)
        return php_quote(val.py)
    if isinstance(val.py, bool):
        return "true" if val.py else "false"
    if val.py is None:
        return "null"
    if isinstance(val.py, int):
        if val.py.bit_length() > 256:
            return None
        return format_php_number(val.py)
    if isinstance(val.py, float):
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
        return env.reaching(node, name)
    if t == "dynamic_variable_name" and env is not None:
        inner = next((c for c in node.named_children if c.type == "variable_name"), None)
        if inner is None:
            return None
        name = node_text(source, inner).lstrip("$")
        val = env.reaching(inner, name)
        if val is None or not isinstance(val.py, str):
            return None
        return env.reaching(inner, val.py)
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


def _binary_op(node, source: str) -> str | None:
    op_node = node.child_by_field_name("operator")
    if op_node is not None:
        return op_node.type
    for child in node.children:
        if not child.is_named:
            return child.type
    return None


def _eval_concat_chain(node, source: str, env: FoldEnv | None) -> Value | None:
    pieces = []
    cur = node
    while cur is not None and cur.type == "binary_expression" and _binary_op(cur, source) == ".":
        right = cur.child_by_field_name("right")
        left = cur.child_by_field_name("left")
        if right is None or left is None:
            return None
        pieces.append(right)
        cur = left
    pieces.append(cur)
    out: list[str] = []
    for part in reversed(pieces):
        val = const_eval(part, source, env)
        if val is None:
            return None
        out.append(_as_php_string(val.py))
    return Value("".join(out))


def _eval_binary(node, source: str, env: FoldEnv | None = None) -> Value | None:
    op = _binary_op(node, source)
    if op == ".":
        return _eval_concat_chain(node, source, env)
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
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
        if b < 0 or b >= 63 or a.bit_length() + (b if op == "<<" else 0) > 256:
            return None
        if op == "<<":
            return Value(a << b)
        return Value(a >> b)
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
                if isinstance(lv.py, int) and isinstance(rv.py, int):
                    if rv.py == 0:
                        return None
                    return Value(lv.py % rv.py)
                return Value(lv.py % rv.py)
        except Exception:
            return None
    return None


def _as_php_string(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    if value is True:
        return "1"
    if value is False or value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
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
        val = env.reaching(fn, node_text(source, fn).lstrip("$"))
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

    if name in {"hex2ascii", "hextobin", "unhex"} and values:
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

    if name == "strtr" and values:
        hay = as_str(values[0])
        if hay is None:
            return None
        if len(values) >= 2 and isinstance(values[1].py, (list, dict)):
            mapping = values[1].py
            if isinstance(mapping, list):
                return None
            out = hay
            items = list(mapping.items())
            items.sort(key=lambda kv: -len(str(kv[0])))
            for key, item in items:
                src = key if isinstance(key, str) else _as_php_string(key)
                dst = as_str(item if isinstance(item, Value) else Value(item))
                if dst is None:
                    return None
                out = out.replace(src, dst)
            return Value(out)
        if len(values) >= 3:
            frm = as_str(values[1])
            to = as_str(values[2])
            if frm is None or to is None:
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
        subject = as_str(values[2])
        if subject is None:
            return None

        def as_list(val: Value) -> list[str] | None:
            if isinstance(val.py, list):
                out: list[str] = []
                for item in val.py:
                    raw = as_str(item if isinstance(item, Value) else Value(item))
                    if raw is None:
                        return None
                    out.append(raw)
                return out
            raw = as_str(val)
            return None if raw is None else [raw]

        searches = as_list(values[0])
        repls = as_list(values[1])
        if searches is None or repls is None:
            return None
        out = subject
        flags = re.I if name == "str_ireplace" else 0
        for index, search in enumerate(searches):
            repl = repls[index] if index < len(repls) else repls[-1]
            if name == "str_ireplace":
                out = re.compile(re.escape(search), flags).sub(lambda _m, r=repl: r, out)
            else:
                out = out.replace(search, repl)
        return Value(out)

    if name == "substr" and len(values) >= 2 and isinstance(values[0].py, (str, bytes)) and _is_num(values[1].py):
        s = as_str(values[0])
        if s is None:
            return None
        length = int(values[2].py) if len(values) > 2 and _is_num(values[2].py) else None
        version = env.php_version if env is not None else "8.3"
        return Value(php_substr(s, int(values[1].py), length, php_version=version))

    if name in {"strtolower", "mb_strtolower"} and values:
        s = as_str(values[0])
        return Value(php_strtolower(s)) if s is not None else None
    if name in {"strtoupper", "mb_strtoupper"} and values:
        s = as_str(values[0])
        return Value(php_strtoupper(s)) if s is not None else None

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
        if re.search(r"%[0-9$.]*[xXeEfFgGbB]", fmt):
            return None
        try:
            args = []
            for v in values[1:]:
                if _is_num(v.py):
                    args.append(int(v.py) if isinstance(v.py, float) and float(v.py).is_integer() else v.py)
                else:
                    args.append(_as_php_string(v.py))
            # PHP %x is unsigned; keep width-free conversions that Python's % handles.
            return Value(fmt % tuple(args))
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
        chars = as_str(values[1]) if len(values) > 1 else PHP_TRIM_DEFAULT
        chars = expand_php_charlist(chars)
        if name == "trim":
            return Value(s.strip(chars))
        if name == "ltrim":
            return Value(s.lstrip(chars))
        return Value(s.rstrip(chars))

    if name == "str_pad" and len(values) >= 2 and _is_num(values[1].py):
        s = as_str(values[0])
        if s is None:
            return None
        pad = as_str(values[2]) if len(values) > 2 else " "
        style = int(values[3].py) if len(values) > 3 and _is_num(values[3].py) else 1
        out = php_str_pad(s, int(values[1].py), pad or " ", style)
        return Value(out) if out is not None else None

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
    if name == "hex2bin" and values:
        s = as_str(values[0])
        if s is None:
            return None
        data = hex_decode(s)
        return Value(data) if data is not None else None
    if name in {"hex2ascii", "hextobin", "unhex"} and values:
        s = as_str(values[0])
        if s is None:
            return None
        data = hex_decode(s)
        return Value(data) if data is not None else None
    if name == "urldecode" and values:
        s = as_str(values[0])
        return Value(php_urldecode(s)) if s is not None else None
    if name in {"strtoupper", "mb_strtoupper"} and values:
        s = as_str(values[0])
        return Value(php_strtoupper(s)) if s is not None else None
    if name in {"strtolower", "mb_strtolower"} and values:
        s = as_str(values[0])
        return Value(php_strtolower(s)) if s is not None else None
    if name == "gzuncompress" and values:
        data = values[0].py if isinstance(values[0].py, bytes) else None
        if data is None and isinstance(values[0].py, str):
            try:
                data = php_string_bytes(values[0].py)
            except ValueError:
                data = None
        if data is None:
            return None
        out = zlib_bytes(data)
        return Value(out) if out is not None else None
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
    return looks_like_php_source(text)


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
    reached = env.reaching(obj, name) if env is not None and name else None
    if isinstance(idx_val.py, str) and reached is not None and isinstance(reached.py, dict):
        item = reached.py.get(idx_val.py)
        return item if isinstance(item, Value) or item is None else Value(item)
    if not _is_num(idx_val.py):
        return None
    idx = int(idx_val.py)
    elems = None
    if reached is not None and isinstance(reached.py, list):
        elems = reached.py
    elif reached is not None and isinstance(reached.py, dict):
        item = reached.py.get(idx)
        if item is not None:
            return item if isinstance(item, Value) else Value(item)
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
            return raw.read_text(encoding="latin-1", errors="replace")
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
