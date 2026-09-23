from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from evilbox.decode import (
    b64decode,
    bytes_to_text,
    format_js_number,
    hex_payload_to_text,
    js_quote,
    js_unescape,
    parse_js_quoted_string,
    percent_decode,
    rc4_crypt,
    unescape_html_entities,
    unescape_js_string_body,
)
from evilbox.js.structure import simplify_js_structure
from evilbox.parsers import parse_js
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

JS_JUNK_RE = re.compile(r"^_0x[0-9a-fA-F]+$")
JS_HEX_NAME_RE = re.compile(r"^_?[a-f0-9]{6,}$", re.I)
JS_LOOKALIKE_RE = re.compile(r"^[O0Il]{4,}$")

JS_RESERVED = {
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "let",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
    "enum",
    "await",
    "arguments",
    "eval",
    "undefined",
    "NaN",
    "Infinity",
    "console",
    "window",
    "document",
    "String",
    "Number",
    "Array",
    "Object",
    "Math",
    "JSON",
    "Function",
    "Boolean",
    "RegExp",
    "Date",
    "Error",
    "parseInt",
    "parseFloat",
    "isNaN",
    "atob",
    "btoa",
    "unescape",
    "escape",
    "decodeURIComponent",
    "encodeURIComponent",
    "decodeURI",
    "encodeURI",
}


@dataclass
class Value:
    py: Any
    splice_raw: bool = False


@dataclass
class DecoderInfo:
    array: str
    offset: int
    encoding: str = "none"


ScopeKey = tuple[int, str]


@dataclass
class FoldEnv:
    arrays: dict[ScopeKey, list[Value]] = field(default_factory=dict)
    named_arrays: dict[str, list[Value]] = field(default_factory=dict)
    scalars: dict[ScopeKey, Value] = field(default_factory=dict)
    decoders: dict[str, DecoderInfo] = field(default_factory=dict)
    concat_rhs: dict[ScopeKey, object] = field(default_factory=dict)
    concat_extra: dict[ScopeKey, list] = field(default_factory=dict)

    def key(self, node, name: str) -> ScopeKey:
        return (enclosing_function_id(node), name)

    def has_named_array(self, name: str) -> bool:
        if name in self.named_arrays:
            return True
        return any(key[1] == name for key in self.arrays)

    def array_by_name(self, name: str) -> list[Value] | None:
        if name in self.named_arrays:
            return self.named_arrays[name]
        for key, items in self.arrays.items():
            if key[1] == name:
                return items
        return None


KNOWN_GLOBALS = {
    "eval",
    "atob",
    "btoa",
    "unescape",
    "escape",
    "decodeURIComponent",
    "encodeURIComponent",
    "decodeURI",
    "encodeURI",
    "parseInt",
    "parseFloat",
    "Number",
    "String",
    "Boolean",
    "Function",
}


def transform_js(source: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    token = use_source_encoding(source)
    try:
        for _ in range(6):
            folded, fold_warnings = _fold_js(source)
            structured, struct_warnings = simplify_js_structure(folded)
            warnings.extend(fold_warnings)
            warnings.extend(struct_warnings)
            if structured == source:
                break
            source = structured
        deduped: list[str] = []
        for warning in warnings:
            if warning not in deduped:
                deduped.append(warning)
        return source, deduped
    finally:
        reset_source_encoding(token)


def _fold_js(source: str) -> tuple[str, list[str]]:
    tree = parse_js(source)
    env = collect_env(tree, source)
    replacements: list[tuple[int, int, str]] = list(_concat_collapse_replacements(source, env, js_quote))
    for node in walk(tree.root_node):
        rendered = _render_if_simplified(node, source, env)
        if rendered is None:
            continue
        original = node_text(source, node)
        if rendered != original:
            replacements.append((node.start_byte, node.end_byte, rendered))
    text = apply_replacements(source, replacements)
    text = _rename_junk(text)
    return text, []


def collect_const_arrays(tree, source: str) -> dict[str, list[Value]]:
    """Map `var name = [literals...]` so later `name[i]` can be folded."""
    env = collect_env(tree, source)
    out = dict(env.named_arrays)
    for (_scope, name), items in env.arrays.items():
        out.setdefault(name, items)
    return out


def collect_env(tree, source: str) -> FoldEnv:
    env = FoldEnv()
    assign_count: dict[ScopeKey, int] = {}
    for node in walk(tree.root_node):
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                name = node_text(source, name_node)
                key = env.key(name_node, name)
                assign_count[key] = assign_count.get(key, 0) + 1
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                name = node_text(source, left)
                key = env.key(left, name)
                assign_count[key] = assign_count.get(key, 0) + 1

    for node in walk(tree.root_node):
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or value is None or name_node.type != "identifier":
            continue
        name = node_text(source, name_node)
        key = env.key(name_node, name)
        if assign_count.get(key, 0) != 1:
            continue
        if inside_loop(node) or inside_branch(node):
            continue
        if value.type == "array":
            elems: list[Value] = []
            ok = True
            for el in value.named_children:
                item = _array_element(el, source)
                if item is None:
                    ok = False
                    break
                elems.append(item)
            if ok:
                env.arrays[key] = elems
            continue
        if value.type == "identifier" and node_text(source, value) in KNOWN_GLOBALS:
            env.scalars[key] = Value(node_text(source, value), splice_raw=True)
            continue
        item = const_eval(value, source, env)
        if item is not None and not item.splice_raw:
            env.scalars[key] = item
            env.concat_rhs[key] = value
            env.concat_extra[key] = []

    for node in walk(tree.root_node):
        if node.type != "augmented_assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op_node = node.child_by_field_name("operator")
        op = op_node.type if op_node is not None else ""
        if left is None or right is None or left.type != "identifier" or op != "+=":
            continue
        name = node_text(source, left)
        key = env.key(left, name)
        if inside_loop(node) or inside_branch(node) or assign_count.get(key, 0) != 1:
            env.scalars.pop(key, None)
            env.concat_rhs.pop(key, None)
            env.concat_extra.pop(key, None)
            continue
        prev = env.scalars.get(key)
        item = const_eval(right, source, env)
        if prev is not None and item is not None and isinstance(prev.py, str) and isinstance(item.py, str):
            env.scalars[key] = Value(prev.py + item.py)
            env.concat_extra.setdefault(key, []).append(node)
        elif key in env.scalars and (item is None or not isinstance(item.py, str)):
            env.scalars.pop(key, None)

    _collect_array_functions(tree, source, env)
    _rotate_string_arrays(tree, source, env)
    _collect_array_decoders(tree, source, env)
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


def _rotate_string_arrays(tree, source: str, env: FoldEnv) -> None:
    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = _call_args(node)
        if fn is None or len(args) < 2:
            continue
        inner = fn
        if inner.type == "parenthesized_expression" and inner.named_children:
            inner = inner.named_children[0]
        if inner.type not in {"function_expression", "arrow_function"}:
            continue
        if args[0].type != "identifier":
            continue
        arr_name = node_text(source, args[0])
        items = env.named_arrays.get(arr_name)
        if items is None:
            items = env.arrays.get(env.key(args[0], arr_name))
        if items is None:
            continue
        count_val = const_eval(args[1], source, env)
        if count_val is None or not _is_num(count_val.py):
            continue
        n = int(count_val.py)
        body = node_text(source, inner)
        if "push" not in body or "shift" not in body:
            continue
        if re.search(r"\+\+\s*[A-Za-z_$]", body) and re.search(r"while\s*\(\s*--", body):
            rot = n
        elif re.search(r"while\s*\(\s*--", body):
            rot = max(0, n - 1)
        elif re.search(r"while\s*\(\s*[A-Za-z_$][\w$]*\s*--", body):
            rot = n
        else:
            rot = n
        items = items
        if not items:
            continue
        rot %= len(items)
        if rot:
            rotated = items[rot:] + items[:rot]
            if arr_name in env.named_arrays:
                env.named_arrays[arr_name] = rotated
            else:
                env.arrays[env.key(args[0], arr_name)] = rotated


def _collect_array_functions(tree, source: str, env: FoldEnv) -> None:
    """javascript-obfuscator wraps the string table in `function name() { var a = [...]; ... }`."""
    for node in walk(tree.root_node):
        if node.type != "function_declaration":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = node_text(source, name_node)
        if name in env.named_arrays:
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        best: list[Value] | None = None
        for inner in walk(body):
            if inner.type != "array":
                continue
            elems: list[Value] = []
            ok = True
            for el in inner.named_children:
                item = _array_element(el, source)
                if item is None or item.splice_raw or not isinstance(item.py, str):
                    ok = False
                    break
                elems.append(item)
            if ok and elems and (best is None or len(elems) > len(best)):
                best = elems
        if best:
            env.named_arrays[name] = best


def _collect_array_decoders(tree, source: str, env: FoldEnv) -> None:
    for node in walk(tree.root_node):
        if node.type not in {"function_declaration", "function_expression", "arrow_function"}:
            continue
        name = None
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = node_text(source, name_node)
        text = node_text(source, node)
        params = _function_param_names(node, source)
        match = re.search(
            r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\b[^)]*\)\s*\{.{0,800}?"
            r"(?:(?:\2\s*=\s*\2\s*-\s*(0x[0-9a-fA-F]+|\d+).{0,400})?"
            r"return\s+([A-Za-z_$][\w$]*)\s*\[\s*\2(?:\s*-\s*(0x[0-9a-fA-F]+|\d+))?\s*\])",
            text,
            re.S | re.I,
        )
        if not match:
            match = re.search(
                r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\b[^)]*\)\s*\{.{0,800}?"
                r"\2\s*=\s*\2\s*-\s*(0x[0-9a-fA-F]+|\d+).{0,400}?"
                r"return\s+([A-Za-z_$][\w$]*)\[",
                text,
                re.S | re.I,
            )
        func = name or (match.group(1) if match else None)
        arr = match.group(4) if match and match.lastindex and match.lastindex >= 4 else None
        offset_txt = "0"
        if match:
            offset_txt = match.group(3) or (match.group(5) if match.lastindex and match.lastindex >= 5 else "0")
        if not arr:
            found = re.findall(r"return\s+([A-Za-z_$][\w$]*)\s*\[", text)
            arr = next((n for n in found if env.has_named_array(n)), None)
        if not arr:
            found = re.findall(
                r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\(\s*\)",
                text,
            )
            for local, callee in found:
                if env.has_named_array(callee):
                    arr = callee
                    break
                if env.has_named_array(local):
                    arr = local
                    break
        if not arr:
            found = re.findall(r"([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\[", text)
            arr = next((n for n in found if env.has_named_array(n)), None)
        if not arr:
            found = re.findall(r"return\s+([A-Za-z_$][\w$]*)\s*[;\n}]", text)
            for cand in found:
                if env.has_named_array(cand):
                    arr = cand
                    break
            if not arr:
                indexed = re.findall(
                    r"([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*(?:\([^)]*\))?\s*\[",
                    text,
                )
                for _local, callee in indexed:
                    if env.has_named_array(callee):
                        arr = callee
                        break
        if not func or not arr:
            continue
        if not env.has_named_array(arr):
            alias = re.search(
                r"(?:var|let|const)\s+" + re.escape(arr) + r"\s*=\s*([A-Za-z_$][\w$]*)\s*\(\s*\)",
                text,
            )
            if alias and env.has_named_array(alias.group(1)):
                arr = alias.group(1)
        if not env.has_named_array(arr):
            continue
        try:
            offset = int(offset_txt, 0) if offset_txt else 0
        except ValueError:
            offset = 0
        if offset == 0:
            off_match = re.search(r"=\s*[A-Za-z_$][\w$]*\s*-\s*(0x[0-9a-fA-F]+|\d+)", text)
            if off_match:
                offset = int(off_match.group(1), 0)
        encoding = _decoder_encoding(text, len(params))
        env.decoders[func] = DecoderInfo(arr, offset, encoding)


def _function_param_names(node, source: str) -> list[str]:
    params = node.child_by_field_name("parameters")
    if params is None:
        for child in node.children:
            if child.type in {"formal_parameters", "parameters"}:
                params = child
                break
    if params is None:
        return []
    names: list[str] = []
    for child in params.named_children:
        if child.type == "identifier":
            names.append(node_text(source, child))
        elif child.type == "required_parameter" and child.named_children:
            inner = child.named_children[0]
            if inner.type == "identifier":
                names.append(node_text(source, inner))
    return names


def _decoder_encoding(text: str, param_count: int) -> str:
    has_b64 = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=" in text
        or re.search(r"\batob\b", text) is not None
    )
    compact = re.sub(r"\s+", "", text)
    has_rc4 = "charCodeAt" in text and ("%256" in compact or "% 256" in text) and param_count >= 2
    has_hex = (
        re.search(r"parseInt\s*\([^,]+,\s*16\s*\)", text) is not None
        or re.search(r"fromCharCode\s*\(\s*parseInt", text) is not None
    )
    if has_rc4:
        return "rc4"
    if has_b64:
        return "base64"
    if has_hex:
        return "hex"
    return "none"


def _jo_decode_base64(text: str) -> str | None:
    data = b64decode(text)
    if data is None:
        return None
    return bytes_to_text(data)


def _jo_decode_rc4(text: str, key: str) -> str | None:
    data = b64decode(text)
    if data is None:
        return None
    out = rc4_crypt(data, key.encode("latin-1"))
    if out is None:
        return None
    decoded = bytes_to_text(out)
    if decoded is not None:
        return decoded
    # javascript-obfuscator sometimes URI-decodes the ciphertext before RC4.
    as_text = bytes_to_text(data)
    if as_text is None:
        return None
    uri = percent_decode(as_text) or as_text
    out = rc4_crypt(uri.encode("latin-1"), key.encode("latin-1"))
    if out is None:
        return None
    return bytes_to_text(out)


def _array_element(node, source: str) -> Value | None:
    if node.type == "identifier":
        return Value(node_text(source, node), splice_raw=True)
    if node.type == "spread_element":
        return None
    return const_eval(node, source, env=None)


def _parens_are_syntax(node) -> bool:
    """`if` / `while` / `switch` / `for` need the parentheses even when the test is constant."""
    parent = node.parent
    return parent is not None and parent.type in {
        "if_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
        "for_statement",
    }


def _render_if_simplified(node, source: str, env: FoldEnv | None = None) -> str | None:
    if node.type == "parenthesized_expression" and _parens_are_syntax(node):
        return None
    if node.type in {"string", "string_fragment"}:
        if node.type == "string":
            return _simplified_string(node, source)
        return None
    if node.type in {
        "unary_expression",
        "binary_expression",
        "parenthesized_expression",
        "call_expression",
        "subscript_expression",
        "new_expression",
        "template_string",
    }:
        if node.type == "binary_expression" and _binary_op(node) == "+":
            parent = node.parent
            if parent is not None and parent.type == "binary_expression" and _binary_op(parent) == "+":
                return None
        val = const_eval(node, source, env)
        if val is None:
            return None
        if node.type == "unary_expression" and val.splice_raw:
            return None
        return _format_value(val)
    return None


def _simplified_string(node, source: str) -> str | None:
    raw = node_text(source, node)
    parsed = parse_js_quoted_string(raw)
    if parsed is None:
        return None
    unescaped = unescape_html_entities(parsed)
    quoted = js_quote(unescaped)
    if quoted == raw:
        return None
    # Only rewrite if we actually expanded escapes / entities
    if unescaped == parsed and "\\" not in raw and "&#" not in raw:
        return None
    return quoted


def _format_value(val: Value) -> str:
    if val.splice_raw and isinstance(val.py, str):
        return val.py
    if isinstance(val.py, list):
        parts = [_format_value(item if isinstance(item, Value) else Value(item)) for item in val.py]
        return "[" + ", ".join(parts) + "]"
    if isinstance(val.py, str):
        return js_quote(val.py)
    if isinstance(val.py, bool):
        return "true" if val.py else "false"
    if val.py is None:
        return "null"
    if isinstance(val.py, (int, float)):
        return format_js_number(val.py)
    return js_quote(str(val.py))


def const_eval(node, source: str, env: FoldEnv | None = None) -> Value | None:
    t = node.type
    if t == "string":
        parsed = parse_js_quoted_string(node_text(source, node))
        if parsed is None:
            return None
        return Value(unescape_html_entities(parsed))
    if t == "template_string":
        return _eval_template(node, source, env)
    if t == "number":
        return _parse_js_number(node_text(source, node))
    if t == "true":
        return Value(True)
    if t == "false":
        return Value(False)
    if t == "null":
        return Value(None)
    if t == "identifier" and env is not None:
        name = node_text(source, node)
        return env.scalars.get(env.key(node, name))
    if t == "parenthesized_expression":
        inner = node.named_children[0] if node.named_children else None
        return const_eval(inner, source, env) if inner is not None else None
    if t == "unary_expression":
        return _eval_unary(node, source, env)
    if t == "binary_expression":
        return _eval_binary(node, source, env)
    if t == "call_expression":
        return _eval_call(node, source, env)
    if t == "new_expression":
        return _eval_new(node, source, env)
    if t == "subscript_expression":
        return _eval_subscript(node, source, env)
    if t == "array":
        elems: list[Value] = []
        for el in node.named_children:
            item = _array_element(el, source)
            if item is None:
                return None
            elems.append(item)
        return Value(elems)
    if t == "arguments":
        return None
    return None


def _eval_template(node, source: str, env: FoldEnv | None) -> Value | None:
    parts: list[str] = []
    for child in node.children:
        if child.type == "`":
            continue
        if child.type == "template_substitution":
            inner = child.named_children[0] if child.named_children else None
            if inner is None:
                return None
            val = const_eval(inner, source, env)
            if val is None or val.splice_raw:
                return None
            if isinstance(val.py, bool):
                parts.append("true" if val.py else "false")
            elif val.py is None:
                parts.append("null")
            else:
                parts.append(str(val.py))
            continue
        raw = node_text(source, child)
        if child.type in {"string_fragment", "escape_sequence"}:
            parts.append(unescape_js_string_body(raw))
        elif raw not in {"`", "${", "}"}:
            parts.append(unescape_js_string_body(raw))
    return Value("".join(parts))


def _eval_subscript(node, source: str, env: FoldEnv | None) -> Value | None:
    obj = node.child_by_field_name("object")
    index = node.child_by_field_name("index")
    if obj is None or index is None:
        return None
    idx_val = const_eval(index, source, env)
    if idx_val is None:
        return None
    if isinstance(idx_val.py, str):
        recv = const_eval(obj, source, env)
        if recv is not None and isinstance(recv.py, str) and idx_val.py == "length":
            return Value(len(recv.py))
        return None
    if not isinstance(idx_val.py, int) or isinstance(idx_val.py, bool):
        return None
    idx = idx_val.py
    elems: list[Value] | None = None
    if obj.type == "array":
        elems = []
        for el in obj.named_children:
            item = _array_element(el, source)
            if item is None:
                return None
            elems.append(item)
    elif obj.type == "identifier" and env is not None:
        name = node_text(source, obj)
        elems = env.arrays.get(env.key(obj, name))
        if elems is None:
            elems = env.array_by_name(name)
    if elems is not None:
        if idx < 0 or idx >= len(elems):
            return None
        return elems[idx]
    recv = const_eval(obj, source, env)
    if recv is not None and isinstance(recv.py, str):
        if idx < 0:
            idx += len(recv.py)
        if 0 <= idx < len(recv.py):
            return Value(recv.py[idx])
    if recv is not None and isinstance(recv.py, list):
        if 0 <= idx < len(recv.py):
            item = recv.py[idx]
            return item if isinstance(item, Value) else Value(item)
    return None


def _parse_js_number(text: str) -> Value | None:
    text = text.replace("_", "").strip()
    try:
        if text.lower().startswith("0x"):
            return Value(int(text, 16))
        if text.lower().startswith("0b"):
            return Value(int(text, 2))
        if text.lower().startswith("0o"):
            return Value(int(text, 8))
        if "." in text or "e" in text.lower():
            return Value(float(text))
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
        if not child.is_named and child.type in {"!", "+", "-", "~", "typeof", "void"}:
            op = child.type
        elif child.is_named:
            arg = child
    if op is None or arg is None:
        text = node_text(source, node).strip()
        if text.startswith("!") or text.startswith("+") or text.startswith("-"):
            op = text[0]
            if node.named_children:
                arg = node.named_children[0]
    if arg is None:
        return None
    val = const_eval(arg, source, env)
    if val is None:
        return None
    if op == "!":
        return Value(not _js_truthy(val.py))
    if op == "+" and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(+val.py)
    if op == "-" and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(-val.py)
    if op == "~" and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(~int(val.py))
    return None


def _binary_op(node) -> str | None:
    op_node = node.child_by_field_name("operator")
    if op_node is not None:
        return op_node.type
    for child in node.children:
        if not child.is_named:
            return child.type
    return None


def _eval_js_concat_chain(node, source: str, env: FoldEnv | None) -> Value | None:
    pieces = []
    cur = node
    while cur is not None and cur.type == "binary_expression" and _binary_op(cur) == "+":
        right = cur.child_by_field_name("right")
        left = cur.child_by_field_name("left")
        if right is None or left is None:
            return None
        pieces.append(right)
        cur = left
    pieces.append(cur)
    values = []
    for part in reversed(pieces):
        val = const_eval(part, source, env)
        if val is None or val.splice_raw:
            return None
        values.append(val)
    if all(isinstance(v.py, str) for v in values):
        return Value("".join(v.py for v in values))
    acc = values[0]
    for nxt in values[1:]:
        if isinstance(acc.py, str) or isinstance(nxt.py, str):
            acc = Value(str(acc.py) + str(nxt.py))
        elif _is_num(acc.py) and _is_num(nxt.py):
            acc = Value(acc.py + nxt.py)
        else:
            return None
    return acc


def _eval_binary(node, source: str, env: FoldEnv | None = None) -> Value | None:
    op = _binary_op(node)
    if op == "+":
        return _eval_js_concat_chain(node, source, env)
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or op is None:
        return None
    lv = const_eval(left, source, env)
    rv = const_eval(right, source, env)
    if lv is None or rv is None or lv.splice_raw or rv.splice_raw:
        return None
    if op in {"^", "&", "|", "<<", ">>", ">>>"} and _is_num(lv.py) and _is_num(rv.py):
        a, b = int(lv.py), int(rv.py)
        if op == "^":
            return Value(a ^ b)
        if op == "&":
            return Value(a & b)
        if op == "|":
            return Value(a | b)
        if op == "<<":
            return Value(a << (b & 31))
        if op == ">>>":
            return Value((a & 0xFFFFFFFF) >> (b & 31))
        return Value(a >> (b & 31))
    if op in {"-", "*", "/", "%"} and _is_num(lv.py) and _is_num(rv.py):
        try:
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


def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and not (isinstance(value, float) and math.isnan(value))


def _js_truthy(value: Any) -> bool:
    """JavaScript ToBoolean, including empty arrays (objects are truthy)."""
    if value is None or value is False:
        return False
    if value is True:
        return True
    if isinstance(value, float) and math.isnan(value):
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value != ""
    return True


def _call_args(node):
    args = node.child_by_field_name("arguments")
    if args is None:
        for child in node.children:
            if child.type == "arguments":
                args = child
                break
    if args is None:
        return []
    return [c for c in args.named_children]


def _callee(node, source: str, env: FoldEnv | None) -> tuple[str | None, str | None, Value | None]:
    """Return (object_name, property_name, receiver_value)."""
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    if fn is None:
        return None, None, None
    if fn.type == "identifier":
        name = node_text(source, fn)
        alias = env.scalars.get(env.key(fn, name)) if env is not None else None
        if alias is not None and isinstance(alias.py, str):
            if alias.splice_raw or alias.py in KNOWN_GLOBALS or name in env.decoders or alias.py in env.decoders:
                return str(alias.py), None, None
        return name, None, None
    if fn.type in {"parenthesized_expression", "binary_expression", "string", "template_string"}:
        val = const_eval(fn, source, env)
        if val is not None and isinstance(val.py, str):
            return val.py, None, None
        return None, None, None
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        if obj is None or prop is None:
            return None, None, None
        prop_name = node_text(source, prop)
        recv = const_eval(obj, source, env)
        obj_name = node_text(source, obj) if obj.type == "identifier" else None
        if obj.type == "member_expression":
            obj_name = node_text(source, obj)
        return obj_name, prop_name, recv
    if fn.type == "subscript_expression":
        obj = fn.child_by_field_name("object")
        index = fn.child_by_field_name("index")
        if obj is None or index is None:
            return None, None, None
        idx = const_eval(index, source, env)
        if idx is None or not isinstance(idx.py, str):
            return None, None, None
        recv = const_eval(obj, source, env)
        obj_name = node_text(source, obj) if obj.type == "identifier" else None
        return obj_name, idx.py, recv
    return None, None, None


def _from_char_code(values: list[Value]) -> Value | None:
    chars: list[str] = []
    for val in values:
        if isinstance(val.py, list):
            inner = _from_char_code([item if isinstance(item, Value) else Value(item) for item in val.py])
            if inner is None:
                return None
            chars.append(inner.py)
            continue
        if not _is_num(val.py):
            return None
        chars.append(chr(int(val.py) & 0xFFFF))
    return Value("".join(chars))


def _js_int(value: Any, radix: int | None = None) -> int | None:
    if _is_num(value):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            if radix:
                return int(text, radix)
            return int(text, 0) if text[:2].lower() in {"0x", "0o", "0b"} else int(text, 10)
        except ValueError:
            try:
                return int(float(text))
            except ValueError:
                return None
    return None


def _decode_array_item(item: Value, encoding: str, values: list[Value]) -> Value | None:
    if encoding == "none" or not isinstance(item.py, str):
        return item
    text = item.py
    if encoding == "base64":
        decoded = _jo_decode_base64(text)
        return Value(decoded) if decoded is not None else item
    if encoding == "rc4":
        key = values[1].py if len(values) > 1 and isinstance(values[1].py, str) else None
        if key is None:
            return None
        decoded = _jo_decode_rc4(text, key)
        return Value(decoded) if decoded is not None else item
    if encoding == "hex":
        decoded = hex_payload_to_text(text, min_bytes=1)
        return Value(decoded) if decoded is not None else item
    return item


def _eval_new(node, source: str, env: FoldEnv | None = None) -> Value | None:
    ctor = node.child_by_field_name("constructor")
    if ctor is None and node.named_children:
        ctor = node.named_children[0]
    if ctor is None:
        return None
    name = node_text(source, ctor) if ctor.type == "identifier" else None
    if name == "Function":
        args = _call_args(node)
        values = [const_eval(arg, source, env) for arg in args]
        if any(v is None or not isinstance(v.py, str) for v in values) or not values:
            return None
        return Value(values[-1].py, splice_raw=True)
    return None


def _eval_call(node, source: str, env: FoldEnv | None = None) -> Value | None:
    args = _call_args(node)
    values: list[Value] = []
    for arg in args:
        val = const_eval(arg, source, env)
        if val is None:
            return None
        values.append(val)

    obj, prop, recv = _callee(node, source, env)

    if env is not None and obj is not None and prop is None and obj in env.decoders:
        info = env.decoders[obj]
        items = env.array_by_name(info.array) or []
        raw_idx = values[0].py if values else None
        idx = _js_int(raw_idx)
        if idx is None:
            return None
        idx -= info.offset
        if 0 <= idx < len(items):
            item = items[idx]
            return _decode_array_item(item, info.encoding, values)
        return None

    if obj == "eval" and prop is None:
        if values and isinstance(values[0].py, str):
            text = values[0].py
            decoded = hex_payload_to_text(text, min_bytes=8)
            return Value(decoded or text, splice_raw=True)
        return None
    if obj == "eval" and prop == "call" and len(values) >= 2 and isinstance(values[1].py, str):
        return Value(values[1].py, splice_raw=True)
    if obj in {"window", "globalThis", "self", "this"} and prop == "eval":
        if values and isinstance(values[0].py, str):
            return Value(values[0].py, splice_raw=True)
        return None
    if obj in {"setTimeout", "setInterval"} and prop is None and values and isinstance(values[0].py, str):
        return Value(values[0].py, splice_raw=True)
    if obj in {"window", "globalThis", "self"} and prop in {"setTimeout", "setInterval"}:
        if values and isinstance(values[0].py, str):
            return Value(values[0].py, splice_raw=True)

    if (obj == "atob" and prop is None) or (
        obj in {"window", "globalThis", "self", "this"} and prop == "atob"
    ):
        s = values[0].py if values and isinstance(values[0].py, str) else None
        if s is None:
            return None
        data = b64decode(s)
        if data is None:
            return None
        text = bytes_to_text(data)
        return Value(text) if text is not None else None

    if obj == "unescape" and prop is None:
        s = values[0].py if values and isinstance(values[0].py, str) else None
        if s is None:
            return None
        return Value(js_unescape(s))
    if obj in {"decodeURIComponent", "decodeURI"} and prop is None:
        s = values[0].py if values and isinstance(values[0].py, str) else None
        if s is None:
            return None
        decoded = percent_decode(s)
        return Value(decoded if decoded is not None else s)

    if obj == "Buffer" and prop == "from" and values:
        raw = values[0].py
        enc = values[1].py.lower() if len(values) > 1 and isinstance(values[1].py, str) else "utf8"
        if enc == "hex" and isinstance(raw, str):
            decoded = hex_payload_to_text(raw, min_bytes=1)
            return Value(decoded) if decoded is not None else None
        if isinstance(raw, str):
            return Value(raw)
        if isinstance(raw, list):
            return _from_char_code([x if isinstance(x, Value) else Value(x) for x in raw])

    if obj == "Function" and prop is None:
        if values and isinstance(values[-1].py, str):
            return Value(values[-1].py, splice_raw=True)
        return None

    if obj == "parseInt" and prop is None and values:
        radix = _js_int(values[1].py) if len(values) > 1 else None
        parsed = _js_int(values[0].py, radix)
        return Value(parsed) if parsed is not None else None
    if obj == "Number" and prop is None and values:
        parsed = _js_int(values[0].py)
        if parsed is not None:
            return Value(parsed)
        if isinstance(values[0].py, str):
            try:
                return Value(float(values[0].py))
            except ValueError:
                return None
        return None
    if obj == "String" and prop is None and values:
        py = values[0].py
        if isinstance(py, bool):
            return Value("true" if py else "false")
        if py is None:
            return Value("null")
        return Value(str(py))

    from_cc = (
        (obj == "String" and prop == "fromCharCode")
        or (obj == "fromCharCode" and prop is None)
        or (isinstance(obj, str) and obj.endswith("fromCharCode") and prop == "apply")
        or (obj == "String" and prop == "fromCharCode")
    )
    if obj == "String" and prop == "fromCharCode":
        return _from_char_code(values)
    if obj is not None and obj.endswith(".fromCharCode") and prop == "apply":
        seq = values[1:] if values else []
        flat: list[Value] = []
        for item in seq:
            if isinstance(item.py, list):
                flat.extend(x if isinstance(x, Value) else Value(x) for x in item.py)
            else:
                flat.append(item)
        return _from_char_code(flat)
    if from_cc and prop is None:
        return _from_char_code(values)

    if recv is not None:
        methoded = _eval_method(recv, prop or "", values)
        if methoded is not None:
            return methoded
    _ = from_cc
    return None


def _eval_method(recv: Value, prop: str, values: list[Value]) -> Value | None:
    name = prop
    py = recv.py
    if isinstance(py, str):
        if name == "charAt" and values and _is_num(values[0].py):
            i = int(values[0].py)
            return Value(py[i] if 0 <= i < len(py) else "")
        if name == "charCodeAt" and values and _is_num(values[0].py):
            i = int(values[0].py)
            if 0 <= i < len(py):
                return Value(ord(py[i]))
            return None
        if name == "concat":
            out = py
            for val in values:
                if isinstance(val.py, (str, int, float)) and not isinstance(val.py, bool):
                    out += str(val.py)
                elif isinstance(val.py, str):
                    out += val.py
                else:
                    return None
            return Value(out)
        if name in {"slice", "substring", "substr"}:
            if not values or not _is_num(values[0].py):
                return None
            start = int(values[0].py)
            end = int(values[1].py) if len(values) > 1 and _is_num(values[1].py) else None
            if name == "substr":
                if start < 0:
                    start = max(len(py) + start, 0)
                length = end
                return Value(py[start:] if length is None else py[start : start + length])
            return Value(py[start:end])
        if name == "split":
            sep = values[0].py if values and isinstance(values[0].py, str) else None
            if sep is None:
                return None
            if len(py) > 500_000:
                return None
            parts = list(py) if sep == "" else py.split(sep)
            return Value([Value(p) for p in parts])
        if name == "replace" and len(values) >= 2 and isinstance(values[0].py, str) and isinstance(values[1].py, str):
            return Value(py.replace(values[0].py, values[1].py, 1))
        if name == "replaceAll" and len(values) >= 2 and isinstance(values[0].py, str) and isinstance(values[1].py, str):
            return Value(py.replace(values[0].py, values[1].py))
        if name == "toLowerCase":
            return Value(py.lower())
        if name == "toUpperCase":
            return Value(py.upper())
        if name == "toString":
            return Value(py)
        if name == "indexOf" and values and isinstance(values[0].py, str):
            return Value(py.find(values[0].py))
        if name == "repeat" and values and _is_num(values[0].py):
            n = int(values[0].py)
            if n < 0 or n * len(py) > 2_000_000:
                return None
            return Value(py * n)
    if isinstance(py, list):
        items = [x.py if isinstance(x, Value) else x for x in py]
        if name == "join":
            sep = values[0].py if values and isinstance(values[0].py, str) else ","
            return Value(sep.join("" if v is None else str(v) for v in items))
        if name == "reverse":
            return Value(list(reversed(py)))
        if name == "concat":
            out = list(py)
            for val in values:
                if isinstance(val.py, list):
                    out.extend(val.py)
                else:
                    out.append(val)
            return Value(out)
        if name == "slice" and values and _is_num(values[0].py):
            start = int(values[0].py)
            end = int(values[1].py) if len(values) > 1 and _is_num(values[1].py) else None
            return Value(py[start:end])
    if _is_num(py) and name == "toString":
        radix = int(values[0].py) if values and _is_num(values[0].py) else 10
        if radix < 2 or radix > 36:
            return None
        n = int(py)
        if radix == 10:
            return Value(str(n))
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        if n == 0:
            return Value("0")
        sign = "-" if n < 0 else ""
        n = abs(n)
        out = []
        while n:
            n, rem = divmod(n, radix)
            out.append(chars[rem])
        return Value(sign + "".join(reversed(out)))
    return None


def _rename_junk(source: str) -> str:
    tree = parse_js(source)
    mapping: dict[str, str] = {}
    order = 0
    replacements: list[tuple[int, int, str]] = []
    for node in walk(tree.root_node):
        if node.type not in {"identifier", "property_identifier", "shorthand_property_identifier"}:
            continue
        name = node_text(source, node)
        if name in JS_RESERVED:
            continue
        if not (
            JS_JUNK_RE.match(name)
            or (JS_HEX_NAME_RE.match(name) and name.lower().startswith("_0x"))
            or JS_LOOKALIKE_RE.match(name)
            or any(ord(ch) > 127 for ch in name)
        ):
            continue
        if name not in mapping:
            mapping[name] = f"v{order}"
            order += 1
        replacements.append((node.start_byte, node.end_byte, mapping[name]))
    return apply_replacements(source, replacements)
