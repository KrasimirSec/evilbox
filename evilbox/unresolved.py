"""Scan a layer for decoder folds that did not simplify."""

from __future__ import annotations

import re
from dataclasses import dataclass

from evilbox.parsers import parse_js, parse_php
from evilbox.rewrite import node_text, reset_source_encoding, use_source_encoding, walk

PHP_DECODERS = frozenset(
    {
        "base64_decode",
        "gzinflate",
        "gzuncompress",
        "gzdecode",
        "bzdecompress",
        "bzinflate",
        "str_rot13",
        "strrev",
        "hex2bin",
        "convert_uudecode",
        "quoted_printable_decode",
        "gzinflate",
        "pack",
        "unpack",
        "stripslashes",
        "urldecode",
        "rawurldecode",
        "utf8_decode",
    }
)

PHP_DISPATCH = frozenset(
    {
        "eval",
        "assert",
        "create_function",
        "preg_replace",
        "call_user_func",
        "call_user_func_array",
        "register_shutdown_function",
        "register_tick_function",
        "array_map",
        "array_filter",
        "array_walk",
        "usort",
        "uasort",
        "uksort",
        "ob_start",
    }
)

JS_DECODERS = frozenset(
    {
        "atob",
        "unescape",
        "decodeURIComponent",
        "decodeURI",
        "eval",
        "Function",
        "setTimeout",
        "setInterval",
        "fromCharCode",
    }
)

REMOTE_RE = re.compile(
    r"https?://[^\s\"']*(?:pastebin\.|githubusercontent|discord\.com/api|api\.telegram|"
    r"dns-query|etherscan|infura\.io|cdn\.jsdelivr|unpkg\.com|gist\.github)[^\s\"']*",
    re.I,
)

PACKER_LEFTOVER = (
    ("dean-edwards-packer", re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,", re.I)),
    ("jsfuck", re.compile(r"(?:\[\s*\]|!\s*\[|!\s*!|\+\s*\[){12,}")),
    ("jjencode", re.compile(r"=\s*~\s*\[\s*\]\s*;\s*[$\w]+\s*=\s*\{")),
    ("aaencode", re.compile(r"ﾟωﾟ|ﾟｰﾟ|ﾟДﾟ")),
    ("setTimeout-string", re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]", re.I)),
)


@dataclass
class UnresolvedFold:
    layer: str
    kind: str
    callee: str
    snippet: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "layer": self.layer,
            "kind": self.kind,
            "callee": self.callee,
            "snippet": self.snippet,
            "reason": self.reason,
        }


def _snippet(source: str, start: int, end: int, width: int = 160) -> str:
    text = source[start:end]
    return re.sub(r"\s+", " ", text).strip()[:width]


def _php_call_name(node, source: str) -> str | None:
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    if fn is None:
        return None
    if fn.type == "name":
        return node_text(source, fn).lstrip("\\").lower()
    if fn.type == "variable_name":
        return node_text(source, fn)
    return node_text(source, fn).strip()[:80]


def scan_unresolved(source: str, *, language: str, layer: str) -> list[UnresolvedFold]:
    if not source:
        return []
    token = use_source_encoding(source)
    try:
        found: list[UnresolvedFold] = []
        if language == "php":
            found.extend(_scan_php(source, layer))
        else:
            found.extend(_scan_js(source, layer))
        found.extend(_scan_packers(source, layer))
        found.extend(_scan_remote(source, layer))
        return found
    finally:
        reset_source_encoding(token)


def _scan_php(source: str, layer: str) -> list[UnresolvedFold]:
    out: list[UnresolvedFold] = []
    try:
        tree = parse_php(source)
    except Exception:
        return out
    for node in walk(tree.root_node):
        if node.type not in {"function_call_expression", "eval_expression"}:
            continue
        if node.type == "eval_expression":
            name = "eval"
        else:
            name = _php_call_name(node, source) or ""
        key = name.lstrip("\\$").lower()
        if key not in PHP_DECODERS and key not in PHP_DISPATCH and name[:1] != "$":
            continue
        snippet = _snippet(source, node.start_byte, node.end_byte)
        if key == "pack" and not re.search(r"pack\s*\(\s*['\"][hH]", snippet):
            continue
        if key in {"str_rot13", "stripslashes", "urldecode", "rawurldecode", "strrev"} and re.search(
            r"\$_|\$[A-Za-z_]", snippet
        ):
            continue
        if key in PHP_DECODERS:
            kind = "decoder"
            reason = "decoder call did not fold to a constant"
        elif name[:1] == "$":
            kind = "dispatch"
            reason = "variable function was not resolved"
        else:
            kind = "dispatch"
            reason = "dynamic dispatch or sink did not fold"
        out.append(
            UnresolvedFold(layer=layer, kind=kind, callee=name or key, snippet=snippet, reason=reason)
        )
        if len(out) >= 40:
            break
    return out


def _scan_js(source: str, layer: str) -> list[UnresolvedFold]:
    out: list[UnresolvedFold] = []
    try:
        tree = parse_js(source)
    except Exception:
        return out
    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None and node.named_children:
            fn = node.named_children[0]
        if fn is None:
            continue
        name = node_text(source, fn).strip()
        key = re.sub(r"[^A-Za-z]", "", name).lower()
        tail = name.split(".")[-1].split("[")[0].strip("'\"")
        tail_key = tail.lower()
        if tail_key not in JS_DECODERS and key not in JS_DECODERS:
            continue
        snippet = _snippet(source, node.start_byte, node.end_byte)
        kind = "decoder" if tail_key in {"atob", "unescape", "decodeuricomponent"} else "dispatch"
        out.append(
            UnresolvedFold(
                layer=layer,
                kind=kind,
                callee=name[:80],
                snippet=snippet,
                reason="call did not fold to a constant",
            )
        )
        if len(out) >= 40:
            break
    return out


def _scan_packers(source: str, layer: str) -> list[UnresolvedFold]:
    out: list[UnresolvedFold] = []
    for label, pattern in PACKER_LEFTOVER:
        match = pattern.search(source)
        if not match:
            continue
        out.append(
            UnresolvedFold(
                layer=layer,
                kind="packer",
                callee=label,
                snippet=re.sub(r"\s+", " ", match.group(0))[:160],
                reason="packer or encoder still present after unwrap",
            )
        )
    return out


def _scan_remote(source: str, layer: str) -> list[UnresolvedFold]:
    out: list[UnresolvedFold] = []
    for match in REMOTE_RE.finditer(source):
        url = match.group(0)
        out.append(
            UnresolvedFold(
                layer=layer,
                kind="remote-loader",
                callee="fetch",
                snippet=url[:200],
                reason="remote loader endpoint is an unresolved stage",
            )
        )
        if len(out) >= 8:
            break
    return out


def failed_fold_exit(unresolved: list[UnresolvedFold]) -> bool:
    """Exit 1 for leftover decoder/packer folds, not for request-driven sinks."""
    for item in unresolved:
        if item.kind in {"decoder", "packer", "recovered"}:
            return True
        if item.kind == "dispatch" and item.callee.lower().lstrip("\\") in PHP_DECODERS:
            return True
    return False
