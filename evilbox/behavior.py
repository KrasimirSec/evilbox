"""Canonical structural form and behavior extraction after deobfuscation.

Variable renaming and filler are normalized away so signatures and cluster
keys can match the same family across samples.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from evilbox.hashutil import sha256_text
from evilbox.parsers import parse_js, parse_php
from evilbox.rewrite import (
    apply_replacements,
    has_error,
    node_text,
    reset_source_encoding,
    use_source_encoding,
    walk,
)

# Side-effect / malware sinks used as behavior endpoints.
PHP_SINKS: frozenset[str] = frozenset(
    {
        "eval",
        "assert",
        "create_function",
        "preg_replace",
        "system",
        "passthru",
        "shell_exec",
        "exec",
        "proc_open",
        "popen",
        "file_put_contents",
        "fwrite",
        "move_uploaded_file",
        "copy",
        "unlink",
        "rmdir",
        "curl_exec",
        "fsockopen",
        "stream_socket_client",
        "mail",
        "wp_mail",
        "include",
        "include_once",
        "require",
        "require_once",
        "call_user_func",
        "call_user_func_array",
    }
)

JS_SINKS: frozenset[str] = frozenset(
    {
        "eval",
        "function",
        "settimeout",
        "setinterval",
        "exec",
        "shellexecute",
        "wscript.shell",
        "activexobject",
        "xmlhttp",
        "fetch",
        "websocket",
    }
)

PHP_DECODERS: frozenset[str] = frozenset(
    {
        "base64_decode",
        "gzinflate",
        "gzuncompress",
        "gzdecode",
        "bzdecompress",
        "str_rot13",
        "strrev",
        "urldecode",
        "rawurldecode",
        "convert_uudecode",
        "hex2bin",
        "quoted_printable_decode",
    }
)

JS_DECODERS: frozenset[str] = frozenset(
    {
        "atob",
        "unescape",
        "decodeuricomponent",
        "fromcharcode",
    }
)

SUPERGLOBAL_RE = re.compile(r"^_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV|SESSION)$")

PHP_KEEP_VARS = frozenset(
    {
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
)


@dataclass
class FlowEdge:
    """One hop from a data source or decoder toward a sink."""

    kind: str
    from_name: str
    to_name: str
    snippet: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "from": self.from_name,
            "to": self.to_name,
            "snippet": self.snippet,
        }


@dataclass
class BehaviorProfile:
    """Structural summary: sinks, sources, decoder/eval chains."""

    sinks: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    decoders: list[str] = field(default_factory=list)
    eval_chains: list[list[str]] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)
    has_eval_chain: bool = False
    features: list[str] = field(default_factory=list)
    canonical_sha256: str = ""
    canonical: str = ""

    def to_dict(self) -> dict:
        return {
            "sinks": list(self.sinks),
            "sources": list(self.sources),
            "decoders": list(self.decoders),
            "eval_chains": [list(chain) for chain in self.eval_chains],
            "edges": [edge.to_dict() for edge in self.edges],
            "has_eval_chain": self.has_eval_chain,
            "features": list(self.features),
            "canonical_sha256": self.canonical_sha256,
            "canonical": self.canonical,
        }


def _snippet(text: str, start: int, end: int, width: int = 80) -> str:
    a = max(0, start - 8)
    b = min(len(text), end + width)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:120]


def _php_callee(node, source: str) -> str | None:
    if node.type in {
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
    }:
        return node.type.replace("_expression", "").replace("_once", "_once")
    if node.type == "eval_expression":
        return "eval"
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "name":
        return node_text(source, fn).lstrip("\\").lower()
    return None


def _js_callee(node, source: str) -> str:
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    if fn is None:
        return ""
    return node_text(source, fn).strip("\"'").lower()


def _nested_call_names(node, source: str, language: str) -> list[str]:
    """Callee names nested under a call, outermost first."""
    names: list[str] = []
    current = node
    for _ in range(12):
        if language == "php":
            if current.type == "eval_expression":
                names.append("eval")
                args = current.named_children
                current = args[0] if args else None
                continue
            if current.type in {
                "include_expression",
                "include_once_expression",
                "require_expression",
                "require_once_expression",
            }:
                names.append(_php_callee(current, source) or current.type)
                args = current.named_children
                current = args[0] if args else None
                continue
            if current.type == "function_call_expression":
                callee = _php_callee(current, source)
                if callee:
                    names.append(callee)
                args = current.child_by_field_name("arguments")
                if args is None or not args.named_children:
                    break
                inner = args.named_children[0]
                if inner.type == "argument" and inner.named_children:
                    inner = inner.named_children[0]
                current = inner
                continue
            break
        if current.type == "call_expression":
            callee = _js_callee(current, source)
            if callee:
                names.append(callee)
            args = current.child_by_field_name("arguments")
            if args is None or not args.named_children:
                break
            current = args.named_children[0]
            continue
        if current.type == "new_expression":
            callee = _js_callee(current, source)
            if callee:
                names.append(callee)
            break
        break
    return names


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def extract_behavior(source: str, *, language: str) -> BehaviorProfile:
    """Walk the parse tree and record sinks, sources, and eval-style chains."""
    profile = BehaviorProfile()
    if not source:
        return profile
    token = use_source_encoding(source)
    try:
        tree = parse_php(source) if language == "php" else parse_js(source)
        sinks: list[str] = []
        sources: list[str] = []
        decoders: list[str] = []
        chains: list[list[str]] = []
        edges: list[FlowEdge] = []
        sink_set = PHP_SINKS if language == "php" else JS_SINKS
        decoder_set = PHP_DECODERS if language == "php" else JS_DECODERS

        for node in walk(tree.root_node):
            if language == "php" and node.type == "variable_name":
                raw = node_text(source, node)
                name = raw[1:] if raw.startswith("$") else raw
                if SUPERGLOBAL_RE.match(name) or name in PHP_KEEP_VARS:
                    label = raw if raw.startswith("$") else "$" + name
                    sources.append(label)
                continue

            names: list[str] = []
            if language == "php" and node.type in {
                "function_call_expression",
                "eval_expression",
                "include_expression",
                "include_once_expression",
                "require_expression",
                "require_once_expression",
            }:
                names = _nested_call_names(node, source, language)
            elif language == "js" and node.type in {"call_expression", "new_expression"}:
                names = _nested_call_names(node, source, language)
            if not names:
                continue

            head = names[0]
            if head in sink_set or head in decoder_set:
                if head in sink_set:
                    sinks.append(head)
                if head in decoder_set:
                    decoders.append(head)
            for name in names[1:]:
                if name in decoder_set:
                    decoders.append(name)
                if name in sink_set:
                    sinks.append(name)

            # eval(base64_decode(...)) / Function(atob(...)) style chains
            if len(names) >= 2 and (
                names[0] in {"eval", "assert", "create_function", "function"}
                or (names[0] == "preg_replace" and any(d in names for d in decoder_set))
            ):
                chain = [n for n in names if n in sink_set or n in decoder_set]
                if len(chain) >= 2:
                    chains.append(chain)
                    edges.append(
                        FlowEdge(
                            kind="eval-chain",
                            from_name=" -> ".join(chain[1:]),
                            to_name=chain[0],
                            snippet=_snippet(source, node.start_byte, node.end_byte),
                        )
                    )

            # Source flowing into a sink: eval($_POST[...]) / system($_GET[...])
            if language == "php" and names[0] in sink_set:
                snippet = _snippet(source, node.start_byte, node.end_byte)
                for match in re.finditer(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)", snippet):
                    sources.append(match.group(0))
                    edges.append(
                        FlowEdge(
                            kind="source-to-sink",
                            from_name=match.group(0),
                            to_name=names[0],
                            snippet=snippet,
                        )
                    )

        profile.sinks = _uniq(sinks)
        profile.sources = _uniq(sources)
        profile.decoders = _uniq(decoders)
        # Prefer longest unique chains.
        unique_chains: list[list[str]] = []
        seen_chains: set[tuple[str, ...]] = set()
        for chain in sorted(chains, key=len, reverse=True):
            key = tuple(chain)
            if key in seen_chains:
                continue
            seen_chains.add(key)
            unique_chains.append(chain)
        profile.eval_chains = unique_chains[:16]
        profile.edges = edges[:48]
        profile.has_eval_chain = bool(unique_chains) or (
            "eval" in profile.sinks and bool(profile.decoders)
        )
        profile.features = _behavior_features(profile)
    except Exception:
        pass
    finally:
        reset_source_encoding(token)
    return profile


def _behavior_features(profile: BehaviorProfile) -> list[str]:
    features: list[str] = []
    for sink in profile.sinks:
        features.append(f"sink:{sink}")
    for source in profile.sources:
        features.append(f"source:{source}")
    for decoder in profile.decoders:
        features.append(f"decoder:{decoder}")
    for chain in profile.eval_chains:
        features.append("chain:" + ">".join(chain))
    if profile.has_eval_chain:
        features.append("flag:eval-chain")
    if profile.sources and profile.sinks:
        features.append("flag:source-to-sink")
    return features


def canonicalize(source: str, *, language: str) -> str:
    """Alpha-rename locals, drop comments, collapse whitespace for stable matching."""
    if not source:
        return ""
    token = use_source_encoding(source)
    try:
        tree = parse_php(source) if language == "php" else parse_js(source)
        if has_error(tree.root_node):
            # Still strip comments/whitespace on a best-effort text pass.
            return _collapse_ws(_strip_comment_text(source, language))
        replacements: list[tuple[int, int, str]] = []
        if language == "php":
            mapping: dict[str, str] = {}
            order = 0
            for node in walk(tree.root_node):
                if node.type == "comment":
                    replacements.append((node.start_byte, node.end_byte, ""))
                    continue
                if node.type != "variable_name":
                    continue
                raw = node_text(source, node)
                name = raw[1:] if raw.startswith("$") else raw
                if name in PHP_KEEP_VARS:
                    continue
                if name not in mapping:
                    mapping[name] = f"v{order}"
                    order += 1
                replacements.append((node.start_byte, node.end_byte, "$" + mapping[name]))
        else:
            mapping = {}
            order = 0
            reserved = {
                "undefined",
                "null",
                "true",
                "false",
                "this",
                "window",
                "document",
                "console",
                "Math",
                "JSON",
                "Object",
                "Array",
                "String",
                "Number",
                "Boolean",
                "Function",
                "Error",
                "RegExp",
                "Date",
                "Promise",
                "Map",
                "Set",
                "parseInt",
                "parseFloat",
                "isNaN",
                "encodeURIComponent",
                "decodeURIComponent",
                "escape",
                "unescape",
                "atob",
                "btoa",
                "eval",
                "setTimeout",
                "setInterval",
                "clearTimeout",
                "clearInterval",
                "fetch",
                "XMLHttpRequest",
                "ActiveXObject",
                "WScript",
            }
            declared: set[str] = set()
            for node in walk(tree.root_node):
                if node.type == "comment":
                    replacements.append((node.start_byte, node.end_byte, ""))
                    continue
                if node.type == "variable_declarator":
                    name_node = node.child_by_field_name("name")
                    if name_node is not None and name_node.type == "identifier":
                        declared.add(node_text(source, name_node))
                elif node.type in {"function_declaration", "function_expression", "method_definition"}:
                    name_node = node.child_by_field_name("name")
                    if name_node is not None and name_node.type == "identifier":
                        declared.add(node_text(source, name_node))
                elif node.type == "formal_parameters":
                    for child in node.named_children:
                        if child.type == "identifier":
                            declared.add(node_text(source, child))
            for node in walk(tree.root_node):
                if node.type != "identifier":
                    continue
                name = node_text(source, node)
                if name in reserved or name not in declared:
                    continue
                if name not in mapping:
                    mapping[name] = f"v{order}"
                    order += 1
                replacements.append((node.start_byte, node.end_byte, mapping[name]))

        text = apply_replacements(source, replacements)
        return _collapse_ws(text)
    except Exception:
        return _collapse_ws(_strip_comment_text(source, language))
    finally:
        reset_source_encoding(token)


def _strip_comment_text(source: str, language: str) -> str:
    if language == "php":
        source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
        source = re.sub(r"//[^\n]*", "", source)
        source = re.sub(r"#[^\n]*", "", source)
    else:
        source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
        source = re.sub(r"//[^\n]*", "", source)
    return source


def _collapse_ws(text: str) -> str:
    return re.sub(r"[ \t]+\n", "\n", re.sub(r"[ \t]{2,}", " ", text)).strip() + ("\n" if text.strip() else "")


def analyze_structure(source: str, *, language: str) -> BehaviorProfile:
    """Canonicalize then extract behavior; attach the canonical text and digest."""
    canonical = canonicalize(source, language=language)
    profile = extract_behavior(canonical or source, language=language)
    profile.canonical = canonical
    profile.canonical_sha256 = sha256_text(canonical) if canonical else ""
    features = list(profile.features) if profile.features else _behavior_features(profile)
    if profile.canonical_sha256:
        features.append(f"canon:{profile.canonical_sha256[:16]}")
    profile.features = _uniq(features)
    return profile
