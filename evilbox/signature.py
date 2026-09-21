"""Scanner-visible signatures from the original (packed) layer only."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from evilbox.parsers import parse_js, parse_php
from evilbox.rewrite import node_text, reset_source_encoding, use_source_encoding, walk

WRAPPER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\([^)]{0,80}", re.I),
    re.compile(r"eval\s*\(\s*base64_decode\s*\([^)]{0,80}", re.I),
    re.compile(r"eval\s*\(\s*str_rot13\s*\([^)]{0,80}", re.I),
    re.compile(r"eval\s*\(\s*gzuncompress\s*\([^)]{0,80}", re.I),
    re.compile(r"eval\s*\(\s*atob\s*\([^)]{0,80}", re.I),
    re.compile(r"String\.fromCharCode\s*\([^)]{0,80}"),
    re.compile(r"preg_replace\s*\(\s*['\"][^'\"]{0,40}e['\"]", re.I),
    re.compile(r"create_function\s*\([^)]{0,80}", re.I),
    re.compile(r"assert\s*\(\s*base64_decode\s*\([^)]{0,80}", re.I),
    re.compile(r"(?:include|require)(?:_once)?\s*\(\s*base64_decode\s*\([^)]{0,80}", re.I),
)

STRING_LIT_RE = re.compile(r"'(?:[^'\\]|\\.){8,}'|\"(?:[^\"\\]|\\.){8,}\"", re.S)
PHP_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]{3,40})")
JS_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,40})\b")
COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]{8,}|#[^\n]{8,}", re.S)

JUNK_IDENT = re.compile(r"^_0x[0-9a-fA-F]+$|^[0-9a-f]{8,}$", re.I)

COMMON = {
    "this",
    "that",
    "function",
    "return",
    "undefined",
    "window",
    "document",
    "console",
    "length",
    "object",
    "string",
    "number",
    "boolean",
    "array",
    "true",
    "false",
    "null",
    "php",
    "echo",
    "print",
    "eval",
    "base64_decode",
    "gzinflate",
    "gzuncompress",
    "str_rot13",
    "file_get_contents",
    "file_put_contents",
    "preg_replace",
    "create_function",
    "include",
    "require",
    "assert",
    "system",
    "passthru",
    "shell_exec",
    "wscript",
    "activexobject",
    "xmlhttp",
    "fromcharcode",
    "string",
    "charcodeat",
    "prototype",
    "jquery",
    "undefined",
    "arguments",
    "constructor",
    "tostring",
    "indexof",
    "substr",
    "substring",
    "replace",
    "split",
    "join",
    "push",
    "http",
    "https",
    "utf8",
    "utf-8",
    "content",
    "type",
    "name",
    "value",
    "data",
    "temp",
    "tmp",
    "test",
    "text",
    "html",
    "body",
    "head",
    "script",
    "style",
    "wpdb",
    "wp_query",
    "wp_scripts",
    "wp_styles",
    "wp_mail",
    "wp_enqueue_script",
    "wp_enqueue_style",
    "add_action",
    "add_filter",
    "get_option",
    "update_option",
    "is_admin",
    "abspath",
    "plugin_dir_url",
    "plugins_url",
    "get_header",
    "get_footer",
    "the_content",
    "post_title",
    "post_id",
    "get_template_directory",
}


@dataclass
class SurfaceItem:
    kind: str
    value: str
    yara: str
    pcre: str
    why: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "value": self.value,
            "yara": self.yara,
            "pcre": self.pcre,
            "why": self.why,
        }


@dataclass
class SurfaceSignatures:
    items: list[SurfaceItem] = field(default_factory=list)
    yara_rule: str = ""

    def to_dict(self) -> dict:
        return {
            "layer": "original",
            "items": [i.to_dict() for i in self.items],
            "yara_rule": self.yara_rule,
        }


def yara_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")


def pcre_escape(text: str) -> str:
    return re.escape(text)


def render_yara_rule(items: list[SurfaceItem], *, rule_name: str = "evilbox_surface") -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", rule_name) or "evilbox_surface"
    if ident[0].isdigit():
        ident = "r_" + ident
    lines = [
        f"rule {ident}",
        "{",
        "  meta:",
        '    tool = "evilbox"',
        '    layer = "original"',
        "  strings:",
    ]
    if not items:
        lines.append('    $empty = "evilbox-no-surface-needles" ascii')
        lines.extend(["  condition:", "    false", "}"])
        return "\n".join(lines) + "\n"
    for index, item in enumerate(items):
        lines.append(f'    $s{index} = "{item.yara}" ascii wide nocase')
    lines.extend(["  condition:", "    any of them", "}"])
    return "\n".join(lines) + "\n"


def _needle(text: str, size: int = 32) -> str:
    if len(text) <= size:
        return text
    best = text[:size]
    best_score = len(set(best))
    step = max(1, (len(text) - size) // 64)
    for i in range(0, len(text) - size + 1, step):
        window = text[i : i + size]
        score = len(set(window))
        if score > best_score:
            best = window
            best_score = score
    return best


def _skip_literal(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return True
    lower = stripped.lower()
    if lower in COMMON:
        return True
    if lower.startswith(("http://www.w3.org", "http://schema.org", "https://schema.org")):
        return True
    if re.fullmatch(r"[\s0-9]+", stripped):
        return True
    return False


def extract_surface(source: str, *, language: str) -> SurfaceSignatures:
    items: list[SurfaceItem] = []
    seen: set[str] = set()

    def add(kind: str, value: str, why: str) -> None:
        key = value.strip()
        if not key or key.lower() in seen:
            return
        seen.add(key.lower())
        needle = _needle(key, 40 if len(key) > 40 else len(key))
        items.append(
            SurfaceItem(
                kind=kind,
                value=key[:400],
                yara=yara_escape(needle),
                pcre=pcre_escape(needle),
                why=why,
            )
        )

    for pattern in WRAPPER_PATTERNS:
        match = pattern.search(source)
        if match:
            add("code-sequence", match.group(0).strip(), "decoder wrapper visible in the original file")

    for match in STRING_LIT_RE.finditer(source):
        raw = match.group(0)
        inner = raw[1:-1]
        if _skip_literal(inner):
            continue
        why = "packed blob / distinctive string in the original file"
        if len(inner) >= 80:
            why = "long payload string a scanner can match without unpacking"
        add("string", inner, why)

    for match in COMMENT_RE.finditer(source):
        text = match.group(0).strip()
        if len(text) < 12 or "license" in text.lower() or "copyright" in text.lower():
            continue
        add("comment", re.sub(r"\s+", " ", text)[:240], "comment present on the original sample")

    if language == "php":
        for match in PHP_VAR_RE.finditer(source):
            name = match.group(1)
            if name.lower() in COMMON or JUNK_IDENT.match(name):
                continue
            if name in {"GLOBALS", "GET", "POST", "COOKIE", "SERVER", "REQUEST", "FILES", "ENV", "SESSION"}:
                continue
            add("variable", "$" + name, "stable PHP variable name in the original file")
    else:
        for match in JS_IDENT_RE.finditer(source):
            name = match.group(1)
            if name.lower() in COMMON or JUNK_IDENT.match(name):
                continue
            if name[0].isupper() and name.lower() in {"wscript", "activexobject", "xmlhttp"}:
                continue
            add("identifier", name, "stable identifier in the original file")

    token = use_source_encoding(source)
    try:
        tree = parse_php(source) if language == "php" else parse_js(source)
        for node in walk(tree.root_node):
            if node.type in {"string", "encapsed_string", "string_literal"}:
                raw = node_text(source, node)
                if len(raw) >= 10 and raw[0] in "'\"" and raw[-1] == raw[0]:
                    inner = raw[1:-1]
                    if not _skip_literal(inner):
                        why = "packed blob / distinctive string in the original file"
                        if len(inner) >= 80:
                            why = "long payload string a scanner can match without unpacking"
                        add("string", inner, why)
            if node.type in {"function_definition", "function_declaration", "method_declaration"}:
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    continue
                name = node_text(source, name_node)
                if name and name.lower() not in COMMON and not JUNK_IDENT.match(name):
                    add("function", name, "function name declared in the original file")
    except Exception:
        pass
    finally:
        reset_source_encoding(token)

    # Prefer longer / wrapper items first; cap for analysts.
    def rank(item: SurfaceItem) -> tuple:
        kind_rank = {"code-sequence": 0, "string": 1, "function": 2, "variable": 3, "identifier": 4, "comment": 5}.get(
            item.kind, 9
        )
        return (kind_rank, -len(item.value))

    items.sort(key=rank)
    chosen = items[:36]
    return SurfaceSignatures(items=chosen, yara_rule=render_yara_rule(chosen))
