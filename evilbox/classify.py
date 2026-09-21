"""Capability tags and multi-label malware roles, with evidence snippets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from evilbox.hashutil import minhash_hex, minhash_jaccard, minhash_values, sha256_text
from evilbox.parsers import parse_js, parse_php
from evilbox.rewrite import node_text, reset_source_encoding, use_source_encoding, walk


@dataclass
class Evidence:
    capability: str
    layer: str
    snippet: str


@dataclass
class Capability:
    id: str
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "evidence": [e.__dict__ for e in self.evidence],
        }


@dataclass
class Role:
    name: str
    score: float
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": self.score,
            "evidence": [e.__dict__ for e in self.evidence],
        }


@dataclass
class Classification:
    capabilities: list[Capability]
    roles: list[Role]

    def to_dict(self) -> dict:
        return {
            "capabilities": [c.to_dict() for c in self.capabilities],
            "roles": [r.to_dict() for r in self.roles],
        }


PHP_CALL_CAPS: dict[str, tuple[str, ...]] = {
    "eval": ("eval-runtime",),
    "assert": ("eval-runtime",),
    "create_function": ("eval-runtime",),
    "system": ("exec",),
    "passthru": ("exec",),
    "shell_exec": ("exec",),
    "proc_open": ("exec",),
    "popen": ("exec",),
    "exec": ("exec",),
    "file_put_contents": ("fs-write",),
    "fwrite": ("fs-write",),
    "move_uploaded_file": ("fs-write",),
    "copy": ("fs-write",),
    "file_get_contents": ("fs-read",),
    "fread": ("fs-read",),
    "readfile": ("fs-read",),
    "fopen": ("fs-read",),
    "unlink": ("fs-delete",),
    "rmdir": ("fs-delete",),
    "curl_exec": ("net-egress",),
    "curl_init": ("net-egress",),
    "fsockopen": ("net-egress",),
    "stream_socket_client": ("net-egress",),
    "mail": ("mail",),
    "wp_mail": ("mail",),
    "include": ("include-remote",),
    "include_once": ("include-remote",),
    "require": ("include-remote",),
    "require_once": ("include-remote",),
}

JS_CALL_CAPS: dict[str, tuple[str, ...]] = {
    "eval": ("eval-runtime",),
    "exec": ("exec",),
    "shellexecute": ("exec",),
    "wscript.shell": ("exec",),
}

STRING_SKIP_TYPES = {
    "string",
    "encapsed_string",
    "string_content",
    "encapsed_string_content",
    "string_literal",
    "string_fragment",
    "comment",
    "heredoc",
    "nowdoc",
}

# Distinctive payloads only — not generic words like "password" in HTML forms.
STRING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("persist", re.compile(r"crontab|schtasks|CurrentVersion\\Run|HKEY_", re.I)),
    ("seo-inject", re.compile(r"wp_posts|wp_insert_post|googlebot|bingbot|doorway|<a\s+href=.{0,40}style\s*=\s*['\"]display\s*:\s*none", re.I)),
    ("miner", re.compile(r"stratum\+tcp|xmrig|monero|hashvault|nicehash", re.I)),
    ("phishing", re.compile(r"paypal|bankofamerica|account.?verify|one-time.?password", re.I)),
    ("payload-drop", re.compile(r"https?://[^\s\"']+\.(?:exe|dll|scr|ps1|bat|cmd)\b", re.I)),
    ("credential-harvest", re.compile(r"Cookies\\Chrome|Login Data|wallet\.dat", re.I)),
    ("net-egress", re.compile(r"\b(?:https?|hxxp)://", re.I)),
)

SUPERGLOBAL_RE = re.compile(r"^\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)$")


ROLE_RULES: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    ("webshell", frozenset({"eval-runtime", "exec"}), frozenset({"superglobals"})),
    ("backdoor", frozenset({"net-egress"}), frozenset({"eval-runtime", "exec", "persist"})),
    ("dropper", frozenset({"fs-write", "net-egress"}), frozenset({"exec"})),
    ("injector", frozenset({"include-remote", "eval-runtime"}), frozenset({"fs-write", "superglobals"})),
    ("seo-spam", frozenset({"seo-inject"}), frozenset()),
    ("mailer", frozenset({"mail"}), frozenset({"superglobals"})),
    ("stealer", frozenset({"credential-harvest"}), frozenset({"net-egress", "fs-read"})),
    ("phishing-kit", frozenset({"phishing"}), frozenset({"credential-harvest", "fs-write"})),
    ("cryptominer", frozenset({"miner"}), frozenset({"exec", "net-egress"})),
    ("wiper", frozenset({"fs-delete"}), frozenset()),
)


def _snippet_text(text: str, start: int, end: int, width: int = 96) -> str:
    a = max(0, start - 12)
    b = min(len(text), end + width)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:160]


def _add(found: dict[str, list[Evidence]], cap_id: str, layer: str, snippet: str) -> None:
    bucket = found.setdefault(cap_id, [])
    if len(bucket) >= 4:
        return
    bucket.append(Evidence(capability=cap_id, layer=layer, snippet=snippet))


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


def _first_arg_text(node, source: str) -> str:
    args = node.child_by_field_name("arguments")
    if args is None:
        named = node.named_children
        return node_text(source, named[0]) if named else ""
    named = args.named_children
    if not named:
        return ""
    inner = named[0]
    if inner.type == "argument" and inner.named_children:
        inner = inner.named_children[0]
    return node_text(source, inner)


def _looks_like_url(text: str) -> bool:
    lowered = text.lower()
    return "http://" in lowered or "https://" in lowered or "hxxp" in lowered


def _js_callee(node, source: str) -> str:
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    if fn is None:
        return ""
    return node_text(source, fn).strip("\"'")


def _walk_calls(text: str, language: str) -> list[tuple[str, int, int, str]]:
    """Return (callee, start, end, first_arg_text) for call-like nodes."""
    token = use_source_encoding(text)
    out: list[tuple[str, int, int, str]] = []
    try:
        tree = parse_php(text) if language == "php" else parse_js(text)
        for node in walk(tree.root_node):
            if node.type in STRING_SKIP_TYPES:
                continue
            if language == "php":
                if node.type == "variable_name":
                    raw = node_text(text, node)
                    if SUPERGLOBAL_RE.match(raw):
                        out.append((raw, node.start_byte, node.end_byte, ""))
                    continue
                if node.type in {
                    "function_call_expression",
                    "eval_expression",
                    "include_expression",
                    "include_once_expression",
                    "require_expression",
                    "require_once_expression",
                }:
                    callee = _php_callee(node, text)
                    if callee:
                        out.append((callee, node.start_byte, node.end_byte, _first_arg_text(node, text)))
                continue
            if node.type in {"call_expression", "new_expression"}:
                callee = _js_callee(node, text)
                if callee:
                    out.append((callee, node.start_byte, node.end_byte, _first_arg_text(node, text)))
    except Exception:
        pass
    finally:
        reset_source_encoding(token)
    return out


def _string_regions(text: str, language: str) -> list[tuple[int, int]]:
    token = use_source_encoding(text)
    spans: list[tuple[int, int]] = []
    try:
        tree = parse_php(text) if language == "php" else parse_js(text)
        for node in walk(tree.root_node):
            if node.type in STRING_SKIP_TYPES:
                spans.append((node.start_byte, node.end_byte))
    except Exception:
        pass
    finally:
        reset_source_encoding(token)
    return spans


def _outside_strings(text: str, start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    for a, b in spans:
        if a <= start and end <= b:
            return False
    return True


def classify_layers(layers: list[tuple[str, str]], *, language: str | None = None) -> Classification:
    """layers: (name, text), including original and inner."""
    found: dict[str, list[Evidence]] = {}
    for name, text in layers:
        if not text:
            continue
        lang = language or ("php" if "<?" in text[:80] or "$_" in text[:400] else "js")
        spans = _string_regions(text, lang)
        for callee, start, end, arg in _walk_calls(text, lang):
            snippet = _snippet_text(text, start, end)
            lowered = callee.lstrip("\\").lower()
            if SUPERGLOBAL_RE.match(callee):
                _add(found, "superglobals", name, snippet)
                continue
            caps = PHP_CALL_CAPS.get(lowered) or JS_CALL_CAPS.get(lowered)
            if lowered in {"new function", "function"} or re.search(r"\bfunction\b", lowered):
                if "Function" in callee or lowered == "function":
                    _add(found, "eval-runtime", name, snippet)
            if "ActiveXObject" in callee or "XMLHTTP" in callee.upper() or "WinHttp" in callee:
                _add(found, "net-egress", name, snippet)
            if "WScript.Shell" in callee or "ShellExecute" in callee:
                _add(found, "exec", name, snippet)
            if "FileSystemObject" in callee or "SaveToFile" in callee or "ADODB.Stream" in callee:
                _add(found, "fs-write", name, snippet)
            if caps:
                for cap_id in caps:
                    if cap_id == "include-remote" and not (
                        _looks_like_url(arg) or "$_GET" in arg or "$_POST" in arg or "$_REQUEST" in arg
                    ):
                        continue
                    if cap_id == "fs-read" and lowered == "file_get_contents" and _looks_like_url(arg):
                        _add(found, "net-egress", name, snippet)
                    _add(found, cap_id, name, snippet)
            if lowered == "preg_replace" and re.search(r"['\"][^'\"]{0,40}e['\"]", arg + snippet):
                _add(found, "eval-runtime", name, snippet)

        for cap_id, pattern in STRING_PATTERNS:
            for match in pattern.finditer(text):
                if not _outside_strings(text, match.start(), match.end(), spans) and cap_id not in {
                    "payload-drop",
                    "net-egress",
                    "miner",
                    "phishing",
                    "seo-inject",
                    "persist",
                    "credential-harvest",
                }:
                    continue
                # Skip generic matches that live only in comments.
                in_comment = False
                for a, b in spans:
                    region = text[a:b]
                    if a <= match.start() < b and (region.lstrip().startswith("/*") or region.lstrip().startswith("//") or region.lstrip().startswith("#")):
                        in_comment = True
                        break
                if in_comment:
                    continue
                _add(found, cap_id, name, _snippet_text(text, match.start(), match.end()))

        if lang == "js":
            if re.search(r"\bnew\s+Function\s*\(", text):
                _add(found, "eval-runtime", name, "new Function")
            if re.search(r"WScript\.Shell|ShellExecute|\bcmd\.exe\b|\bpowershell(?:\.exe)?\b", text, re.I):
                # only if not exclusively inside a comment; cheap check
                if "WScript" in text or "cmd.exe" in text.lower() or "powershell" in text.lower():
                    _add(found, "exec", name, "command execution API")

    capabilities = [Capability(id=k, evidence=v[:4]) for k, v in found.items()]
    have = set(found)

    roles: list[Role] = []
    for role_name, need, extra in ROLE_RULES:
        if role_name == "webshell":
            ok = ("eval-runtime" in have or "exec" in have) and "superglobals" in have
        elif role_name == "dropper":
            ok = ("fs-write" in have and "net-egress" in have) or "payload-drop" in have
        elif role_name == "injector":
            ok = "include-remote" in have or ("eval-runtime" in have and "fs-write" in have)
        elif role_name == "backdoor":
            ok = "net-egress" in have and bool(have & {"eval-runtime", "exec", "persist"})
        elif role_name == "wiper":
            ok = "fs-delete" in have and "superglobals" not in have and "eval-runtime" not in have
        else:
            ok = bool(need <= have)
        if not ok:
            continue
        boost = len(extra & have)
        score = min(0.99, 0.62 + 0.12 * boost)
        ev: list[Evidence] = []
        for cap in list(need) + list(extra):
            ev.extend(found.get(cap, [])[:2])
        roles.append(Role(name=role_name, score=round(score, 2), evidence=ev[:6]))

    roles.sort(key=lambda r: r.score, reverse=True)
    return Classification(capabilities=capabilities, roles=roles)


def cluster_key(inner_text: str) -> str:
    from evilbox.hashutil import normalize_code

    return sha256_text(normalize_code(inner_text))


def cluster_minhash(inner_text: str) -> str:
    return minhash_hex(inner_text)


def cluster_similar(left: str, right: str, *, threshold: float = 0.55) -> bool:
    return minhash_jaccard(minhash_values(left), minhash_values(right)) >= threshold


def cluster_groups(samples: list[tuple[str, str]], *, threshold: float = 0.55) -> dict[str, list[str]]:
    """Fuzzy groups: (path, inner_text) -> representative minhash -> paths."""
    sigs = [(path, minhash_values(text)) for path, text in samples]
    parent = list(range(len(sigs)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            if minhash_jaccard(sigs[i][1], sigs[j][1]) >= threshold:
                a, b = find(i), find(j)
                if a != b:
                    parent[b] = a
    groups: dict[str, list[str]] = {}
    for i, (path, _values) in enumerate(sigs):
        root = find(i)
        key = minhash_hex(samples[root][1])
        groups.setdefault(key, []).append(path)
    return groups
