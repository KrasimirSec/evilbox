"""Capability tags and multi-label malware roles, with evidence snippets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from evilbox.hashutil import minhash_hex, minhash_jaccard, minhash_values, sha256_text


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


CAP_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("eval-runtime", re.compile(r"\b(?:eval|assert|create_function)\s*\(|preg_replace\s*\([^;]{0,160}e['\"]|\bnew\s+Function\s*\(", re.I)),
    ("exec", re.compile(r"\b(?:system|passthru|shell_exec|proc_open|popen|exec)\s*\(|WScript\.Shell|ShellExecute|\bcmd\.exe\b|\bpowershell(?:\.exe)?\b", re.I)),
    ("superglobals", re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b")),
    ("fs-write", re.compile(r"\b(?:file_put_contents|fwrite|move_uploaded_file|copy)\s*\(|ADODB\.Stream|SaveToFile|Scripting\.FileSystemObject", re.I)),
    ("fs-read", re.compile(r"\b(?:file_get_contents|fread|readfile|fopen)\s*\(", re.I)),
    ("fs-delete", re.compile(r"\b(?:unlink|rmdir|shutil\.rmtree)\s*\(", re.I)),
    ("net-egress", re.compile(r"\b(?:curl_exec|curl_init|fsockopen|stream_socket_client|file_get_contents)\s*\(|MSXML2\.XMLHTTP|WinHttp|XMLHTTP|\b(?:https?|hxxp)://", re.I)),
    ("persist", re.compile(r"crontab|schtasks|CurrentVersion\\Run|HKEY_|WScript\.Shell.*RegWrite", re.I)),
    ("seo-inject", re.compile(r"wp_posts|wp_insert_post|googlebot|bingbot|doorway|<a\s+href=.{0,40}style\s*=\s*['\"]display\s*:\s*none|preg_replace\s*\([^;]*(?:<a |<div )", re.I)),
    ("mail", re.compile(r"\bmail\s*\(|PHPMailer|SMTP|wp_mail\s*\(", re.I)),
    ("credential-harvest", re.compile(r"\b(?:password|passwd|credit.?card|wallet|login)\b|Cookies\\Chrome|Login Data", re.I)),
    ("miner", re.compile(r"stratum\+tcp|xmrig|monero|hashvault|nicehash", re.I)),
    ("phishing", re.compile(r"paypal|bankofamerica|account.?verify|one-time.?password", re.I)),
    ("payload-drop", re.compile(r"https?://[^\s\"']+\.(?:exe|dll|scr|ps1|bat|cmd|js)\b", re.I)),
    ("include-remote", re.compile(r"\b(?:include|require)(?:_once)?\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|['\"]https?://)", re.I)),
)

ROLE_RULES: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    # name, required any-of groups are encoded as: must have all of `need`, optionally boosted by `boost`
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


def _snippet(text: str, match: re.Match[str], width: int = 96) -> str:
    start = max(0, match.start() - 12)
    end = min(len(text), match.end() + width)
    return re.sub(r"\s+", " ", text[start:end]).strip()[:160]


def classify_layers(layers: list[tuple[str, str]]) -> Classification:
    """layers: (name, text), including original and inner."""
    found: dict[str, list[Evidence]] = {}
    for name, text in layers:
        if not text:
            continue
        for cap_id, pattern in CAP_PATTERNS:
            for match in pattern.finditer(text):
                found.setdefault(cap_id, []).append(
                    Evidence(capability=cap_id, layer=name, snippet=_snippet(text, match))
                )
                if len(found[cap_id]) >= 4:
                    break

    capabilities = [Capability(id=k, evidence=v[:4]) for k, v in found.items()]
    have = set(found)

    roles: list[Role] = []
    for name, need, extra in ROLE_RULES:
        if name == "webshell":
            ok = ("eval-runtime" in have or "exec" in have) and "superglobals" in have
        elif name == "dropper":
            ok = ("fs-write" in have and "net-egress" in have) or "payload-drop" in have
        elif name == "injector":
            ok = "include-remote" in have or ("eval-runtime" in have and "fs-write" in have)
        elif name == "backdoor":
            ok = "net-egress" in have and bool(have & {"eval-runtime", "exec", "persist"})
        elif name == "wiper":
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
        roles.append(Role(name=name, score=round(score, 2), evidence=ev[:6]))

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
