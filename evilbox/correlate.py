"""Campaign-correlation pivots and ATT&CK tags derived from a decode result."""

from __future__ import annotations

from typing import Any

from dataclasses import fields

from evilbox.extract import Indicators

CAP_TO_ATTACK: dict[str, tuple[tuple[str, str], ...]] = {
    "eval-runtime": (
        ("T1059", "Command and Scripting Interpreter"),
        ("T1059.007", "JavaScript"),
    ),
    "exec": (
        ("T1059", "Command and Scripting Interpreter"),
        ("T1059.004", "Unix Shell"),
    ),
    "fs-write": (("T1105", "Ingress Tool Transfer"),),
    "fs-read": (("T1005", "Data from Local System"),),
    "fs-delete": (("T1485", "Data Destruction"),),
    "net-egress": (
        ("T1071", "Application Layer Protocol"),
        ("T1071.001", "Web Protocols"),
    ),
    "persist": (
        ("T1547", "Boot or Logon Autostart Execution"),
        ("T1053", "Scheduled Task/Job"),
    ),
    "mail": (("T1071.003", "Mail Protocols"),),
    "credential-harvest": (
        ("T1555", "Credentials from Password Stores"),
        ("T1539", "Steal Web Session Cookie"),
    ),
    "miner": (("T1496", "Resource Hijacking"),),
    "phishing": (("T1566", "Phishing"),),
    "payload-drop": (("T1105", "Ingress Tool Transfer"),),
    "include-remote": (
        ("T1105", "Ingress Tool Transfer"),
        ("T1505.003", "Web Shell"),
    ),
    "seo-inject": (("T1583.006", "SEO Poisoning"),),
    "superglobals": (("T1505.003", "Web Shell"),),
}

ROLE_TO_ATTACK: dict[str, tuple[tuple[str, str], ...]] = {
    "webshell": (("T1505.003", "Web Shell"),),
    "backdoor": (("T1583", "Acquire Infrastructure"),),
    "dropper": (("T1105", "Ingress Tool Transfer"),),
    "injector": (("T1055", "Process Injection"),),
    "stealer": (("T1555", "Credentials from Password Stores"),),
    "phishing-kit": (("T1566", "Phishing"),),
    "cryptominer": (("T1496", "Resource Hijacking"),),
    "wiper": (("T1485", "Data Destruction"),),
    "mailer": (("T1071.003", "Mail Protocols"),),
    "seo-spam": (("T1583.006", "SEO Poisoning"),),
}


def _cap_ids(capabilities: list[Any]) -> list[str]:
    out: list[str] = []
    for item in capabilities or []:
        if isinstance(item, dict):
            cap_id = str(item.get("id") or "")
        else:
            cap_id = str(getattr(item, "id", "") or "")
        if cap_id:
            out.append(cap_id)
    return out


def _role_names(roles: list[Any]) -> list[str]:
    out: list[str] = []
    for item in roles or []:
        if isinstance(item, dict):
            name = str(item.get("name") or "")
        else:
            name = str(getattr(item, "name", "") or "")
        if name:
            out.append(name)
    return out


def attack_from_classification(
    capabilities: list[Any],
    roles: list[Any],
    *,
    language: str | None = None,
) -> list[dict[str, str]]:
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for cap_id in _cap_ids(capabilities):
        for technique_id, name in CAP_TO_ATTACK.get(cap_id, ()):
            if technique_id == "T1059.007" and language == "php":
                continue
            if technique_id == "T1059.004" and language == "js":
                continue
            if technique_id in seen:
                continue
            seen.add(technique_id)
            rows.append({"id": technique_id, "name": name, "from": cap_id})
    for role_name in _role_names(roles):
        for technique_id, name in ROLE_TO_ATTACK.get(role_name, ()):
            if technique_id in seen:
                continue
            seen.add(technique_id)
            rows.append({"id": technique_id, "name": name, "from": role_name})
    rows.sort(key=lambda row: row["id"])
    return rows


def _prefixed(kind: str, values: list[str]) -> list[str]:
    return [f"{kind}:{value}" for value in values if value]


def campaign_keys(iocs: Indicators) -> list[str]:
    """Stable, typed pivots for joining this sample to other campaigns."""
    keys: list[str] = []
    keys.extend(_prefixed("domain", iocs.domains))
    keys.extend(_prefixed("url", iocs.urls))
    keys.extend(_prefixed("ipv4", iocs.ipv4))
    keys.extend(_prefixed("ipv6", iocs.ipv6))
    keys.extend(_prefixed("endpoint", iocs.endpoints or iocs.ip_ports))
    keys.extend(_prefixed("onion", iocs.onion))
    keys.extend(_prefixed("email", iocs.emails))
    keys.extend(_prefixed("wallet", iocs.wallets))
    keys.extend(_prefixed("telegram", iocs.telegram))
    keys.extend(_prefixed("discord", iocs.discord))
    keys.extend(_prefixed("secret", iocs.secrets))
    keys.extend(_prefixed("key", iocs.crypto_keys))
    keys.extend(_prefixed("md5", iocs.md5))
    keys.extend(_prefixed("sha1", iocs.sha1))
    keys.extend(_prefixed("sha256", iocs.sha256))
    keys.extend(_prefixed("uuid", iocs.uuids))
    keys.extend(_prefixed("cve", iocs.cves))
    keys.extend(_prefixed("mutex", iocs.mutexes))
    keys.extend(_prefixed("pipe", iocs.named_pipes))
    keys.extend(_prefixed("ua", iocs.user_agents))
    keys.extend(_prefixed("path", iocs.url_paths))
    keys.extend(_prefixed("param", iocs.request_params))
    keys.extend(_prefixed("stratum", iocs.stratum))
    keys.extend(_prefixed("paste", iocs.paste_urls))
    # Deduplicate while keeping kind prefix (case-insensitive).
    seen: set[str] = set()
    out: list[str] = []
    for key in keys:
        folded = key.lower()
        if folded in seen:
            continue
        seen.add(folded)
        out.append(key)
    return out


def build_correlation(
    *,
    indicators: Indicators | dict[str, list[str]],
    capabilities: list[Any] | None = None,
    roles: list[Any] | None = None,
    sample: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if isinstance(indicators, Indicators):
        iocs = indicators
    else:
        names = {item.name for item in fields(Indicators)}
        iocs = Indicators(**{k: list(v) for k, v in indicators.items() if k in names and v is not None})
    attack = attack_from_classification(
        capabilities or [],
        roles or [],
        language=(sample or {}).get("language"),
    )
    sample = sample or {}
    keys = campaign_keys(iocs)
    return {
        "attack": attack,
        "campaign_keys": keys,
        "pivots": {
            "network": iocs.urls + iocs.domains + iocs.ipv4 + iocs.ipv6 + iocs.onion + iocs.endpoints,
            "identities": iocs.emails + iocs.wallets + iocs.telegram + iocs.discord,
            "secrets": iocs.secrets + iocs.crypto_keys,
            "artifacts": iocs.md5 + iocs.sha1 + iocs.sha256 + iocs.uuids + iocs.mutexes + iocs.named_pipes + iocs.files,
            "behaviors": iocs.apis + iocs.request_params + iocs.user_agents + iocs.stratum + [row["id"] for row in attack],
        },
        "cluster": {
            "sha256": sample.get("cluster_sha256") or "",
            "minhash": sample.get("cluster_minhash") or "",
            "inner_sha256": sample.get("inner_sha256") or "",
        },
    }
