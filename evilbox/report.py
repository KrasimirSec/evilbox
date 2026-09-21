from __future__ import annotations

import html
import json
from typing import Any

from evilbox.correlate import build_correlation


def build_report(
    *,
    result,
    path: str | None,
    sandbox: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sample = {
        "path": path,
        "language": result.language,
        "sha256": result.original_sha256,
        "inner_sha256": result.inner_sha256,
        "cluster_sha256": result.cluster_sha256,
        "cluster_minhash": getattr(result, "cluster_minhash", ""),
        "php_version": getattr(result, "php_version", None),
    }
    roles = [r.to_dict() for r in result.classification.roles]
    capabilities = [c.to_dict() for c in result.classification.capabilities]
    report: dict[str, Any] = {
        "schema": "evilbox.report.v1",
        "sample": sample,
        "packer": result.packer,
        "parse_ok": result.parse_ok,
        "failed_folds": getattr(result, "failed_folds", False),
        "warnings": result.warnings,
        "layers": [layer.to_dict() for layer in result.layers],
        "unresolved_folds": [item.to_dict() if hasattr(item, "to_dict") else item for item in getattr(result, "unresolved_folds", [])],
        "encoded_not_analyzable": getattr(result, "encoded_not_analyzable", []),
        "roles": roles,
        "capabilities": capabilities,
        "indicators": result.indicators.to_dict(),
        "indicators_by_layer": result.indicators_by_layer,
        "correlation": build_correlation(
            indicators=result.indicators,
            capabilities=capabilities,
            roles=roles,
            sample=sample,
        ),
        "surface_signatures": result.surface.to_dict(),
        "sandbox": sandbox,
        "sandbox_cross_check": (sandbox or {}).get("cross_check") if sandbox else getattr(result, "sandbox_cross_check", None),
    }
    return report


def format_analysis(report: dict[str, Any]) -> str:
    lines: list[str] = []
    roles = report.get("roles") or []
    if roles:
        lines.append("roles:")
        for role in roles:
            lines.append(f"  {role['name']} ({role['score']})")
            for ev in (role.get("evidence") or [])[:2]:
                lines.append(f"    [{ev.get('layer')}] {ev.get('snippet', '')[:100]}")
    else:
        lines.append("roles: (none)")
    caps = report.get("capabilities") or []
    if caps:
        lines.append("capabilities: " + ", ".join(c["id"] for c in caps))
    packer = report.get("packer") or []
    if packer:
        lines.append("packer: " + ", ".join(packer))
    sample = report.get("sample") or {}
    if sample.get("cluster_sha256"):
        lines.append(f"cluster: {sample['cluster_sha256']}")
    if sample.get("cluster_minhash"):
        lines.append(f"cluster_minhash: {sample['cluster_minhash']}")
    if report.get("failed_folds"):
        lines.append("failed_folds: yes")
    unresolved = report.get("unresolved_folds") or []
    if unresolved:
        lines.append("unresolved folds:")
        by_layer: dict[str, int] = {}
        for item in unresolved:
            by_layer[item.get("layer", "?")] = by_layer.get(item.get("layer", "?"), 0) + 1
        for layer_name, count in by_layer.items():
            lines.append(f"  {layer_name}: {count}")
        for item in unresolved[:12]:
            lines.append(f"  [{item.get('layer')}] {item.get('kind')} {item.get('callee')}: {item.get('reason')}")
    encoded = report.get("encoded_not_analyzable") or []
    if encoded:
        lines.append("encoded, not analyzable: " + ", ".join(e.get("name", "") for e in encoded))
    cross = report.get("sandbox_cross_check") or {}
    if cross:
        lines.append(f"sandbox cross-check: {cross.get('detail')}")
    surface = (report.get("surface_signatures") or {}).get("items") or []
    if surface:
        lines.append("surface signatures (original layer):")
        for item in surface[:12]:
            lines.append(f"  [{item['kind']}] {item['yara'][:80]}")
            lines.append(f"    why: {item['why']}")
    correlation = report.get("correlation") or {}
    attack = correlation.get("attack") or []
    if attack:
        lines.append("ATT&CK: " + ", ".join(f"{row['id']} ({row['name']})" for row in attack))
    keys = correlation.get("campaign_keys") or []
    if keys:
        lines.append("campaign keys:")
        for key in keys[:24]:
            lines.append(f"  {key}")
        if len(keys) > 24:
            lines.append(f"  … {len(keys) - 24} more")
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    roles = "".join(
        f"<li><strong>{esc(r['name'])}</strong> ({esc(r['score'])})</li>" for r in report.get("roles") or []
    ) or "<li>none</li>"
    caps = "".join(f"<li>{esc(c['id'])}</li>" for c in report.get("capabilities") or []) or "<li>none</li>"
    surface = "".join(
        f"<tr><td>{esc(i['kind'])}</td><td><code>{esc(i['yara'])}</code></td><td>{esc(i['why'])}</td></tr>"
        for i in (report.get("surface_signatures") or {}).get("items") or []
    )
    iocs = "".join(
        f"<tr><td>{esc(row['layer'])}</td><td>{esc(row['kind'])}</td><td><code>{esc(row['value'])}</code></td></tr>"
        for row in report.get("indicators_by_layer") or []
    )
    correlation = report.get("correlation") or {}
    attack_rows = "".join(
        f"<tr><td><code>{esc(row.get('id'))}</code></td><td>{esc(row.get('name'))}</td><td>{esc(row.get('from'))}</td></tr>"
        for row in correlation.get("attack") or []
    ) or "<tr><td colspan='3'>none</td></tr>"
    campaign_keys = "".join(
        f"<li><code>{esc(key)}</code></li>" for key in (correlation.get("campaign_keys") or [])[:80]
    ) or "<li>none</li>"
    folds = "".join(
        f"<tr><td>{esc(item.get('layer'))}</td><td>{esc(item.get('kind'))}</td>"
        f"<td><code>{esc(item.get('callee'))}</code></td><td>{esc(item.get('reason'))}</td>"
        f"<td><code>{esc(item.get('snippet'))}</code></td></tr>"
        for item in report.get("unresolved_folds") or []
    ) or "<tr><td colspan='5'>none</td></tr>"
    warnings = "".join(f"<li>{esc(w)}</li>" for w in report.get("warnings") or []) or "<li>none</li>"
    yara = esc((report.get("surface_signatures") or {}).get("yara_rule") or "")
    sample = report.get("sample") or {}
    encoded = esc(", ".join(e.get("name", "") for e in report.get("encoded_not_analyzable") or []) or "none")
    cross = report.get("sandbox_cross_check") or {}
    cross_html = esc(cross.get("detail") or "")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Evilbox report</title>
<style>
body {{ font-family: sans-serif; margin: 1.5rem; color: #111; }}
code {{ font-size: 0.9em; word-break: break-all; }}
pre {{ white-space: pre-wrap; word-break: break-all; background: #f7f7f7; padding: 0.8rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
td, th {{ border: 1px solid #ccc; padding: 0.4rem 0.5rem; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f4; }}
</style></head><body>
<h1>Evilbox report</h1>
<p>path: {esc(sample.get("path"))}<br>
language: {esc(sample.get("language"))}<br>
sha256: <code>{esc(sample.get("sha256"))}</code><br>
inner: <code>{esc(sample.get("inner_sha256"))}</code><br>
cluster: <code>{esc(sample.get("cluster_sha256"))}</code><br>
cluster minhash: <code>{esc(sample.get("cluster_minhash"))}</code></p>
<p>packer: {esc(", ".join(report.get("packer") or []))}<br>
encoded, not analyzable: {encoded}<br>
failed folds: {esc(report.get("failed_folds"))}<br>
sandbox cross-check: {cross_html}</p>
<h2>Warnings</h2><ul>{warnings}</ul>
<h2>Roles</h2><ul>{roles}</ul>
<h2>Capabilities</h2><ul>{caps}</ul>
<h2>Unresolved folds</h2>
<table><tr><th>layer</th><th>kind</th><th>callee</th><th>why</th><th>snippet</th></tr>{folds}</table>
<h2>Surface signatures (original layer)</h2>
<table><tr><th>kind</th><th>YARA needle</th><th>why</th></tr>{surface}</table>
<h2>YARA rule</h2><pre>{yara}</pre>
<h2>Indicators by layer</h2>
<table><tr><th>layer</th><th>kind</th><th>value</th></tr>{iocs}</table>
<h2>ATT&amp;CK</h2>
<table><tr><th>id</th><th>name</th><th>from</th></tr>{attack_rows}</table>
<h2>Campaign keys</h2>
<ul>{campaign_keys}</ul>
</body></html>
"""


def dump_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"
