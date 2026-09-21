from __future__ import annotations

from dataclasses import dataclass, field

from evilbox.classify import Classification, classify_layers, cluster_key, cluster_minhash
from evilbox.detect import detect_language
from evilbox.encoders import detect_commercial_encoders
from evilbox.extract import Indicators, extract_indicators, locate_indicators
from evilbox.hashutil import minhash_jaccard, minhash_values, sha256_text
from evilbox.js.passes import transform_js
from evilbox.js.pretty import pretty_js
from evilbox.packer import packer_hints
from evilbox.parsers import parse_js, parse_php
from evilbox.php.passes import transform_php
from evilbox.php.pretty import pretty_php
from evilbox.rewrite import has_error
from evilbox.signature import SurfaceSignatures, extract_surface
from evilbox.unresolved import UnresolvedFold, scan_unresolved
from evilbox.unwrap import unwrap_source


@dataclass
class Layer:
    name: str
    kind: str
    text: str
    sha256: str
    unresolved: list[UnresolvedFold] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "sha256": self.sha256,
            "size": len(self.text),
            "unresolved_folds": [item.to_dict() for item in self.unresolved],
        }


@dataclass
class Result:
    text: str
    language: str
    warnings: list[str]
    parse_ok: bool
    indicators: Indicators
    layers: list[Layer] = field(default_factory=list)
    packer: list[str] = field(default_factory=list)
    classification: Classification = field(default_factory=lambda: Classification([], []))
    surface: SurfaceSignatures = field(default_factory=SurfaceSignatures)
    indicators_by_layer: list[dict[str, str]] = field(default_factory=list)
    original_sha256: str = ""
    inner_sha256: str = ""
    cluster_sha256: str = ""
    cluster_minhash: str = ""
    unresolved_folds: list[UnresolvedFold] = field(default_factory=list)
    failed_folds: bool = False
    encoded_not_analyzable: list[dict[str, str]] = field(default_factory=list)
    php_version: str = "8.3"
    sandbox_cross_check: dict | None = None


def _layer(name: str, kind: str, text: str, *, language: str) -> Layer:
    layer = Layer(name=name, kind=kind, text=text, sha256=sha256_text(text))
    layer.unresolved = scan_unresolved(text, language=language, layer=name)
    return layer


def deobfuscate(
    source: str,
    *,
    language: str = "auto",
    path: str | None = None,
    max_passes: int = 16,
    surface_text: str | None = None,
    php_version: str = "8.3",
) -> Result:
    lang = detect_language(source, path=path, lang=language)
    warnings: list[str] = []
    original = surface_text if surface_text is not None else source
    parse = parse_js if lang == "js" else parse_php
    layers = [_layer("original", "original", original, language=lang)]
    text = source
    if surface_text is not None and source != original:
        layers.append(_layer("eval-dump", "eval-dump", source, language=lang))

    encoders = detect_commercial_encoders(original)
    if encoders:
        for hit in encoders:
            warnings.append(f"{hit.name}: {hit.detail}")

    for index in range(max(1, max_passes)):
        nxt, unwrap_warnings = unwrap_source(text, lang)
        warnings.extend(unwrap_warnings)
        if lang == "php":
            transformed, pass_warnings = transform_php(
                nxt, php_version=php_version, path=path, original=original
            )
        else:
            transformed, pass_warnings = transform_js(nxt)
        warnings.extend(pass_warnings)
        nxt = transformed
        if nxt == text:
            break
        tree = parse(nxt)
        if has_error(tree.root_node):
            warnings.append("A pass produced unparseable code; keeping the previous version of that rewrite.")
            prev_tree = parse(text)
            if not has_error(prev_tree.root_node):
                break
        text = nxt
        layers.append(_layer(f"pass-{index + 1}", "unwrap", text, language=lang))

    pretty = pretty_js if lang == "js" else pretty_php
    pretty_text = pretty(text)
    if pretty_text != text:
        text = pretty_text
        layers.append(_layer("inner", "pretty", text, language=lang))
    else:
        layers.append(_layer("inner", "inner", text, language=lang))

    tree = parse(text)
    parse_ok = not has_error(tree.root_node)
    if not parse_ok:
        warnings.append("Parse still reports errors after deobfuscation.")
    if any("recovered" in w for w in warnings):
        layers[-1].unresolved.append(
            UnresolvedFold(
                layer=layers[-1].name,
                kind="recovered",
                callee="convert_uudecode",
                snippet="",
                reason="uudecode used padding recovery; bytes may be wrong",
            )
        )

    unresolved = [item for layer in layers for item in layer.unresolved]
    inner_unresolved = list(layers[-1].unresolved)
    failed_folds = any(
        item.kind in {"decoder", "packer", "recovered"} for item in inner_unresolved
    )
    if encoders:
        failed_folds = True

    indicators = extract_indicators(text, original)
    layer_pairs = [(layer.name, layer.text) for layer in layers]
    classification = classify_layers(layer_pairs)
    surface = extract_surface(original, language=lang)
    packer = packer_hints(original)
    for hit in encoders:
        if hit.name not in packer:
            packer.append(hit.name)

    sandbox_cross_check = None

    return Result(
        text=text,
        language=lang,
        warnings=warnings,
        parse_ok=parse_ok,
        indicators=indicators,
        layers=layers,
        packer=packer,
        classification=classification,
        surface=surface,
        indicators_by_layer=locate_indicators(layer_pairs),
        original_sha256=sha256_text(original),
        inner_sha256=sha256_text(text),
        cluster_sha256=cluster_key(text),
        cluster_minhash=cluster_minhash(text),
        unresolved_folds=unresolved,
        failed_folds=failed_folds,
        encoded_not_analyzable=[hit.to_dict() for hit in encoders],
        php_version=php_version,
        sandbox_cross_check=sandbox_cross_check,
    )


def cross_check_layers(
    *,
    original_inner: str | None,
    dump_text: str | None,
    static_text: str | None,
) -> dict:
    """Compare static inner layer against a sandbox eval dump."""
    static = static_text or ""
    dump = dump_text or ""
    other = original_inner or dump
    same_hash = sha256_text(static) == sha256_text(other) if other else False
    score = minhash_jaccard(minhash_values(static), minhash_values(other)) if other else 0.0
    agree = same_hash or score >= 0.8
    return {
        "agree": agree,
        "jaccard": round(score, 3),
        "static_inner_sha256": sha256_text(static),
        "dump_sha256": sha256_text(dump) if dump else "",
        "detail": "static inner matches sandbox dump" if agree else "static inner disagrees with sandbox dump",
    }
