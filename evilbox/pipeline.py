from __future__ import annotations

from dataclasses import dataclass, field

from evilbox.classify import Classification, classify_layers, cluster_key
from evilbox.detect import detect_language
from evilbox.extract import Indicators, extract_indicators, locate_indicators
from evilbox.hashutil import sha256_text
from evilbox.js.passes import transform_js
from evilbox.js.pretty import pretty_js
from evilbox.packer import packer_hints
from evilbox.parsers import parse_js, parse_php
from evilbox.php.passes import transform_php
from evilbox.php.pretty import pretty_php
from evilbox.rewrite import has_error
from evilbox.signature import SurfaceSignatures, extract_surface
from evilbox.unwrap import unwrap_source


@dataclass
class Layer:
    name: str
    kind: str
    text: str
    sha256: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "sha256": self.sha256,
            "size": len(self.text),
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


def _layer(name: str, kind: str, text: str) -> Layer:
    return Layer(name=name, kind=kind, text=text, sha256=sha256_text(text))


def deobfuscate(
    source: str,
    *,
    language: str = "auto",
    path: str | None = None,
    max_passes: int = 16,
    surface_text: str | None = None,
) -> Result:
    lang = detect_language(source, path=path, lang=language)
    warnings: list[str] = []
    original = surface_text if surface_text is not None else source
    transform = transform_js if lang == "js" else transform_php
    parse = parse_js if lang == "js" else parse_php
    layers = [_layer("original", "original", original)]
    text = source
    if surface_text is not None and source != original:
        layers.append(_layer("eval-dump", "eval-dump", source))

    for index in range(max(1, max_passes)):
        nxt, unwrap_warnings = unwrap_source(text, lang)
        warnings.extend(unwrap_warnings)
        transformed, pass_warnings = transform(nxt)
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
        layers.append(_layer(f"pass-{index + 1}", "unwrap", text))

    pretty = pretty_js if lang == "js" else pretty_php
    pretty_text = pretty(text)
    if pretty_text != text:
        text = pretty_text
        layers.append(_layer("inner", "pretty", text))
    else:
        layers.append(_layer("inner", "inner", text))

    tree = parse(text)
    parse_ok = not has_error(tree.root_node)
    if not parse_ok:
        warnings.append("Parse still reports errors after deobfuscation.")
    indicators = extract_indicators(text, original)
    layer_pairs = [(layer.name, layer.text) for layer in layers]
    classification = classify_layers(layer_pairs)
    surface = extract_surface(original, language=lang)
    return Result(
        text=text,
        language=lang,
        warnings=warnings,
        parse_ok=parse_ok,
        indicators=indicators,
        layers=layers,
        packer=packer_hints(original),
        classification=classification,
        surface=surface,
        indicators_by_layer=locate_indicators(layer_pairs),
        original_sha256=sha256_text(original),
        inner_sha256=sha256_text(text),
        cluster_sha256=cluster_key(text),
    )
