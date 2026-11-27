"""Signature candidate generator over a cluster of normalized samples.

Finds invariants that survive renaming and filler, proposes a scanner rule,
then checks the rule against a clean WordPress plugin/theme corpus so false
positives are rejected before an analyst spends time on them.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from evilbox.behavior import BehaviorProfile, analyze_structure
from evilbox.hashutil import sha256_text
from evilbox.signature import SurfaceItem, extract_surface, render_yara_rule, yara_escape, pcre_escape

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "tests" / "corpus" / "wordpress_benign"


@dataclass
class CandidateRule:
    """A proposed detection rule with false-positive check results."""

    kind: str
    features: list[str]
    needles: list[str]
    yara_rule: str
    pcre: list[str]
    support: int
    cluster_size: int
    false_positives: list[str] = field(default_factory=list)
    accepted: bool = False
    why: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "features": list(self.features),
            "needles": list(self.needles),
            "yara_rule": self.yara_rule,
            "pcre": list(self.pcre),
            "support": self.support,
            "cluster_size": self.cluster_size,
            "false_positives": list(self.false_positives),
            "accepted": self.accepted,
            "why": self.why,
        }


@dataclass
class CandidateReport:
    cluster_id: str
    samples: list[str]
    rules: list[CandidateRule] = field(default_factory=list)
    shared_features: list[str] = field(default_factory=list)
    canonical_agreement: float = 0.0

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "samples": list(self.samples),
            "shared_features": list(self.shared_features),
            "canonical_agreement": self.canonical_agreement,
            "rules": [rule.to_dict() for rule in self.rules],
            "accepted_count": sum(1 for rule in self.rules if rule.accepted),
        }


def _feature_sets(profiles: list[BehaviorProfile]) -> list[set[str]]:
    return [set(profile.features) for profile in profiles]


def _shared_features(profiles: list[BehaviorProfile], *, min_ratio: float = 1.0) -> list[str]:
    if not profiles:
        return []
    counts: Counter[str] = Counter()
    for profile in profiles:
        for feature in set(profile.features):
            # Ignore per-sample canonical digests when looking for invariants.
            if feature.startswith("canon:"):
                continue
            counts[feature] += 1
    need = max(1, int(len(profiles) * min_ratio + 0.999))
    shared = [feature for feature, count in counts.items() if count >= need]
    # Prefer structural chain/sink features first.
    rank = {"chain": 0, "flag": 1, "sink": 2, "source": 3, "decoder": 4}
    shared.sort(key=lambda f: (rank.get(f.split(":", 1)[0], 9), f))
    return shared


def _structural_needles(features: list[str]) -> list[str]:
    """Turn shared behavior features into scanner-visible textual needles where possible."""
    needles: list[str] = []
    for feature in features:
        if feature.startswith("chain:"):
            parts = feature.split(":", 1)[1].split(">")
            if len(parts) >= 2:
                # eval(base64_decode( style surface
                needles.append(f"{parts[0]}({parts[1]}(")
        elif feature.startswith("sink:") and feature.split(":", 1)[1] in {
            "eval",
            "assert",
            "create_function",
            "system",
            "passthru",
            "shell_exec",
            "preg_replace",
        }:
            needles.append(feature.split(":", 1)[1] + "(")
        elif feature.startswith("source:"):
            needles.append(feature.split(":", 1)[1])
    # Dedup preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for needle in needles:
        key = needle.lower()
        if key in seen or len(needle) < 3:
            continue
        seen.add(key)
        out.append(needle)
    return out


def _surface_invariants(sources: list[str], *, language: str, min_ratio: float = 1.0) -> list[str]:
    """Needles from the original packed layer that appear in enough samples."""
    counts: Counter[str] = Counter()
    for source in sources:
        surface = extract_surface(source, language=language)
        for item in surface.items:
            if item.kind not in {"code-sequence", "string"}:
                continue
            if len(item.value) < 8:
                continue
            # Prefer short distinctive needles already computed for YARA.
            counts[item.yara] += 1
    need = max(1, int(len(sources) * min_ratio + 0.999))
    return [needle for needle, count in counts.most_common() if count >= need][:12]


def check_false_positives(
    needles: list[str],
    *,
    corpus: Path | None = None,
) -> list[str]:
    """Return corpus file names that contain any proposed needle (case-insensitive)."""
    root = corpus or DEFAULT_CORPUS
    if not root.is_dir():
        return []
    hits: list[str] = []
    lowered = [(needle, needle.lower()) for needle in needles if needle]
    for path in sorted(root.glob("*.php")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lower = text.lower()
        for needle, needle_l in lowered:
            if needle_l and needle_l in lower:
                hits.append(f"{path.name}:{needle[:40]}")
                break
    return hits


def propose_cluster_signatures(
    samples: list[tuple[str, str, str]],
    *,
    language: str = "php",
    corpus: Path | None = None,
    min_support_ratio: float = 1.0,
    cluster_id: str | None = None,
) -> CandidateReport:
    """samples: (path, original_source, inner_deobfuscated_text).

    Builds behavior profiles on the inner layer, finds invariants, proposes
    structural and surface rules, and false-positive-checks them.
    """
    if not samples:
        return CandidateReport(cluster_id=cluster_id or "empty", samples=[])

    paths = [path for path, _original, _inner in samples]
    originals = [original for _path, original, _inner in samples]
    inners = [inner for _path, _original, inner in samples]
    profiles = [analyze_structure(inner, language=language) for inner in inners]
    shared = _shared_features(profiles, min_ratio=min_support_ratio)

    # Canonical agreement: fraction of samples sharing the most common digest.
    digests = [profile.canonical_sha256 for profile in profiles if profile.canonical_sha256]
    agreement = 0.0
    if digests:
        most = Counter(digests).most_common(1)[0][1]
        agreement = most / len(digests)

    cid = cluster_id or sha256_text("|".join(sorted(paths)))[:16]
    report = CandidateReport(
        cluster_id=cid,
        samples=paths,
        shared_features=shared,
        canonical_agreement=round(agreement, 3),
    )

    # Structural rule from shared behavior features.
    structural_needles = _structural_needles(shared)
    if structural_needles or shared:
        items = [
            SurfaceItem(
                kind="behavior",
                value=needle,
                yara=yara_escape(needle),
                pcre=pcre_escape(needle),
                why="invariant after normalization across cluster",
            )
            for needle in structural_needles
        ]
        # If we only have abstract features (no textual needle), encode features as meta.
        yara = render_yara_rule(items, rule_name=f"evilbox_struct_{cid}")
        if not items and shared:
            # Feature-only rule: condition false for scanners, but kept for analysts.
            feature_blob = ", ".join(shared[:12])
            yara = (
                f"rule evilbox_struct_{re.sub(r'[^A-Za-z0-9_]', '_', cid)}\n"
                "{\n"
                "  meta:\n"
                '    tool = "evilbox"\n'
                '    kind = "structural-features"\n'
                f'    features = "{yara_escape(feature_blob)}"\n'
                "  strings:\n"
                '    $empty = "evilbox-feature-only" ascii\n'
                "  condition:\n"
                "    false\n"
                "}\n"
            )
        fps = check_false_positives(structural_needles, corpus=corpus) if structural_needles else []
        accepted = bool(structural_needles) and not fps
        why = "shared behavior features after canonicalization"
        if fps:
            why = "rejected: needles hit clean WordPress corpus"
        elif not structural_needles:
            why = "feature-only structural summary (no scanner needle)"
            accepted = False
        report.rules.append(
            CandidateRule(
                kind="structural",
                features=shared,
                needles=structural_needles,
                yara_rule=yara,
                pcre=[pcre_escape(n) for n in structural_needles],
                support=len(samples),
                cluster_size=len(samples),
                false_positives=fps,
                accepted=accepted,
                why=why,
            )
        )

    # Surface invariants from the packed originals.
    surface_needles = _surface_invariants(originals, language=language, min_ratio=min_support_ratio)
    if surface_needles:
        items = [
            SurfaceItem(
                kind="code-sequence",
                value=needle,
                yara=needle,
                pcre=pcre_escape(needle),
                why="invariant packed-layer needle across cluster",
            )
            for needle in surface_needles
        ]
        yara = render_yara_rule(items, rule_name=f"evilbox_surface_cluster_{cid}")
        # check_false_positives needs the raw needle text (unescape basic yara escapes)
        raw = [needle.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\") for needle in surface_needles]
        fps = check_false_positives(raw, corpus=corpus)
        report.rules.append(
            CandidateRule(
                kind="surface-cluster",
                features=[],
                needles=surface_needles,
                yara_rule=yara,
                pcre=[pcre_escape(n) for n in raw],
                support=len(samples),
                cluster_size=len(samples),
                false_positives=fps,
                accepted=not fps,
                why="shared original-layer needles" if not fps else "rejected: needles hit clean WordPress corpus",
            )
        )

    return report


def propose_from_cluster_groups(
    groups: dict[str, list[str]],
    sample_data: dict[str, tuple[str, str]],
    *,
    language: str = "php",
    corpus: Path | None = None,
    min_cluster_size: int = 2,
) -> list[CandidateReport]:
    """groups: cluster_minhash -> paths; sample_data: path -> (original, inner)."""
    reports: list[CandidateReport] = []
    for cluster_key, paths in groups.items():
        if len(paths) < min_cluster_size:
            continue
        samples: list[tuple[str, str, str]] = []
        for path in paths:
            if path not in sample_data:
                continue
            original, inner = sample_data[path]
            samples.append((path, original, inner))
        if len(samples) < min_cluster_size:
            continue
        # Infer language from first path when mixed batches are unlikely.
        lang = language
        if language == "auto":
            lang = "js" if samples[0][0].lower().endswith(".js") else "php"
        reports.append(
            propose_cluster_signatures(
                samples,
                language=lang,
                corpus=corpus,
                cluster_id=cluster_key[:16],
            )
        )
    return reports
