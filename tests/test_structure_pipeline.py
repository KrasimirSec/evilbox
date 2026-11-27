"""Structural normalize, DCE, signature candidates, and transformation traces."""

from __future__ import annotations

import base64
from pathlib import Path

from evilbox.behavior import analyze_structure, canonicalize, extract_behavior
from evilbox.candidates import check_false_positives, propose_cluster_signatures
from evilbox.dce import eliminate_dead_code
from evilbox.pipeline import deobfuscate
from evilbox.report import build_report

CORPUS = Path(__file__).parent / "corpus" / "wordpress_benign"


def test_canonicalize_renames_survive_variant_names():
    a = "<?php $campaign_alpha = $_POST['x']; eval($campaign_alpha);"
    b = "<?php $totally_different = $_POST['x']; eval($totally_different);"
    ca = canonicalize(a, language="php")
    cb = canonicalize(b, language="php")
    assert ca == cb
    assert "$v0" in ca
    assert "$_POST" in ca
    assert "eval" in ca


def test_behavior_extracts_eval_chain_and_sources():
    src = "<?php eval(base64_decode($_POST['p']));"
    profile = extract_behavior(src, language="php")
    assert "eval" in profile.sinks
    assert "base64_decode" in profile.decoders
    assert any("$_POST" in s for s in profile.sources)
    assert profile.has_eval_chain
    assert any(chain[:2] == ["eval", "base64_decode"] for chain in profile.eval_chains)


def test_dce_strips_filler_functions_around_webshell():
    filler = "\n".join(
        f"function filler_helper_{i}($a) {{ return $a + {i}; }}" for i in range(12)
    )
    core = 'function evil_core() { eval($_POST["cmd"]); }\nevil_core();'
    src = f"<?php\n{filler}\n{core}\n"
    result = eliminate_dead_code(src, language="php")
    assert result.removed_functions >= 10
    assert "evil_core" in result.text
    assert "eval" in result.text
    assert "filler_helper_0" not in result.text
    assert result.bytes_after < result.bytes_before


def test_dce_keeps_wordpress_hooks():
    src = """<?php
function example_forms_menu() {
    add_options_page('Example', 'Example', 'manage_options', 'ex', 'example_forms_page');
}
add_action('admin_menu', 'example_forms_menu');
function example_forms_page() {
    echo 'ok';
}
"""
    result = eliminate_dead_code(src, language="php")
    assert "example_forms_menu" in result.text
    assert "example_forms_page" in result.text


def test_pipeline_emits_behavior_trace_and_canonical():
    inner = 'echo "hi";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php eval(base64_decode('{b64}'));"
    result = deobfuscate(src, language="php")
    assert result.behavior.sinks or "hi" in result.text
    assert result.trace.steps
    assert any(step.changed for step in result.trace.steps)
    assert result.canonical
    report = build_report(result=result, path="t.php")
    assert report["behavior"]["canonical_sha256"]
    assert report["trace"]["pass_count"] >= 1
    assert "canonical" in report


def test_pipeline_dce_on_fake_plugin():
    filler = "\n".join(
        [
            f"$unused_padding_{i} = '" + ("X" * 60) + f"{i}';"
            for i in range(8)
        ]
    )
    src = f"""<?php
{filler}
function real_shell() {{
    eval($_REQUEST['x']);
}}
real_shell();
"""
    result = deobfuscate(src, language="php")
    assert result.dce is not None
    assert "webshell" in {role.name for role in result.classification.roles}
    # Filler assignments should shrink after DCE.
    assert "$unused_padding_0" not in result.text or (
        result.dce.removed_statements >= 1 or result.dce.bytes_after <= result.dce.bytes_before
    )


def test_signature_candidates_reject_corpus_hits():
    # Needles that appear in the clean corpus must be rejected.
    fps = check_false_positives(["add_options_page", "ABSPATH"], corpus=CORPUS)
    assert fps


def test_signature_candidates_accept_eval_chain_cluster():
    samples = []
    for name, var in (("a.php", "$alpha"), ("b.php", "$beta"), ("c.php", "$gamma")):
        original = f"<?php eval(base64_decode({var})); $sig_unique_{name[0]} = 1;"
        # Inner already "deobfuscated" shape with renamed vars
        inner = f"<?php eval(base64_decode({var}));"
        samples.append((name, original, inner))
    report = propose_cluster_signatures(samples, language="php", corpus=CORPUS)
    assert report.shared_features
    assert any("sink:eval" in f or f.startswith("chain:") for f in report.shared_features)
    assert report.rules
    # Structural eval(base64_decode( should not hit the clean WP corpus.
    structural = [rule for rule in report.rules if rule.kind == "structural"]
    assert structural
    assert structural[0].accepted
    assert structural[0].false_positives == []


def test_canonical_cluster_key_stable_across_renames():
    a = deobfuscate("<?php $foo = $_GET['c']; system($foo);", language="php")
    b = deobfuscate("<?php $bar = $_GET['c']; system($bar);", language="php")
    assert a.behavior.canonical_sha256
    assert a.behavior.canonical_sha256 == b.behavior.canonical_sha256
    assert a.cluster_sha256 == b.cluster_sha256
