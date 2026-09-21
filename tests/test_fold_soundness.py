"""Reproduced fold-soundness, regex hang, resource, and classifier bugs."""

from __future__ import annotations

import time

import pytest

from evilbox.classify import classify_layers
from evilbox.cli import main
from evilbox.pipeline import deobfuscate
from evilbox.signature import STRING_LIT_RE, extract_surface


def test_php_reassignment_is_not_folded():
    src = "<?php $a='base64_decode'; echo $a('aGVsbG8='); $a='strrev';"
    result = deobfuscate(src, language="php")
    assert "hello" in result.text
    assert "=8GbsVGa" not in result.text


def test_php_two_functions_reuse_variable_name():
    src = """<?php
function f() { $a = 'base64_decode'; echo $a('aGVsbG8='); }
function g() { $a = 'strrev'; echo $a('olleh'); }
"""
    result = deobfuscate(src, language="php")
    assert "hello" in result.text
    assert "strrev('olleh')" not in result.text.replace(" ", "")


def test_php_loop_concat_is_not_collapsed():
    src = "<?php $s = ''; for ($i = 0; $i < 0; $i++) { $s .= 'ab'; } echo $s;"
    result = deobfuscate(src, language="php")
    assert ".$=" in result.text.replace(" ", "") or ".=" in result.text
    assert "echo 'ab'" not in result.text


def test_js_loop_concat_is_not_collapsed():
    src = "var s = ''; for (var i = 0; i < 0; i++) { s += 'ab'; } console.log(s);"
    result = deobfuscate(src, language="js")
    assert "+=" in result.text
    assert "console.log(\"ab\")" not in result.text


def test_unterminated_quote_does_not_hang():
    blob = "'" + ("\\" * 60)
    started = time.perf_counter()
    list(STRING_LIT_RE.finditer(blob))
    extract_surface(blob, language="php")
    assert time.perf_counter() - started < 1.0


def test_long_chr_chain_does_not_recursion_error():
    parts = [f"chr({ord('A') + (i % 26)})" for i in range(500)]
    src = "<?php echo " + ".".join(parts) + ";"
    result = deobfuscate(src, language="php")
    assert "chr(" not in result.text
    assert "A" in result.text


def test_long_fromcharcode_concat_does_not_recursion_error():
    parts = [f"String.fromCharCode({65 + (i % 26)})" for i in range(1000)]
    src = "var x = " + " + ".join(parts) + ";"
    result = deobfuscate(src, language="js")
    assert "fromCharCode" not in result.text
    assert "A" in result.text


def test_huge_shift_does_not_raise():
    src = "<?php echo 1 << 20000;"
    result = deobfuscate(src, language="php")
    assert "<<" in result.text


def test_batch_isolates_failures_and_unique_names(tmp_path):
    root = tmp_path / "samples"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir()
    (root / "a" / "index.php").write_text("<?php echo 1+1;", encoding="utf-8")
    (root / "b" / "index.php").write_text("<?php echo 2+2;", encoding="utf-8")
    (root / "bad.php").write_text("<?php echo 1 << 20000;", encoding="utf-8")
    out = tmp_path / "out"
    assert main([str(root), "-o", str(out)]) in {0, 1}
    assert (out / "a" / "index.clean.php").is_file()
    assert (out / "b" / "index.clean.php").is_file()
    assert (out / "a" / "index.clean.php").read_text(encoding="utf-8") != (
        out / "b" / "index.clean.php"
    ).read_text(encoding="utf-8")


def test_wp_cache_plugin_is_not_stealer_or_dropper():
    src = r"""<?php
/**
 * Plugin Name: Example Cache
 */
if (!defined('ABSPATH')) { exit; }
$cache_file = WP_CONTENT_DIR . '/cache/page.html';
$html = file_get_contents($cache_file);
file_put_contents($cache_file, $html);
echo '<input type="password" name="pwd" />';
"""
    result = deobfuscate(src, language="php")
    roles = {role.name for role in result.classification.roles}
    assert "stealer" not in roles
    assert "dropper" not in roles
    cls = classify_layers([("original", src)], language="php")
    assert "stealer" not in {r.name for r in cls.roles}
    assert "dropper" not in {r.name for r in cls.roles}


def test_eval_dumps_are_separate_layers():
    original = "<?php eval($x);"
    dump1 = '<?php file_get_contents("http://first.example/a");'
    dump2 = '<?php file_get_contents("http://second.example/b");'
    result = deobfuscate(
        dump2,
        language="php",
        surface_text=original,
        extra_layers=[("eval-dump-1", dump1)],
    )
    names = [layer.name for layer in result.layers]
    assert "eval-dump-1" in names
    blob = " ".join(row["value"] for row in result.indicators_by_layer)
    assert "first.example" in blob
    assert "second.example" in blob
    hypothesis = pytest.importorskip("hypothesis")
    from hypothesis import given, settings
    from hypothesis import strategies as st

    @settings(max_examples=40, deadline=1000)
    @given(st.integers(min_value=0, max_value=80))
    def _run(n: int) -> None:
        blob = "'" + ("\\" * n)
        started = time.perf_counter()
        list(STRING_LIT_RE.finditer(blob))
        assert time.perf_counter() - started < 0.5

    _run()
