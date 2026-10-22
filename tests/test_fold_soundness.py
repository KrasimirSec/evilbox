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


def _php_statements(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def test_php_array_overwrite_keeps_last_key():
    """A later explicit key replaces the earlier element. eval must run that payload."""
    src = """<?php
$p = array("echo 'DECOY';", 0 => "echo 'REAL';");
eval($p[0]);
"""
    result = deobfuscate(src, language="php")
    statements = _php_statements(result.text)
    assert "echo 'REAL';" in statements
    assert "echo 'DECOY';" not in statements
    assert "eval(" not in result.text


def test_php_numeric_string_key_is_the_same_slot():
    src = """<?php
$p = array("0" => "echo 'DECOY';", 0 => "echo 'REAL';");
eval($p["0"]);
"""
    result = deobfuscate(src, language="php")
    statements = _php_statements(result.text)
    assert "echo 'REAL';" in statements
    assert "echo 'DECOY';" not in statements


def test_php_array_autoindex_after_explicit_key():
    src = """<?php
$p = array(0 => "echo 'FIRST';", "echo 'SECOND';");
eval($p[1]);
"""
    result = deobfuscate(src, language="php")
    assert "echo 'SECOND';" in _php_statements(result.text)
    assert "eval(" not in result.text


def test_php_array_hole_does_not_read_another_slot():
    src = """<?php
$p = array(2 => "echo 'A';", "echo 'B';");
eval($p[0]);
eval($p[2]);
eval($p[3]);
"""
    result = deobfuscate(src, language="php")
    compact = result.text.replace(" ", "")
    assert "eval($p[0])" in compact
    assert "echo 'A';" in _php_statements(result.text)
    assert "echo 'B';" in _php_statements(result.text)


def test_php_implode_keeps_keyed_elements():
    src = "<?php $y = implode('', array(1 => 'h', 'i'));"
    result = deobfuscate(src, language="php")
    assert "'hi'" in result.text.replace(" ", "")
    assert "'i'" not in result.text.replace(" ", "").replace("'hi'", "")


def test_php_nested_keyed_array_is_not_python_repr():
    src = """<?php $a = array(1 => array(2 => "echo 'REAL';")); eval($a[1][2]);"""
    result = deobfuscate(src, language="php")
    assert "Value(" not in result.text
    assert "echo 'REAL';" in _php_statements(result.text)
    assert "eval(" not in result.text


def test_php_array_key_casts_leave_non_decimal_strings():
    src = """<?php
$p = array("01" => "echo 'ZERO';", 1 => "echo 'ONE';", "+1" => "echo 'PLUS';");
eval($p["01"]);
eval($p[1]);
eval($p["+1"]);
"""
    result = deobfuscate(src, language="php")
    statements = _php_statements(result.text)
    assert "echo 'ZERO';" in statements
    assert "echo 'ONE';" in statements
    assert "echo 'PLUS';" in statements
    assert "eval(" not in result.text


def test_php_negative_array_key_then_append():
    src = """<?php
$p = array(-1 => "echo 'NEG';", "echo 'ZERO';");
eval($p[0]);
eval($p[-1]);
"""
    result = deobfuscate(src, language="php")
    statements = _php_statements(result.text)
    assert "echo 'ZERO';" in statements
    assert "echo 'NEG';" in statements
    assert "eval(" not in result.text


def test_php_float_and_bool_array_keys_truncate():
    src = """<?php
$a = array(1.9 => "echo 'FLOAT';", true => "echo 'BOOL';");
eval($a[1]);
"""
    result = deobfuscate(src, language="php")
    # true and 1.9 are both key 1; the later bool write wins.
    assert "echo 'BOOL';" in _php_statements(result.text)
    assert "echo 'FLOAT';" not in _php_statements(result.text)


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
