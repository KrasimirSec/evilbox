import base64
import gzip
import io
import zlib
from pathlib import Path

from evilbox.pipeline import deobfuscate

FIXTURES = Path(__file__).parent / "fixtures"


def test_js_fromcharcode_and_concat():
    src = 'var x = String.fromCharCode(72,101,108,108,111) + " " + "world";'
    result = deobfuscate(src, language="js")
    assert "Hello world" in result.text
    assert "fromCharCode" not in result.text


def test_js_eval_atob():
    inner = "console.log('hi');"
    b64 = base64.b64encode(inner.encode()).decode()
    src = f'eval(atob("{b64}"));'
    result = deobfuscate(src, language="js")
    assert "console.log" in result.text
    assert "atob" not in result.text
    assert "eval" not in result.text


def test_js_hex_string_unescape():
    src = r'var a = "\x48\x69";'
    result = deobfuscate(src, language="js")
    assert "Hi" in result.text


def test_js_array_lookup_concat():
    src = 'var a = ["en"]; var b = [39, "op"]; var x = b[1] + a[0];'
    result = deobfuscate(src, language="js")
    assert "open" in result.text


def test_js_array_literal_index_identifier():
    src = "var x = [26, -9, WScript, 34][2];"
    result = deobfuscate(src, language="js")
    assert "WScript" in result.text
    assert "[2]" not in result.text


def test_js_rename_junk():
    src = "var _0xabc123 = 1; console.log(_0xabc123);"
    result = deobfuscate(src, language="js")
    assert "_0xabc123" not in result.text
    assert "v0" in result.text


def test_php_eval_base64():
    inner = 'echo "hi";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php eval(base64_decode('{b64}'));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "hi" in result.text
    assert "base64_decode" not in result.text
    assert "eval" not in result.text


def _gzinflate_b64(payload: str) -> str:
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(payload.encode("latin-1")) + compressor.flush()
    return base64.b64encode(raw).decode("ascii")


def test_php_nested_gzinflate_base64():
    payload = b'echo "nested";'
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(payload) + compressor.flush()
    b64 = base64.b64encode(raw).decode()
    src = f"<?php eval(gzinflate(base64_decode('{b64}')));"
    result = deobfuscate(src, language="php")
    assert "nested" in result.text
    assert "gzinflate" not in result.text
    assert "base64_decode" not in result.text


def test_php_parser_gaps_do_not_drop_decoded_payload():
    """tree-sitter-php rejects valid PHP that shows up in unpacked shells.

    SELF/PARENT constants, `$var[keyword]` / `$var->keyword` interpolation
    (any case, heredoc, backtick, binary string), and a __halt_compiler trailer
    must not cause the pipeline to revert to the packed eval().
    """
    inner = """
define('SELF', 'script.php');
define('PARENT', 'parent.php');
class Box {
    function id() { return self::class; }
}
class Child extends Box {
    function parent_id() { return parent::class; }
}
@header('Location: '.SELF);
echo PARENT;
echo Self;
echo (SELF);
$arg = array('class' => 'c', 'title' => 't');
p("$arg[title]<input class=\\"$arg[class]\\" />");
p("$arg[CLASS]");
p("$obj->class");
echo <<<E
$b[function]
E;
echo <<<'NOW'
$a[class]
NOW;
echo b"$bin[class]";
echo B"$wide[class]";
echo `id $tick[class]`;
echo Foo::SELF;
?>
<div>{keep-html}</div>
<?PHP
echo 1;
"""
    src = "<?php eval(gzinflate(base64_decode('" + _gzinflate_b64(inner) + "')));"
    result = deobfuscate(src, language="php")
    assert "gzinflate" not in result.text
    assert "base64_decode" not in result.text
    assert "define('SELF'" in result.text
    assert "constant('SELF')" in result.text
    assert "constant('PARENT')" in result.text
    assert "constant('Self')" in result.text
    assert "self::class" in result.text
    assert "parent::class" in result.text
    assert "Foo::SELF" in result.text
    assert 'class="c"' in result.text
    assert "{$arg['CLASS']}" in result.text
    assert ">t<" in result.text or "t<input" in result.text
    assert "{$obj->class}" in result.text
    assert "{$b['function']}" in result.text
    assert "{$bin['class']}" in result.text
    assert "{$wide['class']}" in result.text
    assert "{$tick['class']}" in result.text
    assert "`id{$tick['class']}`" in "".join(result.text.split())
    assert "$a[class]" in result.text
    assert "{keep-html}" in result.text
    assert result.parse_ok
    assert result.failed_folds is False


def test_php_control_char_string_fold_stays_parseable():
    """Folding "\\x00" must not emit a raw NUL that the parser then rejects."""
    inner = r"""$search = array("\x00", "\x0a", "\x0d", "\x1a"); echo $search[0];"""
    src = "<?php eval(gzinflate(base64_decode('" + _gzinflate_b64(inner) + "')));"
    result = deobfuscate(src, language="php")
    assert result.parse_ok
    assert "\0" not in result.text
    assert "gzinflate" not in result.text
    assert "\\x00" in result.text or "\\0" in result.text


def test_php_new_self_is_not_rewritten_as_a_constant():
    """`new self` must survive a parser-gap repair.

    tree-sitter rejects `"$arg[class]"`, so the repair runs. `new self` is the
    enclosing class, not a constant. `new constant('self')` still parses and
    instantiates a class named constant.
    """
    src = """<?php
class Box {
    function make() { return new self; }
    function make2() { return new self(); }
}
class Child extends Box {
    function make3() { return new parent; }
    function make4() { return NEW parent(); }
    function check($x) { return $x instanceof self || $x InstanceOf parent; }
}
define('SELF', 'script.php');
define('PARENT', 'parent.php');
echo SELF;
echo (PARENT);
echo "$arg[class]";
"""
    result = deobfuscate(src, language="php")
    assert result.parse_ok
    assert "new self;" in result.text
    assert "new self();" in result.text
    assert "new parent;" in result.text
    assert "NEW parent();" in result.text
    assert "instanceof self" in result.text
    assert "InstanceOf parent" in result.text
    assert "new constant(" not in result.text
    assert "instanceof constant(" not in result.text
    assert "constant('SELF')" in result.text
    assert "constant('PARENT')" in result.text
    assert "{$arg['class']}" in result.text


def test_php_keyword_index_in_valid_file_is_left_alone():
    src = '<?php echo "$arg[title]";'
    result = deobfuscate(src, language="php")
    assert '"$arg[title]"' in result.text
    assert "constant(" not in result.text


def test_php_halt_compiler_trailer_does_not_hide_payload():
    inner = "echo 'kept-halt';\n__halt_compiler();\nNOT PHP\n"
    blob = _gzinflate_b64(inner)
    src = "<?php eval(gzinflate(base64_decode('" + blob + "')));"
    result = deobfuscate(src, language="php")
    assert "kept-halt" in result.text
    assert blob not in result.text
    assert "gzinflate" not in result.text


def test_unparsed_binary_is_not_treated_as_a_decode():
    from evilbox.pipeline import keep_decoded_despite_parse_errors

    before = "<?php eval(gzinflate(base64_decode('" + ("A" * 80) + "')));"
    assert keep_decoded_despite_parse_errors(before, "\x00" * 40, "php") is False
    assert keep_decoded_despite_parse_errors(before, "this is not php source", "php") is False
    assert keep_decoded_despite_parse_errors(before, "<?php echo 'unpacked';", "php") is True


def test_php_gzdecode():
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b'echo "gz";')
    b64 = base64.b64encode(buf.getvalue()).decode()
    src = f"<?php eval(gzdecode(base64_decode('{b64}')));"
    result = deobfuscate(src, language="php")
    assert "gz" in result.text


def test_php_string_concat_and_fold():
    src = "<?php $x = 'hel' . 'lo'; $n = 1 + 2;"
    result = deobfuscate(src, language="php")
    assert "hello" in result.text
    assert "3" in result.text


def test_php_rot13():
    src = "<?php eval(str_rot13('rpub \"ebg\";'));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "rot" in result.text
    assert "str_rot13" not in result.text


def _rot13_gzinflate_blob(payload: str) -> str:
    """str_rot13(gzdeflate(str_rot13(payload))) as base64, matching the bh.php wrapper."""
    import codecs

    rot = codecs.encode(payload, "rot_13")
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(rot.encode("latin-1")) + compressor.flush()
    twisted = codecs.encode(raw.decode("latin-1"), "rot_13")
    return base64.b64encode(twisted.encode("latin-1")).decode("ascii")


def test_php_dead_payload_assignment_is_dropped():
    """A variable used only as eval() ciphertext must not survive next to the shell."""
    marker = "FilesMan" + ("-" * 40)
    payload = f"$default_action = '{marker}';\n" + "\n".join(
        f"$row{i} = 'cell-{i}-" + ("q" * 30) + "';" for i in range(30)
    )
    blob = _rot13_gzinflate_blob(payload)
    assert len(blob) >= 80
    src = (
        "<?php $blackhat = '"
        + blob
        + "'; eval(str_rot13(gzinflate(str_rot13(base64_decode(($blackhat))))));"
    )
    result = deobfuscate(src, language="php")
    assert marker in result.text
    assert "$default_action" in result.text
    assert blob not in result.text
    assert "$blackhat" not in result.text
    assert "gzinflate" not in result.text
    assert "Dropped unused payload assignment" in " ".join(result.warnings)


def test_php_payload_assignment_kept_when_still_read():
    marker = "kept-payload"
    pad = "".join("abcdefghijklmnopqrstuvwxyz012345"[(i * 7 + 3) % 32] for i in range(180))
    payload = f"echo '{marker}'; /* {pad} */"
    blob = _rot13_gzinflate_blob(payload)
    assert len(blob) >= 80
    src = (
        "<?php $blackhat = '"
        + blob
        + "'; eval(str_rot13(gzinflate(str_rot13(base64_decode($blackhat))))); echo $blackhat;"
    )
    result = deobfuscate(src, language="php")
    assert marker in result.text
    assert "$blackhat" in result.text
    assert blob in result.text


def test_fixture_js_fromcharcode():
    src = (FIXTURES / "fromcharcode.js").read_text(encoding="utf-8")
    result = deobfuscate(src, language="auto", path=str(FIXTURES / "fromcharcode.js"))
    assert result.language == "js"
    assert "Hello world" in result.text


def test_fixture_php_eval_base64():
    src = (FIXTURES / "eval_base64.php").read_text(encoding="utf-8")
    result = deobfuscate(src, language="auto", path=str(FIXTURES / "eval_base64.php"))
    assert result.language == "php"
    assert "echo" in result.text
    assert "hi" in result.text
