import base64
import zlib

from evilbox.pipeline import deobfuscate


def test_js_computed_fromcharcode():
    src = 'var x = String["fromCharCode"](72, 105);'
    result = deobfuscate(src, language="js")
    assert "Hi" in result.text
    assert "fromCharCode" not in result.text


def test_js_window_atob():
    src = 'eval(window["atob"]("Y29uc29sZS5sb2coJ2hpJyk7"));'
    result = deobfuscate(src, language="js")
    assert "console.log" in result.text
    assert "atob" not in result.text


def test_js_string_methods_and_reverse():
    src = 'var x = "dlrow".split("").reverse().join("") + "hello".charAt(0);'
    result = deobfuscate(src, language="js")
    assert "worldh" in result.text


def test_js_slice_concat_lower():
    src = 'var x = "HELLO".toLowerCase().concat(" ", "ab".slice(1));'
    result = deobfuscate(src, language="js")
    assert "hello b" in result.text


def test_js_parseint_and_tostring():
    src = "var n = parseInt('10', 16); var h = (255).toString(16);"
    result = deobfuscate(src, language="js")
    assert "16" in result.text
    assert "ff" in result.text


def test_js_array_join():
    src = 'var x = ["Hel", "lo"].join("");'
    result = deobfuscate(src, language="js")
    assert "Hello" in result.text


def test_js_string_index():
    src = 'var x = "abc"[1];'
    result = deobfuscate(src, language="js")
    assert '"b"' in result.text or "'b'" in result.text


def test_js_function_constructor():
    src = 'Function("console.log(1)");'
    result = deobfuscate(src, language="js")
    assert "console.log" in result.text
    assert "Function" not in result.text


def test_js_new_function():
    src = 'new Function("return 2");'
    result = deobfuscate(src, language="js")
    assert "return 2" in result.text


def test_js_fromcharcode_apply():
    src = "var x = String.fromCharCode.apply(null, [72, 105]);"
    result = deobfuscate(src, language="js")
    assert "Hi" in result.text


def test_js_eval_call():
    src = 'eval.call(null, "var z = 1;");'
    result = deobfuscate(src, language="js")
    assert "var z" in result.text


def test_js_unsigned_shift():
    src = "var x = (-1 >>> 0);"
    result = deobfuscate(src, language="js")
    assert "4294967295" in result.text


def test_js_const_string_eval():
    src = 'var s = "ok();"; eval(s);'
    result = deobfuscate(src, language="js")
    assert "ok()" in result.text


def test_js_template_const():
    src = 'var x = `hi ${"there"}`;'
    result = deobfuscate(src, language="js")
    assert "hi there" in result.text


def test_js_string_array_rotate_decoder():
    src = """
var _0x = ['world', 'hello'];
(function(a, n) {
  while (--n) { a.push(a.shift()); }
})(_0x, 2);
function _0xf(i) { i = i - 0; return _0x[i]; }
var x = _0xf(0) + _0xf(1);
"""
    result = deobfuscate(src, language="js")
    assert "hello" in result.text
    assert "world" in result.text


def test_js_decoder_with_offset():
    src = """
var arr = ['aa', 'bb', 'cc'];
function dec(i) { i = i - 1; return arr[i]; }
var x = dec(2);
"""
    result = deobfuscate(src, language="js")
    assert "bb" in result.text


def test_php_strrev_eval():
    inner = 'echo "g";'
    rev = inner[::-1]
    src = f"<?php eval(strrev('{rev}'));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "g" in result.text
    assert "strrev" not in result.text


def test_php_urldecode():
    src = "<?php eval(urldecode('%65%63%68%6f%20%22%75%22%3b'));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text


def test_php_str_replace_and_implode():
    src = "<?php $x = str_replace('X', 'e', 'Xcho'); $y = implode('', array('h', 'i'));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "hi" in result.text


def test_php_sprintf_substr():
    src = "<?php $x = sprintf('%s%s', 'ab', 'cd'); $y = substr('hello', 1, 3);"
    result = deobfuscate(src, language="php")
    assert "abcd" in result.text
    assert "ell" in result.text


def test_php_bitwise_not_eval():
    payload = 'echo "k";'
    neg = bytes((~b) & 0xFF for b in payload.encode("latin-1"))
    esc = "".join("\\x%02x" % b for b in neg)
    src = f'<?php eval(~"{esc}");'
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "k" in result.text


def test_php_variable_function_base64():
    inner = 'echo "vfn";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php $a = 'base64_decode'; eval($a('{b64}'));"
    result = deobfuscate(src, language="php")
    assert "vfn" in result.text
    assert "base64_decode" not in result.text or "$a" in result.text


def test_php_nested_strrev_base64():
    payload = b'echo "revb64";'
    b64 = base64.b64encode(payload).decode()
    rev = b64[::-1]
    src = f"<?php eval(base64_decode(strrev('{rev}')));"
    result = deobfuscate(src, language="php")
    assert "revb64" in result.text


def test_php_gzinflate_strrev():
    payload = b'echo "flip";'
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(payload) + compressor.flush()
    b64 = base64.b64encode(raw).decode()
    rev = b64[::-1]
    src = f"<?php eval(gzinflate(base64_decode(strrev('{rev}'))));"
    result = deobfuscate(src, language="php")
    assert "flip" in result.text


def test_php_stripslashes_and_upper():
    src = r"<?php $x = stripslashes('a\'b'); $y = strtoupper('ok');"
    result = deobfuscate(src, language="php")
    assert "a'b" in result.text or "a\\'b" in result.text
    assert "OK" in result.text
