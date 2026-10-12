import base64

from evilbox.pipeline import deobfuscate


def _xor_latin1(text: str, key: str) -> str:
    return "".join(chr(ord(ch) ^ ord(key[i % len(key)])) for i, ch in enumerate(text))


def test_js_interp_subtract_mod_loop():
    plain = "https://interp.example/gate"
    key = "k3y"
    encoded = "".join(
        chr((ord(ch) + ord(key[i % len(key)])) % 256) for i, ch in enumerate(plain)
    )
    blob = base64.b64encode(encoded.encode("latin-1")).decode("ascii")
    src = (
        "(function(b,k){var r=\"\",x=atob(b);for(var i=0;i<x.length;i++)"
        "r+=String.fromCharCode((x.charCodeAt(i)-k.charCodeAt(i%k.length)+256)%256);"
        f'return r;}})("{blob}","{key}")'
    )
    result = deobfuscate(src, language="js")
    assert plain in result.text
    assert "interp.example" in result.indicators.domains
    assert any("Interpreted a constant JS function" in w for w in result.warnings)


def test_js_interp_while_concat_and_push_join():
    blob = base64.b64encode(b"hello-push").decode("ascii")
    src = (
        "(function(b){var x=atob(b),a=[],i=0;while(i<x.length){a.push(x.charAt(i));i++;}"
        f'return a.join("");}})("{blob}")'
    )
    result = deobfuscate(src, language="js")
    assert "hello-push" in result.text


def test_js_loop_concat_is_still_not_wrongly_collapsed():
    src = "var s = ''; for (var i = 0; i < 0; i++) { s += 'ab'; } console.log(s);"
    result = deobfuscate(src, language="js")
    assert "+=" in result.text
    assert "console.log(\"ab\")" not in result.text


def test_php_anonymous_xor_function():
    inner = "echo 'anon-unpacked';"
    key = "k9"
    xored = _xor_latin1(inner, key)
    blob = base64.b64encode(xored.encode("latin-1")).decode("ascii")
    src = (
        "<?php\n"
        "$p = (function($b,$k){ $x=base64_decode($b); $r=''; "
        "for($i=0;$i<strlen($x);$i++){ $r.=chr(ord($x[$i])^ord($k[$i%strlen($k)])); } "
        f"return $r; }})('{blob}', '{key}');\n"
        "eval($p);\n"
    )
    result = deobfuscate(src, language="php")
    assert "anon-unpacked" in result.text


def test_php_while_xor_loop_eval():
    inner = "echo 'while-unpacked';"
    key = "wz"
    xored = _xor_latin1(inner, key)
    blob = base64.b64encode(xored.encode("latin-1")).decode("ascii")
    src = (
        "<?php\n"
        f"$d=base64_decode('{blob}');\n"
        f"$k='{key}';\n"
        "$o=''; $i=0;\n"
        "while($i<strlen($d)){ $o.=chr(ord($d[$i])^ord($k[$i%strlen($k)])); $i++; }\n"
        "eval($o);\n"
    )
    result = deobfuscate(src, language="php")
    assert "while-unpacked" in result.text
    assert any("Interpreted a constant PHP loop" in w for w in result.warnings)


def test_php_loop_concat_is_still_not_wrongly_collapsed():
    src = "<?php $s = ''; for ($i = 0; $i < 0; $i++) { $s .= 'ab'; } echo $s;"
    result = deobfuscate(src, language="php")
    assert ".$=" in result.text.replace(" ", "") or ".=" in result.text
    assert "echo 'ab'" not in result.text
