import base64
import hashlib
import zlib

from evilbox.decode import pas_autokey_decrypt, pas_recover_payload
from evilbox.packer import packer_hints
from evilbox.pipeline import deobfuscate


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _pas_encrypt(plain: bytes, password: str) -> bytes:
    pw = password.encode("latin-1")
    key = bytearray(
        hashlib.md5(pw).hexdigest().encode("ascii") + hashlib.md5(pw[::-1]).hexdigest().encode("ascii")[: len(pw)]
    )
    out = bytearray()
    for byte in plain:
        out.append((byte + key[len(out)]) % 256)
        key.append(byte)
    return bytes(out)


INNER = (
    "@ini_set('display_errors',0); echo 'pas-inner-ok'; "
    "function pas_marker(){ return 1; }"
)


def _wrap_pas(inner: str = INNER, password: str = "root", cookie: str = "sP") -> str:
    raw = _raw_deflate(inner.encode("latin-1"))
    enc = _pas_encrypt(raw, password)
    b64 = base64.b64encode(enc).decode("ascii")
    wrapped = "\n".join(b64[i : i + 76] for i in range(0, len(b64), 76))
    size = len(enc)
    return (
        "<?php $g___g_='base'.(32*2).'_de'.'code';"
        f"$g___g_=$g___g_(str_replace(\"\\n\", '', '{wrapped}'));"
        f"if(isset($_COOKIE['{cookie}']) && $_COOKIE['{cookie}']!==NULL){{"
        f"$g__g_=$_COOKIE['{cookie}'];"
        "$g__g_=md5($g__g_).substr(md5(strrev($g__g_)),0,strlen($g__g_));"
        f"for($g____g_=0;$g____g_<{size};$g____g_++){{"
        "$g___g_[$g____g_]=chr(( ord($g___g_[$g____g_])-ord($g__g_[$g____g_]))%256);"
        "$g__g_.=$g___g_[$g____g_];}"
        "if($g___g_=@gzinflate($g___g_)){$g____g_=create_function('',$g___g_);"
        "unset($g___g_,$g__g_);$g____g_();}} @header(\"Status: 404 Not Found\"); ?>"
    )


def test_pas_recover_payload_roundtrip():
    raw = _raw_deflate(INNER.encode("latin-1"))
    enc = _pas_encrypt(raw, "root")
    assert pas_autokey_decrypt(enc, "root") == raw
    hit = pas_recover_payload(enc)
    assert hit is not None
    payload, password = hit
    assert password == "root"
    assert b"pas-inner-ok" in payload


def test_pas_keyed_unwrap_cookie_root():
    src = _wrap_pas()
    assert "pas-keyed" in packer_hints(src)
    result = deobfuscate(src, language="php")
    assert "pas-inner-ok" in result.text
    assert "create_function" not in result.text
    assert "gzinflate" not in result.text
    assert any("PAS autokey" in w for w in result.warnings)
    assert "pas-keyed" in result.packer


def test_pas_keyed_keeps_html_payload_when_folds_fail():
    inner = (
        "@ini_set('display_errors',0); echo 'pas-html-ok'; "
        "function pas_marker(){ return 1; } ?>"
        "<table class='list'><tr><td><?php echo 1;"
    )
    src = _wrap_pas(inner)
    result = deobfuscate(src, language="php")
    assert "pas-html-ok" in result.text
    assert "create_function" not in result.text


def test_php_variable_function_self_assign():
    src = "<?php $a='base64_decode'; $a=$a('aGVsbG8='); echo $a;"
    result = deobfuscate(src, language="php")
    assert "hello" in result.text
    assert "$a(" not in result.text.replace(" ", "")
