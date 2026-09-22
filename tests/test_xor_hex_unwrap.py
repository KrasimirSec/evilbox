import base64
import zlib

from evilbox.pipeline import deobfuscate
from evilbox.unresolved import scan_unresolved
from evilbox.unwrap import unwrap_hex_php_blob, unwrap_quoted_eval_chain


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


def test_php_repeating_xor_loop_eval():
    inner = "echo 'xor-unpacked';"
    compressed = _raw_deflate(inner.encode("latin-1"))
    key = b"bSnrop"
    xored = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(compressed))
    blob = base64.b64encode(xored).decode("ascii")
    src = (
        "<?php\n"
        "$dwE7sB = 'bas';\n"
        "$Xrp5oU = 'gzi';\n"
        "$dwE7sB .= 'e64_decode';\n"
        "$Xrp5oU .= 'nflate';\n"
        f"$TXxQkK = '{blob}';\n"
        "$TXxQkK=$dwE7sB($TXxQkK);\n"
        "$w51OVjmKQ='';\n"
        '$bV3bY="bSnrop";\n'
        f"for($i=0;$i<{len(xored)};$i++)"
        "$w51OVjmKQ.=chr(ord($TXxQkK[$i])^ord($bV3bY[$i%6]));\n"
        "@eval($Xrp5oU($w51OVjmKQ));\n"
    )
    result = deobfuscate(src, language="php")
    assert "xor-unpacked" in result.text
    assert any("XOR" in warning for warning in result.warnings)
    assert "xor-chr-loop" in result.packer


def test_php_hex2ascii_blob_unwrap():
    payload = "$auth_pass = '';\nfunction FilesMan() { echo 'wso-hex'; }\n" + ("// pad\n" * 20)
    hexed = payload.encode("latin-1").hex()
    src = (
        "<?php\n"
        f"$___ = '{hexed}';\n"
        "function hex2ascii($p)\n"
        "{\n"
        "    $r = '';\n"
        "    for ($i = 0; $i < strLen($p); $i += 2) {\n"
        "        $r .= chr(hexdec($p[$i] . $p[$i + 1]));\n"
        "    }\n"
        "    return $r;\n"
        "}\n"
        "$__ = hex2ascii($___);\n"
        '$X = "{$__}";\n'
        "print($X);\n"
    )
    text, notes = unwrap_hex_php_blob(src)
    assert notes
    assert "FilesMan" in text
    result = deobfuscate(src, language="php")
    assert "FilesMan" in result.text
    assert "wso-hex" in result.text
    assert "hex2ascii" in result.packer
    assert "hex-php-blob" in result.packer


def test_php_quoted_eval_gzinflate_print():
    inner = "echo 'quoted-payload';"
    blob = base64.b64encode(_raw_deflate(inner.encode("latin-1"))).decode("ascii")
    src = "<?php print 'eval(gzinflate(base64_decode(\\'" + blob + "\\')));';"
    text, notes = unwrap_quoted_eval_chain(src)
    assert notes
    assert "quoted-payload" in text
    result = deobfuscate(src, language="php")
    assert "quoted-payload" in result.text
    assert "quoted-eval-chain" in result.packer


def test_latin1_scan_unresolved_does_not_crash():
    src = "<?php echo '\x83\x94'; $x = base64_decode($y);"
    found = scan_unresolved(src, language="php", layer="test")
    assert isinstance(found, list)


def test_html_entity_outside_latin1_does_not_crash():
    src = '<?php echo "&rsquo; and &inodot;"; $a = 1+1;'
    result = deobfuscate(src, language="php")
    assert result.parse_ok
    assert "2" in result.text or "1+1" in result.text
    assert "&rsquo;" in result.text or "rsquo" in result.text
