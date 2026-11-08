import base64

from evilbox.classify import classify_layers
from evilbox.pipeline import deobfuscate
from evilbox.signature import extract_surface


def test_php_array_lookup():
    src = '<?php $a = array("en", "op"); $x = $a[1] . $a[0];'
    result = deobfuscate(src, language="php")
    assert "open" in result.text


def test_php_string_xor():
    # 'P' ^ ' ' == 'p'  (0x50 ^ 0x20)
    src = "<?php $x = 'P' ^ ' ';"
    result = deobfuscate(src, language="php")
    assert "p" in result.text.lower()


def test_php_string_xor_keeps_bytes_past_the_shorter_operand():
    """A shorter key is NUL-padded, so the tail of the payload still runs.

    PHP `^` does not repeat the key and does not stop at the shorter length.
    Truncating here turned `eval($code ^ $mask)` into `e;` and dropped the shell.
    """
    src = r"""<?php
$mask = "\x07";
$code = "\x62cho 'LIVE';";
eval($code ^ $mask);
"""
    result = deobfuscate(src, language="php")
    assert "echo 'LIVE';" in result.text
    assert "\ne;" not in result.text


def test_php_assert_base64():
    inner = 'echo "asserted";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php assert(base64_decode('{b64}'));"
    result = deobfuscate(src, language="php")
    assert "asserted" in result.text
    assert "base64_decode" not in result.text


def test_php_include_decoded():
    inner = '<?php echo "inc";'
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php include(base64_decode('{b64}'));"
    result = deobfuscate(src, language="php")
    assert "inc" in result.text


def test_php_preg_replace_e():
    src = '<?php preg_replace("/.*/e", "echo \\"preg\\";", "x");'
    result = deobfuscate(src, language="php")
    assert "preg" in result.text


def test_php_create_function():
    src = '<?php create_function("", "echo \\"cf\\";");'
    result = deobfuscate(src, language="php")
    assert "cf" in result.text


def test_php_chr_and_strtr():
    src = "<?php $a = chr(65); $b = strtr('abc', 'a', 'z');"
    result = deobfuscate(src, language="php")
    assert "A" in result.text
    assert "zbc" in result.text


def test_layers_include_original_and_inner():
    inner = "echo 1;"
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php eval(base64_decode('{b64}'));"
    result = deobfuscate(src, language="php")
    names = [layer.name for layer in result.layers]
    assert names[0] == "original"
    assert "inner" in names
    assert result.original_sha256 != result.inner_sha256
    assert "eval+base64" in result.packer


def test_surface_from_original_not_inner():
    payload = "this-inner-unique-token-should-not-be-a-surface-string"
    b64 = base64.b64encode(f"echo '{payload}';".encode()).decode()
    src = f"<?php eval(base64_decode('{b64}')); $sig_campaign_var = 1;"
    result = deobfuscate(src, language="php")
    blob = " ".join(item.value for item in result.surface.items)
    assert payload not in blob
    assert b64[:24] in blob or any(b64[:16] in i.yara for i in result.surface.items)
    assert any(i.value == "$sig_campaign_var" for i in result.surface.items)
    assert any(i.kind == "code-sequence" and "eval" in i.value.lower() for i in result.surface.items)


def test_classify_webshell():
    src = '<?php eval($_POST["x"]); system($_GET["c"]);'
    result = deobfuscate(src, language="php")
    names = [r.name for r in result.classification.roles]
    assert "webshell" in names
    assert any(c.id == "eval-runtime" for c in result.classification.capabilities)


def test_classify_dropper_js():
    src = 'var u = "http://evil.example/drop.exe"; var x = new ActiveXObject("MSXML2.XMLHTTP");'
    result = deobfuscate(src, language="js")
    names = [r.name for r in result.classification.roles]
    assert "dropper" in names


def test_classify_seo():
    src = '<?php if (preg_match("/googlebot/i", $_SERVER["HTTP_USER_AGENT"])) { echo "<a href=\'http://spam.example/\' style=\'display:none\'>cheap meds</a>"; }'
    result = deobfuscate(src, language="php")
    names = [r.name for r in result.classification.roles]
    assert "seo-spam" in names


def test_cluster_key_stable():
    a = deobfuscate("var x = 1;\n", language="js")
    b = deobfuscate("var   x=1;", language="js")
    assert a.cluster_sha256 == b.cluster_sha256


def test_indicators_by_layer():
    src = 'var x = "http://evil.example/a.exe";'
    result = deobfuscate(src, language="js")
    assert any(row["kind"] == "urls" and row["layer"] == "original" for row in result.indicators_by_layer)


def test_classify_layers_helper():
    cls = classify_layers([("inner", "<?php mail($_POST['t'], 'x', 'y');")])
    assert "mailer" in [r.name for r in cls.roles]
