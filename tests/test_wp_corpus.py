from pathlib import Path

from evilbox.pipeline import deobfuscate
from evilbox.signature import extract_surface

CORPUS = Path(__file__).parent / "corpus" / "wordpress_benign"


def test_malware_yara_and_pcre_do_not_match_wp_corpus():
    packed = "<?php eval(gzinflate(base64_decode('Sy1LzSspSs0rSSwA0voA'))); $evilbox_campaign_zz = 1;"
    surface = extract_surface(packed, language="php")
    needles = [item.pcre for item in surface.items if item.kind in {"code-sequence", "string"}]
    assert needles
    hits = []
    for path in sorted(CORPUS.glob("*.php")):
        text = path.read_text(encoding="utf-8")
        for item in surface.items:
            if item.kind not in {"code-sequence", "string"}:
                continue
            if item.value and item.value in text:
                hits.append((path.name, item.kind, item.value[:40]))
    assert hits == []


def test_wp_corpus_is_not_classified_as_webshell():
    for path in sorted(CORPUS.glob("*.php")):
        result = deobfuscate(path.read_text(encoding="utf-8"), language="php", path=str(path))
        roles = {role.name for role in result.classification.roles}
        assert "webshell" not in roles
        assert "stealer" not in roles
        assert "dropper" not in roles
        assert not any(item.kind == "code-sequence" for item in result.surface.items)
