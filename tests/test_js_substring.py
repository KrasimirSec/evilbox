from evilbox.pipeline import deobfuscate

URL = "https://evil.example/payload.js"


def test_js_substring_clamps_negatives_and_swaps_ends():
    """JS substring is not Python slicing.

    A negative start is 0, so the whole URL survives. A reversed range is
    swapped, so the host is kept instead of being sliced away.
    """
    src = (
        f'var url = "{URL}";\n'
        "var whole = url.substring(-8);\n"
        "var tail = url.substring(31, 8);\n"
        'var mid = "abcdef".substring(4, 1);\n'
        'var prefix = "abcdef".substring(2, -1);\n'
    )
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert f'var whole = "{URL}";' in result.text
    assert 'var tail = "evil.example/payload.js";' in result.text
    assert 'var mid = "bcd";' in result.text
    assert 'var prefix = "ab";' in result.text
    assert 'var whole = "load.js"' not in result.text
    assert 'var tail = ""' not in result.text
    assert 'var prefix = "cde"' not in result.text


def test_js_slice_and_substr_keep_their_own_index_rules():
    src = 'var tail = "abcdef".slice(-3);\nvar pair = "abcdef".substr(2, 2);\n'
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert 'var tail = "def";' in result.text
    assert 'var pair = "cd";' in result.text
