import binascii
import gzip
import random
import zlib

import pytest

from evilbox.decode import (
    MAX_CODEC_OUTPUT,
    expand_php_charlist,
    gzip_bytes,
    php_b64decode,
    php_bitwise_not,
    php_str_pad,
    php_string_bytes,
    php_strtoupper,
    php_substr,
    raw_inflate,
    stripslashes,
    uudecode_ex,
    xor_strings,
)
from evilbox.phpdiff import php_binary, php_eval_json


def _php_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def test_php_base64_uses_the_standard_alphabet():
    """'_' and '-' are ignored, not read as '/' and '+'."""
    assert php_b64decode("_ZWNobyAnaGknOw") == b"echo 'hi';"
    assert php_b64decode("ZWNo-byAnaGknOw") == b"echo 'hi';"
    assert php_b64decode("ZWNobyAnaGknOw") == b"echo 'hi';"
    # '=' is not a digit. The two chunks are one bit stream, not two payloads.
    assert php_b64decode("YQ==YQ==") == php_b64decode("YQYQ")
    assert php_b64decode("ZWNobyAnaGknOw!!!", strict=True) is None
    assert php_b64decode("ZWNobyAnaGknOw", strict=True) == b"echo 'hi';"
    assert php_b64decode("YQ", strict=True) == b"a"
    assert php_b64decode("YQ=", strict=True) is None


@pytest.mark.skipif(php_binary() is None, reason="php CLI not installed")
def test_php_base64_matches_interpreter():
    rng = random.Random(2026)
    for strict in (False, True):
        for _ in range(30):
            raw = bytes(rng.randrange(256) for _ in range(rng.randint(0, 24))).decode("latin-1")
            chars = ",".join(str(ord(ch)) for ch in raw)
            flag = ", true" if strict else ""
            expr = f"base64_decode(pack('C*', {chars}){flag})" if chars else f"base64_decode(''{flag})"
            php_val = php_eval_json(expr)
            ours = php_b64decode(raw, strict=strict)
            if ours is None:
                assert php_val is False
            else:
                assert php_val == ours.decode("latin-1")


def test_stripslashes_nul_and_trailing_backslash():
    assert stripslashes("a\\0b") == "a\0b"
    assert stripslashes("foo\\") == "foo"
    assert stripslashes("a\\'b") == "a'b"
    assert stripslashes("\\\\") == "\\"


def test_php_bitwise_not_rejects_non_bytes():
    assert php_bitwise_not("A") == chr((~0x41) & 0xFF)
    with pytest.raises(ValueError):
        php_bitwise_not("Ω")
    with pytest.raises(ValueError):
        php_string_bytes("日本語")
    with pytest.raises(ValueError):
        xor_strings("A", "Ω")


def test_php_substr_version_oob():
    assert php_substr("abc", 10, php_version="8.3") == ""
    assert php_substr("abc", 10, php_version="7.4") is False
    assert php_substr("abc", 10, php_version="5.6") is False
    assert php_substr("abcdef", 4, -4, php_version="8.3") == ""
    assert php_substr("abcdef", 4, -4, php_version="7.4") is False
    assert php_substr("hello", 1, 3, php_version="7.4") == "ell"


def test_uudecode_padding_is_recovered():
    payload = b"hello-uu"
    encoded = binascii.b2a_uu(payload).decode("ascii")
    clean = uudecode_ex(encoded)
    assert clean is not None
    assert clean.data == payload
    assert clean.recovered is False
    truncated = encoded.split("\n")[0][:8]
    recovered = uudecode_ex(truncated)
    assert recovered is not None
    assert recovered.recovered is True
    assert recovered.data != payload


def test_inflate_output_is_capped():
    compressor = zlib.compressobj(wbits=-15)
    huge = compressor.compress(b"A" * (MAX_CODEC_OUTPUT + 4096)) + compressor.flush()
    assert raw_inflate(huge) is None
    gzipped = gzip.compress(b"B" * (MAX_CODEC_OUTPUT + 1024))
    assert gzip_bytes(gzipped) is None
    small = zlib.compressobj(wbits=-15).compress(b"ok") + zlib.compressobj(wbits=-15).flush()
    # the compressor above was already flushed; build a fresh small blob
    c = zlib.compressobj(wbits=-15)
    small = c.compress(b"ok") + c.flush()
    assert raw_inflate(small) == b"ok"


@pytest.mark.skipif(php_binary() is None, reason="php CLI not installed")
def test_php_differential_property_folds():
    rng = random.Random(2026)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\\\\0'"
    for _ in range(24):
        raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        php_val = php_eval_json("stripslashes(" + _php_quote(raw) + ")")
        assert php_val == stripslashes(raw)

    sample = "abcdefghij"
    major = php_eval_json("PHP_MAJOR_VERSION")
    version = f"{major}.0"
    for start in (-12, -1, 0, 3, 10, 11):
        for length in (None, -8, -1, 0, 2, 20):
            args = f"{_php_quote(sample)}, {start}"
            if length is not None:
                args += f", {length}"
            php_val = php_eval_json(f"substr({args})")
            ours = php_substr(sample, start, length, php_version=version)
            assert php_val == ours

    assert php_strtoupper("abc\xff") == "ABC\xff"
    assert expand_php_charlist("a..c") == "abc"
    assert php_str_pad("x", 5, "ab", 1) == "xabab"

    chars = [chr(n) for n in range(32, 127) if chr(n) not in "'\\"]
    for _ in range(16):
        raw = "".join(rng.choice(chars) for _ in range(rng.randint(1, 12)))
        php_val = php_eval_json("~" + _php_quote(raw))
        assert php_val == php_bitwise_not(raw)
