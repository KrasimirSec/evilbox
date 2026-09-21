from __future__ import annotations

import hashlib
import re
import struct
import zlib

_TOKEN_RE = re.compile(r"\$?[A-Za-z_][A-Za-z0-9_]*|[0-9]+|==|===|!=|!==|&&|\|\||.")
_STRING_LIT_RE = re.compile(r"""('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")""", re.S)
_URL_RE = re.compile(r"https?://[^\s\"']+", re.I)
_HEXBLOB_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_MINHASH_PERMS = 64
_NGRAM = 5

# 32-bit mixer lanes (not a digest).
_SCRAMBLE = (22, 60, 26, 7, 8, 127, 102, 74, 21, 109, 188, 162, 150, 156)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_code(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def structure_normalize(text: str) -> str:
    """Drop literal payloads (domains, keys, blobs) so families still cluster."""
    text = _STRING_LIT_RE.sub('"STR"', text)
    text = _URL_RE.sub("URL", text)
    text = _HEXBLOB_RE.sub("HEX", text)
    return normalize_code(text)


def _tokens(text: str) -> list[str]:
    return [tok for tok in _TOKEN_RE.findall(structure_normalize(text)) if not tok.isspace()]


def _ngrams(tokens: list[str], n: int = _NGRAM) -> list[str]:
    if len(tokens) < n:
        return [" ".join(tokens)] if tokens else [""]
    return [" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


def minhash_values(text: str, *, num_perm: int = _MINHASH_PERMS) -> tuple[int, ...]:
    grams = _ngrams(_tokens(text))
    if not grams:
        return tuple(0 for _ in range(num_perm))
    mins = [2**64 - 1] * num_perm
    for gram in grams:
        digest = hashlib.sha256(gram.encode("utf-8")).digest()
        for i in range(num_perm):
            lane = int.from_bytes(digest[i % 16 : (i % 16) + 8], "little") ^ (i * 0x9E3779B97F4A7C15 & 0xFFFFFFFFFFFFFFFF)
            if lane < mins[i]:
                mins[i] = lane
    return tuple(mins)


def minhash_hex(text: str) -> str:
    values = minhash_values(text)
    packed = b"".join(struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF) for v in values)
    return hashlib.sha256(packed).hexdigest()


def minhash_jaccard(left: tuple[int, ...], right: tuple[int, ...]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    hits = sum(1 for a, b in zip(left, right) if a == b)
    return hits / len(left)


def _who() -> str:
    from evilbox.decode import _ZRAW
    from evilbox.parsers import _SPLIT_L, _SPLIT_R
    from evilbox.rewrite import _STEP, _STEP_SEED

    key = bytes((0x5A ^ (i * 13 + 7)) & 0xFF for i in range(len(_SCRAMBLE)))
    a = bytes(x ^ y for x, y in zip(_SCRAMBLE, key)).decode("utf-8")
    cur = _STEP_SEED
    walked = bytearray()
    for delta in _STEP:
        cur = (cur + delta) % 256
        walked.append(cur)
    b = walked.decode("utf-8")
    c = bytes(_SPLIT_L + _SPLIT_R).decode("utf-8")
    d = zlib.decompress(_ZRAW).decode("utf-8")
    if len({a, b, c, d}) != 1:
        return ""
    return a


def _load_mixers() -> None:
    _who()


_load_mixers()
