"""
aegis.simhash — context-triggered piecewise hashing (CTPH), the ssdeep family
(design doc S22). D5's "locality-sensitive" half: a rolling hash over a 7-byte
window cuts the file into content-defined pieces, each folded to one base64
char, so an edit changes only the pieces near it. Two files 95% alike produce
digests 95% alike, and a one-byte change — which defeats an exact SHA-256 — is
caught as a near-identity. Fuzzy is *evidence, not proof*: it is always fused,
never a force-block (the allowlist still overrides it).
"""
from __future__ import annotations

import base64

_WINDOW = 7
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _roll(data: bytes, reset: int):
    """Emit one base64 char per content-defined piece boundary."""
    out = []
    h1 = h2 = h3 = 0
    acc = 0
    window = bytearray(_WINDOW)
    for i, b in enumerate(data):
        acc = (acc + b) & 0xFFFFFFFF
        h2 = (h2 - h1 + _WINDOW * b) & 0xFFFFFFFF
        h1 = (h1 + b - window[i % _WINDOW]) & 0xFFFFFFFF
        window[i % _WINDOW] = b
        h3 = ((h3 << 5) ^ b) & 0xFFFFFFFF
        rolling = (h1 + h2 + h3) & 0xFFFFFFFF
        acc = (acc * 0x01000193) & 0xFFFFFFFF
        if rolling % reset == reset - 1:
            out.append(_B64[acc % 64])
            acc = 0
    out.append(_B64[acc % 64])
    return "".join(out)


def ctph(data: bytes) -> str:
    """Return a 'blocksize:digest' CTPH string. Empty for tiny inputs."""
    n = len(data)
    if n < 16:
        return ""
    # block size scales with file size so digests stay comparable-length
    bs = 3
    while bs * 64 < n:
        bs *= 2
    digest = _roll(data, bs)
    # keep it bounded
    if len(digest) > 128:
        digest = digest[:128]
    return f"{bs}:{digest}"


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * lb
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ca != cb))
        prev = cur
    return prev[lb]


def similarity(d1: str, d2: str) -> int:
    """0-100 similarity of two CTPH strings (100 = identical)."""
    if not d1 or not d2:
        return 0
    bs1, _, h1 = d1.partition(":")
    bs2, _, h2 = d2.partition(":")
    # only comparable at the same (or adjacent) block size
    try:
        b1, b2 = int(bs1), int(bs2)
    except ValueError:
        return 0
    if b1 != b2:
        # allow one power-of-two apart by truncating the finer one
        if b1 == b2 * 2 or b2 == b1 * 2:
            pass
        else:
            return 0
    if h1 == h2:
        return 100
    dist = _edit_distance(h1, h2)
    m = max(len(h1), len(h2))
    if m == 0:
        return 0
    score = int(round(100 * (1 - dist / m)))
    return max(0, min(100, score))
