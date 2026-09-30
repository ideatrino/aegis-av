"""
aegis.features — the feature vector for the learned detectors (design doc S10).

A byte histogram alone drew a spurious benign-vs-noise boundary (S4), so the
vector also carries summary statistics and a structural block from the PE/ELF
parser (section count, entropy spread, import count, W^X sections, risk-group
presence, injection flag), so D4/D6 learn a real benign-vs-malicious-structure
boundary.
"""
from __future__ import annotations

import math
import numpy as np

from . import peparse

FEATURE_DIM = 256 + 8 + 8  # histogram + summary stats + structural block


def _entropy_of(counts, n):
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


# API risk groups that D3 also scores (kept here for the structural block)
_INJECTION = {"virtualallocex", "writeprocessmemory", "createremotethread",
              "ntunmapviewofsection", "queueuserapc", "setwindowshookexw"}
_NETWORK = {"wsastartup", "connect", "send", "recv", "internetopenw",
            "internetconnectw", "httpsendrequestw", "urldownloadtofilew"}
_CRYPTO = {"cryptencrypt", "cryptacquirecontextw", "cryptgenkey",
           "bcryptencrypt", "cryptderivekey"}
_PERSIST = {"regsetvalueexw", "regcreatekeyexw", "createservicew"}


def extract(data: bytes) -> np.ndarray:
    v = np.zeros(FEATURE_DIM, dtype=np.float64)
    n = len(data)
    if n == 0:
        return v
    # byte histogram (normalized)
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    v[:256] = counts / n

    # summary stats block (256..264)
    ent = _entropy_of(counts, n)
    printable = int(sum(counts[32:127]))
    nulls = int(counts[0])
    v[256] = ent / 8.0
    v[257] = min(1.0, math.log10(n + 1) / 8.0)     # log size
    v[258] = printable / n                          # printable ratio
    v[259] = nulls / n                              # null ratio
    v[260] = counts.max() / n                        # peak byte freq
    v[261] = int((counts > 0).sum()) / 256.0         # byte diversity
    # windowed max entropy (packing signal)
    v[262] = _windowed_max_entropy(data) / 8.0
    v[263] = 1.0 if data[:2] == b"MZ" or data[:4] == b"\x7fELF" else 0.0

    # structural block (264..272) from PE/ELF parse
    info = peparse.parse(data)
    if info.parsed:
        imports_lower = {i.split(".")[-1].lower() for i in info.imports}
        v[264] = min(1.0, len(info.sections) / 16.0)
        v[265] = info.entropy_spread / 8.0
        v[266] = min(1.0, len(info.imports) / 256.0)
        v[267] = min(1.0, info.wx_sections / 4.0)
        v[268] = 1.0 if imports_lower & _INJECTION else 0.0
        v[269] = 1.0 if imports_lower & _NETWORK else 0.0
        v[270] = 1.0 if (imports_lower & _CRYPTO) and (imports_lower & _PERSIST) else 0.0
        v[271] = 1.0 if info.has_signature else 0.0
    return v


def _windowed_max_entropy(data: bytes, win: int = 2048) -> float:
    if len(data) <= win:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        return _entropy_of(counts, len(data))
    best = 0.0
    step = max(win, len(data) // 16)
    for i in range(0, len(data) - win, step):
        chunk = data[i:i + win]
        counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
        best = max(best, _entropy_of(counts, win))
    return best
