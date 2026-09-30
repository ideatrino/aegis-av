"""
aegis.train — the training pipeline (design doc S9, S12, S21).

Builds the feature matrix, trains D4 (neural) and D6 (anomaly) with Platt
calibration, fits the fusion reliability weights by logistic regression over
the detectors' per-sample LLRs (stacking) — clamped to the [floor, ceiling]
band so a specialist can be RAISED but never MUTED (S9) and no detector can
dominate (S12) — and seeds the known-bad signature DB from malicious hashes,
but ONLY for content that never also appears benign (the label-noise leak fix,
S21). A little label noise is injected so the AUC isn't a meaningless 1.000.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import List, Tuple

import numpy as np

from . import core, features, fixtures
from .allowlist import sha256
from .detectors import learned as L
from .detectors import static as D
from .scanner import Model


def _label_noise(items, rate=0.04, seed=0):
    rng = random.Random(seed)
    noisy = []
    for name, data, label in items:
        if rng.random() < rate:
            noisy.append((name, data, 1 - label))
        else:
            noisy.append((name, data, label))
    return noisy


def build_matrix(items):
    X = np.array([features.extract(d) for _, d, _ in items])
    y = np.array([lab for _, _, lab in items])
    return X, y


def _detector_llrs(items) -> Tuple[np.ndarray, List[str]]:
    """Per-sample LLR from each STATIC detector, for the stacking fit."""
    names = ["structural", "entropy", "api_graph", "ioc"]
    rows = []
    from . import formats, peparse
    for _, data, _ in items:
        is_text = formats.is_text(data)
        fmt = formats.sniff_magic(data)
        info = peparse.parse(data)
        e = {
            "structural": D.d1_structural(data, info, is_text, fmt),
            "entropy": D.d2_entropy(data, is_text, fmt),
            "api_graph": D.d3_api_graph(data, info, is_text, fmt),
            "ioc": D.d7_ioc(data, is_text, fmt, None),
        }
        rows.append([e[n].llr() for n in names])
    return np.array(rows), names


def _fit_weights(llr, y, names, base_weight=1.0, iters=500, lr=0.1):
    """Logistic regression on LLRs -> reliability weights, band-clamped."""
    n, d = llr.shape
    w = np.ones(d) * base_weight
    b = 0.0
    yv = y.astype(float)
    for _ in range(iters):
        z = llr @ w + b
        p = 1.0 / (1.0 + np.exp(-z))
        gw = llr.T @ (p - yv) / n + 1e-3 * w
        gb = (p - yv).mean()
        w -= lr * gw
        b -= lr * gb
    weights = {}
    for i, name in enumerate(names):
        weights[name] = float(min(core.WEIGHT_CEILING,
                                  max(core.WEIGHT_FLOOR, w[i])))
    return weights


def train(items=None, seed=0, augment=False) -> Model:
    if items is None:
        items = fixtures.make_corpus(seed=seed)
    elif augment:
        items = list(items) + fixtures.make_corpus(seed=seed)

    noisy = _label_noise(items, seed=seed)
    X, y = build_matrix(noisy)

    neural = L.NeuralDetector(); neural.fit(X, y, seed=seed)
    anomaly = L.AnomalyDetector(); anomaly.fit(X, y, seed=seed)

    llr, names = _detector_llrs(noisy)
    weights = _fit_weights(llr, y, names)
    # learned detectors keep a floor-guarded default weight (not fit here to
    # avoid the ensemble collapsing onto the neural net, S9)
    weights.setdefault("neural", 1.0)
    weights.setdefault("anomaly", 0.7)
    weights["signature"] = 1.0

    # seed known-bad hashes, but only for content with NO benign twin (S21):
    # a hash is authoritative force-block, so it must be reserved for ground
    # truth — training label noise must never leak into it.
    benign_hashes = {sha256(d) for _, d, lab in items if lab == 0}
    bad = []
    seen = set()
    for _, d, lab in items:
        if lab == 1:
            h = sha256(d)
            if h not in benign_hashes and h not in seen:
                bad.append(h); seen.add(h)

    return Model(neural=neural, anomaly=anomaly, weights=weights, bad_hashes=bad)


def cv_posteriors(items, k=5, prior=0.5, seed=0):
    """Cross-validated fused posteriors for a labeled corpus (honest scores for
    evaluation and threshold calibration — no in-sample leakage)."""
    import numpy as np
    from .scanner import Scanner
    from .allowlist import Allowlist
    import tempfile
    idx = np.arange(len(items))
    rng = np.random.default_rng(seed)
    rng.shuffle(idx)
    folds = np.array_split(idx, k)
    y_all, s_all = [], []
    tmp = Path(tempfile.mkdtemp(prefix="aegis-cv-"))
    for i in range(k):
        test = set(folds[i].tolist())
        train_items = [items[j] for j in idx if j not in test]
        model = train(items=train_items, seed=seed)
        sc = Scanner(model, allowlist=Allowlist(tmp / f"a{i}.json"), blocklist=None)
        for j in folds[i]:
            name, data, label = items[j]
            v = sc.scan_bytes(data, name, prior=prior, profile="balanced")
            y_all.append(label); s_all.append(v.posterior)
    return y_all, s_all


def load_corpus_dir(root: str, max_bytes: int = 32 * 1024 * 1024,
                    dedup: bool = True) -> List[Tuple[str, bytes, int]]:
    """Read a benign/ + malicious/ directory tree into labeled samples.

    Robust to real, messy data: skips unreadable and oversized files, and (by
    default) de-duplicates by content hash so the same sample can't inflate a
    class. A content that appears under BOTH labels is dropped from the training
    set entirely (an unresolved label conflict must never become a force-block —
    §21); `verify-corpus` reports these.
    """
    from .allowlist import sha256
    root = Path(root)
    seen = {}
    conflicts = set()
    items = []
    for label, sub in ((0, "benign"), (1, "malicious")):
        d = root / sub
        if not d.exists():
            continue
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            try:
                if f.stat().st_size > max_bytes:
                    continue
                data = f.read_bytes()
            except Exception:
                continue
            h = sha256(data)
            if dedup and h in seen:
                if seen[h][0] != label:
                    conflicts.add(h)
                continue
            seen[h] = (label, str(f))
            items.append((str(f), data, label))
    if conflicts:
        items = [(n, d, l) for (n, d, l) in items if sha256(d) not in conflicts]
    return items
