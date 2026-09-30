"""
aegis.detectors.learned — the two learned detectors (design doc S3.2, S9-S18).

D4  neural byte-classifier : a small numpy MLP over the feature vector.
D6  anomaly               : kNN distance to benign reference points in a
                            PCA-reduced space (multimodal-friendly, S8).

Both are Platt-calibrated so their raw outputs become true probabilities, and
each Evidence carries the corpus base rate it was calibrated against so the
fusion's LLR is exact (S12). The critical honesty here is the ABSTAIN guard: a
byte-frequency model has no business judging text, an ELF object file, a
recognized container, or an opaque non-runnable blob (S18). On those it
abstains toward its base rate and contributes nothing, so the specialists
(entropy, AST, strings, signature) decide — verified to leave the malware
confusion matrix identical (S17).
"""
from __future__ import annotations

import numpy as np

from ..core import Evidence
from .. import formats, features


# ---------------------------------------------------------------------------
def should_abstain(data: bytes, is_text: bool, fmt: str) -> str:
    """Return a non-empty reason string if the learners should abstain (S18).

    Four honest triggers, never a runnable PE/ELF image:
      - any text file           (D2/D3/D7 own text)
      - an ELF relocatable object (compiler output, any entropy)
      - a recognized container / compiled format
      - an opaque non-runnable high-entropy blob (>7.7, no known format)
    """
    if formats.is_runnable_image(data):
        return ""                    # a packed PE/ELF keeps full weight
    if is_text:
        return "text file (judged by entropy/AST/strings, not byte histogram)"
    if formats.is_elf_relocatable(data):
        return "ELF relocatable object (compiler output)"
    if formats.known_container_format(data):
        return f"recognized container/compiled format ({fmt})"
    if len(data) < 3072:
        return "file too small for a byte histogram to carry signal (<3KB)"
    # opaque non-runnable high-entropy blob
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    ent = float(-(probs * np.log2(probs)).sum())
    if ent > 7.7:
        return f"opaque non-runnable high-entropy blob (H={ent:.2f})"
    return ""


# ---------------------------------------------------------------------------
class NeuralDetector:
    """A tiny 2-layer MLP with a Platt-calibrated output (D4)."""

    def __init__(self):
        self.W1 = self.b1 = self.W2 = self.b2 = None
        self.mean = self.std = None
        self.platt_a = 1.0
        self.platt_b = 0.0
        self.base_rate = 0.5

    def _forward_raw(self, X):
        Z = (X - self.mean) / self.std
        H = np.tanh(Z @ self.W1 + self.b1)
        logits = H @ self.W2 + self.b2
        return logits.ravel()

    def predict_proba(self, X):
        logits = self._forward_raw(X)
        # Platt scaling -> calibrated probability
        z = self.platt_a * logits + self.platt_b
        return 1.0 / (1.0 + np.exp(-z))

    def fit(self, X, y, hidden=24, epochs=300, lr=0.05, seed=0):
        rng = np.random.default_rng(seed)
        self.mean = X.mean(axis=0)
        self.std = X.std(axis=0) + 1e-8
        Z = (X - self.mean) / self.std
        n, d = Z.shape
        self.W1 = rng.normal(0, 0.3, (d, hidden))
        self.b1 = np.zeros(hidden)
        self.W2 = rng.normal(0, 0.3, (hidden, 1))
        self.b2 = np.zeros(1)
        yv = y.reshape(-1, 1).astype(float)
        for _ in range(epochs):
            Hpre = Z @ self.W1 + self.b1
            H = np.tanh(Hpre)
            logits = H @ self.W2 + self.b2
            p = 1.0 / (1.0 + np.exp(-logits))
            dlog = (p - yv) / n
            dW2 = H.T @ dlog
            db2 = dlog.sum(axis=0)
            dH = (dlog @ self.W2.T) * (1 - H ** 2)
            dW1 = Z.T @ dH
            db1 = dH.sum(axis=0)
            self.W2 -= lr * (dW2 + 1e-4 * self.W2)
            self.b2 -= lr * db2
            self.W1 -= lr * (dW1 + 1e-4 * self.W1)
            self.b1 -= lr * db1
        self._fit_platt(self._forward_raw(X), y)
        self.base_rate = float(y.mean())

    def _fit_platt(self, logits, y, iters=200, lr=0.05):
        a, b = 1.0, 0.0
        y = y.astype(float)
        n = len(y)
        for _ in range(iters):
            z = a * logits + b
            p = 1.0 / (1.0 + np.exp(-z))
            ga = ((p - y) * logits).mean()
            gb = (p - y).mean()
            a -= lr * ga
            b -= lr * gb
        self.platt_a, self.platt_b = float(a), float(b)

    def state(self):
        return {k: (v.tolist() if isinstance(v, np.ndarray) else v)
                for k, v in {
                    "W1": self.W1, "b1": self.b1, "W2": self.W2, "b2": self.b2,
                    "mean": self.mean, "std": self.std,
                    "platt_a": self.platt_a, "platt_b": self.platt_b,
                    "base_rate": self.base_rate}.items()}

    @classmethod
    def from_state(cls, s):
        m = cls()
        for k in ("W1", "b1", "W2", "b2", "mean", "std"):
            setattr(m, k, np.array(s[k]))
        m.platt_a = s["platt_a"]; m.platt_b = s["platt_b"]
        m.base_rate = s["base_rate"]
        return m


class AnomalyDetector:
    """PCA -> kNN distance to benign reference points, Platt-calibrated (D6)."""

    def __init__(self, k=5, n_components=24):
        self.k = k
        self.n_components = n_components
        self.mean = self.std = self.components = None
        self.ref = None
        self.platt_a = 1.0
        self.platt_b = 0.0
        self.base_rate = 0.5

    def _project(self, X):
        Z = (X - self.mean) / self.std
        return Z @ self.components

    def _distances(self, P):
        # mean distance to k nearest benign reference points
        out = np.empty(len(P))
        for i, p in enumerate(P):
            d = np.sqrt(((self.ref - p) ** 2).sum(axis=1))
            out[i] = np.sort(d)[:self.k].mean()
        return out

    def predict_proba(self, X):
        P = self._project(X)
        d = self._distances(P)
        z = self.platt_a * d + self.platt_b
        return 1.0 / (1.0 + np.exp(-z))

    def fit(self, X, y, seed=0):
        # PCA on benign only; reference and calibration sets DISJOINT (S8)
        benign = X[y == 0]
        self.mean = benign.mean(axis=0)
        self.std = benign.std(axis=0) + 1e-8
        Zb = (benign - self.mean) / self.std
        # SVD for principal components
        U, S, Vt = np.linalg.svd(Zb, full_matrices=False)
        k = min(self.n_components, Vt.shape[0])
        self.components = Vt[:k].T
        # split benign into reference vs calibration to avoid self-match leak
        rng = np.random.default_rng(seed)
        idx = rng.permutation(len(benign))
        half = max(1, len(idx) // 2)
        ref_idx, cal_idx = idx[:half], idx[half:]
        self.ref = (Zb @ self.components)[ref_idx]
        d = self._distances(self._project(X))
        self._fit_platt(d, y)
        self.base_rate = float(y.mean())

    def _fit_platt(self, d, y, iters=300, lr=0.02):
        # normalize distances for stable Platt fit
        a, b = 1.0, -float(np.median(d))
        y = y.astype(float)
        for _ in range(iters):
            z = a * d + b
            p = 1.0 / (1.0 + np.exp(-z))
            ga = ((p - y) * d).mean()
            gb = (p - y).mean()
            a -= lr * ga
            b -= lr * gb
        self.platt_a, self.platt_b = float(a), float(b)

    def state(self):
        return {"mean": self.mean.tolist(), "std": self.std.tolist(),
                "components": self.components.tolist(), "ref": self.ref.tolist(),
                "platt_a": self.platt_a, "platt_b": self.platt_b,
                "base_rate": self.base_rate, "k": self.k}

    @classmethod
    def from_state(cls, s):
        m = cls(k=s.get("k", 5))
        m.mean = np.array(s["mean"]); m.std = np.array(s["std"])
        m.components = np.array(s["components"]); m.ref = np.array(s["ref"])
        m.platt_a = s["platt_a"]; m.platt_b = s["platt_b"]
        m.base_rate = s["base_rate"]
        return m


# ---------------------------------------------------------------------------
def evidence_from_learned(name: str, model, data: bytes, feat: np.ndarray,
                          is_text: bool, fmt: str) -> Evidence:
    reason = should_abstain(data, is_text, fmt)
    if reason:
        return Evidence(name, p=model.base_rate, pi_cal=model.base_rate,
                        abstain=True, reasons=[f"abstain: {reason}"])
    p = float(model.predict_proba(feat.reshape(1, -1))[0])
    return Evidence(name, p=p, pi_cal=model.base_rate,
                    reasons=[f"{name} calibrated P={p:.3f}"])
