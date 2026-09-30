"""aegis.metrics — ROC-AUC, PR-AUC, confusion matrix (design doc S9, S12)."""
from __future__ import annotations

import numpy as np


def roc_auc(y_true, scores) -> float:
    y = np.asarray(y_true)
    s = np.asarray(scores, dtype=float)
    pos = s[y == 1]
    neg = s[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    # Mann-Whitney U statistic form of AUC
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=float)
    ranks[order] = np.arange(1, len(s) + 1)
    # average ties
    _, inv, counts = np.unique(s, return_inverse=True, return_counts=True)
    csum = np.cumsum(counts)
    avg = {}
    start = 0
    for i, c in enumerate(counts):
        avg[i] = (start + 1 + start + c) / 2.0
        start += c
    ranks = np.array([avg[v] for v in inv])
    sum_pos = ranks[y == 1].sum()
    n_pos, n_neg = len(pos), len(neg)
    return float((sum_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def pr_auc(y_true, scores) -> float:
    """Average precision (area under the precision-recall curve)."""
    y = np.asarray(y_true)
    s = np.asarray(scores, dtype=float)
    order = np.argsort(-s, kind="mergesort")
    y = y[order]
    tp = np.cumsum(y == 1)
    fp = np.cumsum(y == 0)
    n_pos = int((y == 1).sum())
    if n_pos == 0:
        return float("nan")
    precision = tp / np.maximum(tp + fp, 1)
    recall = tp / n_pos
    # step integration over recall
    ap = 0.0
    prev_r = 0.0
    for p, r in zip(precision, recall):
        ap += p * (r - prev_r)
        prev_r = r
    return float(ap)


def roc_curve(y_true, scores):
    """Return sorted (fpr, tpr, threshold) points."""
    y = np.asarray(y_true)
    s = np.asarray(scores, dtype=float)
    order = np.argsort(-s, kind="mergesort")
    y = y[order]; s = s[order]
    P = max(1, int((y == 1).sum()))
    N = max(1, int((y == 0).sum()))
    tp = fp = 0
    pts = [(0.0, 0.0, 1.0)]
    for i in range(len(s)):
        if y[i] == 1:
            tp += 1
        else:
            fp += 1
        pts.append((fp / N, tp / P, float(s[i])))
    return pts


def best_threshold_by_cost(y_true, scores, c_fn=1.0, c_fp=1.0, prior=None):
    """Cost-optimal threshold (§3.4): minimise expected loss
        E[Loss] = c_fn·P(M)·(1-TPR) + c_fp·P(¬M)·FPR
    over the empirical ROC. prior defaults to the corpus base rate. Returns
    (threshold, expected_loss)."""
    y = np.asarray(y_true)
    pm = float((y == 1).mean()) if prior is None else float(prior)
    pn = 1.0 - pm
    best_t, best_loss = 0.5, float("inf")
    for fpr, tpr, thr in roc_curve(y, scores):
        loss = c_fn * pm * (1 - tpr) + c_fp * pn * fpr
        if loss < best_loss:
            best_loss, best_t = loss, thr
    return best_t, best_loss


def threshold_at_fpr(y_true, scores, target_fpr=0.01):
    """Largest threshold whose FPR is <= target_fpr (a safe ALLOW boundary)."""
    best = 1.0
    for fpr, tpr, thr in roc_curve(y_true, scores):
        if fpr <= target_fpr:
            best = min(best, thr)
    return best


def confusion(y_true, y_pred):
    y = np.asarray(y_true); p = np.asarray(y_pred)
    tp = int(((y == 1) & (p == 1)).sum())
    tn = int(((y == 0) & (p == 0)).sum())
    fp = int(((y == 0) & (p == 1)).sum())
    fn = int(((y == 1) & (p == 0)).sum())
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def rates(cm):
    tp, tn, fp, fn = cm["tp"], cm["tn"], cm["fp"], cm["fn"]
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {"recall": recall, "fpr": fpr, "precision": precision}
