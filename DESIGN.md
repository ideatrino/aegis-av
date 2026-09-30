# AEGIS — the mathematics

### *Adaptive Ensemble with Guaranteed-envelope Integrity Scoring*

This is the condensed mathematical rationale behind the reference
implementation in this package. It is the *why*; the README is the *how*.

---

## 0. The honest premise

You cannot build a *provably perfect* antivirus. This is not an engineering
gap — it is a theorem.

**Cohen (1987).** Suppose a program `PERFECT(P)` returns true iff `P` will ever
behave maliciously. Construct `EVIL` that calls `PERFECT(EVIL)` and does the
opposite of its verdict. Either way `PERFECT` is wrong about `EVIL`.
Contradiction — the same diagonal argument as Turing's halting problem.
Detection reduces to it, so no perfect classifier exists.

Consequently the only rational goal is to **shape the error tradeoff
deliberately** — decide where false positives and false negatives go, quantify
uncertainty, and never pretend a verdict is certain. Every component exists
because the theorem says one component can never be enough.

---

## 1. The base-rate layer (Bayes)

Almost every file is benign. With a detector 99.9% accurate both ways and 1 in
10,000 files malicious:

```
P(M|alarm) = (0.999 · 0.0001) / (0.999·0.0001 + 0.001·0.9999) ≈ 0.09
```

A 99.9%-accurate alarm is right ~9% of the time. So AEGIS never reports a raw
score; it reports the **posterior** P(M | evidence) against an explicit prior
that the environment sets. This is why scanning 17,000 benign files with a
"usually right" detector yields hundreds of false alarms — the base rate
punishes any detector that is merely usually right.

## 2. The consensus layer (ensemble math)

For *n* independent detectors each correct with probability *p > ½*, the
Condorcet Jury Theorem gives majority-vote accuracy

```
Σ_{k=⌈n/2⌉}^{n} C(n,k) p^k (1-p)^{n-k}  →  1   as n → ∞
```

The catch is *independent*. So AEGIS draws its detectors from **different
mathematical families** (grammar, information theory, graph theory,
differentiable optimization, hashing, manifold distance, indicator
co-occurrence, and hand-authored rules) so their errors are uncorrelated. An
attacker must fool them all at once, and evasions that beat one tend to worsen
the score on another. `aegis adversarial` tests this empirically.

Fusion is a **weighted log-odds sum** — the exact Bayes update for independent
evidence:

```
logit P(M|E) = logit P(M) + Σ wᵢ · [logit(pᵢ) − logit(π_cal,ᵢ)]
```

where each detector carries the base rate π_cal it was calibrated against, so
the LLR is the exact naive-Bayes likelihood ratio.

## 3. The envelope layer (information theory + reachability)

- **Entropy.** H(X) = −Σ p(b) log₂ p(b), 0 ≤ H ≤ 8 bits/byte. Packed/encrypted
  payloads push toward 8. Weak alone (compressed files are high-entropy too) —
  hence it belongs in an ensemble, and AEGIS uses *windowed* max entropy so a
  packed region stays visible even under low-entropy padding.
- **Behavior envelope.** Model a running program as a state machine over
  observable actions. Define an allowed region 𝒮_safe. A violation is
  `Reach(P) ∩ 𝒮_safe^∁ ≠ ∅`. This is decidable for a *bounded* observation
  window — a finite trace against a policy, not the halting problem — which is
  why Stage 3 can lean on it.

## 4. The optimization layer (decision theory)

"Most secure" only has meaning once a cost model is fixed. With C_FN the cost of
a miss and C_FP the cost of a false alarm, the optimal threshold τ minimises

```
E[Loss] = C_FN·P(M)·(1−TPR) + C_FP·P(¬M)·FPR
```

equivalently the ROC point where `dTPR/dFPR = C_FP·P(¬M) / C_FN·P(M)`. So
"maximum security" is not a vibe — set C_FN ≫ C_FP and slide τ down the curve.
`aegis calibrate` fits exactly this operating point from a corpus.

## 5. The decision core

For evidence E = (ℓ₁,…,ℓₙ):

1. **Prior** π = P(M) from the environment profile.
2. **Fuse**: `z = logit(π) + Σ wᵢ ℓᵢ`.
3. **Disagreement penalty**: widen the uncertain band with the variance of the
   detectors' votes — when they fight, distrust and escalate, don't guess.
4. **Posterior**: `p = σ(z)`.
5. **Decide** against cost-model thresholds: `p < τ_low` allow, `p > τ_high`
   block, between → contained dynamic analysis. A strong "surface for review"
   signal is never silently allowed; a code signature or visible-text indicator
   downgrades a block to review; the allowlist beats everything.
6. **Explain**: emit the evidence vector so every verdict shows its reasons.

---

## The detectors

| Detector | Basis | Fooled by | Covered by |
|---|---|---|---|
| D1 structural | grammar/parsing | malformed-but-valid | entropy, neural |
| D2 entropy | information theory | low-entropy malware | neural, api-graph |
| D3 api-graph | graph theory | obfuscated calls | entropy |
| D4 neural | differentiable opt. | adversarial examples | non-differentiable detectors |
| D5 signature | hashing / LSH | novel malware | anomaly (+ fuzzy CTPH, imphash) |
| D6 anomaly | manifold distance | good-file mimicry | structural, api-graph |
| D7 ioc | indicator co-occurrence | string-free payloads | structural, entropy |
| D8 rules | analyst-authored | author error | fused, allowlist-overridable |
| D9 documents | format structure | non-macro delivery | the rest of the ensemble |

Plus Stage-3 dynamic analysis (audit-hook behavior envelope for Python, a
pluggable external backend for binaries), fuzzy CTPH near-variant matching,
Mandiant imphash family clustering, a malicious-pickle opcode scanner, and
model-aware bomb-guarded archive descent.

---

## Limits, stated plainly

Not perfect (§0). Calibration is only as good as each detector's calibration and
the honesty of the prior. Binaries need an external dynamic backend to detonate.
Text indicators are surfaced, never auto-blocked. Signatures are detected, not
verified. The learned detectors are only as real as the corpus — which is why
the real-labeled-data path (`make-corpus → verify-corpus → train --augment →
calibrate`) is the highest-value step a user with samples can take.

Naming these *is* the security posture. An antivirus that hides its own failure
modes is the least secure kind.
