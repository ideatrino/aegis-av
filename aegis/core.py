"""
aegis.core — the Bayesian consensus core (design doc S3-S5).

Every detector emits an `Evidence`, never a yes/no. Evidence carries a
calibrated probability p together with the base rate pi_cal it was
calibrated against, so its log-likelihood-ratio is the *exact* naive-Bayes
update  LLR = logit(p) - logit(pi_cal)  (design doc S12, the base-rate
double-count fix). Fusion is a weighted sum of LLRs in log-odds space,
which is Bayes' rule for independent evidence (S3.2). The posterior is the
logistic of that sum against an explicit environment prior (S3.1). The
decision is a threshold on the posterior chosen by a cost model (S3.4),
with a disagreement penalty that routes contested files to review/escalate
rather than guessing (S5.3).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ----------------------------------------------------------------------------
# math helpers
# ----------------------------------------------------------------------------
_EPS = 1e-6


def clamp01(p: float) -> float:
    return min(1.0 - _EPS, max(_EPS, float(p)))


def logit(p: float) -> float:
    p = clamp01(p)
    return math.log(p / (1.0 - p))


def sigmoid(z: float) -> float:
    # numerically stable logistic
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


# ----------------------------------------------------------------------------
# Evidence — one detector's contribution
# ----------------------------------------------------------------------------
@dataclass
class Evidence:
    """A single detector's calibrated contribution to the consensus.

    p         : calibrated P(malicious | this detector's view)
    pi_cal    : base rate this detector was calibrated against (for the LLR)
    weight    : learned reliability weight (clamped to [floor, ceiling])
    detector  : short name, e.g. "entropy", "api_graph"
    reasons   : human-readable evidence lines (S5.6 explainability)
    review_only: strong signal that must never *silently allow*, but that on
                 its own should surface for review rather than force a block
                 unless it is a binary (see cap_review).
    cap_review : this signal's strings are visible content, not concealed
                 payload (text files, S18) -> downgrade a BLOCK to REVIEW.
    force_block: authoritative known-bad identity (exact hash / block rule).
    force_allow: authoritative known-good identity (allowlist).
    abstain    : detector declined to vote (OOD guard) -> contributes 0 LLR.
    """
    detector: str
    p: float = 0.5
    pi_cal: float = 0.5
    weight: float = 1.0
    reasons: List[str] = field(default_factory=list)
    review_only: bool = False
    cap_review: bool = False
    force_block: bool = False
    force_allow: bool = False
    abstain: bool = False
    soft_benign: bool = False    # e.g. a detected code signature (§15): never
                                 # trusted to ALLOW, but downgrades BLOCK/ESCALATE
                                 # to REVIEW — a signed binary is not quarantined.

    def llr(self) -> float:
        """Exact naive-Bayes log-likelihood ratio for independent evidence."""
        if self.abstain:
            return 0.0
        return logit(self.p) - logit(self.pi_cal)

    def contribution(self) -> float:
        """Signed log-odds this evidence adds to the fused score."""
        if self.abstain:
            return 0.0
        return self.weight * self.llr()


# ----------------------------------------------------------------------------
# cost-model operating points (design doc S3.4)
# ----------------------------------------------------------------------------
# "max security" slides tau down the ROC curve (C_FN >> C_FP);
# "relaxed" does the opposite; "balanced" sits between.
PROFILES: Dict[str, Dict[str, float]] = {
    "max":      {"tau_low": 0.12, "tau_high": 0.55},
    "balanced": {"tau_low": 0.30, "tau_high": 0.80},
    "relaxed":  {"tau_low": 0.50, "tau_high": 0.92},
}

# learned-weight band (S9 floors, S12 ceiling): a detector may be raised but
# never muted, and no detector may dominate the ensemble.
WEIGHT_FLOOR = 0.35
WEIGHT_CEILING = 1.8


@dataclass
class Verdict:
    path: str
    posterior: float
    decision: str                      # ALLOW | REVIEW | BLOCK | ESCALATE
    prior: float
    disagreement: float
    evidence: List[Evidence]
    reasons: List[str] = field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return self.decision != "ALLOW"

    def contributions(self) -> List[Dict]:
        """Per-detector signed contributions, for reports / `inspect` (S5.6)."""
        rows = []
        for e in self.evidence:
            rows.append({
                "detector": e.detector,
                "p": e.p,
                "weight": e.weight,
                "llr": e.llr(),
                "contribution": e.contribution(),
                "abstain": e.abstain,
                "reasons": list(e.reasons),
            })
        return rows


def _disagreement(evidence: List[Evidence]) -> float:
    """Variance of the voting detectors' probabilities (S5.3).

    High variance = the detectors are fighting = AEGIS should distrust itself
    and route to review/escalate rather than commit to a confident verdict.
    """
    votes = [e.p for e in evidence if not e.abstain and not e.force_allow
             and not e.force_block]
    if len(votes) < 2:
        return 0.0
    mean = sum(votes) / len(votes)
    return sum((v - mean) ** 2 for v in votes) / len(votes)


def fuse(path: str,
         evidence: List[Evidence],
         prior: float,
         profile: str = "balanced",
         thresholds: Optional[tuple] = None) -> Verdict:
    """Fuse detector evidence into a calibrated posterior and a verdict.

    Order of authority (S11, S15, S20, S21):
      1. force_allow (allowlist) beats everything — trust wins.
      2. force_block (known-bad hash / block rule) blocks, UNLESS a
         cap_review signal says the indicators are visible text (S18),
         in which case it is downgraded to REVIEW.
      3. otherwise: log-odds fusion -> posterior -> cost-model threshold,
         widened by the disagreement penalty.
    """
    if thresholds is not None:
        p_low, p_high = thresholds       # calibrated operating point (§3.4)
    else:
        p_low = PROFILES.get(profile, PROFILES["balanced"])["tau_low"]
        p_high = PROFILES.get(profile, PROFILES["balanced"])["tau_high"]

    # 1. allowlist / known-good identity short-circuits to ALLOW.
    for e in evidence:
        if e.force_allow:
            return Verdict(path, 0.0, "ALLOW", prior, 0.0, evidence,
                           reasons=list(e.reasons) or ["allowlisted (trusted hash)"])

    # Is any evidence asking us to treat strong signals as visible text?
    cap_review = any(e.cap_review for e in evidence)
    # Is this a signed binary? (soft-benign: never auto-quarantine it — §15)
    soft_benign = any(e.soft_benign and not e.abstain for e in evidence)

    # 2. authoritative force-block (honest verdict: reason from the evidence
    #    that actually fired — S21 fix, never a hard-coded "hash match").
    for e in evidence:
        if e.force_block:
            reason = e.reasons[0] if e.reasons else f"{e.detector}: force-block"
            if cap_review:
                # e.g. a block rule matched a *document* quoting indicators.
                return Verdict(path, 0.999, "REVIEW", prior,
                               _disagreement(evidence), evidence,
                               reasons=[reason,
                                        "downgraded to REVIEW: indicators are "
                                        "visible text, not concealed payload"])
            return Verdict(path, 1.0, "BLOCK", prior,
                           _disagreement(evidence), evidence, reasons=[reason])

    # 3. Bayesian log-odds fusion.
    z = logit(prior) + sum(e.contribution() for e in evidence)
    posterior = sigmoid(z)
    d = _disagreement(evidence)

    # disagreement penalty widens the uncertain band monotonically in d.
    widen = 1.0 + 6.0 * d          # d in [0,0.25]; widen in [1,2.5]
    lo = p_low
    hi = min(0.98, p_high * widen)

    # collect the "why it matters" lines even on a confident block (S22).
    strong_reasons: List[str] = []
    for e in evidence:
        if e.abstain:
            continue
        if (e.review_only or e.force_block) and e.reasons:
            strong_reasons.append(e.reasons[0])

    if posterior >= hi:
        decision = "BLOCK"
        reasons = [f"posterior {posterior:.3f} >= block threshold {hi:.2f}"] + strong_reasons
        # a review-capped signal (visible text) can never auto-quarantine.
        if cap_review or any(e.review_only and e.cap_review for e in evidence):
            decision = "REVIEW"
            reasons.append("capped to REVIEW: indicators are visible text (S18)")
        # a review_only signal with no binary backing surfaces, never blocks.
        elif _only_review_drove_it(evidence, prior):
            decision = "REVIEW"
            reasons.append("surfaced for review: strong signal not confirmable "
                           "without execution (S4/S7)")
    elif posterior <= lo:
        # a strong "surface for a human" signal is never silently allowed,
        # even when the low prior would otherwise clear it (S4/S7/S18).
        strong_review = [e for e in evidence
                         if e.review_only and not e.abstain and e.p >= 0.7]
        if strong_review:
            decision = "REVIEW"
            reasons = [f"posterior {posterior:.3f} low, but a strong signal is "
                       f"surfaced for review (never silently allowed)"] + strong_reasons
        else:
            decision = "ALLOW"
            reasons = [f"posterior {posterior:.3f} <= allow threshold {lo:.2f}"]
    else:
        # uncertain band: escalate to contained dynamic analysis (S5.5),
        # or REVIEW if there is a review_only signal to show a human.
        if any(e.review_only and not e.abstain for e in evidence):
            decision = "REVIEW"
            reasons = [f"posterior {posterior:.3f} in uncertain band"] + strong_reasons
        else:
            decision = "ESCALATE"
            reasons = [f"posterior {posterior:.3f} in uncertain band "
                       f"[{lo:.2f},{hi:.2f}] -> contained dynamic analysis"]

    # a detected code signature never auto-quarantines and never sits in
    # ESCALATE limbo: it is surfaced for review (§15). It does NOT override a
    # known-bad hash (handled above) — a signature can be stolen.
    if soft_benign and decision in ("BLOCK", "ESCALATE"):
        reasons = [f"{decision} downgraded to REVIEW: code signature present "
                   f"(detected, not verified — never trusted to ALLOW, §15)"] + reasons
        decision = "REVIEW"

    return Verdict(path, posterior, decision, prior, d, evidence, reasons=reasons)


def _only_review_drove_it(evidence: List[Evidence], prior: float) -> bool:
    """True if the block is carried by a review_only signal that cannot be
    confirmed without executing the sample (non-binary IOC/rule), so it
    should surface for a human rather than auto-quarantine (S4, S18, S20)."""
    review_only_present = any(e.review_only and not e.cap_review and not e.abstain
                              for e in evidence)
    if not review_only_present:
        return False
    # if some *non*-review_only detector also pushed strongly positive, the
    # block stands (the binary machinery, not just the indicator, fired).
    hard_positive = any((not e.review_only) and (not e.abstain)
                        and e.contribution() > 1.5 for e in evidence)
    return not hard_positive
