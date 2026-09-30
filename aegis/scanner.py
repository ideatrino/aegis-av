"""
aegis.scanner — orchestration (design doc S4, S5).

Gathers each detector's Evidence for a sample, applies the learned reliability
weights (clamped to the [floor, ceiling] band, S9/S12), and hands the whole set
to the Bayesian fusion core. The allowlist is checked first (force ALLOW), the
signature DB can force BLOCK, and everything else is fused into a calibrated
posterior against the environment prior.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

from . import core, features, formats, peparse, rules as rulemod
from .core import Evidence, Verdict
from .allowlist import Allowlist, sha256
from .detectors import static as D
from .detectors import learned as L
from .pickle_scan import scan as pickle_scan, looks_like_pickle

DEFAULT_PRIOR = 0.001   # deployment base rate (S3.1): almost all files benign


@dataclass
class Model:
    neural: Optional[L.NeuralDetector] = None
    anomaly: Optional[L.AnomalyDetector] = None
    weights: Dict[str, float] = field(default_factory=dict)
    bad_hashes: List[str] = field(default_factory=list)
    # a calibrated operating point (tau_low, tau_high) fit by `aegis calibrate`
    # from the corpus ROC at a chosen cost ratio (§3.4). None = use profiles.
    thresholds: Optional[list] = None

    def weight(self, name: str) -> float:
        w = self.weights.get(name, 1.0)
        return max(core.WEIGHT_FLOOR, min(core.WEIGHT_CEILING, w))

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "weights": self.weights,
            "bad_hashes": self.bad_hashes,
            "thresholds": self.thresholds,
            "neural": self.neural.state() if self.neural else None,
            "anomaly": self.anomaly.state() if self.anomaly else None,
        }
        path.write_text(json.dumps(state), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "Model":
        s = json.loads(Path(path).read_text(encoding="utf-8"))
        m = cls(weights=s.get("weights", {}), bad_hashes=s.get("bad_hashes", []),
                thresholds=s.get("thresholds"))
        if s.get("neural"):
            m.neural = L.NeuralDetector.from_state(s["neural"])
        if s.get("anomaly"):
            m.anomaly = L.AnomalyDetector.from_state(s["anomaly"])
        return m


class Scanner:
    def __init__(self, model: Model, allowlist: Allowlist = None,
                 blocklist=None, extra_rules: List[rulemod.Rule] = None):
        self.model = model
        self.allowlist = allowlist
        self.blocklist = blocklist
        self.rules = rulemod.builtin_rules() + (extra_rules or [])
        self._bad = set(h.lower() for h in model.bad_hashes)

    # -----------------------------------------------------------------
    def evidence_for(self, data: bytes, sha: str) -> List[Evidence]:
        is_text = formats.is_text(data)
        fmt = formats.sniff_magic(data)
        info = peparse.parse(data)
        ev: List[Evidence] = []

        # allowlist short-circuit signal (checked first by core.fuse)
        if self.allowlist and self.allowlist.contains(sha):
            ev.append(Evidence("allowlist", force_allow=True,
                               reasons=["allowlisted (trusted SHA-256)"]))
            return ev

        # static detectors D1,D2,D3,D5,D7
        ev.append(D.d1_structural(data, info, is_text, fmt))
        ev.append(D.d2_entropy(data, is_text, fmt))
        ev.append(D.d3_api_graph(data, info, is_text, fmt))
        ev.append(D.d5_signature(data, sha, info, self._bad, self.blocklist, is_text))
        ev.append(D.d7_ioc(data, is_text, fmt, self.blocklist))

        # D9: document-malware vectors (Office macros, PDF JavaScript)
        from .detectors import documents
        doc_ev = documents.detect(data)
        if doc_ev is not None:
            ev.append(doc_ev)

        # code-signature awareness (§15): a present Authenticode block is a
        # soft-benign signal — pulls the posterior down and, crucially,
        # downgrades any BLOCK/ESCALATE to REVIEW. Detected, not verified.
        if info.parsed and info.has_signature:
            ev.append(Evidence("codesign", p=0.12, soft_benign=True,
                               reasons=["Authenticode signature present "
                                        "(detected, not verified — §15)"]))

        # learned detectors D4,D6
        feat = features.extract(data)
        if self.model.neural:
            ev.append(L.evidence_from_learned("neural", self.model.neural,
                                              data, feat, is_text, fmt))
        if self.model.anomaly:
            ev.append(L.evidence_from_learned("anomaly", self.model.anomaly,
                                              data, feat, is_text, fmt))

        # malicious-pickle scanner (ML-model RCE vector, S23)
        if looks_like_pickle(data):
            pr = pickle_scan(data)
            if pr.is_pickle and pr.malicious:
                e = Evidence("pickle", p=pr.probability(), review_only=True,
                             reasons=pr.reasons[:3])
                ev.append(e)

        # D8: custom + built-in rules
        ev.extend(self._rule_evidence(data, is_text))
        return ev

    def _rule_evidence(self, data: bytes, is_text: bool) -> List[Evidence]:
        out: List[Evidence] = []
        hits = rulemod.match_rules(data, self.rules)
        for h in hits:
            if h.severity == "block":
                e = Evidence("rule", p=1.0, force_block=True,
                             reasons=[f"custom rule match: {h.name} (block rule)"])
                if is_text:
                    e.cap_review = True
                out.append(e)
            elif h.severity == "review":
                e = Evidence("rule", p=0.75, review_only=True,
                             reasons=[f"custom rule match: {h.name} (review)"])
                if is_text:
                    e.cap_review = True
                out.append(e)
            else:  # score
                out.append(Evidence("rule", p=min(0.9, 0.5 + h.weight * 0.2),
                                    weight=h.weight,
                                    reasons=[f"custom rule match: {h.name} (score)"]))
        return out

    # -----------------------------------------------------------------
    def _apply_weights(self, ev):
        # apply learned reliability weights (band-clamped), except identity
        # and behavioral signals which keep weight 1 for the exact update.
        for e in ev:
            if e.force_allow or e.force_block or e.abstain:
                continue
            if e.detector in ("signature", "pickle", "rule", "dynamic", "codesign"):
                continue
            e.weight = self.model.weight(e.detector)
        return ev

    def scan_bytes(self, data: bytes, path: str,
                   prior: float = DEFAULT_PRIOR,
                   profile: str = "balanced",
                   dynamic: bool = False,
                   dynamic_force: bool = False,
                   calibrated: bool = False) -> Verdict:
        sha = sha256(data)
        ev = self._apply_weights(self.evidence_for(data, sha))
        thresholds = tuple(self.model.thresholds) if (calibrated and
                                                      self.model.thresholds) else None
        verdict = core.fuse(path, ev, prior, profile, thresholds=thresholds)
        # Stage 3 (§5 step 5): contained dynamic analysis — Python samples only.
        #   dynamic_force  : always detonate this sample (single-file `inspect`).
        #   dynamic (bulk) : only the uncertain band escalates, so a big scan
        #                    doesn't execute every script.
        run_dyn = dynamic_force or (dynamic and verdict.decision == "ESCALATE")
        if run_dyn:
            from . import dynamic as dyn
            res = dyn.analyze(data)
            if res.ran:
                ev.append(dyn.evidence_from(res))
                verdict = core.fuse(path, ev, prior, profile, thresholds=thresholds)
        return verdict

    def scan_file(self, filepath: str, prior: float = DEFAULT_PRIOR,
                  profile: str = "balanced", dynamic: bool = False,
                  dynamic_force: bool = False, calibrated: bool = False) -> Verdict:
        data = Path(filepath).read_bytes()
        return self.scan_bytes(data, str(filepath), prior, profile,
                               dynamic, dynamic_force, calibrated)
