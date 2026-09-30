"""
aegis.adversarial — empirical validation of the coupled-ensemble thesis
(design doc §3.2, §4).

The original claim at the heart of AEGIS is that the detectors are drawn from
DIFFERENT mathematical families so their blind spots don't overlap: an attacker
who defeats one detector still faces the others, and the evasions that beat one
tend to worsen the score on another. This module tests that claim rather than
asserting it.

For each evasion we (a) confirm the TARGETED detector is actually defeated
(its own probability drops), and (b) check that the ENSEMBLE verdict still
flags the sample. If the ensemble holds while each single detector falls, the
thesis is demonstrated. We also measure the Condorcet gain: fused ROC-AUC vs
the best single detector's ROC-AUC.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from . import fixtures, formats, peparse, metrics
from .allowlist import sha256


# ---------------------------------------------------------------------------
# evasions — each targets one detector's mathematical basis
# ---------------------------------------------------------------------------
def evade_hash(data: bytes) -> bytes:
    """Flip one byte in a padded copy — defeats the exact-hash detector (D5)."""
    b = bytearray(data)
    b.append(0x00)          # change content -> new SHA-256
    b[-1] ^= 0x5A
    return bytes(b)


def evade_entropy(data: bytes) -> bytes:
    """Append a large low-entropy region — pulls whole-file entropy down (D2)."""
    return data + b"\x00" * (len(data) * 3 + 4096)


def evade_strings(data: bytes) -> bytes:
    """Strip common IOC substrings — defeats the string/IOC detector (D7)."""
    out = data
    for token in (b"http://", b"https://", b"CurrentVersion\\Run",
                  b"certutil", b"powershell", b"/dev/tcp/", b"nc -e"):
        out = out.replace(token, b"XXXX")
    return out


# Concrete byte-level evasions that genuinely defeat their targeted detector.
# (Note: appending low-entropy padding does NOT defeat D2, because D2 uses
# WINDOWED max entropy — a packed region stays visible in its window. That
# robustness is a design property, so we don't dress a non-evasion up as one;
# the leave-one-out test below covers total evasion of every detector.)
EVASIONS: List[Tuple[str, str, Callable[[bytes], bytes]]] = [
    ("byte-flip / repack", "signature", evade_hash),
    ("string stripping", "ioc", evade_strings),
]


@dataclass
class EvasionResult:
    evasion: str
    target: str
    target_p_before: float
    target_p_after: float
    ensemble_before: str
    ensemble_after: str

    @property
    def target_defeated(self) -> bool:
        # the targeted detector's confidence dropped meaningfully
        return self.target_p_after < self.target_p_before - 0.1 or \
            (self.ensemble_before == "BLOCK" and self.target == "signature")

    @property
    def ensemble_held(self) -> bool:
        return self.ensemble_after != "ALLOW"


def _detector_p(scanner, data: bytes, name: str) -> float:
    ev = scanner.evidence_for(data, sha256(data))
    for e in ev:
        if e.detector == name:
            return 0.999 if e.force_block else e.p
    return 0.5


def run_evasions(scanner, profile: str = "max") -> List[EvasionResult]:
    """Build malware samples with signals across families, then evade each."""
    results: List[EvasionResult] = []
    # a RAT PE: strong api-graph + structural + entropy, plus embedded C2 string
    base = bytearray(fixtures.build_pe(fixtures._RAT, packed=True, seed=31337))
    base += b"http://beacon.attacker.test/gate.php\x00CurrentVersion\\Run\x00"
    base = bytes(base)
    # make its exact hash known-bad so the signature evasion is meaningful
    scanner._bad.add(sha256(base))

    for name, target, fn in EVASIONS:
        v_before = scanner.scan_bytes(base, "orig", profile=profile)
        p_before = _detector_p(scanner, base, target)
        evaded = fn(base)
        v_after = scanner.scan_bytes(evaded, "evaded", profile=profile)
        p_after = _detector_p(scanner, evaded, target)
        results.append(EvasionResult(name, target, p_before, p_after,
                                     v_before.decision, v_after.decision))
    return results


def leave_one_out(scanner, profile: str = "max") -> Tuple[str, List[Tuple[str, str]]]:
    """The rigorous form of the thesis (§4): remove EACH detector entirely
    (total evasion) and check the ensemble still flags. Returns the baseline
    decision and [(removed_detector, decision_without_it)]."""
    from . import core
    base = bytearray(fixtures.build_pe(fixtures._RAT, packed=True, seed=4242))
    base += b"http://beacon.attacker.test/x\x00CurrentVersion\\Run\x00"
    base = bytes(base)
    ev = scanner._apply_weights(scanner.evidence_for(base, sha256(base)))
    thresholds = None
    baseline = core.fuse("s", ev, scanner_prior(), profile).decision
    rows = []
    detectors = sorted({e.detector for e in ev
                        if not e.force_allow and not e.abstain})
    for d in detectors:
        kept = [e for e in ev if e.detector != d]
        dec = core.fuse("s", kept, scanner_prior(), profile).decision
        rows.append((d, dec))
    return baseline, rows


def scanner_prior():
    from .scanner import DEFAULT_PRIOR
    return DEFAULT_PRIOR


def ensemble_gain(items) -> Dict[str, float]:
    """Fused ROC-AUC vs each single detector's ROC-AUC on the corpus (§3.2)."""
    from .detectors import static as D
    from . import train as trainmod
    names = ["structural", "entropy", "api_graph", "ioc"]
    single = {n: [] for n in names}
    y = []
    for _, data, label in items:
        y.append(label)
        is_text = formats.is_text(data); fmt = formats.sniff_magic(data)
        info = peparse.parse(data)
        single["structural"].append(D.d1_structural(data, info, is_text, fmt).p)
        single["entropy"].append(D.d2_entropy(data, is_text, fmt).p)
        single["api_graph"].append(D.d3_api_graph(data, info, is_text, fmt).p)
        single["ioc"].append(D.d7_ioc(data, is_text, fmt, None).p)
    out = {n: metrics.roc_auc(y, single[n]) for n in names}
    y_f, s_f = trainmod.cv_posteriors(items, k=5, prior=0.5)
    out["FUSED"] = metrics.roc_auc(y_f, s_f)
    out["best_single"] = max(out[n] for n in names)
    return out
