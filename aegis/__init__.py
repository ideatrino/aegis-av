"""
AEGIS — Adaptive Ensemble with Guaranteed-envelope Integrity Scoring.

An original antivirus architecture grounded in the mathematics of what
detection can and cannot do (Cohen 1987: perfect detection is undecidable).
AEGIS therefore never claims certainty; it reports a calibrated Bayesian
posterior fused in log-odds space from independent detectors drawn from
different mathematical families, decided against an explicit cost model.

See the design document for the full derivation. This package is the runnable
reference implementation.
"""
__version__ = "5.9.1"

from .core import Evidence, Verdict, fuse           # noqa: F401
from .scanner import Scanner, Model                 # noqa: F401
