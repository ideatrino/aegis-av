"""
aegis.dynamic — Stage-3 contained dynamic analysis (design doc §5, §6 Phase 3).

Runs a Python sample in the isolated sandbox_runner subprocess, collects the
action trace, and checks it against a behavior envelope S_safe (§3.3): the
reachable set of observed OS-facing actions must stay inside the allowed region,
or it's a violation:

    Reach(P) ∩ S_safe^∁ ≠ ∅  ⇒  violation

This is decidable because we check a FINITE trace over a bounded observation
window against a policy — we are not solving the halting problem (§3.3).

Only runs on Python-source samples and only when the caller opts in (`--dynamic`),
typically for the ESCALATE band (§5 step 5). A confirmed runtime escape is much
stronger than a static guess, so it enters the fusion as a high-confidence,
behavioral (non-cap_review) signal.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, List

from .core import Evidence

_RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox_runner.py")

# the default safe envelope: an unknown script may compute and read, but must
# NOT reach the network, spawn processes, load native code, or mutate the disk.
_ESCAPE_CATEGORIES = frozenset(
    {"network", "process", "native", "destructive_fs", "fs_write"})


@dataclass
class DynamicResult:
    ran: bool = False
    events: List[dict] = field(default_factory=list)
    violations: List[dict] = field(default_factory=list)
    reason: str = ""

    @property
    def violated(self) -> bool:
        return bool(self.violations)


def is_python_source(data: bytes) -> bool:
    from . import formats
    if not formats.is_text(data):
        return False
    head = data[:4096]
    try:
        text = head.decode("utf-8", "replace")
    except Exception:
        return False
    import re
    return bool(re.search(r"(^|\n)\s*(import |from |def |class |print\()", text))


def analyze_file(filepath: str, timeout: float = 5.0,
                 allowed: FrozenSet[str] = frozenset()) -> DynamicResult:
    trace_fd, trace_path = tempfile.mkstemp(suffix=".aegistrace")
    os.close(trace_fd)
    # Inherit the real environment (S13: `python -I` + a stripped env broke the
    # sandbox on Windows; isolation comes from -I, the audit hook and limits).
    env = dict(os.environ)
    env["AEGIS_TRACE"] = trace_path
    env["AEGIS_BLOCK"] = "1"
    # Frozen build (PyInstaller): sys.executable is the app itself, not a Python
    # interpreter, so `-I runner.py` is impossible. Instead re-invoke the frozen
    # exe with AEGIS_SANDBOX_CHILD set; the app's entry point detects that and
    # runs the sandbox runner instead of the GUI. Same audit hook, same limits.
    if getattr(sys, "frozen", False):
        env["AEGIS_SANDBOX_CHILD"] = "1"
        argv = [sys.executable, str(Path(filepath).resolve())]
    else:
        argv = [sys.executable, "-I", _RUNNER, str(Path(filepath).resolve())]
    try:
        subprocess.run(
            argv, env=env, timeout=timeout, capture_output=True,
            cwd=tempfile.gettempdir(),
        )
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    events: List[dict] = []
    try:
        with open(trace_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
    finally:
        try:
            os.remove(trace_path)
        except OSError:
            pass
    res = DynamicResult(ran=True, events=events)
    res.violations = [e for e in events
                      if e.get("category") in _ESCAPE_CATEGORIES
                      and e.get("category") not in allowed]
    return res


def analyze_bytes(data: bytes, timeout: float = 5.0,
                  allowed: FrozenSet[str] = frozenset()) -> DynamicResult:
    if not is_python_source(data):
        return DynamicResult(ran=False, reason="not a python-source sample")
    fd, path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return analyze_file(path, timeout=timeout, allowed=allowed)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Pluggable backends (design doc §6, §7): the Python audit-hook sandbox is the
# built-in default; binaries need an OS/VM backend, which a user wires in via
# the AEGIS_DYNAMIC_CMD environment variable rather than us pretending to
# detonate an .exe in-process. This turns the honest "binaries can't be
# detonated here" limit into a documented extension point.
# ---------------------------------------------------------------------------
def _external_backend_cmd() -> str:
    return os.environ.get("AEGIS_DYNAMIC_CMD", "").strip()


def analyze_external(data: bytes, timeout: float = 30.0,
                     allowed: FrozenSet[str] = frozenset()) -> DynamicResult:
    """Detonate a binary via a user-supplied sandbox command.

    AEGIS_DYNAMIC_CMD is a command template with {sample} substituted by the
    sample path; it must print a JSON trace {"events": [{"category","event",
    "detail"}...]} to stdout. Categories matching the escape set are violations.
    Example: AEGIS_DYNAMIC_CMD='my-sandbox --json {sample}'
    """
    cmd = _external_backend_cmd()
    if not cmd:
        return DynamicResult(ran=False, reason="no external dynamic backend "
                             "configured (set AEGIS_DYNAMIC_CMD for binaries)")
    fd, path = tempfile.mkstemp(suffix=".sample")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        import shlex
        # POSIX shlex mangles Windows backslash paths; non-POSIX preserves them
        # but keeps surrounding quotes inside each token, so strip those.
        if os.name == "nt":
            try:
                toks = shlex.split(cmd, posix=False)
            except ValueError:
                toks = cmd.split()
            toks = [t[1:-1] if len(t) >= 2 and t[0] in "\"'" and t[-1] == t[0]
                    else t for t in toks]
        else:
            try:
                toks = shlex.split(cmd)
            except ValueError:
                toks = cmd.split()
        argv = [path if tok == "{sample}" else tok for tok in toks]
        if "{sample}" not in cmd:
            argv.append(path)
        try:
            out = subprocess.run(argv, timeout=timeout, capture_output=True)
        except Exception as e:
            return DynamicResult(ran=False, reason=f"external backend failed: {e}")
        events = []
        try:
            payload = json.loads(out.stdout.decode("utf-8", "replace") or "{}")
            events = payload.get("events", [])
        except Exception:
            return DynamicResult(ran=False, reason="external backend produced no JSON trace")
        res = DynamicResult(ran=True, events=events)
        res.violations = [e for e in events
                          if e.get("category") in _ESCAPE_CATEGORIES
                          and e.get("category") not in allowed]
        return res
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def analyze(data: bytes, timeout: float = 5.0,
            allowed: FrozenSet[str] = frozenset()) -> DynamicResult:
    """Dispatch to the right backend by sample type (§5, §6).

    Python source -> the built-in audit-hook sandbox (safe, no external deps).
    A runnable PE/ELF -> the external backend if one is configured, else
    reported honestly as not-run (binaries are never detonated in-process).
    """
    from . import formats
    if is_python_source(data):
        return analyze_bytes(data, timeout=timeout, allowed=allowed)
    if formats.is_runnable_image(data) and _external_backend_cmd():
        return analyze_external(data, timeout=max(timeout, 30.0), allowed=allowed)
    if formats.is_runnable_image(data):
        return DynamicResult(ran=False, reason="binary sample: no OS/VM backend "
                             "(set AEGIS_DYNAMIC_CMD to enable)")
    return DynamicResult(ran=False, reason="not a detonatable sample type")


def evidence_from(res: DynamicResult) -> Evidence:
    """Fold a dynamic result into the consensus (§5)."""
    if not res.ran:
        return Evidence("dynamic", p=0.5, abstain=True,
                        reasons=[res.reason or "not run"])
    if res.violated:
        cats = sorted({v["category"] for v in res.violations})
        detail = "; ".join(f"{v['category']}:{v['event']}" for v in res.violations[:4])
        # A confirmed runtime escape is behavioral proof, not a static guess, so
        # it is never silently allowed — surfaced (REVIEW) at minimum, and it
        # drives BLOCK when the rest of the ensemble agrees.
        return Evidence("dynamic", p=0.96, review_only=True,
                        reasons=[f"behavior-envelope violation ({', '.join(cats)}): "
                                 f"{detail}"])
    return Evidence("dynamic", p=0.15,
                    reasons=["ran in sandbox; stayed inside the safe envelope"])
