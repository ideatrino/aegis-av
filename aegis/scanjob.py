"""
aegis.scanjob — the headless engine layer the desktop GUI drives.

Everything here is Tk-free and thread-safe by design (it only calls back; it
never touches widgets), so the whole scan/quarantine/real-time flow is testable
without a display. gui.py is a thin view on top of this.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

_DEV_NOISE = {"node_modules", ".venv", "venv", "__pycache__", "target",
              ".hypothesis", ".ruff_cache", ".gradle", ".cargo", "vendor",
              ".git", "dist", "build", ".mypy_cache", ".pytest_cache",
              "$Recycle.Bin", "System Volume Information", "Windows", "AppData"}


def quick_targets() -> List[Path]:
    """Common user folders for a Quick Scan (those that exist)."""
    home = Path.home()
    names = ["Downloads", "Desktop", "Documents"]
    out = [home / n for n in names if (home / n).is_dir()]
    return out or [home]


def full_targets() -> List[Path]:
    """The user's home tree for a Full Scan (drive-wide is opt-in, slow)."""
    return [Path.home()]


def walk(paths: List[Path], skip_dev: bool = True, exclude=None):
    """Yield files under the given paths, pruning dev-noise and system trees."""
    exclude = exclude or []
    seen = set()
    for root in paths:
        root = Path(root)
        if root.is_file():
            yield root
            continue
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dp = Path(dirpath)
            if skip_dev:
                dirnames[:] = [d for d in dirnames if d not in _DEV_NOISE
                               and not d.startswith(".")]
            for fn in filenames:
                fp = dp / fn
                key = str(fp)
                if key in seen:
                    continue
                seen.add(key)
                if any(pat in key for pat in exclude):
                    continue
                yield fp


@dataclass
class ScanSummary:
    scanned: int = 0
    allow: int = 0
    review: int = 0
    escalate: int = 0
    block: int = 0
    flagged: List = field(default_factory=list)   # list of dict rows
    started: float = 0.0
    finished: float = 0.0
    cancelled: bool = False

    @property
    def threats(self) -> int:
        return self.block + self.review + self.escalate

    @property
    def elapsed(self) -> float:
        return (self.finished or time.time()) - self.started


class ScanJob:
    """A cancellable scan running on a background thread.

    Callbacks are invoked from the worker thread; the GUI marshals them onto the
    Tk main loop itself (via a queue). Kept dead simple so it is easy to test.
    """

    def __init__(self, scanner, targets: List[Path], profile: str = "balanced",
                 prior: float = 0.001, quarantine=None, auto_quarantine: bool = False,
                 skip_dev: bool = True):
        self.scanner = scanner
        self.targets = list(targets)
        self.profile = profile
        self.prior = prior
        self.quarantine = quarantine
        self.auto_quarantine = auto_quarantine
        self.skip_dev = skip_dev
        self._cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.summary = ScanSummary()

    def cancel(self):
        self._cancel.set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def run(self, on_progress: Callable = None, on_flagged: Callable = None,
            on_done: Callable = None):
        """Synchronous run (used by tests); start() wraps this in a thread."""
        s = self.summary
        s.started = time.time()
        files = list(walk(self.targets, skip_dev=self.skip_dev))
        total = len(files)
        for i, fp in enumerate(files, 1):
            if self._cancel.is_set():
                s.cancelled = True
                break
            try:
                v = self.scanner.scan_file(str(fp), prior=self.prior,
                                           profile=self.profile)
            except Exception:
                continue
            s.scanned += 1
            d = v.decision
            if d == "ALLOW":
                s.allow += 1
            elif d == "REVIEW":
                s.review += 1
            elif d == "ESCALATE":
                s.escalate += 1
            elif d == "BLOCK":
                s.block += 1
            if v.decision != "ALLOW":
                row = {"path": v.path, "decision": v.decision,
                       "posterior": v.posterior,
                       "reason": (v.reasons[0] if v.reasons else "")}
                if self.auto_quarantine and d == "BLOCK" and self.quarantine \
                        and Path(v.path).exists():
                    try:
                        row["qid"] = self.quarantine.store(v.path, row)
                    except Exception:
                        pass
                s.flagged.append(row)
                if on_flagged:
                    on_flagged(row)
            if on_progress:
                on_progress(i, total, str(fp))
        s.finished = time.time()
        if on_done:
            on_done(s)
        return s

    def start(self, on_progress=None, on_flagged=None, on_done=None):
        self._thread = threading.Thread(
            target=self.run, args=(on_progress, on_flagged, on_done),
            daemon=True)
        self._thread.start()
        return self._thread


class RealtimeWatcher:
    """Polling on-access protection — AEGIS's realistic stand-in for a kernel
    minifilter (which would need a signed driver). Scans new/changed files in
    watched folders and reports threats via a callback."""

    def __init__(self, scanner, folders: List[Path], profile: str = "balanced",
                 prior: float = 0.001, quarantine=None, interval: float = 4.0):
        self.scanner = scanner
        self.folders = list(folders)
        self.profile = profile
        self.prior = prior
        self.quarantine = quarantine
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen: Dict[str, float] = {}
        self.checked = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, on_threat: Callable = None):
        self._stop.clear()
        # prime with existing files so we only react to NEW/CHANGED ones
        for fp in walk(self.folders, skip_dev=True):
            try:
                self._seen[str(fp)] = fp.stat().st_mtime
            except OSError:
                pass
        self._thread = threading.Thread(target=self._loop, args=(on_threat,),
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self, on_threat):
        while not self._stop.is_set():
            for fp in walk(self.folders, skip_dev=True):
                if self._stop.is_set():
                    break
                try:
                    m = fp.stat().st_mtime
                except OSError:
                    continue
                if self._seen.get(str(fp)) == m:
                    continue
                self._seen[str(fp)] = m
                self.checked += 1
                try:
                    v = self.scanner.scan_file(str(fp), prior=self.prior,
                                               profile=self.profile)
                except Exception:
                    continue
                if v.decision != "ALLOW" and on_threat:
                    on_threat({"path": v.path, "decision": v.decision,
                               "posterior": v.posterior,
                               "reason": v.reasons[0] if v.reasons else ""})
            self._stop.wait(self.interval)
