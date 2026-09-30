"""
aegis.allowlist — known-good identities that short-circuit to ALLOW before any
detector runs (design doc S11). The mirror image of D5's known-bad hashes:
recognizing a file you already trust is the cheapest possible false-positive
fix, and S3.1 proves perfect precision is otherwise unreachable. The allowlist
always wins over every force-block (S20).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Set


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Allowlist:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.hashes: Set[str] = set()
        self.load()

    def load(self):
        if self.path.exists():
            try:
                self.hashes = set(json.loads(self.path.read_text(encoding="utf-8")))
            except Exception:
                self.hashes = set()

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(sorted(self.hashes), indent=2),
                             encoding="utf-8")

    def add_file(self, filepath: str) -> str:
        h = sha256(Path(filepath).read_bytes())
        self.hashes.add(h)
        self.save()
        return h

    def add_hash(self, h: str):
        self.hashes.add(h.lower().strip())
        self.save()

    def contains(self, h: str) -> bool:
        return h.lower() in self.hashes
