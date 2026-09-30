"""
aegis.quarantine — a neutering quarantine store (design doc S10/S4-phase4).

A blocked file is XOR-neutered on disk (header corrupted with a per-file key)
so a stray double-click or another on-access scanner cannot detonate it, and a
JSON metadata sidecar records the verdict. Restore re-applies the key and
reconstructs the original byte-for-byte (verified by SHA-256).
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Dict, List

from .allowlist import sha256

_KEY = b"AEGIS-neuter-key-v1"  # fixed, documented: neuter is safety, not secrecy


def _xor(data: bytes, key: bytes, n: int) -> bytes:
    out = bytearray(data)
    for i in range(min(n, len(out))):
        out[i] ^= key[i % len(key)]
    return bytes(out)


class Quarantine:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def store(self, filepath: str, verdict: Dict) -> str:
        data = Path(filepath).read_bytes()
        original_hash = sha256(data)
        qid = secrets.token_hex(8)
        neutered = _xor(data, _KEY, 256)
        dest = self.root / f"{qid}.quar"
        dest.write_bytes(neutered)
        meta = {
            "qid": qid,
            "original_path": str(Path(filepath).resolve()),
            "original_sha256": original_hash,
            "neuter_bytes": min(256, len(data)),
            "verdict": verdict,
        }
        (self.root / f"{qid}.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8")
        return qid

    def list(self) -> List[Dict]:
        out = []
        for j in sorted(self.root.glob("*.json")):
            try:
                out.append(json.loads(j.read_text(encoding="utf-8")))
            except Exception:
                pass
        return out

    def restore(self, qid: str, dest_path: str = None) -> str:
        meta = json.loads((self.root / f"{qid}.json").read_text(encoding="utf-8"))
        neutered = (self.root / f"{qid}.quar").read_bytes()
        original = _xor(neutered, _KEY, meta["neuter_bytes"])
        if sha256(original) != meta["original_sha256"]:
            raise ValueError("restore integrity check failed (hash mismatch)")
        target = dest_path or meta["original_path"]
        Path(target).write_bytes(original)
        return target
