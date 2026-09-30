"""
aegis.intel — curated threat-intelligence blocklist (design doc S20, S22, S24).

The sharpest design line in the whole system lives here:

    IDENTITY (a whole-file SHA-256) is authoritative and FORCES a block;
    an INDICATOR (a substring: a C2 domain, a mutex, a dropped path) is
    strong evidence and is FUSED, never forced;
    a NEAR-IDENTITY (fuzzy CTPH) and a FAMILY fingerprint (imphash) are
    fused in proportion to how near they are.

Everything here is empty by default: threat intel is opt-in, and a user who
curates nothing runs exactly the seven/eight-detector engine.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Set

from . import simhash
from .allowlist import sha256


class Blocklist:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.hashes: Set[str] = set()          # exact SHA-256 -> force block
        self.indicators: Set[str] = set()      # substrings -> fused
        self.fuzzy: List[str] = []             # CTPH digests -> fused by similarity
        self.imphashes: Set[str] = set()       # imphash -> fused (family, S24)
        self.load()

    def load(self):
        if self.path.exists():
            try:
                d = json.loads(self.path.read_text(encoding="utf-8"))
                self.hashes = set(d.get("hashes", []))
                self.indicators = set(d.get("indicators", []))
                self.fuzzy = list(d.get("fuzzy", []))
                self.imphashes = set(d.get("imphashes", []))
            except Exception:
                pass

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({
            "hashes": sorted(self.hashes),
            "indicators": sorted(self.indicators),
            "fuzzy": self.fuzzy,
            "imphashes": sorted(self.imphashes),
        }, indent=2), encoding="utf-8")

    # --- curation ---------------------------------------------------------
    def add_file(self, filepath: str) -> Dict:
        """Record a known-bad file by exact hash + fuzzy digest + imphash."""
        from . import peparse
        data = Path(filepath).read_bytes()
        h = sha256(data)
        self.hashes.add(h)
        ct = simhash.ctph(data)
        if ct:
            self.fuzzy.append(ct)
        info = peparse.parse(data)
        if info.imphash:
            self.imphashes.add(info.imphash)
        self.save()
        return {"sha256": h, "ctph": ct, "imphash": info.imphash}

    def add_hash(self, h: str):
        self.hashes.add(h.lower().strip()); self.save()

    def add_ioc(self, s: str):
        self.indicators.add(s.strip()); self.save()

    def add_imphash(self, h: str):
        self.imphashes.add(h.lower().strip()); self.save()

    def import_feed(self, filepath: str) -> Dict:
        """Bulk import: 64-hex lines -> hashes, 32-hex -> imphashes, rest IOCs."""
        n = {"hashes": 0, "imphashes": 0, "indicators": 0}
        for line in Path(filepath).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if len(low) == 64 and all(c in "0123456789abcdef" for c in low):
                self.hashes.add(low); n["hashes"] += 1
            elif len(low) == 32 and all(c in "0123456789abcdef" for c in low):
                self.imphashes.add(low); n["imphashes"] += 1
            else:
                self.indicators.add(line); n["indicators"] += 1
        self.save()
        return n

    def remove(self, v: str):
        v2 = v.lower().strip()
        self.hashes.discard(v2)
        self.imphashes.discard(v2)
        self.indicators.discard(v.strip())
        self.fuzzy = [f for f in self.fuzzy if f != v.strip()]
        self.save()

    # --- matching ---------------------------------------------------------
    def best_fuzzy(self, ctph_digest: str) -> int:
        best = 0
        for known in self.fuzzy:
            best = max(best, simhash.similarity(ctph_digest, known))
        return best
