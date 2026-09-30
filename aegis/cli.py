"""
aegis.cli — the command surface (design doc S12, S19, S20, S22).

  scan · train · make-corpus · evaluate · watch · selftest
  quarantine · allowlist · blocklist · rules · fuzzy · imphash · inspect
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List

from . import fixtures, metrics, peparse, report, rules as rulemod, simhash
from .allowlist import Allowlist, sha256
from .intel import Blocklist
from .quarantine import Quarantine
from .scanner import Scanner, Model, DEFAULT_PRIOR

AEGIS_HOME = Path(os.environ.get("AEGIS_HOME", Path.home() / ".aegis"))
MODEL_PATH = AEGIS_HOME / "model.json"
ALLOW_PATH = AEGIS_HOME / "allowlist.json"
BLOCK_PATH = AEGIS_HOME / "blocklist.json"
QUAR_DIR = AEGIS_HOME / "quarantine"
RULES_DIR = AEGIS_HOME / "rules"

_DEV_NOISE = {"node_modules", ".venv", "venv", "__pycache__", "target",
              ".hypothesis", ".ruff_cache", ".gradle", ".cargo", "vendor",
              ".git", "dist", "build", ".mypy_cache", ".pytest_cache"}


def _expand(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p))).resolve()


def _load_scanner(extra_rules_path=None) -> Scanner:
    if not MODEL_PATH.exists():
        print("No trained model found. Run `aegis train` first.", file=sys.stderr)
        sys.exit(2)
    model = Model.load(MODEL_PATH)
    al = Allowlist(ALLOW_PATH)
    bl = Blocklist(BLOCK_PATH)
    extra = []
    if RULES_DIR.exists():
        for f in RULES_DIR.glob("*"):
            if f.suffix in (".rules", ".yar", ".yara"):
                extra += rulemod.parse_rules(f.read_text(encoding="utf-8", errors="replace"))
    if extra_rules_path:
        p = _expand(extra_rules_path)
        if p.is_dir():
            for f in p.glob("*"):
                if f.suffix in (".rules", ".yar", ".yara"):
                    extra += rulemod.parse_rules(f.read_text(encoding="utf-8", errors="replace"))
        elif p.exists():
            extra += rulemod.parse_rules(p.read_text(encoding="utf-8", errors="replace"))
    return Scanner(model, allowlist=al, blocklist=bl, extra_rules=extra)


def _read_aegisignore(root: Path) -> List[str]:
    patterns = []
    for base in (root, Path.home()):
        f = base / ".aegisignore"
        if f.exists():
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    return patterns


def _walk(root: Path, exclude: List[str], skip_dev: bool):
    ignore = _read_aegisignore(root)
    exclude = list(exclude) + ignore
    def excluded(path: Path) -> bool:
        parts = set(path.parts)
        if skip_dev and (_DEV_NOISE & parts):
            return True
        s = str(path)
        for pat in exclude:
            bare = pat.strip("*/")
            if bare and bare in parts:
                return True
            if Path(s).match(pat):
                return True
        return False
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not excluded(dp / d)]
        for fn in filenames:
            fp = dp / fn
            if fn == ".aegisignore":
                continue
            if not excluded(fp):
                yield fp


# ---------------------------------------------------------------------------
def cmd_train(args):
    from . import train as trainmod
    if args.corpus:
        items = trainmod.load_corpus_dir(_expand(args.corpus))
        print(f"Loaded {len(items)} labeled samples from {args.corpus}")
        model = trainmod.train(items=items, augment=args.augment)
    else:
        model = trainmod.train()
    model.save(MODEL_PATH)
    print(f"Trained model saved to {MODEL_PATH}")
    print(f"  fusion weights: " +
          ", ".join(f"{k}={v:.2f}" for k, v in sorted(model.weights.items())))
    print(f"  signature DB: {len(model.bad_hashes)} known-bad hashes")


def cmd_make_corpus(args):
    root = _expand(args.dir)
    (root / "benign").mkdir(parents=True, exist_ok=True)
    (root / "malicious").mkdir(parents=True, exist_ok=True)
    n_b = n_m = 0
    for name, data, label in fixtures.make_corpus():
        safe = name.replace("/", "_")
        sub = "malicious" if label else "benign"
        (root / sub / safe).write_bytes(data)
        if label: n_m += 1
        else: n_b += 1
    print(f"Wrote corpus to {root}: {n_b} benign, {n_m} malicious (inert fixtures).")
    print("Drop your own labeled samples into benign/ and malicious/, then:")
    print(f"  aegis train --corpus {args.dir} --augment")


def _load_eval_items(args):
    from . import train as trainmod
    if args.corpus:
        items = trainmod.load_corpus_dir(_expand(args.corpus))
        if args.augment:
            items = items + fixtures.make_corpus()
    else:
        items = fixtures.make_corpus()
    return items


def _per_detector_auc(items):
    """Per-detector ROC-AUC on the corpus (§9): each detector's own p-score."""
    from . import formats, peparse
    from .detectors import static as D
    rows = {}
    names = ["structural", "entropy", "api_graph", "ioc"]
    scores = {n: [] for n in names}
    y = []
    for _, data, label in items:
        y.append(label)
        is_text = formats.is_text(data); fmt = formats.sniff_magic(data)
        info = peparse.parse(data)
        scores["structural"].append(D.d1_structural(data, info, is_text, fmt).p)
        scores["entropy"].append(D.d2_entropy(data, is_text, fmt).p)
        scores["api_graph"].append(D.d3_api_graph(data, info, is_text, fmt).p)
        scores["ioc"].append(D.d7_ioc(data, is_text, fmt, None).p)
    for n in names:
        rows[n] = metrics.roc_auc(y, scores[n])
    return rows


def cmd_evaluate(args):
    from . import train as trainmod
    items = _load_eval_items(args)
    y_all, s_all = trainmod.cv_posteriors(items, k=5, prior=0.5)
    auc = metrics.roc_auc(y_all, s_all)
    pr = metrics.pr_auc(y_all, s_all)
    preds = [1 if s >= 0.5 else 0 for s in s_all]
    cm = metrics.confusion(y_all, preds)
    r = metrics.rates(cm)
    print(f"Corpus: {len(items)} samples "
          f"({sum(1 for _,_,l in items if l==0)} benign, "
          f"{sum(1 for _,_,l in items if l==1)} malicious)")
    print(f"Fused 5-fold CV ROC-AUC: {auc:.4f}   PR-AUC: {pr:.4f}")
    print(f"  confusion @0.5: {cm}")
    print(f"  recall={r['recall']:.3f}  FPR={r['fpr']:.3f}  precision={r['precision']:.3f}")
    print("Per-detector ROC-AUC (independent views, §3.2/§9):")
    for name, a in sorted(_per_detector_auc(items).items(), key=lambda x: -x[1]):
        print(f"  {name:<12} {a:.3f}")


def cmd_calibrate(args):
    """Fit the operating point (τ_low, τ_high) from the corpus ROC at a chosen
    cost ratio (§3.4), and persist it so `scan --calibrated` uses it."""
    from . import train as trainmod
    if not MODEL_PATH.exists():
        print("Train first: aegis train", file=sys.stderr); sys.exit(2)
    items = _load_eval_items(args)
    y, s = trainmod.cv_posteriors(items, k=5, prior=args.prior)
    tau_high, loss = metrics.best_threshold_by_cost(
        y, s, c_fn=args.cost_fn, c_fp=args.cost_fp, prior=args.prior)
    tau_low = metrics.threshold_at_fpr(y, s, target_fpr=args.target_fpr)
    tau_low = min(tau_low, tau_high)
    model = Model.load(MODEL_PATH)
    model.thresholds = [round(tau_low, 4), round(tau_high, 4)]
    model.save(MODEL_PATH)
    print(f"Calibrated operating point (C_FN={args.cost_fn}, C_FP={args.cost_fp}, "
          f"prior={args.prior}):")
    print(f"  tau_low  (allow  boundary) = {tau_low:.4f}  (FPR <= {args.target_fpr})")
    print(f"  tau_high (block  boundary) = {tau_high:.4f}  (min expected loss={loss:.5f})")
    print(f"  saved to model; use with:  aegis scan <path> --calibrated")


def cmd_adversarial(args):
    """Empirically test the coupled-ensemble thesis (§3.2/§4)."""
    from . import adversarial
    sc = _load_scanner(None)
    print("Adversarial evasion test — evade one detector, check the ensemble holds:\n")
    print(f"  {'evasion':<22}{'targets':<11}{'target p':>16}   {'ensemble':>16}")
    print("  " + "-" * 68)
    all_held = True
    for r in adversarial.run_evasions(sc, profile=args.profile):
        held = "HELD" if r.ensemble_held else "EVADED!"
        if not r.ensemble_held:
            all_held = False
        print(f"  {r.evasion:<22}{r.target:<11}"
              f"{r.target_p_before:>7.2f}->{r.target_p_after:<7.2f}"
              f"{r.ensemble_before:>8}->{r.ensemble_after:<8} [{held}]")
    print()
    print("  Reading: each evasion defeats its targeted detector (p drops), but the")
    print("  ensemble still flags the sample because the other detectors — drawn from")
    print("  different mathematical families — don't share that blind spot (§4).")
    if all_held:
        print("  RESULT: the ensemble held against every single-detector evasion.")

    # rigorous form: remove each detector ENTIRELY (total evasion)
    print("\nLeave-one-out (total evasion of each detector — does the ensemble hold?):")
    baseline, rows = adversarial.leave_one_out(sc, profile=args.profile)
    print(f"  baseline (all detectors): {baseline}")
    held = True
    for d, dec in rows:
        ok = dec != "ALLOW"
        held = held and ok
        print(f"  without {d:<12} -> {dec:<10} [{'HELD' if ok else 'EVADED!'}]")
    if held:
        print("  RESULT: removing any single detector still flags the sample (§4).")

    print("\nCondorcet ensemble gain (§3.2) — ROC-AUC, single detectors vs fused:")
    items = _load_eval_items(args)
    gain = adversarial.ensemble_gain(items)
    for name in ("structural", "entropy", "api_graph", "ioc"):
        print(f"  {name:<12} {gain[name]:.3f}")
    print(f"  {'best single':<12} {gain['best_single']:.3f}")
    print(f"  {'FUSED':<12} {gain['FUSED']:.3f}   "
          f"(+{gain['FUSED'] - gain['best_single']:.3f} over best single detector)")


def cmd_verify_corpus(args):
    """Sanity-check a real labeled benign/ + malicious/ tree before training
    (guards the label-leak / conflict traps of §21)."""
    from .allowlist import sha256
    root = _expand(args.dir)
    counts = {"benign": 0, "malicious": 0}
    hashes = {"benign": {}, "malicious": {}}
    unreadable = 0
    sizes = []
    for label in ("benign", "malicious"):
        d = root / label
        if not d.exists():
            print(f"  missing {label}/ directory", file=sys.stderr)
            continue
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            try:
                data = f.read_bytes()
            except Exception:
                unreadable += 1; continue
            counts[label] += 1
            sizes.append(len(data))
            hashes[label].setdefault(sha256(data), []).append(str(f))
    conflicts = set(hashes["benign"]) & set(hashes["malicious"])
    dup_b = sum(len(v) - 1 for v in hashes["benign"].values() if len(v) > 1)
    dup_m = sum(len(v) - 1 for v in hashes["malicious"].values() if len(v) > 1)
    print(f"Corpus at {root}:")
    print(f"  benign:    {counts['benign']} files ({len(hashes['benign'])} unique)")
    print(f"  malicious: {counts['malicious']} files ({len(hashes['malicious'])} unique)")
    if sizes:
        sizes.sort()
        print(f"  size: min={sizes[0]}  median={sizes[len(sizes)//2]}  max={sizes[-1]}")
    print(f"  duplicate files: {dup_b} benign, {dup_m} malicious")
    if unreadable:
        print(f"  unreadable/skipped: {unreadable}")
    if conflicts:
        print(f"  !! {len(conflicts)} content(s) labeled BOTH benign and malicious "
              f"-> will be dropped from training (never force-blocked, §21):")
        for h in list(conflicts)[:5]:
            print(f"       {h[:16]}  {hashes['benign'][h][0]}  <->  {hashes['malicious'][h][0]}")
    bal = counts["malicious"] / max(1, counts["benign"] + counts["malicious"])
    print(f"  class balance: {bal:.1%} malicious", end="")
    if bal < 0.05 or bal > 0.95:
        print("  (very imbalanced — use --augment to add benign diversity)")
    else:
        print()
    ok = counts["benign"] > 0 and counts["malicious"] > 0 and not conflicts
    print("  READY to train." if ok else "  Fix the issues above before training.")


# --- process-parallel worker (§24): each worker builds its own scanner from
# the on-disk model and scans independent files, giving real parallelism past
# the GIL with byte-identical verdicts and preserved order. -------------------
_WORKER = {}


def _worker_init(rules_path):
    _WORKER["sc"] = _load_scanner(rules_path)


def _worker_scan(job):
    path, prior, profile, dynamic, calibrated = job
    try:
        v = _WORKER["sc"].scan_file(path, prior=prior, profile=profile,
                                    dynamic=dynamic, calibrated=calibrated)
        return {"path": v.path, "decision": v.decision, "posterior": v.posterior,
                "reasons": v.reasons,
                "contributions": v.contributions(), "prior": v.prior,
                "disagreement": v.disagreement}
    except Exception as e:
        return {"path": path, "decision": "ALLOW", "posterior": 0.0,
                "reasons": [f"unreadable: {e}"], "contributions": [],
                "prior": prior, "disagreement": 0.0}


class _V:
    """Lightweight verdict shim reconstructed from a worker result."""
    def __init__(self, d):
        self.__dict__.update(d)
        self._contribs = d.get("contributions", [])

    @property
    def is_flagged(self):
        return self.decision != "ALLOW"

    def contributions(self):
        return self._contribs


def cmd_scan(args):
    sc = _load_scanner(args.rules)
    quar = Quarantine(QUAR_DIR) if args.quarantine else None
    root = _expand(args.path)
    if not root.exists():
        print(f"Path not found: {args.path}", file=sys.stderr)
        sys.exit(2)
    verdicts = []
    flagged = []
    n = 0
    from . import archives
    jobs = max(1, getattr(args, "jobs", 1))

    # parallel path: plain per-file directory scan (not archives, which expand
    # per-file and are handled sequentially).
    if jobs > 1 and not args.archives and root.is_dir():
        files = [str(fp) for fp in _walk(root, args.exclude or [], args.skip_dev_noise)]
        n = len(files)
        joblist = [(f, args.prior, args.profile, getattr(args, "dynamic", False),
                    getattr(args, "calibrated", False)) for f in files]
        try:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=jobs, initializer=_worker_init,
                                     initargs=(args.rules,)) as ex:
                results = list(ex.map(_worker_scan, joblist, chunksize=8))
        except Exception:
            # clean fallback to sequential if the platform can't spawn (§24)
            _worker_init(args.rules)
            results = [_worker_scan(j) for j in joblist]
        for d in results:
            v = _V(d)
            verdicts.append(v)
            if v.is_flagged:
                flagged.append(v)
            if not args.flagged_only:
                _print_verdict(v)
            if quar and v.decision == "BLOCK" and Path(v.path).exists():
                qid = quar.store(v.path, {"decision": v.decision,
                                          "posterior": v.posterior})
                print(f"        quarantined -> {qid}")
        _finish_scan(args, verdicts, flagged, n)
        return

    for fp in _walk(root, args.exclude or [], args.skip_dev_noise):
        try:
            data = fp.read_bytes()
        except Exception:
            continue
        n += 1
        samples = [(str(fp), data)]
        if args.archives and archives.is_archive(data):
            # iter_members already yields fully-qualified logical paths
            samples = list(archives.iter_members(data, str(fp)))
        for label, body in samples:
            if not body:
                continue
            v = sc.scan_bytes(body, label, prior=args.prior, profile=args.profile,
                              dynamic=getattr(args, "dynamic", False),
                              calibrated=getattr(args, "calibrated", False))
            verdicts.append(v)
            if v.is_flagged:
                flagged.append(v)
            if not args.flagged_only:
                _print_verdict(v)
            if quar and v.decision == "BLOCK":
                # only quarantine real files on disk (not archive members)
                if "::" not in label and Path(label).exists():
                    qid = quar.store(label, {"decision": v.decision,
                                             "posterior": v.posterior})
                    print(f"        quarantined -> {qid}")
    _finish_scan(args, verdicts, flagged, n)


def _finish_scan(args, verdicts, flagged, n):
    print(f"\nScanned {n} file(s); {len(flagged)} flagged.")
    if flagged:
        print("Flagged:")
        for v in flagged:
            print(f"  [{v.decision}] P={v.posterior:.3f}  {v.path}")
    if args.html:
        report.render(verdicts, _expand(args.html))
        print(f"HTML report -> {args.html}")
    if args.json:
        out = [{"path": v.path, "decision": v.decision,
                "posterior": v.posterior, "reasons": v.reasons} for v in verdicts]
        Path(_expand(args.json)).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"JSON report -> {args.json}")


def _print_verdict(v):
    tag = {"ALLOW": " ok ", "REVIEW": "REVW", "ESCALATE": "ESCL", "BLOCK": "BLCK"}
    print(f"  [{tag.get(v.decision,'?')}] P={v.posterior:.3f}  {v.path}")
    if v.is_flagged:
        for r in v.reasons[:3]:
            print(f"         - {r}")


def cmd_inspect(args):
    sc = _load_scanner(args.rules)
    v = sc.scan_file(str(_expand(args.file)), prior=args.prior, profile=args.profile,
                     dynamic_force=getattr(args, "dynamic", False),
                     calibrated=getattr(args, "calibrated", False))
    print(f"File: {v.path}")
    print(f"Decision: {v.decision}   posterior P(malicious)={v.posterior:.4f}")
    print(f"Prior: {v.prior}   disagreement(var)={v.disagreement:.4f}   profile={args.profile}")
    print("\nPer-detector contributions (signed log-odds):")
    print(f"  {'detector':<12}{'p':>7}{'weight':>8}{'LLR':>8}{'contrib':>9}")
    for c in sorted(v.contributions(), key=lambda x: -abs(x["contribution"])):
        state = "abstain" if c["abstain"] else ""
        print(f"  {c['detector']:<12}{c['p']:>7.3f}{c['weight']:>8.2f}"
              f"{c['llr']:>8.2f}{c['contribution']:>9.2f}  {state}")
    print("\nReasons:")
    for r in v.reasons:
        print(f"  - {r}")
    ct = simhash.ctph(_expand(args.file).read_bytes())
    print(f"\nCTPH digest: {ct or '(file too small)'}")
    info = peparse.parse(_expand(args.file).read_bytes())
    if info.imphash:
        print(f"imphash: {info.imphash}")


def cmd_fuzzy(args):
    d1 = _expand(args.file1).read_bytes()
    d2 = _expand(args.file2).read_bytes()
    s = simhash.similarity(simhash.ctph(d1), simhash.ctph(d2))
    print(f"CTPH similarity: {s}/100")


def cmd_imphash(args):
    info = peparse.parse(_expand(args.file).read_bytes())
    print(info.imphash or "(no import table / not a PE)")


def cmd_watch(args):
    sc = _load_scanner(args.rules)
    quar = Quarantine(QUAR_DIR)
    root = _expand(args.path)
    seen = {}
    audit = AEGIS_HOME / "watch.jsonl"
    AEGIS_HOME.mkdir(parents=True, exist_ok=True)
    print(f"Watching {root} (Ctrl-C to stop)...")
    try:
        while True:
            for fp in _walk(root, args.exclude or [], True):
                try:
                    st = fp.stat().st_mtime
                except OSError:
                    continue
                if seen.get(str(fp)) == st:
                    continue
                seen[str(fp)] = st
                try:
                    v = sc.scan_file(str(fp), profile=args.profile)
                except Exception:
                    continue
                if v.is_flagged:
                    rec = {"time": time.time(), "path": v.path,
                           "decision": v.decision, "posterior": v.posterior}
                    with open(audit, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(rec) + "\n")
                    print(f"  [{v.decision}] P={v.posterior:.3f} {v.path}")
                    if v.decision == "BLOCK":
                        quar.store(str(fp), rec)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")


def cmd_selftest(args):
    from . import selftest
    ok = selftest.main()
    sys.exit(0 if ok else 1)


def cmd_gui(args):
    from . import gui
    sys.exit(gui.launch())


def cmd_allowlist(args):
    al = Allowlist(ALLOW_PATH)
    if args.action == "add":
        h = al.add_file(str(_expand(args.value)))
        print(f"allowlisted {h}")
    elif args.action == "list":
        for h in sorted(al.hashes):
            print(h)


def cmd_quarantine(args):
    quar = Quarantine(QUAR_DIR)
    if args.action == "list":
        for m in quar.list():
            print(f"{m['qid']}  {m['verdict'].get('decision','?')}  {m['original_path']}")
    elif args.action == "restore":
        target = quar.restore(args.value)
        print(f"restored -> {target}")


def cmd_blocklist(args):
    bl = Blocklist(BLOCK_PATH)
    if args.action == "add":
        r = bl.add_file(str(_expand(args.value)))
        print(f"blocklisted: sha256={r['sha256']} imphash={r['imphash'] or '-'}")
    elif args.action == "add-hash":
        bl.add_hash(args.value); print("added hash")
    elif args.action == "add-ioc":
        bl.add_ioc(args.value); print("added indicator")
    elif args.action == "import":
        n = bl.import_feed(str(_expand(args.value))); print(f"imported {n}")
    elif args.action == "remove":
        bl.remove(args.value); print("removed")
    elif args.action == "list":
        print(f"hashes: {len(bl.hashes)}  indicators: {len(bl.indicators)} "
              f"fuzzy: {len(bl.fuzzy)}  imphashes: {len(bl.imphashes)}")


def cmd_rules(args):
    if args.action == "list":
        built = rulemod.builtin_rules()
        print(f"built-in rules ({len(built)}):")
        for r in built:
            print(f"  {r.name}  [{r.severity}]")
        if RULES_DIR.exists():
            for f in RULES_DIR.glob("*"):
                if f.suffix in (".rules", ".yar", ".yara"):
                    for r in rulemod.parse_rules(f.read_text(encoding="utf-8")):
                        print(f"  {r.name}  [{r.severity}]  ({f.name})")
    elif args.action == "add":
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        src = _expand(args.value)
        parsed = rulemod.parse_rules(src.read_text(encoding="utf-8", errors="replace"))
        if not parsed:
            print("no valid rules found", file=sys.stderr); sys.exit(1)
        dest = RULES_DIR / src.name
        dest.write_text(src.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        print(f"installed {len(parsed)} rule(s) -> {dest}")
    elif args.action == "check":
        # value = rules file, file2 = target
        parsed = rulemod.parse_rules(_expand(args.value).read_text(encoding="utf-8"))
        data = _expand(args.file2).read_bytes()
        hits = rulemod.match_rules(data, parsed)
        if hits:
            for h in hits:
                print(f"  MATCH {h.name} [{h.severity}]")
        else:
            print("  no matches")


def build_parser():
    p = argparse.ArgumentParser(prog="aegis",
                                description="AEGIS — calibrated Bayesian-consensus antivirus")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan a file or directory")
    sp.add_argument("path")
    sp.add_argument("--profile", choices=["max", "balanced", "relaxed"], default="balanced")
    sp.add_argument("--prior", type=float, default=DEFAULT_PRIOR)
    sp.add_argument("--html"); sp.add_argument("--json")
    sp.add_argument("--rules")
    sp.add_argument("--quarantine", action="store_true")
    sp.add_argument("--archives", action="store_true",
                    help="scan inside zip/tar/gz archives (bomb-guarded)")
    sp.add_argument("--dynamic", action="store_true",
                    help="Stage-3: run ESCALATE-band Python samples in the sandbox")
    sp.add_argument("--jobs", "-j", type=int, default=1,
                    help="parallel worker processes for a directory scan")
    sp.add_argument("--exclude", action="append")
    sp.add_argument("--skip-dev-noise", action="store_true",
                    help="skip node_modules/.venv/etc (a security trade-off you opt into)")
    sp.add_argument("--flagged-only", action="store_true")
    sp.add_argument("--calibrated", action="store_true",
                    help="use the cost-model operating point from `aegis calibrate`")
    sp.set_defaults(func=cmd_scan)

    tp = sub.add_parser("train", help="train the learned detectors + fusion")
    tp.add_argument("--corpus"); tp.add_argument("--augment", action="store_true")
    tp.set_defaults(func=cmd_train)

    mp = sub.add_parser("make-corpus", help="write a benign/+malicious/ corpus to disk")
    mp.add_argument("dir")
    mp.set_defaults(func=cmd_make_corpus)

    ep = sub.add_parser("evaluate", help="k-fold CV ROC-AUC + confusion matrix")
    ep.add_argument("--corpus"); ep.add_argument("--augment", action="store_true")
    ep.set_defaults(func=cmd_evaluate)

    ip = sub.add_parser("inspect", help="full per-detector breakdown for one file")
    ip.add_argument("file")
    ip.add_argument("--profile", choices=["max", "balanced", "relaxed"], default="balanced")
    ip.add_argument("--prior", type=float, default=DEFAULT_PRIOR)
    ip.add_argument("--rules")
    ip.add_argument("--dynamic", action="store_true")
    ip.add_argument("--calibrated", action="store_true")
    ip.set_defaults(func=cmd_inspect)

    cp = sub.add_parser("calibrate", help="fit τ_low/τ_high from the corpus ROC "
                        "at a cost ratio (§3.4)")
    cp.add_argument("--corpus"); cp.add_argument("--augment", action="store_true")
    cp.add_argument("--cost-fn", type=float, default=10.0,
                    help="cost of a missed malware (default 10x a false alarm)")
    cp.add_argument("--cost-fp", type=float, default=1.0)
    cp.add_argument("--prior", type=float, default=0.05)
    cp.add_argument("--target-fpr", type=float, default=0.01)
    cp.set_defaults(func=cmd_calibrate)

    vp = sub.add_parser("verify-corpus", help="sanity-check a benign/+malicious/ tree")
    vp.add_argument("dir")
    vp.set_defaults(func=cmd_verify_corpus)

    ap2 = sub.add_parser("adversarial", help="test the coupled-ensemble thesis "
                         "(evade one detector, ensemble holds) + Condorcet gain")
    ap2.add_argument("--profile", choices=["max", "balanced", "relaxed"], default="max")
    ap2.add_argument("--corpus"); ap2.add_argument("--augment", action="store_true")
    ap2.set_defaults(func=cmd_adversarial)

    fp = sub.add_parser("fuzzy", help="CTPH similarity of two files")
    fp.add_argument("file1"); fp.add_argument("file2")
    fp.set_defaults(func=cmd_fuzzy)

    hp = sub.add_parser("imphash", help="print a PE's imphash")
    hp.add_argument("file")
    hp.set_defaults(func=cmd_imphash)

    wp = sub.add_parser("watch", help="poll a folder and scan on change")
    wp.add_argument("path")
    wp.add_argument("--interval", type=float, default=3.0)
    wp.add_argument("--profile", choices=["max", "balanced", "relaxed"], default="balanced")
    wp.add_argument("--exclude", action="append")
    wp.add_argument("--rules")
    wp.set_defaults(func=cmd_watch)

    stp = sub.add_parser("selftest", help="run the invariant suite")
    stp.set_defaults(func=cmd_selftest)

    gp = sub.add_parser("gui", help="launch the AEGIS Security Center desktop app")
    gp.set_defaults(func=cmd_gui)

    ap = sub.add_parser("allowlist"); ap.add_argument("action", choices=["add", "list"])
    ap.add_argument("value", nargs="?"); ap.set_defaults(func=cmd_allowlist)

    qp = sub.add_parser("quarantine")
    qp.add_argument("action", choices=["list", "restore"])
    qp.add_argument("value", nargs="?"); qp.set_defaults(func=cmd_quarantine)

    bp = sub.add_parser("blocklist")
    bp.add_argument("action", choices=["add", "add-hash", "add-ioc", "import", "remove", "list"])
    bp.add_argument("value", nargs="?"); bp.set_defaults(func=cmd_blocklist)

    rp = sub.add_parser("rules")
    rp.add_argument("action", choices=["list", "add", "check"])
    rp.add_argument("value", nargs="?"); rp.add_argument("file2", nargs="?")
    rp.set_defaults(func=cmd_rules)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
