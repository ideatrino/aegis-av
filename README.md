<p align="center">
  <img src="assets/aegis-logo.png" width="118" alt="AEGIS logo">
</p>

<h1 align="center">AEGIS</h1>
<p align="center"><em>Adaptive Ensemble with Guaranteed-envelope Integrity Scoring</em></p>

<p align="center">
  <a href="https://github.com/ideatrino/aegis/actions/workflows/ci.yml"><img src="https://github.com/ideatrino/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-3fc2bc" alt="MIT">
  <img src="https://img.shields.io/badge/python-3.9%2B-3fc2bc" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/deps-numpy_only-3fc2bc" alt="numpy only">
  <img src="https://img.shields.io/badge/selftest-28%2F28-3ec37a" alt="selftest 27/27">
</p>

A working, dependency-light (numpy-only) antivirus engine built from the
mathematics of what malware detection can and cannot do — a calibrated Bayesian
consensus over **nine detectors from nine different mathematical families**,
fused in log-odds space against an explicit cost model, with a desktop Security
Center, a Stage-3 behavior sandbox, and an `adversarial` command that
empirically proves the ensemble has no single point of failure.

> **The honest premise (design doc §0).** You cannot build a *provably perfect*
> antivirus — Cohen (1987) proved detection is undecidable by the same diagonal
> argument as the halting problem. So AEGIS never claims certainty. It reports a
> **calibrated posterior probability** with the evidence behind it, and lets you
> choose where your errors go.

---

## Install

Requires Python 3.9+ and numpy (the only dependency).

```bash
pip install numpy
cd aegis-project
python -m aegis train        # trains the learned detectors on the built-in corpus
python -m aegis selftest     # 16 invariants — should print 16/16
```

State (model, allowlist, blocklist, quarantine, rules) lives under `~/.aegis`
(override with the `AEGIS_HOME` environment variable).

---

## Desktop app (Security Center)

For the Norton/Bitdefender-style experience — a protection dashboard, scan
buttons, a quarantine manager, and a real-time protection toggle — launch the
GUI (Tkinter ships with standard Python, no extra install):

```bash
python -m aegis gui        # or: aegis-gui
```

It wraps the same engine. Honest scope, stated in the app: "real-time
protection" is a polling on-access watcher, not a kernel filesystem driver
(which needs a signed minifilter a pure-Python tool can't provide), and
"definitions" are your local signature/blocklist, not a cloud feed. It's an
original, educational engine — not a certified replacement for a commercial AV.

### Build a double-clickable .exe (Windows)

To open it from a desktop icon instead of a terminal:

```bash
pip install pyinstaller
python build_exe.py            # -> dist\AEGIS Security Center.exe
```

Use `python build_exe.py` (not the bare `pyinstaller` command): pip usually
installs `pyinstaller.exe` into a Scripts folder that isn't on PATH, so the bare
command fails with "not recognized" — invoking it through Python avoids that
entirely. Or just double-click `build_exe.bat`. The `.exe` carries the engine;
it reads your model from `%USERPROFILE%\.aegis` at runtime and offers to train
on first launch if none exists. If the windowed app vanishes on launch, rebuild
with `python build_exe.py --console` to see the traceback.

### Build a double-click app (.exe)

To open it from a desktop icon instead of a terminal, build a standalone binary
with the included PyInstaller spec — one command (on Windows, just run
`build_exe.bat`):

```bash
pip install pyinstaller
pyinstaller --clean --noconfirm AEGIS.spec
# -> dist/"AEGIS Security Center"(.exe)
```

The spec bundles a pre-trained model (so first launch is instant) and makes the
dynamic sandbox freeze-safe: inside a frozen build the app re-invokes itself as
the isolated sandbox child, since `python -I` isn't available. Verified: a built
binary blocks an `os.system` escape as a sandbox child. Drop an `aegis.ico` next
to the spec and uncomment its `icon=` line for a custom icon.

## Quick start

```bash
python -m aegis scan ./Downloads --profile balanced        # scan a folder
python -m aegis scan ./Downloads --jobs 8                  # parallel (real, past-GIL)
python -m aegis scan file.exe --profile max                # maximum security
python -m aegis inspect file.exe                           # full per-detector breakdown
python -m aegis inspect suspect.py --dynamic               # Stage-3: detonate in sandbox
python -m aegis scan release.zip --archives                # look inside archives
python -m aegis scan ./Downloads --html report.html        # shareable HTML report
```

---

## The eight detectors (why an ensemble, design doc §3.2, §4)

The Condorcet Jury Theorem says independent weak detectors combine into a strong
one — *if their errors are uncorrelated*. So each detector comes from a
different mathematical family, and evading one tends to worsen your score on
another. An attacker must fool all of them at once.

| Detector | Basis | Catches |
|---|---|---|
| **D1 structural** | grammar / parsing | packed code, W^X sections |
| **D2 entropy** | information theory | encrypted / packed payloads |
| **D3 api-graph** | graph theory | injection / RAT / ransomware clusters; dropper scripts (AST) |
| **D4 neural** | differentiable optimization | learned byte + structure patterns |
| **D5 signature** | hashing / LSH | known-bad (exact), repacked variants (fuzzy CTPH), families (imphash) |
| **D6 anomaly** | distance on a learned manifold | novelty, off-manifold files |
| **D7 ioc** | indicator co-occurrence | C2 URLs, persistence, LOLBins, encoded PowerShell |
| **D8 rules** | analyst-authored (YARA-lite) | anything you can teach it, fused not bypassed |
| **D9 documents** | format structure | Office VBA macros, PDF JavaScript/OpenAction/Launch |

Binary coverage spans PE, ELF, and Mach-O (macOS). Static reach also includes
fuzzy CTPH near-variant matching, Mandiant imphash family clustering, and a
static malicious-pickle opcode scanner for the ML-model supply chain.

Each detector emits an **`Evidence`** — a calibrated probability plus the base
rate it was calibrated against — never a yes/no. The core fuses them:

```
logit P(malicious | evidence) = logit(prior) + Σ wᵢ · [logit(pᵢ) − logit(π_calibration,ᵢ)]
```

which is exactly Bayes' rule for independent evidence.

---

## The decision (design doc §3.4, §5)

"Maximum security" is not a vibe — it is a point on the ROC curve. You set the
cost of a miss (`C_FN`) vs. a false alarm (`C_FP`) and slide the threshold:

- `--profile max` — `C_FN ≫ C_FP`, catches more, flags more (server / high-threat).
- `--profile balanced` — the default.
- `--profile relaxed` — fewer alarms (a trusted personal drive).

Every scan produces one of four verdicts:

- **ALLOW** — posterior below the allow threshold.
- **BLOCK** — posterior above the block threshold (auto-quarantine with `--quarantine`).
- **REVIEW** — a strong signal that can't be confirmed without executing the
  file (an indicator in a document, a signed installer, a fuzzy match): surfaced
  for a human, never auto-quarantined.
- **ESCALATE** — the detectors disagree; route to contained dynamic analysis
  rather than guess.

Set `--prior` to your environment's base rate. The default is 0.001 (almost all
files are benign — this is the base-rate math of §3.1 that defeats naive AV).

---

## Training on real data (design doc §9, §19)

The learned detectors ship trained on inert synthetic fixtures + real host
files. To make them real, train on labeled samples of your own:

```bash
python -m aegis make-corpus ./corpus       # writes benign/ + malicious/ (inert templates)
# drop your own labeled files into corpus/benign/ and corpus/malicious/
python -m aegis verify-corpus ./corpus     # class balance, dupes, label conflicts
python -m aegis train    --corpus ./corpus --augment
python -m aegis evaluate --corpus ./corpus --augment    # per-detector + fused AUC/PR-AUC
python -m aegis calibrate --corpus ./corpus --augment --cost-fn 20 --cost-fp 1
python -m aegis scan ./target --calibrated              # use the fitted operating point
```

`--augment` folds in the built-in benign grounding, which matters for a small
real malicious set: a handful of real samples sharpen the malicious boundary
while the grounding supplies benign diversity.

**`verify-corpus`** guards the traps §21 warned about before you train: it
reports class balance, duplicate files, and — critically — any content labeled
BOTH benign and malicious (dropped from training, never force-blocked).

**`calibrate`** turns §3.4 from theory into a dial: it fits the operating point
(τ_low, τ_high) from the corpus ROC at your cost ratio. Set `--cost-fn` high
(missing malware is expensive) and the block threshold slides down; that's
"maximum security" as a point on the curve, not a vibe. Saved to the model and
used by `scan --calibrated`.

**Real malware samples** come from reputable sources — MalwareBazaar / abuse.ch,
VirusShare, theZoo. **Handle them in a VM.** AEGIS reads the bytes; it never
executes a sample.

---

## The extensible layer: custom rules + threat intel (design doc §20–§22)

```bash
python -m aegis rules add my.rules            # install YARA-lite rules
python -m aegis rules check my.rules file.exe # test rules against a file
python -m aegis blocklist add malware.exe     # records exact + fuzzy + imphash
python -m aegis blocklist add-ioc "evil.example"
python -m aegis blocklist import feed.txt     # bulk: hashes + imphashes + IOCs
```

A rule's `severity` maps into the fusion, never around it:
`block` force-blocks (but the allowlist still wins), `review` surfaces,
`score` is a plain weighted vote. See `rules.example` for the full grammar.

---

## Honest performance (design doc §16, §19)

- Fused 5-fold CV **ROC-AUC ≈ 0.999**, **recall ≈ 0.98**, **FPR ≈ 0.00** on the
  built-in corpus (with injected label noise, so it isn't a meaningless 1.000).
- Real-world false-alarm rate driven from **~14% → ~0.2%** across the design's
  iterations by better data, more honest signals, and controls you own — never a
  fudged threshold.
- Real system binaries (`/bin/ls`, `python3`, `curl`) read ALLOW at P ≈ 0.0003
  even though they import powerful/network APIs.

---

## Limits (design doc §7 — stated plainly, because hiding them is the real flaw)

- **Not perfect, provably.** AEGIS shapes error; it never eliminates it.
- **Calibration debt.** The math is only as good as each detector's calibration
  and the honesty of the prior.
- **Dynamic analysis is Python-only.** Stage-3 (`--dynamic`) runs Python samples
  in an isolated subprocess under a CPython audit hook that blocks and records
  network/process/native/destructive-FS escapes, then checks the trace against a
  behavior envelope. Binaries can't be detonated in this build (they need an
  OS/VM backend); a near-signature-grade static signal on a binary is surfaced
  for review, never silently allowed. Running untrusted code is inherently risky,
  so `--dynamic` is off by default and opt-in.
- **Text is surfaced, never auto-blocked.** A script's indicator strings are
  visible content, not concealed payload, so a malicious script is REVIEW.
- **Signatures are detected, not verified.** A code signature downgrades a
  verdict but the cert chain isn't validated, so it's softened to REVIEW,
  never trusted to ALLOW.
- **The learned detectors are only as real as the corpus.** `make-corpus` +
  `train --augment` on real labeled data is the fix.

---

## Detonating binaries (external dynamic backend)

The built-in sandbox handles Python samples. For binaries — which must never be
run in-process — AEGIS calls out to a sandbox you supply:

```bash
export AEGIS_DYNAMIC_CMD='my-sandbox --json {sample}'   # must print {"events":[...]}
python -m aegis scan suspect.exe --dynamic
```

Each event is `{"category": "network|process|native|destructive_fs|fs_write",
"event": "...", "detail": "..."}`; any category in the escape set is an envelope
violation. Without a backend configured, binaries are honestly reported as
not-detonated rather than guessed at.

## Commands

```
scan · train · make-corpus · verify-corpus · evaluate · calibrate · adversarial
watch · selftest · quarantine · allowlist · blocklist · rules · fuzzy · imphash · inspect
```

`aegis adversarial` is worth a look: it empirically tests the design's central
claim by evading each detector in turn (and removing each one entirely) to show
the ensemble still catches the sample, then reports the Condorcet gain of the
fused score over the best single detector.

`python -m aegis <command> --help` for each.

---

*Still not provably perfect — that was never on the table (§0). But complete,
measured, honest about every limit, and built from the mathematics up.*
