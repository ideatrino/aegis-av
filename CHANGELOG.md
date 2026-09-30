# Changelog

All notable changes to AEGIS. The project began as a single prompt — *build,
from the mathematics, the most secure and most functional antivirus you can* —
and grew by closing one real failure at a time.

## 5.9.1
- **Fix:** the scanner no longer leaks the compiler's `SyntaxWarning`s to the
  console when D3 parses Python files that contain invalid escape sequences
  (Windows paths, un-raw regexes) — `ast.parse` now runs under suppressed
  warnings. Locked in by a self-test invariant (now **28**) and a unit test.
- Frozen `.exe` builds from `aegis_app.py` (GUI + sandbox-child dispatch), so
  Stage-3 dynamic analysis works inside the packaged app.
- Packaged as an open-source repo: MIT LICENSE, CI, SECURITY/CONTRIBUTING/
  CHANGELOG, README with logo + badges, PUBLISHING guide.

## 5.9.0
- Desktop **Security Center** GUI (`aegis gui`): protection dashboard, scans,
  quarantine manager, real-time protection toggle, settings.
- Pre-trained model bundled for instant first launch; PyInstaller build
  (`build_exe.py`) for a standalone Windows `.exe`.

## 5.7.0
- **D9 document detector** — Office VBA macros (OLE2 + OOXML) and PDF JavaScript.
- **Mach-O** parsing (macOS binaries) alongside PE/ELF.
- **`aegis adversarial`** — empirically validates the coupled-ensemble thesis:
  single-detector evasions and leave-one-out both show the ensemble holds, plus
  the Condorcet gain (fused vs. best single detector).
- Self-contained `DESIGN.md` (the §0–§5 mathematics).

## 5.6.0
- **`aegis calibrate`** — fits the cost-model operating point (τ_low, τ_high)
  from the corpus ROC at a chosen C_FN/C_FP (§3.4).
- **`verify-corpus`** — class balance, duplicates, and benign/malicious label
  conflicts before training.
- Enriched `evaluate` — per-detector ROC-AUC + fused ROC/PR-AUC.
- Pluggable dynamic backend (`AEGIS_DYNAMIC_CMD`) so binaries can be detonated
  by a user-supplied sandbox.

## 5.5.0
- **Stage-3 dynamic sandbox** — Python samples run in an isolated subprocess
  under an audit hook that blocks and records network/process/native/FS escapes.
- Signature-aware downgrade (signed binaries never auto-quarantine).
- D7 stands down on Python source (fixes self-detection on the project's own
  files); process-parallel scanning (`--jobs`).

## 5.2–5.4
- Fuzzy CTPH near-variant matching; Mandiant imphash family clustering.
- Recursive, bomb-guarded, model-aware archive scanning.
- Static malicious-pickle opcode scanner (ML-model RCE vector);
  safetensors/GGUF/npy recognition.
- Real YARA-lite rule grammar; `inspect` command.

## 5.0–5.1
- Corpus builder + real-labeled-data training path.
- **D8 extensible layer** — custom YARA-lite rules and a curated threat-intel
  blocklist, both fused (never a bypass). Built-in EICAR self-check.

## 4.x
- Seven-detector ensemble; real PE/ELF parsing; learned reliability weights with
  security floors; allowlisting; neutered quarantine; HTML reports; and the
  real-world false-alarm rate driven from ~14% to ~0.2% across successive fixes.

## 2.0–3.0
- The four-stage pipeline and the Bayesian consensus core, built from the
  design: static ensemble → log-odds fusion → contained dynamics → guardian.
