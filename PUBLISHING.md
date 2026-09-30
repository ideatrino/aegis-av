# Publishing AEGIS to GitHub

This folder is a ready-to-publish repository: MIT license, `.gitignore`, CI that
runs the test suite on every push, and a GitHub-styled README. Commit it under
**your own** GitHub identity (not this machine's), so the history is yours.

## 1. One-time git identity (skip if already set)

```bash
git config --global user.name  "Ideatrino"
git config --global user.email "ideatrino@proton.me"
```

## 2. Create the local history

From inside this `aegis-project` folder:

```bash
git init
git add .
git commit -m "AEGIS v5.9 — a calibrated Bayesian-consensus antivirus, from the mathematics up"
git branch -M main
```

## 3. Publish — pick ONE route

**A. With the GitHub CLI (easiest).** Install `gh` from https://cli.github.com,
then:

```bash
gh auth login
gh repo create aegis --public --source=. --remote=origin --push
```

**B. Without gh.** Create an empty repo on github.com (no README/license — you
already have them), then:

```bash
git remote add origin https://github.com/<your-username>/aegis.git
git push -u origin main
```

## 4. After the first push

- The **CI badge** in the README points at `ideatrino/aegis`. If your repo path
  is different, edit the two `ideatrino/aegis` occurrences at the top of
  `README.md` to `<your-username>/<repo>` and push again — the badge will turn
  green once the first CI run finishes.
- GitHub reads `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` automatically and
  shows them in the repo's sidebar and "Security" / "Insights" tabs.

## What is and isn't committed

Committed: all source, the tests, the docs (`README`, `DESIGN.md`, `CHANGELOG`,
`SECURITY`, `CONTRIBUTING`), the app icon, the build scripts, and the pre-trained
`aegis/data/model.json` (so the app works on first launch).

Ignored (see `.gitignore`): `__pycache__/`, PyInstaller `build/` and `dist/`
output, the generated `corpus/`, sandbox `*.trace` files, and virtualenvs.

**Do not commit real malware samples.** If you train on real data, keep the
`corpus/malicious/` samples out of the repo (it's already gitignored) and handle
them in a VM — see `SECURITY.md`.

## Optional polish

- Add repository **topics** on GitHub: `antivirus`, `malware-detection`,
  `machine-learning`, `security`, `bayesian`, `python`.
- Set the repo **description** to the one-liner from `pyproject.toml`.
- Attach the built `.exe` to a GitHub **Release** (Releases → Draft a new
  release → upload `dist\AEGIS Security Center.exe`) so people can download it
  without building.
