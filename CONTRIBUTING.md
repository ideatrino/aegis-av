# Contributing to AEGIS

Thanks for your interest. AEGIS is a dependency-light (numpy-only) project and
aims to stay that way.

## Setup

```bash
python -m pip install numpy pytest
python -m aegis selftest      # 27 invariants — should be 27/27
python -m pytest -q           # unit tests
```

## The bar for a change

Every fix in AEGIS's history followed one rule, and new work should too:

> A false positive is fixed by a **more honest signal**, a **more honest
> verdict**, a **repaired self-inflicted blind spot**, or an **operational
> control the user drives** — never by a fudged constant.

Concretely:

- **Add a test.** New detection logic gets a `pytest` case; a new invariant that
  must never regress gets added to `aegis/selftest.py`.
- **Keep detectors independent.** The ensemble's strength (see `aegis
  adversarial`) comes from detectors reasoning in different mathematical
  families. A new detector should bring a genuinely new view, not duplicate an
  existing one's blind spot.
- **Extend the ensemble, never bypass it.** New signals enter through the same
  log-odds fusion, allowlist override, and cost-model thresholds as everything
  else (see how D8 rules and D9 documents are wired).
- **Stay honest about limits.** If a change trades recall for precision or vice
  versa, say so. The project's credibility is its honesty about what it can't do.

## Running the full loop

```bash
python -m aegis make-corpus ./corpus
python -m aegis verify-corpus ./corpus
python -m aegis train    --corpus ./corpus --augment
python -m aegis evaluate --corpus ./corpus --augment
python -m aegis adversarial
```

Please run `selftest` and `pytest` before opening a pull request.
