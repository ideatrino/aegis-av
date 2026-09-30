# Security Policy

## What AEGIS is — and is not

AEGIS is an **original, educational antivirus engine** built to demonstrate a
calibrated Bayesian-consensus approach to malware detection. It is **not** a
certified replacement for a commercial antivirus on a machine that needs
guaranteed protection.

Two capabilities that commercial products have, a pure-Python project cannot
provide, and AEGIS is deliberately honest about this:

- **No kernel-level real-time interception.** "Real-time protection" is a
  polling on-access watcher, not a signed filesystem minifilter driver.
- **No cloud signature/reputation backend.** "Definitions" are your local
  signature list and blocklist, which you curate.

And, as the design states up front (Cohen 1987): perfect malware detection is
**undecidable**. AEGIS shapes and quantifies its error; it never claims
certainty. Use it to learn, to scan, and to triage — not as your only line of
defense.

## Handling malware samples

AEGIS reads bytes; it never executes a sample during a scan. If you train it on
real malware (`make-corpus` → `train --augment`), obtain samples only from
reputable sources (MalwareBazaar / abuse.ch, VirusShare, theZoo) and handle them
**in an isolated VM**. Do not commit real malware to this repository.

The Stage-3 dynamic sandbox (`--dynamic`) *does* execute Python samples in an
isolated subprocess under an audit hook that blocks OS-facing escapes. Running
untrusted code is inherently risky; it is off by default and opt-in.

## Reporting a vulnerability

If you find a security issue in AEGIS itself (for example, a way to make the
scanner crash on hostile input, or a sandbox escape), please open a GitHub issue
describing the problem and how to reproduce it. For anything you'd rather not
disclose publicly, note that in the issue and ask for a private channel.
