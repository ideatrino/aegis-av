"""
aegis.detectors.static — the five non-learned detectors (design doc S4).

D1 structural   (grammar/parsing)     — packed *code*, W^X sections
D2 entropy      (information theory)   — Shannon entropy, container-aware
D3 api_graph    (graph theory)         — AST calls (py) / import clusters (bin)
D5 signature    (LSH / hashing)        — exact hash force, fuzzy+imphash fused
D7 ioc          (indicator co-occur.)  — strings, with text cap_review (S18)

Each returns an Evidence with pi_cal=0.5 (neutral): these are rule-based, not
corpus-calibrated, so their LLR is exactly logit(p) and a p=0.5 vote is silent.
Content-awareness (text vs binary, recognized formats) is what stops the
self-detection traps (S8/S14/S18): D3 scores real Python *calls* not string
literals, and D7 caps its verdict to REVIEW on text because there the strings
are visible content, not concealed payload.
"""
from __future__ import annotations

import ast
import math
import re
import warnings
from typing import List, Optional

import numpy as np

from ..core import Evidence
from .. import peparse, simhash, formats
from ..pickle_scan import scan as pickle_scan, looks_like_pickle


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    n = len(data)
    probs = counts[counts > 0] / n
    return float(-(probs * np.log2(probs)).sum())


# ===========================================================================
# D1 — structural / format sanity
# ===========================================================================
def d1_structural(data: bytes, info: peparse.BinaryInfo,
                  is_text: bool, fmt: str) -> Evidence:
    reasons: List[str] = []
    if is_text or fmt in ("pyc",) or formats.known_container_format(data):
        # text and recognized containers are not "packed code" (S17/S18)
        return Evidence("structural", p=0.5, reasons=["not packed code"])
    if not formats.is_runnable_image(data):
        # dense data / object file: structure is expected, not suspicious
        if formats.is_elf_relocatable(data):
            reasons.append("ELF relocatable object (compiler output)")
        return Evidence("structural", p=0.45, reasons=reasons or ["non-executable binary"])

    p = 0.35
    if info.parsed and info.sections:
        wx = info.wx_sections
        high_e = [s for s in info.sections if s.entropy > 7.2 and s.executable]
        if wx:
            p += 0.25 * min(wx, 2)
            reasons.append(f"{wx} writable+executable section(s) (W^X violation)")
        if high_e:
            p += 0.2
            reasons.append(f"{len(high_e)} high-entropy executable section(s) "
                           f"(packed code)")
        if info.entropy_spread > 3.5:
            p += 0.1
            reasons.append(f"large section entropy spread ({info.entropy_spread:.1f})")
        if info.has_signature:
            p -= 0.25
            reasons.append("Authenticode signature present (soft-benign, S15)")
    p = max(0.05, min(0.95, p))
    return Evidence("structural", p=p, reasons=reasons or ["clean structure"])


# ===========================================================================
# D2 — Shannon entropy
# ===========================================================================
def d2_entropy(data: bytes, is_text: bool, fmt: str) -> Evidence:
    if is_text:
        return Evidence("entropy", p=0.4, reasons=["text (entropy not a payload signal)"])
    if formats.known_container_format(data):
        return Evidence("entropy", p=0.4,
                        reasons=[f"recognized container/compiled format ({fmt})"])
    h = _entropy(data)
    # windowed max for packed regions
    wmax = h
    if len(data) > 4096:
        step = max(2048, len(data) // 16)
        for i in range(0, len(data) - 2048, step):
            wmax = max(wmax, _entropy(data[i:i + 2048]))
    reasons = [f"entropy {h:.2f} bits/byte (windowed max {wmax:.2f})"]
    # map entropy to a weak probability (entropy alone is deliberately weak, S3.3)
    if wmax >= 7.9:
        p = 0.72
    elif wmax >= 7.5:
        p = 0.6
    elif wmax >= 7.0:
        p = 0.52
    else:
        p = 0.42
    return Evidence("entropy", p=p, reasons=reasons)


# ===========================================================================
# D3 — API / import-graph
# ===========================================================================
# payload-FETCHING primitives that make exec()/eval() a dropper (S16):
# deliberately excludes compile/read/get (too common in benign code).
_DROPPER_FETCH = {"b64decode", "b85decode", "a85decode", "urlopen", "urlretrieve",
                  "decompress", "unhexlify", "fromhex", "decodebytes"}
_EXECISH = {"exec", "eval"}

_INJECTION = {"virtualallocex", "writeprocessmemory", "createremotethread",
              "ntunmapviewofsection", "queueuserapc", "setwindowshookexw",
              "getasynckeystate"}
_NETWORK = {"wsastartup", "connect", "send", "recv", "internetopenw",
            "internetconnectw", "httpsendrequestw", "urldownloadtofilew"}
_CRYPTO = {"cryptencrypt", "cryptacquirecontextw", "cryptgenkey",
           "bcryptencrypt", "cryptderivekey"}
_PERSIST = {"regsetvalueexw", "regcreatekeyexw", "createservicew",
            "schtasks", "startservicew"}
_EXEC_LAUNCH = {"winexec", "createprocessw", "createprocessa",
                "shellexecutew", "shellexecutea"}


def d3_api_graph(data: bytes, info: peparse.BinaryInfo,
                 is_text: bool, fmt: str) -> Evidence:
    # Python source -> AST is authoritative (S8): score real calls, not strings
    if is_text:
        text = _safe_text(data)
        if text is not None and _looks_like_python(text):
            return _d3_python_ast(text)
        return Evidence("api_graph", p=0.42, reasons=["text, no AST-scorable calls"])

    if not info.parsed or not info.imports:
        return Evidence("api_graph", p=0.45, reasons=["no import table to analyze"])

    imports = {i.split(".")[-1].lower() for i in info.imports}
    reasons: List[str] = []
    p = 0.3
    named_cluster = False        # a specific, rare-in-benign malware pattern
    inj = imports & _INJECTION
    net = imports & _NETWORK
    cry = imports & _CRYPTO
    per = imports & _PERSIST
    # injection primitives are RARE in benign code -> carry the weight (S10)
    if len(inj) >= 2:
        p += 0.45
        named_cluster = True
        reasons.append(f"process-injection cluster: {sorted(inj)}")
    if inj and net:
        p += 0.15
        named_cluster = True
        reasons.append("inject + network (RAT pattern)")
    if cry and per:
        p += 0.45
        named_cluster = True
        reasons.append("crypto + persistence (ransomware pattern)")
    exe = imports & _EXEC_LAUNCH
    if net and exe:
        p += 0.35
        named_cluster = True
        reasons.append("network + process-launch (downloader pattern)")
    # network or exec alone is common (S10) -> small weight only
    if net and not inj and not cry and not exe:
        p += 0.05
    p = max(0.05, min(0.95, p))
    ev = Evidence("api_graph", p=p, reasons=reasons or ["imports read clean"])
    # a named, near-signature-grade static cluster on a binary we can't
    # detonate must be surfaced, never silently allowed (S9/S10).
    if named_cluster or p >= 0.7:
        ev.review_only = True
    return ev


def _d3_python_ast(text: str) -> Evidence:
    try:
        # Parse silently: a scanner must never leak the compiler's warnings
        # about the files it inspects. ast.parse reports the file as
        # "<unknown>", and real code is full of invalid escape sequences
        # (Windows paths, regexes without raw strings) that would otherwise
        # spew SyntaxWarnings to the console during a scan.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return Evidence("api_graph", p=0.42, reasons=["unparseable python"])
    calls = _collect_calls(tree)
    names = {c[0] for c in calls}
    reasons: List[str] = []
    p = 0.2
    # composition signal: exec/eval wrapping a payload-fetch (S14/S16)
    for func, inner in calls:
        if func in _EXECISH and inner & _DROPPER_FETCH:
            p = 0.9
            reasons.append(f"dropper composition: {func}({sorted(inner & _DROPPER_FETCH)})")
            break
    if "system" in names or "popen" in names:
        p = max(p, 0.55)
        reasons.append("os.system/popen call")
    p = max(0.05, min(0.95, p))
    ev = Evidence("api_graph", p=p, reasons=reasons or ["python calls read clean"])
    if p >= 0.85:
        # a real payload dropper in a script we can't safely detonate: surface it
        ev.review_only = True
    return ev


def _collect_calls(tree):
    """Return list of (called_name, {inner call names}) for each Call node."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            inner = set()
            for arg in ast.walk(node):
                if isinstance(arg, ast.Call) and arg is not node:
                    inner.add(_call_name(arg.func))
            out.append((name, inner))
    return out


def _call_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _looks_like_python(text: str) -> bool:
    head = text[:4096]
    return bool(re.search(r"^\s*(import |from |def |class |print\()", head, re.M))


# ===========================================================================
# D5 — signature / similarity (exact hash force, fuzzy + imphash fused)
# ===========================================================================
def d5_signature(data: bytes, sha: str, info: peparse.BinaryInfo,
                 bad_hashes, blocklist, is_text: bool) -> Evidence:
    # exact known-bad hash -> authoritative FORCE (identity, S20)
    if sha in bad_hashes or (blocklist and sha in blocklist.hashes):
        return Evidence("signature", p=1.0, force_block=True,
                        reasons=["SHA-256 matches known-malicious signature"])
    reasons: List[str] = []
    p = 0.3
    review = False
    # fuzzy near-identity -> fused in proportion to similarity (S22)
    if blocklist and blocklist.fuzzy:
        ct = simhash.ctph(data)
        if ct:
            sim = blocklist.best_fuzzy(ct)
            if sim >= 80:
                p = 0.9; review = True
                reasons.append(f"fuzzy CTPH {sim}% match to known-malicious "
                               f"(repacked variant)")
            elif sim >= 50:
                p = 0.65; review = True
                reasons.append(f"fuzzy CTPH {sim}% partial match to known-malicious")
    # imphash family fingerprint -> fused, never forced (S24)
    if info.imphash and blocklist and info.imphash in blocklist.imphashes:
        p = max(p, 0.8); review = True
        reasons.append(f"imphash {info.imphash[:12]} matches known malware family")
    ev = Evidence("signature", p=p, reasons=reasons or ["no signature/fuzzy match"])
    # near-identity is evidence, not proof; on text it's cap_review (S18/S22)
    if review:
        ev.review_only = True
        if is_text:
            ev.cap_review = True
    return ev


# ===========================================================================
# D7 — embedded IOC / string analysis
# ===========================================================================
_URL_RE = re.compile(rb"https?://[A-Za-z0-9.\-/_:%?=&]{4,}")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RUN_KEY = b"CurrentVersion\\Run"
_PS_ENC = re.compile(rb"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I)
_LOLBINS = [b"certutil -decode", b"certutil.exe -decode", b"rundll32",
            b"bitsadmin", b"nc -e", b"/dev/tcp/", b"mshta ", b"regsvr32 /s /u"]
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")


def _extract_strings(data: bytes) -> bytes:
    """ASCII + a cheap UTF-16LE fold, concatenated for scanning."""
    utf16 = data[::2] if len(data) > 2 else b""  # crude wide-char fold
    return data + b"\x00" + utf16


def d7_ioc(data: bytes, is_text: bool, fmt: str, blocklist=None) -> Evidence:
    # Python bytecode embeds its source's string literals, so a module that
    # DEFINES indicator lists (like this one) would read as malware in .pyc
    # form. D3's AST is authoritative for the source; D7 stands down on the
    # raw command-string signals for bytecode, exactly as for source (S15).
    if fmt == "pyc":
        return Evidence("ioc", p=0.4, reasons=["python bytecode (D3/AST authoritative)"])
    # On Python SOURCE, D3's AST is authoritative for what the code actually
    # does (§8, §14); D7 stands down on its raw command-string signals so a
    # module that merely DEFINES indicator lists (like AEGIS's own detectors,
    # fixtures and tests) is not read as malware for the strings it documents.
    # Explicit, user-curated threat-intel indicators still count, since those
    # are a deliberate signal, not incidental content.
    python_source = is_text and _safe_text(data) is not None and \
        _looks_like_python(_safe_text(data) or "")
    if python_source:
        blob = _extract_strings(data)
        reasons: List[str] = []
        if blocklist and blocklist.indicators:
            for ind in blocklist.indicators:
                if ind.encode("latin1", "replace") in blob:
                    ev = Evidence("ioc", p=0.85, review_only=True, cap_review=True,
                                  reasons=[f"threat-intel indicator: {ind[:48]}"])
                    return ev
        return Evidence("ioc", p=0.4,
                        reasons=["python source (D3/AST authoritative for calls)"])
    blob = _extract_strings(data)
    reasons: List[str] = []
    net = persist = execish = 0

    urls = _URL_RE.findall(blob)
    ips = _IP_RE.findall(blob)
    if urls:
        net += len(urls)
    if ips:
        net += len(ips)
    if _RUN_KEY in blob:
        persist += 1
        reasons.append("Run-key persistence string")
    if _PS_ENC.search(blob):
        execish += 1
        reasons.append("encoded PowerShell command")
    for lol in _LOLBINS:
        if lol in blob:
            execish += 1
            reasons.append(f"living-off-the-land: {lol.decode('latin1','replace')}")
    if _B64_BLOB.search(blob):
        execish += 0  # a big base64 blob alone is weak; needs company

    # curated threat-intel indicator strings -> fused, never forced (S20)
    ioc_hit = False
    if blocklist and blocklist.indicators:
        for ind in blocklist.indicators:
            if ind.encode("latin1", "replace") in blob:
                ioc_hit = True
                reasons.append(f"threat-intel indicator: {ind[:48]}")

    # a lone URL barely moves the needle (benign files carry URLs); the
    # DAMNING thing is the cluster — network + persistence/exec together (S10)
    score = 0.0
    if net:
        score += min(0.15, 0.05 * net)
    if persist:
        score += 0.2
    if execish:
        score += 0.3
    if net and (persist or execish):
        score += 0.25          # co-occurrence bonus
        reasons.append("network + persistence/exec co-occurrence")
    if ioc_hit:
        score += 0.4

    p = max(0.1, min(0.95, 0.3 + score))
    ev = Evidence("ioc", p=p, reasons=reasons or ["no notable indicators"])
    strong = (net and (persist or execish)) or ioc_hit or execish >= 2
    if strong:
        ev.review_only = True
        # S18: on TEXT the strings are visible content, not hidden payload ->
        # downgrade a would-be block to REVIEW. On a binary they are concealed
        # payload -> a strong cluster may drive BLOCK.
        if is_text:
            ev.cap_review = True
    return ev


# ===========================================================================
# helpers
# ===========================================================================
def _safe_text(data: bytes) -> Optional[str]:
    for cut in range(min(len(data), 65536), max(0, min(len(data), 65536) - 4), -1):
        try:
            return data[:cut].decode("utf-8")
        except UnicodeDecodeError:
            continue
    return None
