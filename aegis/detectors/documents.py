"""
aegis.detectors.documents — the document-malware vector detector (D9).

Office macros and PDF JavaScript are two of the most common real-world delivery
vectors, and they are neither packed binaries nor plain scripts, so the earlier
detectors miss them. This is an additive, fused signal in exactly the spirit of
D8 (§20): extend the ensemble, never bypass it — it emits an Evidence like every
other detector and is subject to the same allowlist override and cost-model
thresholds.

  - OLE2 compound documents (.doc/.xls/.ppt): magic D0 CF 11 E0, VBA macro
    storage, and dangerous VBA tokens (AutoOpen, Shell, WScript, powershell).
  - OOXML with macros (.docm/.xlsm/.pptm): a zip carrying */vbaProject.bin.
  - PDF: /JavaScript, /JS, /OpenAction, /AA, /Launch, /EmbeddedFile clusters.

An auto-executing macro or an OpenAction-triggered script is concealed
executable content, so a strong cluster is `review_only` (surfaced, and it can
drive BLOCK when the ensemble agrees) rather than silently allowed.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Optional

from ..core import Evidence

_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# VBA / script tokens that make a macro dangerous (auto-run + execution)
_VBA_AUTORUN = (b"AutoOpen", b"Auto_Open", b"Document_Open", b"AutoExec",
                b"Workbook_Open", b"Document_Close", b"AutoClose")
_VBA_EXEC = (b"Shell", b"WScript", b"CreateObject", b"powershell", b"cmd.exe",
             b"WScript.Shell", b"ShellExecute", b"URLDownloadToFile",
             b"MSXML2.XMLHTTP", b"ADODB.Stream", b"Process", b"Run(")
_PDF_ACTIVE = (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch",
               b"/EmbeddedFile", b"/RichMedia", b"/SubmitForm")


def is_document(data: bytes) -> bool:
    return (data[:8] == _OLE2_MAGIC or data[:5] == b"%PDF-"
            or _is_ooxml(data))


def _is_ooxml(data: bytes) -> bool:
    if data[:4] != b"PK\x03\x04":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            return any(n == "[Content_Types].xml" for n in names)
    except Exception:
        return False


def detect(data: bytes) -> Optional[Evidence]:
    """Return document-vector Evidence, or None if not a document."""
    if data[:8] == _OLE2_MAGIC:
        return _ole2(data)
    if data[:5] == b"%PDF-":
        return _pdf(data)
    if _is_ooxml(data):
        return _ooxml(data)
    return None


def _score(base, reasons, strong):
    ev = Evidence("document", p=base, reasons=reasons or ["document, no active content"])
    if strong:
        ev.review_only = True     # auto-executing content -> surfaced, at least
    return ev


def _ole2(data: bytes) -> Evidence:
    reasons = ["OLE2 compound document"]
    p = 0.35
    has_macro_storage = b"VBA" in data or b"Macros" in data or b"_VBA_PROJECT" in data
    autorun = [t for t in _VBA_AUTORUN if t in data]
    execs = [t for t in _VBA_EXEC if t in data]
    strong = False
    if has_macro_storage:
        p = 0.55
        reasons.append("VBA macro storage present")
    if autorun:
        p = max(p, 0.72); strong = True
        reasons.append(f"auto-run macro trigger: {autorun[0].decode('latin1')}")
    if execs:
        p = max(p, 0.8); strong = True
        reasons.append(f"macro execution API: {execs[0].decode('latin1')}")
    if autorun and execs:
        p = 0.9
        reasons.append("auto-run + execution (weaponized macro pattern)")
    return _score(p, reasons, strong)


def _ooxml(data: bytes) -> Evidence:
    reasons = ["OOXML document"]
    p = 0.2
    strong = False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            vba = [n for n in names if n.endswith("vbaProject.bin")]
            if vba:
                p = 0.7; strong = True
                reasons.append("embedded VBA macro project (vbaProject.bin)")
                # peek at the macro blob for dangerous tokens
                try:
                    blob = zf.read(vba[0])
                    execs = [t for t in _VBA_EXEC if t in blob]
                    autorun = [t for t in _VBA_AUTORUN if t in blob]
                    if execs:
                        p = max(p, 0.85)
                        reasons.append(f"macro execution API: {execs[0].decode('latin1')}")
                    if autorun and execs:
                        p = 0.92
                        reasons.append("auto-run + execution (weaponized macro)")
                except Exception:
                    pass
            if any("/externalLink" in n or "oleObject" in n for n in names):
                p = max(p, 0.55); strong = True
                reasons.append("external link / embedded OLE object")
    except Exception:
        pass
    return _score(p, reasons, strong)


def _pdf(data: bytes) -> Evidence:
    reasons = ["PDF document"]
    p = 0.2
    hits = [t for t in _PDF_ACTIVE if t in data]
    strong = False
    if b"/JavaScript" in data or b"/JS" in data:
        p = max(p, 0.7); strong = True
        reasons.append("embedded JavaScript")
    if b"/OpenAction" in data or b"/AA" in data:
        p = max(p, 0.75); strong = True
        reasons.append("auto-executing OpenAction/AA")
    if b"/Launch" in data:
        p = max(p, 0.82); strong = True
        reasons.append("/Launch action (external program execution)")
    if (b"/JavaScript" in data or b"/JS" in data) and (b"/OpenAction" in data or b"/AA" in data):
        p = 0.88
        reasons.append("JavaScript + auto-execute (weaponized PDF pattern)")
    if len(hits) >= 1 and p < 0.5:
        reasons.append(f"active content: {', '.join(h.decode('latin1') for h in hits[:3])}")
    return _score(p, reasons, strong)
