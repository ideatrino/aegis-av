"""
aegis.formats — "what kind of thing am I looking at?" (design doc S17, S18, S23, S24).

The deepest false positives in this project all came from judging one kind of
thing as another: text as bytes, a compiled proof as packed code, a model's
tensor storage as a file. Format recognition is the honest fix — a magic
number read from the tool that writes it, never an extension we trust.
"""
from __future__ import annotations

# --- magic numbers, each cited to the toolchain that writes it (S17) ---
_OCAML_CMI = b"Caml1999"                    # utils/config.ml compilation units
_OCAML_MARSHAL = b"\x84\x95\xa6\xbe"        # runtime Intext_magic_number (.lia.cache)
_COQ_VO = b"Coq!"                           # lib/objFile.ml  (.vo object files)
_SAFETENSORS_HINT = b'{"'                    # JSON manifest after 8-byte length (S24)
_GGUF = b"GGUF"                             # llama.cpp GGUF magic (S24)
_NUMPY = b"\x93NUMPY"                       # numpy .npy magic (S24)
_PYC_TAIL = b"\r\n"                         # CPython bytecode: bytes 2-3 are \r\n (S15)
_ZIP = b"PK\x03\x04"
_GZIP = b"\x1f\x8b"
_BZIP2 = b"BZh"
_XZ = b"\xfd7zXZ\x00"
_ELF = b"\x7fELF"
_PE = b"MZ"


def sniff_magic(data: bytes) -> str:
    """Return a short format tag, or '' if unrecognized."""
    if len(data) < 4:
        return ""
    if data[:4] == _ELF:
        return "elf"
    if data[:2] == _PE and b"PE\x00\x00" in data[:1024]:
        return "pe"
    if data[:4] == _ZIP:
        return "zip"
    if data[:2] == _GZIP:
        return "gzip"
    if data[:3] == _BZIP2:
        return "bzip2"
    if data[:6] == _XZ:
        return "xz"
    if data[:8] == _OCAML_CMI:
        return "ocaml"
    if data[:4] == _OCAML_MARSHAL:
        return "ocaml_marshal"
    if data[:4] == _COQ_VO:
        return "coq_vo"
    if data[:4] == _GGUF:
        return "gguf"
    if data[:6] == _NUMPY:
        return "npy"
    # python bytecode: 4-byte magic whose bytes 2-3 are \r\n
    if len(data) >= 4 and data[2:4] == _PYC_TAIL:
        return "pyc"
    if _looks_safetensors(data):
        return "safetensors"
    if data[:2] in (b"BM",) or data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff":
        return "image"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole2"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:4] == b"\xca\xfe\xba\xbe" or data[:4] == b"\xfe\xed\xfa\xce" \
            or data[:4] == b"\xfe\xed\xfa\xcf" or data[:4] == b"\xcf\xfa\xed\xfe" \
            or data[:4] == b"\xce\xfa\xed\xfe":
        return "macho"
    return ""


def _looks_safetensors(data: bytes) -> bool:
    """safetensors: little-endian u64 header length + JSON manifest (S24)."""
    if len(data) < 16:
        return False
    n = int.from_bytes(data[:8], "little")
    if not (2 <= n <= 100_000_000) or 8 + n > len(data) + 8:
        return False
    head = data[8:8 + min(n, 64)]
    return head[:2] == _SAFETENSORS_HINT or head[:1] == b"{"


# formats whose byte histogram is meaningless to a frequency-based learner:
# compressed / serialized / tensor containers and compiled artifacts (S17,S24).
_CONTAINER_FORMATS = {
    "zip", "gzip", "bzip2", "xz", "ocaml", "ocaml_marshal", "coq_vo",
    "gguf", "npy", "safetensors", "pyc", "image",
    # documents are judged by the document detector (D9), not a byte histogram
    "ole2", "pdf",
}


def known_container_format(data: bytes) -> bool:
    """True for a recognized dense-but-benign container / compiled format."""
    return sniff_magic(data) in _CONTAINER_FORMATS


def is_elf_relocatable(data: bytes) -> bool:
    """ELF e_type == ET_REL (1): a compiler object file, not a runnable image.

    Its dense .text is unlinked machine code and legitimately high-entropy, so
    the learners abstain on it at ANY entropy (S18 gap 1)."""
    if data[:4] != _ELF or len(data) < 18:
        return False
    little = data[5] == 1
    e_type = int.from_bytes(data[16:18], "little" if little else "big")
    return e_type == 1  # ET_REL


def is_runnable_image(data: bytes) -> bool:
    """A genuine executable/shared object (ELF ET_EXEC/ET_DYN or PE).

    A packed malicious binary keeps its full learned-detector weight; the
    abstain guards deliberately never fire on one (S17 'precision not
    blindness')."""
    tag = sniff_magic(data)
    if tag == "pe":
        return True
    if data[:4] == _ELF and len(data) >= 18:
        little = data[5] == 1
        e_type = int.from_bytes(data[16:18], "little" if little else "big")
        return e_type in (2, 3)  # ET_EXEC, ET_DYN
    if tag == "macho":
        return True
    return False


def is_text(data: bytes) -> bool:
    """UTF-8-aware text test (S18 gap 2): decode a char-boundary-safe prefix
    and check the *characters* are overwhelmingly printable, so unicode-heavy
    source and locale tables read as text and get an AST — not as binary."""
    if not data:
        return True
    if b"\x00" in data[:8192]:
        return False
    prefix = data[:8192]
    # trim to a valid utf-8 boundary
    for cut in range(len(prefix), max(0, len(prefix) - 4), -1):
        try:
            text = prefix[:cut].decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    else:
        return False
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t\f\v ")
    return printable / len(text) >= 0.95
