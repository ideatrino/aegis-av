"""
aegis.fixtures — the synthetic training corpus (design doc S8, S10, S12, S14).

Everything here is INERT: the "malicious" fixtures have valid headers, real
import tables and packed (random) sections, but no working payload — AEGIS
reads bytes, it never executes them. The corpus deliberately includes HARD
overlap cases (benign-but-high-entropy files, benign scripts that use sockets,
short scripts, realistic prose) so the AUC isn't a meaningless 1.000 and the
ensemble/calibration actually earn their keep (S8).

A small `build_pe` produces structurally-real PE files with a chosen import
table, so D3's import-cluster detection is trained and tested on genuine
structure, not string search.
"""
from __future__ import annotations

import random
import struct
import zipfile
import zlib
from typing import List, Tuple

# EICAR standard test string (the real thing; detected as a small FILE, S21)
EICAR = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


# ---------------------------------------------------------------------------
# a minimal but valid PE builder (VirtualAddress == PointerToRawData so RVAs
# map to file offsets 1:1, which aegis.peparse resolves correctly)
# ---------------------------------------------------------------------------
def build_pe(imports_by_dll, packed=True, signed=False, seed=0, text_size=None) -> bytes:
    rng = random.Random(seed)
    e_lfanew = 0x80
    coff = e_lfanew + 4
    opt = coff + 20
    opt_size = 96 + 16 * 8          # PE32 optional header + 16 data dirs
    sec_hdr = opt + opt_size
    num_sections = 2
    headers_end = sec_hdr + num_sections * 40
    text_rva = 0x400
    if text_size is None:
        text_size = 0x600 if packed else 0x200

    # build .idata contents (import descriptors + ILTs + name strings)
    idata_rva = text_rva + text_size
    descriptors = bytearray()
    thunks_blob = bytearray()
    names_blob = bytearray()

    # we lay out: [descriptors][terminator][thunks][names], all within .idata
    n_dlls = len(imports_by_dll)
    desc_size = (n_dlls + 1) * 20
    thunks_start = idata_rva + desc_size
    # first compute names layout
    name_offsets = {}
    cursor = 0  # offset within names_blob
    for dll, funcs in imports_by_dll.items():
        name_offsets[("dll", dll)] = cursor
        names_blob += dll.encode() + b"\x00"
        cursor = len(names_blob)
        for f in funcs:
            name_offsets[("fn", dll, f)] = cursor
            names_blob += b"\x00\x00" + f.encode() + b"\x00"   # hint + name
            cursor = len(names_blob)

    # thunk arrays
    thunk_offsets = {}
    tcursor = 0
    for dll, funcs in imports_by_dll.items():
        thunk_offsets[dll] = tcursor
        for f in funcs:
            tcursor += 4
        tcursor += 4  # null terminator

    names_start = thunks_start + tcursor

    # now materialize thunks (RVAs point into names_blob region)
    for dll, funcs in imports_by_dll.items():
        for f in funcs:
            fn_rva = names_start + name_offsets[("fn", dll, f)]
            thunks_blob += struct.pack("<I", fn_rva)
        thunks_blob += struct.pack("<I", 0)

    # descriptors
    for dll, funcs in imports_by_dll.items():
        ilt_rva = thunks_start + thunk_offsets[dll]
        name_rva = names_start + name_offsets[("dll", dll)]
        descriptors += struct.pack("<IIIII", ilt_rva, 0, 0, name_rva, ilt_rva)
    descriptors += struct.pack("<IIIII", 0, 0, 0, 0, 0)  # terminator

    idata = bytes(descriptors) + bytes(thunks_blob) + bytes(names_blob)
    idata_size = len(idata)

    # section bodies
    if packed:
        text_body = bytes(rng.randrange(256) for _ in range(text_size))
    else:
        text_body = (b"\x90" * text_size)

    # certificate (Authenticode) blob if signed
    cert = b"\x00\x30\x82\x01" + bytes(rng.randrange(256) for _ in range(200)) if signed else b""

    # assemble file
    text_ptr = 0x400
    idata_ptr = text_ptr + text_size
    cert_ptr = idata_ptr + idata_size
    total = cert_ptr + len(cert)

    buf = bytearray(total)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    # COFF
    struct.pack_into("<H", buf, coff, 0x14C)          # machine i386
    struct.pack_into("<H", buf, coff + 2, num_sections)
    struct.pack_into("<H", buf, coff + 16, opt_size)
    struct.pack_into("<H", buf, coff + 18, 0x102)     # executable image
    # optional header
    struct.pack_into("<H", buf, opt, 0x10B)           # PE32 magic
    struct.pack_into("<I", buf, opt + 92, 16)         # NumberOfRvaAndSizes
    dd = opt + 96
    # data dir 1 = import table
    struct.pack_into("<II", buf, dd + 1 * 8, idata_rva, idata_size)
    # data dir 4 = certificate
    if signed:
        struct.pack_into("<II", buf, dd + 4 * 8, cert_ptr, len(cert))
    # section headers
    def write_section(i, name, vaddr, vsize, rawptr, rawsize, chars):
        so = sec_hdr + i * 40
        buf[so:so + 8] = name.encode().ljust(8, b"\x00")
        struct.pack_into("<IIII", buf, so + 8, vsize, vaddr, rawsize, rawptr)
        struct.pack_into("<I", buf, so + 36, chars)
    text_chars = 0x60000020 | (0x80000000 if packed else 0)  # code+exec (+write if packed => W^X)
    write_section(0, ".text", text_rva, text_size, text_ptr, text_size, text_chars)
    write_section(1, ".idata", idata_rva, idata_size, idata_ptr, idata_size, 0x40000040)
    buf[text_ptr:text_ptr + text_size] = text_body
    buf[idata_ptr:idata_ptr + idata_size] = idata
    if signed:
        buf[cert_ptr:cert_ptr + len(cert)] = cert
    return bytes(buf)


# malicious import clusters (S10)
_INJECTOR = {"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory",
                              "CreateRemoteThread", "OpenProcess"]}
_RAT = {"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "ws2_32.dll": ["WSAStartup", "connect", "send", "recv"]}
_RANSOM = {"advapi32.dll": ["CryptAcquireContextW", "CryptEncrypt", "CryptGenKey",
                            "RegSetValueExW", "RegCreateKeyExW"],
           "kernel32.dll": ["CreateFileW", "WriteFile", "FindFirstFileW"]}
_KEYLOGGER = {"user32.dll": ["SetWindowsHookExW", "GetAsyncKeyState",
                             "GetForegroundWindow", "GetWindowTextW"],
              "kernel32.dll": ["CreateFileW", "WriteFile"]}
_DOWNLOADER = {"urlmon.dll": ["URLDownloadToFileW"],
               "wininet.dll": ["InternetOpenW", "InternetConnectW",
                               "HttpSendRequestW"],
               "kernel32.dll": ["WinExec", "CreateFileW", "WriteFile"]}
_BENIGN_APP = {"kernel32.dll": ["CreateFileW", "ReadFile", "CloseHandle",
                                "GetProcAddress", "LoadLibraryW"],
               "user32.dll": ["MessageBoxW", "CreateWindowExW", "ShowWindow"]}


# ---------------------------------------------------------------------------
# text / script fixtures
# ---------------------------------------------------------------------------
_WORDS = ("please review the attached report before the meeting tomorrow "
          "the quarterly numbers look strong and the team should be proud "
          "let me know if you have questions regarding the budget or timeline "
          "thanks for your continued hard work on this important project").split()


def _realistic_prose(rng, n_sentences=6) -> bytes:
    lines = []
    for _ in range(n_sentences):
        k = rng.randint(6, 16)
        s = " ".join(rng.choice(_WORDS) for _ in range(k)).capitalize() + "."
        lines.append(s)
    return ("Dear team,\n\n" + " ".join(lines) + "\n\nBest regards,\nAlex\n").encode()


def _benign_python(rng) -> bytes:
    src = f'''"""A small benign utility module."""
import json
import os


def load_config(path):
    with open(path) as fh:
        return json.load(fh)


def summarize(items):
    total = sum(i.get("value", 0) for i in items)
    return {{"count": len(items), "total": total}}


if __name__ == "__main__":
    cfg = load_config(os.environ.get("CFG", "config.json"))
    print(summarize(cfg.get("items", [])))
'''
    return src.encode()


def _benign_network_python(rng) -> bytes:
    # legitimately uses sockets/subprocess (a HARD benign case, S8)
    src = '''import socket
import subprocess


def check_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def git_status():
    return subprocess.run(["git", "status"], capture_output=True).stdout
'''
    return src.encode()


def _malicious_python(rng) -> bytes:
    # dropper composition exec(b64decode(...)) — inert (payload is random b64)
    blob = "".join(rng.choice("ABCDEFGHIJKLMNOP") for _ in range(60))
    return (f'import base64\n'
            f'exec(base64.b64decode("{blob}"))\n').encode()


def _high_entropy_benign(rng) -> bytes:
    # a real zlib stream with a recognizable header (benign compressed data)
    payload = bytes(rng.randrange(256) for _ in range(4000))
    return b"PK\x03\x04" + zlib.compress(payload)  # zip-like container header


def _json_config(rng) -> bytes:
    return (b'{"name":"widget","version":"1.2.3","deps":['
            b'"numpy","requests"],"settings":{"debug":false}}')


# ---------------------------------------------------------------------------
def make_corpus(seed=0) -> List[Tuple[str, bytes, int]]:
    """Return [(name, bytes, label)] with label 1 = malicious."""
    rng = random.Random(seed)
    items: List[Tuple[str, bytes, int]] = []

    # benign
    for i in range(40):
        items.append((f"ben_prose_{i}.txt", _realistic_prose(rng), 0))
    for i in range(30):
        items.append((f"ben_script_{i}.py", _benign_python(rng), 0))
    for i in range(15):
        items.append((f"ben_net_{i}.py", _benign_network_python(rng), 0))
    for i in range(20):
        items.append((f"ben_hे_{i}.zip", _high_entropy_benign(rng), 0))
    for i in range(15):
        items.append((f"ben_cfg_{i}.json", _json_config(rng), 0))
    for i in range(25):
        items.append((f"ben_app_{i}.exe", build_pe(_BENIGN_APP, packed=False, seed=i), 0))
    for i in range(12):
        items.append((f"ben_signed_{i}.exe",
                      build_pe(_BENIGN_APP, packed=True, signed=True, seed=100 + i), 0))
    # large, packed, SIGNED installer-shaped fixtures so the learned detectors
    # see "big packed + signed = benign" and don't saturate on real installers (§15)
    for i in range(10):
        items.append((f"ben_installer_{i}.exe",
                      build_pe(_BENIGN_APP, packed=True, signed=True, seed=500 + i,
                               text_size=0x8000 + i * 0x1000), 0))

    # malicious (inert)
    for i in range(20):
        items.append((f"mal_inject_{i}.exe", build_pe(_INJECTOR, packed=True, seed=200 + i), 1))
    for i in range(20):
        items.append((f"mal_rat_{i}.exe", build_pe(_RAT, packed=True, seed=300 + i), 1))
    for i in range(20):
        items.append((f"mal_ransom_{i}.exe", build_pe(_RANSOM, packed=True, seed=400 + i), 1))
    for i in range(20):
        items.append((f"mal_dropper_{i}.py", _malicious_python(rng), 1))
    for i in range(14):
        items.append((f"mal_keylog_{i}.exe", build_pe(_KEYLOGGER, packed=True, seed=600 + i), 1))
    for i in range(14):
        items.append((f"mal_downloader_{i}.exe", build_pe(_DOWNLOADER, packed=True, seed=700 + i), 1))
    # document-vector malware (macros, PDF JS) and their benign counterparts
    for i in range(10):
        items.append((f"mal_macro_{i}.doc", build_ole2_doc(malicious=True), 1))
    for i in range(8):
        items.append((f"mal_macro_{i}.docm", build_docx(macro=True), 1))
    for i in range(8):
        items.append((f"mal_pdfjs_{i}.pdf", build_pdf(malicious=True), 1))
    for i in range(12):
        items.append((f"ben_doc_{i}.pdf", build_pdf(malicious=False), 0))
    for i in range(10):
        items.append((f"ben_doc_{i}.docx", build_docx(macro=False), 0))
    for i in range(8):
        items.append((f"ben_doc_{i}.doc", build_ole2_doc(malicious=False), 0))

    # extra benign diversity so "normal" covers the long tail (§14)
    for i in range(18):
        items.append((f"ben_image_{i}.png", _benign_image(rng), 0))
    for i in range(12):
        items.append((f"ben_yaml_{i}.yaml", _benign_yaml(rng), 0))
    for i in range(10):
        items.append((f"ben_intl_{i}.txt", _benign_intl(rng), 0))

    return items


def _benign_image(rng) -> bytes:
    # a PNG-headed blob of compressed pixel-ish data (high-entropy but benign)
    body = zlib.compress(bytes(rng.randrange(256) for _ in range(3000)))
    return b"\x89PNG\r\n\x1a\n" + body


def _benign_yaml(rng) -> bytes:
    return (b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
            b"spec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n"
            b"        - name: app\n          image: registry/app:1.2.3\n"
            b"          ports:\n            - containerPort: 8080\n")


def build_macho(dylibs=("/usr/lib/libSystem.B.dylib",), seed=0) -> bytes:
    """A minimal valid 64-bit Mach-O with LC_LOAD_DYLIB commands."""
    hdr = b"\xcf\xfa\xed\xfe"  # MH_MAGIC_64 little-endian
    lcs = b""
    for d in dylibs:
        name = d.encode() + b"\x00"
        # pad name to 4-byte alignment
        pad = (-len(name)) % 4
        name += b"\x00" * pad
        cmdsize = 24 + len(name)
        lcs += struct.pack("<III", 0xC, cmdsize, 24) + b"\x00" * 12 + name
    ncmds = len(dylibs)
    # mach_header_64: magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved
    header = hdr + struct.pack("<IIIIIII", 0x0100000C, 0, 2, ncmds, len(lcs), 0, 0)
    return header + lcs + b"\x00" * 64


def build_ole2_doc(malicious=True) -> bytes:
    body = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 200 + b"_VBA_PROJECT"
    if malicious:
        body += b"AutoOpen" + b"CreateObject" + b"WScript.Shell" + b"powershell -enc AABB"
    body += b"\x00" * 300
    return body


def build_pdf(malicious=True) -> bytes:
    head = b"%PDF-1.7\n1 0 obj<</Type/Catalog"
    if malicious:
        head += b"/OpenAction<</S/JavaScript/JS(app.alert\\('x'\\))>>"
    head += b">>\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    return head


def build_docx(macro=True) -> bytes:
    import io as _io
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<?xml version='1.0'?><Types/>")
        z.writestr("word/document.xml", "<?xml version='1.0'?><document/>")
        if macro:
            z.writestr("word/vbaProject.bin",
                       b"AutoOpen" + b"Shell" + b"CreateObject" + b"WScript.Shell")
    return buf.getvalue()


def _benign_intl(rng) -> bytes:
    # multi-language, unicode-heavy text (must read as benign text, §18)
    return ("Bonjour l'équipe, merci pour votre travail. "
            "こんにちは、レポートを確認してください。 "
            "Здравствуйте, отчёт готов. 团队你好，请查看报告。\n"
            "Grüße und schöne Grüße aus dem Büro.\n").encode("utf-8")
