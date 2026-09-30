"""
aegis.peparse — dependency-free, defensive PE/ELF structure parser (S9, S24).

Packing hides strings, so D1/D3 must read *structure* — sections (with
per-section entropy and W^X checks) and the import table — not raw bytes.
The parser never trusts a length or offset from the (hostile) file: every
read is bounds-checked and any malformed field yields a partial result
rather than an exception. It also computes the Mandiant imphash (S24), an
md5 over the ordered lower-cased dll.func import list, which fingerprints a
whole malware *family* rather than one file.
"""
from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


@dataclass
class Section:
    name: str
    vsize: int
    rawsize: int
    entropy: float
    executable: bool
    writable: bool

    @property
    def wx(self) -> bool:
        return self.executable and self.writable


@dataclass
class BinaryInfo:
    kind: str = ""                 # "pe" | "elf" | ""
    sections: List[Section] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)     # "dll.func"
    import_pairs: List[Tuple[str, str]] = field(default_factory=list)
    has_signature: bool = False    # PE Authenticode block present (S15)
    imphash: str = ""              # Mandiant imphash (S24)
    parsed: bool = False

    @property
    def wx_sections(self) -> int:
        return sum(1 for s in self.sections if s.wx)

    @property
    def entropy_spread(self) -> float:
        if not self.sections:
            return 0.0
        es = [s.entropy for s in self.sections]
        return max(es) - min(es)


_MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                 b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"}


def parse(data: bytes) -> BinaryInfo:
    if data[:2] == b"MZ":
        try:
            return _parse_pe(data)
        except Exception:
            return BinaryInfo(kind="pe", parsed=False)
    if data[:4] == b"\x7fELF":
        try:
            return _parse_elf(data)
        except Exception:
            return BinaryInfo(kind="elf", parsed=False)
    if data[:4] in _MACHO_MAGICS or data[:4] == b"\xca\xfe\xba\xbe":
        try:
            return _parse_macho(data)
        except Exception:
            return BinaryInfo(kind="macho", parsed=False)
    return BinaryInfo()


def _parse_macho(data: bytes) -> BinaryInfo:
    """Minimal Mach-O: read load commands for imported dylibs (LC_LOAD_DYLIB).

    Enough for D1/D3 to reason about a macOS binary's dependencies; a fat/
    universal binary (0xcafebabe) is reported as a Mach-O without deep parse."""
    info = BinaryInfo(kind="macho", parsed=True)
    if data[:4] == b"\xca\xfe\xba\xbe":       # fat/universal — shallow
        return info
    magic = data[:4]
    little = magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
    is64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    en = "<" if little else ">"
    if len(data) < 32:
        return info
    ncmds = struct.unpack_from(en + "I", data, 16)[0]
    off = 32 if is64 else 28
    LC_LOAD_DYLIB = 0xC
    LC_LOAD_WEAK_DYLIB = 0x18
    LC_REEXPORT_DYLIB = 0x1F
    dylib_cmds = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB}
    for _ in range(min(ncmds, 512)):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(en + "II", data, off)
        if cmdsize == 0:
            break
        if cmd in dylib_cmds and off + 24 <= len(data):
            name_off = struct.unpack_from(en + "I", data, off + 8)[0]
            p = off + name_off
            if 0 < name_off < cmdsize and p < len(data):
                end = data.find(b"\x00", p, off + cmdsize)
                if end > p:
                    dylib = data[p:end].decode("latin1", "replace")
                    base = dylib.rsplit("/", 1)[-1]
                    info.imports.append(f"{base}.dylib")
        off += cmdsize
    return info


def _u16(d, o): return struct.unpack_from("<H", d, o)[0]
def _u32(d, o): return struct.unpack_from("<I", d, o)[0]


def _parse_pe(data: bytes) -> BinaryInfo:
    info = BinaryInfo(kind="pe")
    if len(data) < 0x40:
        return info
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return info
    coff = e_lfanew + 4
    num_sections = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    if opt + 2 > len(data):
        return info
    magic = _u16(data, opt)
    is_pe32plus = (magic == 0x20B)
    # data directories
    dd_off = opt + (112 if is_pe32plus else 96)
    num_dd = _u32(data, opt + (108 if is_pe32plus else 92)) if opt + 112 <= len(data) else 0
    # data dir 4 = certificate table (Authenticode) -> signature present (S15)
    if num_dd > 4 and dd_off + 5 * 8 <= len(data):
        cert_rva = _u32(data, dd_off + 4 * 8)
        cert_sz = _u32(data, dd_off + 4 * 8 + 4)
        info.has_signature = cert_rva != 0 and cert_sz != 0
    # data dir 1 = import table
    import_rva = import_sz = 0
    if num_dd > 1 and dd_off + 2 * 8 <= len(data):
        import_rva = _u32(data, dd_off + 1 * 8)
        import_sz = _u32(data, dd_off + 1 * 8 + 4)

    # sections
    sec_off = opt + opt_size
    sections: List[Tuple[int, int, int]] = []   # (vaddr, rawptr, rawsize)
    for i in range(num_sections):
        so = sec_off + i * 40
        if so + 40 > len(data):
            break
        name = data[so:so + 8].rstrip(b"\x00").decode("latin1", "replace")
        vsize = _u32(data, so + 8)
        vaddr = _u32(data, so + 12)
        rawsize = _u32(data, so + 16)
        rawptr = _u32(data, so + 20)
        chars = _u32(data, so + 36)
        body = data[rawptr:rawptr + rawsize] if rawptr + rawsize <= len(data) else b""
        info.sections.append(Section(
            name=name, vsize=vsize, rawsize=rawsize, entropy=_entropy(body),
            executable=bool(chars & 0x20000000),
            writable=bool(chars & 0x80000000),
        ))
        sections.append((vaddr, rawptr, rawsize))

    def rva_to_off(rva: int) -> int:
        for vaddr, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(rawsize, 1) + 0x2000:
                return rawptr + (rva - vaddr)
        return -1

    # import table walk (bounded)
    if import_rva:
        off = rva_to_off(import_rva)
        guard = 0
        while off >= 0 and off + 20 <= len(data) and guard < 256:
            guard += 1
            name_rva = _u32(data, off + 12)
            first_thunk = _u32(data, off + 16)
            orig_thunk = _u32(data, off)
            if name_rva == 0 and first_thunk == 0:
                break
            noff = rva_to_off(name_rva)
            dll = "?"
            if noff >= 0:
                end = data.find(b"\x00", noff, noff + 128)
                if end > noff:
                    dll = data[noff:end].decode("latin1", "replace")
            # thunk array
            thunk_rva = orig_thunk or first_thunk
            toff = rva_to_off(thunk_rva)
            tguard = 0
            ptr = 8 if is_pe32plus else 4
            ordflag = (1 << 63) if is_pe32plus else (1 << 31)
            while toff >= 0 and toff + ptr <= len(data) and tguard < 4096:
                tguard += 1
                val = (struct.unpack_from("<Q", data, toff)[0] if is_pe32plus
                       else _u32(data, toff))
                if val == 0:
                    break
                if val & ordflag:
                    func = f"ord{val & 0xffff}"
                else:
                    hoff = rva_to_off(val & 0x7fffffff)
                    func = "?"
                    if hoff >= 0 and hoff + 2 < len(data):
                        end = data.find(b"\x00", hoff + 2, hoff + 2 + 128)
                        if end > hoff + 2:
                            func = data[hoff + 2:end].decode("latin1", "replace")
                info.import_pairs.append((dll, func))
                info.imports.append(f"{dll}.{func}")
                toff += ptr
            off += 20

    info.imphash = _imphash(info.import_pairs)
    info.parsed = True
    return info


def _imphash(pairs: List[Tuple[str, str]]) -> str:
    """Mandiant imphash: md5 of the ordered, lower-cased dll.func list (S24)."""
    if not pairs:
        return ""
    parts = []
    for dll, func in pairs:
        d = dll.lower()
        for ext in (".dll", ".ocx", ".sys"):
            if d.endswith(ext):
                d = d[:-len(ext)]
                break
        parts.append(f"{d}.{func.lower()}")
    return hashlib.md5(",".join(parts).encode()).hexdigest()


def _parse_elf(data: bytes) -> BinaryInfo:
    info = BinaryInfo(kind="elf")
    if len(data) < 64:
        return info
    little = data[5] == 1
    is64 = data[4] == 2
    en = "<" if little else ">"
    if is64:
        e_shoff = struct.unpack_from(en + "Q", data, 40)[0]
        e_shentsize = struct.unpack_from(en + "H", data, 58)[0]
        e_shnum = struct.unpack_from(en + "H", data, 60)[0]
        e_shstrndx = struct.unpack_from(en + "H", data, 62)[0]
    else:
        e_shoff = struct.unpack_from(en + "I", data, 32)[0]
        e_shentsize = struct.unpack_from(en + "H", data, 46)[0]
        e_shnum = struct.unpack_from(en + "H", data, 48)[0]
        e_shstrndx = struct.unpack_from(en + "H", data, 50)[0]
    if not e_shoff or e_shnum == 0 or e_shoff > len(data):
        info.parsed = True
        return info
    # section header string table
    def sh(i):
        return e_shoff + i * e_shentsize
    strtab_off = 0
    if e_shstrndx < e_shnum:
        so = sh(e_shstrndx)
        if is64 and so + 40 <= len(data):
            strtab_off = struct.unpack_from(en + "Q", data, so + 24)[0]
        elif not is64 and so + 20 <= len(data):
            strtab_off = struct.unpack_from(en + "I", data, so + 16)[0]

    def name_at(nameoff):
        if not strtab_off:
            return ""
        p = strtab_off + nameoff
        end = data.find(b"\x00", p, p + 64)
        return data[p:end].decode("latin1", "replace") if end > p else ""

    for i in range(min(e_shnum, 128)):
        so = sh(i)
        if so + e_shentsize > len(data):
            break
        if is64:
            nameoff = struct.unpack_from(en + "I", data, so)[0]
            flags = struct.unpack_from(en + "Q", data, so + 8)[0]
            offset = struct.unpack_from(en + "Q", data, so + 24)[0]
            size = struct.unpack_from(en + "Q", data, so + 32)[0]
        else:
            nameoff = struct.unpack_from(en + "I", data, so)[0]
            flags = struct.unpack_from(en + "I", data, so + 8)[0]
            offset = struct.unpack_from(en + "I", data, so + 16)[0]
            size = struct.unpack_from(en + "I", data, so + 20)[0]
        body = data[offset:offset + size] if offset + size <= len(data) else b""
        info.sections.append(Section(
            name=name_at(nameoff), vsize=size, rawsize=size,
            entropy=_entropy(body),
            executable=bool(flags & 0x4),   # SHF_EXECINSTR
            writable=bool(flags & 0x1),     # SHF_WRITE
        ))
    info.parsed = True
    return info
