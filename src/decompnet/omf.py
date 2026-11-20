"""OMF object files (Watcom, Borland, Microsoft) as ELF32 relocatable objects objdiff can read.

DOS compilers write the Intel/Microsoft Object Module Format; objdiff reads ELF and COFF. A 32-bit DOS game built
with Watcom C (DOS/4GW) is judged by compiling a candidate with the same compiler, so every compile goes through
this conversion: each segment becomes a section, PUBDEF/LPUBDEF names become symbols (a function's size runs to the
next name in its segment, OMF records none), EXTDEF names become undefined symbols, and FIXUPP fixups become REL
relocations (R_386_32 for an offset, R_386_PC32 for a call or jump). Only what a compiler writes for flat-model
32-bit code is handled; anything else (16-bit fixups, LIDATA past one level, COMDAT) raises OMFError rather than
converting wrongly. Agner Fog's objconv refuses OpenWatcom 2's objects ("Pointer out of range"), hence this.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


class OMFError(ValueError):
    pass


R_386_32, R_386_PC32 = 1, 2
CODE_CLASSES = {"CODE"}
BSS_CLASSES = {"BSS", "STACK"}


@dataclass
class Segment:
    name: str
    klass: str
    length: int
    align: int
    data: bytearray = field(default_factory=bytearray)
    relocs: list[tuple[int, int, tuple[str, int]]] = field(default_factory=list)  # (offset, R_386_*, ("seg"|"ext", n))


@dataclass
class Module:
    segments: list[Segment] = field(default_factory=list)
    publics: list[tuple[str, int, int, bool]] = field(default_factory=list)  # (name, segment index, offset, global)
    externs: list[str] = field(default_factory=list)


class _Reader:
    def __init__(self, data: bytes, at: int = 0):
        self.data, self.at = data, at

    def byte(self) -> int:
        self.at += 1
        return self.data[self.at - 1]

    def word(self) -> int:
        self.at += 2
        return struct.unpack_from("<H", self.data, self.at - 2)[0]

    def dword(self) -> int:
        self.at += 4
        return struct.unpack_from("<I", self.data, self.at - 4)[0]

    def offset(self, big: bool) -> int:
        return self.dword() if big else self.word()

    def index(self) -> int:  # 1 or 2 bytes: high bit of the first says two
        first = self.byte()
        return ((first & 0x7F) << 8) | self.byte() if first & 0x80 else first

    def name(self) -> str:
        n = self.byte()
        self.at += n
        return self.data[self.at - n:self.at].decode("latin-1")


def parse(data: bytes) -> Module:
    """The segments, names and fixups of one OMF object module."""
    mod = Module()
    lnames = [""]  # 1-based
    seg_of: list[int] = [-1]  # OMF segment index (1-based) -> mod.segments index
    groups = [""]
    last: tuple[int, int] | None = None  # (segment, offset) of the last LEDATA, which FIXUPP refers to
    threads: dict[tuple[str, int], tuple[int, int]] = {}  # (target/frame, number) -> (method, index)
    at = 0
    while at < len(data):
        kind, length = data[at], struct.unpack_from("<H", data, at + 1)[0]
        body = _Reader(data[at + 3:at + 3 + length - 1])  # (the last byte is the checksum)
        big = bool(kind & 1)
        base = kind & 0xFE
        at += 3 + length
        if base == 0x96:  # LNAMES
            while body.at < len(body.data):
                lnames.append(body.name())
        elif base == 0x98:  # SEGDEF
            attrs = body.byte()
            align = (attrs >> 5) & 7
            if align == 0:
                raise OMFError("absolute segments aren't supported")
            seg_len = body.offset(big)
            name, klass = lnames[body.index()], lnames[body.index()]
            body.index()  # overlay
            seg_of.append(len(mod.segments))
            mod.segments.append(Segment(name, klass, seg_len, {1: 1, 2: 2, 3: 16, 4: 256, 5: 4}.get(align, 1)))
        elif base == 0x9A:  # GRPDEF (FLAT, DGROUP): names only, flat model resolves through segments
            groups.append(lnames[body.index()])
        elif base in (0x8C, 0xB4):  # EXTDEF, LEXTDEF
            while body.at < len(body.data):
                mod.externs.append(body.name())
                body.index()  # type
        elif base in (0x90, 0xB6):  # PUBDEF, LPUBDEF
            body.index()  # group
            seg = body.index()
            if seg == 0:
                body.word()  # frame of an absolute symbol
            while body.at < len(body.data):
                name, off = body.name(), body.offset(big)
                body.index()  # type
                mod.publics.append((name, seg_of[seg], off, base == 0x90))
        elif base == 0xA0:  # LEDATA
            seg, off = seg_of[body.index()], body.offset(big)
            chunk = body.data[body.at:]
            s = mod.segments[seg].data
            if len(s) < off + len(chunk):
                s.extend(bytes(off + len(chunk) - len(s)))
            s[off:off + len(chunk)] = chunk
            last = (seg, off)
        elif base == 0xA2:  # LIDATA: one level of repeat blocks (what compilers write for zeroed arrays)
            seg, off = seg_of[body.index()], body.offset(big)
            out = bytearray()
            while body.at < len(body.data):
                repeat, blocks = body.offset(big), body.word()
                if blocks:
                    raise OMFError("nested LIDATA blocks aren't supported")
                n = body.byte()
                out += body.data[body.at:body.at + n] * repeat
                body.at += n
            s = mod.segments[seg].data
            if len(s) < off + len(out):
                s.extend(bytes(off + len(out) - len(s)))
            s[off:off + len(out)] = out
            last = None
        elif base == 0x9C:  # FIXUPP
            while body.at < len(body.data):
                lead = body.byte()
                if not lead & 0x80:  # THREAD subrecord
                    method, number = (lead >> 2) & 7, lead & 3
                    which = "f" if lead & 0x40 else "t"
                    idx = body.index() if (which == "t" or method < 3) else 0
                    threads[(which, number)] = (method, idx)
                    continue
                if last is None:
                    raise OMFError("a fixup with no LEDATA before it")
                mode_self = not lead & 0x40
                loc = (lead >> 2) & 0xF
                where = ((lead & 3) << 8) | body.byte()
                fixdat = body.byte()
                if fixdat & 0x80:  # frame from a thread
                    pass
                else:
                    fmethod = (fixdat >> 4) & 7
                    if fmethod < 3:
                        body.index()
                if fixdat & 0x08:  # target from a thread
                    if ("t", fixdat & 3) not in threads:
                        raise OMFError("a fixup names a target thread never defined")
                    tmethod, tidx = threads[("t", fixdat & 3)]
                    tmethod &= 3
                else:
                    tmethod, tidx = fixdat & 3, body.index()
                disp = 0 if fixdat & 0x04 else body.offset(big)
                if loc not in (9, 13):  # 32-bit offset (9, or 13 for a loader-resolved one)
                    raise OMFError(f"fixup location {loc} isn't a 32-bit offset")
                seg, base_off = last
                off = base_off + where
                if tmethod == 0:  # a segment: its section symbol
                    target: tuple[str, int] = ("seg", seg_of[tidx])
                elif tmethod == 2:  # an external name
                    target = ("ext", tidx - 1)
                else:
                    raise OMFError("group and frame-relative fixup targets aren't supported")
                rtype = R_386_PC32 if mode_self else R_386_32
                segment = mod.segments[seg]
                value = struct.unpack_from("<I", segment.data, off)[0] + disp
                if rtype == R_386_PC32:
                    value -= 4  # OMF counts from the field's end, ELF from its start
                struct.pack_into("<I", segment.data, off, value & 0xFFFFFFFF)
                segment.relocs.append((off, rtype, target))  # (resolved to a symbol index when written)
        elif base == 0x8A:  # MODEND
            break
        elif base in (0xC2, 0xB0, 0xBC):
            raise OMFError(f"record {kind:#x} (COMDAT/COMDEF/CEXTDEF) isn't supported")
    for s in mod.segments:  # BSS and short LEDATA: the declared length
        if len(s.data) < s.length:
            s.data.extend(bytes(s.length - len(s.data)))
    return mod


def to_elf(mod: Module) -> bytes:
    """An ELF32 little-endian i386 relocatable object of `mod`."""
    strtab, shstr = bytearray(b"\0"), bytearray(b"\0")

    def string(table: bytearray, s: str) -> int:
        at = len(table)
        table += s.encode("latin-1") + b"\0"
        return at

    sections: list[tuple] = []  # (name, type, flags, data, link, info, align, entsize, size if NOBITS)
    sec_index = {}  # segment -> ELF section index
    for i, s in enumerate(mod.segments):
        code, bss = s.klass.upper() in CODE_CLASSES, s.klass.upper() in BSS_CLASSES
        flags = 0x2 | (0x4 if code else 0) | (0 if code else 0x1)  # ALLOC | EXECINSTR or WRITE
        sec_index[i] = len(sections) + 1
        name = ".text" if code and i == next(j for j, t in enumerate(mod.segments) if t.klass.upper() in CODE_CLASSES) \
            else f"{'.text' if code else '.bss' if bss else '.data'}.{s.name}"
        sections.append((name, 8 if bss else 1, flags, bytes(s.data) if not bss else b"", 0, 0, s.align, 0, len(s.data)))
    # symbols: null, one section symbol per segment, local names, then globals and externs
    syms = [(0, 0, 0, 0, 0)]  # (name, value, size, info, shndx)
    seg_sym = {}
    for i in range(len(mod.segments)):
        seg_sym[i] = len(syms)
        syms.append((0, 0, 0, 3, sec_index[i]))  # STT_SECTION, STB_LOCAL
    by_seg: dict[int, list[int]] = {}
    for name, seg, off, _ in mod.publics:
        by_seg.setdefault(seg, []).append(off)
    def size_of(seg: int, off: int) -> int:
        later = sorted(o for o in by_seg[seg] if o > off)
        return (later[0] if later else len(mod.segments[seg].data)) - off
    locals_ = [p for p in mod.publics if not p[3]]
    globals_ = [p for p in mod.publics if p[3]]
    for name, seg, off, glob in locals_ + globals_:
        code = mod.segments[seg].klass.upper() in CODE_CLASSES
        info = ((1 if glob else 0) << 4) | (2 if code else 1)  # FUNC or OBJECT
        syms.append((string(strtab, name), off, size_of(seg, off), info, sec_index[seg]))
    first_global = 1 + len(mod.segments) + len(locals_)
    ext_sym = {}
    defined = {name: 1 + len(mod.segments) + k for k, (name, *_) in enumerate(locals_ + globals_)}
    for i, name in enumerate(mod.externs):
        if name in defined:  # (Watcom declares a module's own data external too: the definition is the target)
            ext_sym[i] = defined[name]
            continue
        ext_sym[i] = len(syms)
        syms.append((string(strtab, name), 0, 0, 1 << 4, 0))  # GLOBAL NOTYPE UNDEF
    symtab_index = len(sections) + 1 + sum(1 for s in mod.segments if s.relocs)
    for i, s in enumerate(mod.segments):
        if not s.relocs:
            continue
        rel = bytearray()
        for off, rtype, (kind, ref) in s.relocs:
            sym = seg_sym[ref] if kind == "seg" else ext_sym[ref]
            rel += struct.pack("<II", off, (sym << 8) | rtype)
        sections.append((f".rel{sections[sec_index[i] - 1][0]}", 9, 0x40, bytes(rel), symtab_index, sec_index[i], 4, 8, 0))
    symdata = b"".join(struct.pack("<IIIBBH", n, v, z, info, 0, sh) for n, v, z, info, sh in syms)
    sections.append((".symtab", 2, 0, symdata, symtab_index + 1, first_global, 4, 16, 0))
    sections.append((".strtab", 3, 0, bytes(strtab), 0, 0, 1, 0, 0))
    sections.append((".shstrtab", 3, 0, b"", 0, 0, 1, 0, 0))
    names = [string(shstr, s[0]) for s in sections]
    sections[-1] = sections[-1][:3] + (bytes(shstr),) + sections[-1][4:]
    out = bytearray(52)
    headers = [bytes(40)]
    for (name, stype, flags, data, link, info, align, entsize, bss_size), noff in zip(sections, names):
        while len(out) % max(align, 1):
            out.append(0)
        size = bss_size if stype == 8 else len(data)
        headers.append(struct.pack("<IIIIIIIIII", noff, stype, flags, 0, len(out), size, link, info, align, entsize))
        out += data
    while len(out) % 4:
        out.append(0)
    shoff = len(out)
    out += b"".join(headers)
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)  # ELFCLASS32, little-endian, EV_CURRENT
    struct.pack_into("<16sHHIIIIIHHHHHH", out, 0, ident, 1, 3, 1, 0, 0, shoff, 0, 52, 0, 0, 40,
                     len(headers), len(headers) - 1)
    return bytes(out)


def convert(data: bytes) -> bytes:
    return to_elf(parse(data))
