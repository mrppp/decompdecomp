"""DOS/4GW executables: the Linear Executable (LE) format a 32-bit Watcom DOS game is linked into.

A bound DOS/4GW game is an MZ program (the extender) with the LE module behind it; the MZ header's word at 0x3C
says where. The module holds objects (a code object and a data object, typically) at their link-time base
addresses, split into pages, and a fixup table per page naming every place that holds an absolute address: the
loader adds each object's real base to them. Those fixups are what a delinker wants, as relocations: a data address,
a function pointer, a switch table entry, a call into another object. A call or jump within one object is relative
and has no fixup; those come from reading the code (as for an Xbox 360 game's calls).

Only what a DOS/4GW game needs is read: objects, pages, internal fixups of 32-bit offsets, 32-bit self-relative
references and 16-bit selectors. Imports (a DLL's names, which a DOS game has none of) raise LEError.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


class LEError(ValueError):
    pass


OFFSET32, SELF32, SELECTOR16, OFFSET16, POINTER48 = 7, 8, 2, 5, 6
EXECUTABLE = 0x0004  # object flag: executable
WRITABLE = 0x0002


@dataclass
class Object:
    number: int  # 1-based, as fixups name it
    base: int  # link-time address of its first byte
    size: int  # virtual size (the data after the pages is zero)
    flags: int
    data: bytes

    @property
    def executable(self) -> bool:
        return bool(self.flags & EXECUTABLE)


@dataclass
class Fixup:
    source: int  # absolute address of the field
    kind: int  # OFFSET32, SELF32, SELECTOR16, ...
    target: int  # absolute address it refers to (an object's base, for a selector)
    target_object: int


@dataclass
class Module:
    objects: list[Object] = field(default_factory=list)
    fixups: list[Fixup] = field(default_factory=list)
    entry: int = 0  # absolute address of the program's first instruction
    stack: int = 0

    def object_at(self, address: int) -> Object | None:
        return next((o for o in self.objects if o.base <= address < o.base + o.size), None)

    def relocated(self) -> None:
        """Apply the fixups as the loader does at the link-time bases: a field holds its offset in the target
        object (12,100 of one game's 12,103 do; the rest are offset 0), and becomes the target's address, so the image
        reads as the game's code and data refer to each other."""
        for f in self.fixups:
            o = self.object_at(f.source)
            if o is None:
                continue
            at = f.source - o.base
            data = bytearray(o.data)
            if f.kind == OFFSET32 and at + 4 <= len(data):
                struct.pack_into("<I", data, at, f.target & 0xFFFFFFFF)
            elif f.kind == SELF32 and at + 4 <= len(data):
                struct.pack_into("<I", data, at, (f.target - (f.source + 4)) & 0xFFFFFFFF)
            elif f.kind == OFFSET16 and at + 2 <= len(data):
                struct.pack_into("<H", data, at, f.target & 0xFFFF)
            o.data = bytes(data)

    def read(self, address: int, length: int) -> bytes:
        o = self.object_at(address)
        if o is None:
            raise LEError(f"{address:#x} is in no object")
        at = address - o.base
        return o.data[at:at + length]


def module_start(data: bytes, header: int) -> int:
    """Where the LE module's own MZ header is: the LE format counts its "from the file's start" offsets (the data
    pages) from there. Bound to DOS/4GW, that header follows the extender's program (one game's is at 0x25214, its LE
    header 0x28B8 after it), so it is the MZ header whose pointer at 0x3C reaches `header`."""
    at = data.rfind(b"MZ", 0, header)
    while at >= 0:
        if at + 0x40 <= len(data) and at + struct.unpack_from("<I", data, at + 0x3C)[0] == header:
            return at
        at = data.rfind(b"MZ", 0, at)
    return 0


def header_offset(data: bytes) -> int:
    """Where the LE header starts: the MZ header's pointer at 0x3C, or (a stub that doesn't set it) the first "LE"
    on a 16-byte boundary after the stub."""
    if data[:2] != b"MZ":
        raise LEError("not an MZ executable")
    at = struct.unpack_from("<I", data, 0x3C)[0]
    if 0 < at < len(data) - 4 and data[at:at + 2] == b"LE":
        return at
    # bound to DOS/4GW, the extender's own MZ program comes first and its "BW" blocks chain on to the module,
    # which needn't start on any boundary (one game's is at 0x27ACC): the first "LE" whose fields make sense
    at = data.find(b"LE\0\0")
    while at >= 0:
        cpu, os_ = struct.unpack_from("<HH", data, at + 8)
        if 1 <= cpu <= 3 and 1 <= os_ <= 4 and struct.unpack_from("<I", data, at + 0x28)[0] in (0x1000, 0x200):
            return at
        at = data.find(b"LE\0\0", at + 1)
    raise LEError("no LE module in this executable")


def parse(data: bytes) -> Module:
    le = header_offset(data)
    u32 = lambda off: struct.unpack_from("<I", data, le + off)[0]  # noqa: E731
    if data[le + 2] or data[le + 3]:
        raise LEError("only little-endian LE modules are supported")
    pages, page_size, last_page = u32(0x14), u32(0x28), u32(0x2C)
    obj_table, n_objects, page_table = u32(0x40), u32(0x44), u32(0x48)
    fixup_pages, fixup_records = u32(0x68), u32(0x6C)
    data_pages = module_start(data, le) + u32(0x80)  # (from the module's MZ header, unlike the others)
    if u32(0x74):
        raise LEError("this module imports from other modules: not a DOS/4GW game")

    def page_offset(page: int) -> tuple[int, int]:  # (file offset, length) of a 1-based logical page
        entry = data[le + page_table + 4 * (page - 1):le + page_table + 4 * page]
        number = (entry[0] << 16) | (entry[1] << 8) | entry[2]
        if entry[3] not in (0, 3):  # legal/zero-filled only: no iterated (compressed) pages
            raise LEError(f"page {page} has type {entry[3]}, which isn't supported")
        length = last_page if number == pages else page_size
        return data_pages + (number - 1) * page_size, length

    mod = Module()
    page_object: dict[int, tuple[Object, int]] = {}  # logical page -> (its object, the page's index in it)
    for i in range(n_objects):
        size, base, flags, first, count, _ = struct.unpack_from("<IIIIII", data, le + obj_table + 24 * i)
        chunks = []
        for k in range(count):
            off, length = page_offset(first + k)
            chunks.append(data[off:off + length].ljust(page_size if k < count - 1 else length, b"\0"))
        body = b"".join(chunks)[:size].ljust(size, b"\0")
        obj = Object(i + 1, base, size, flags, body)
        mod.objects.append(obj)
        for k in range(count):
            page_object[first + k] = (obj, k)

    eip_obj, eip, esp_obj, esp = u32(0x18), u32(0x1C), u32(0x20), u32(0x24)
    if 1 <= eip_obj <= n_objects:
        mod.entry = mod.objects[eip_obj - 1].base + eip
    if 1 <= esp_obj <= n_objects:
        mod.stack = mod.objects[esp_obj - 1].base + esp

    def fixup_offset(page: int) -> int:
        return struct.unpack_from("<I", data, le + fixup_pages + 4 * (page - 1))[0]

    for page in range(1, pages + 1):
        if page not in page_object:
            continue
        obj, index = page_object[page]
        page_base = obj.base + index * page_size
        at, end = le + fixup_records + fixup_offset(page), le + fixup_records + fixup_offset(page + 1)
        while at < end:
            src_type, flags = data[at], data[at + 1]
            at += 2
            kind = src_type & 0x0F
            count = 0
            if src_type & 0x20:  # a list of source offsets follows the target
                count, at = data[at], at + 1
                sources = None
            else:
                sources = [struct.unpack_from("<h", data, at)[0]]  # (signed: a field may start on the page before)
                at += 2
            if flags & 0x03 != 0:
                raise LEError(f"page {page} has a fixup to an import or entry ({flags & 3}): not supported")
            if flags & 0x40:
                target_obj, at = struct.unpack_from("<H", data, at)[0], at + 2
            else:
                target_obj, at = data[at], at + 1
            if kind == SELECTOR16:
                target_off = 0
            elif flags & 0x10:
                target_off, at = struct.unpack_from("<I", data, at)[0], at + 4
            else:
                target_off, at = struct.unpack_from("<H", data, at)[0], at + 2
            if flags & 0x04:  # additive value
                at += 4 if flags & 0x20 else 2
            if sources is None:
                sources = [struct.unpack_from("<h", data, at + 2 * k)[0] for k in range(count)]
                at += 2 * count
            if not 1 <= target_obj <= n_objects:
                raise LEError(f"page {page} has a fixup to object {target_obj}, which doesn't exist")
            if kind not in (OFFSET32, SELF32, SELECTOR16, OFFSET16, POINTER48):
                raise LEError(f"page {page} has a fixup of type {kind}, which isn't supported")
            target = mod.objects[target_obj - 1].base + target_off
            for s in sources:
                mod.fixups.append(Fixup(page_base + s, kind, target, target_obj))
    # A field that straddles two pages is listed in both pages' records (the second page's with a negative offset):
    # one fixup, which relocating twice would add twice
    unique = {(f.source, f.kind, f.target, f.target_object): f for f in mod.fixups}
    mod.fixups = sorted(unique.values(), key=lambda f: f.source)
    return mod
