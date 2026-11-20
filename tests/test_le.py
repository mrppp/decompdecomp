"""DOS/4GW executables (LE): a synthetic module built here (no game in the repository), bound like DOOM's, with its
own MZ header after an extender's and its data pages counted from that header."""

import struct

import pytest

from decompnet import le


def _bound(code: bytes, fixups: list[tuple[int, int]]) -> bytes:
    """An extender stub, then the module's MZ header at an odd offset, its LE header, one code object of one page
    at 0x10000 and one data object at 0x20000, and OFFSET32 fixups (code offset -> data offset)."""
    stub = b"MZ" + bytes(0x3E) + b"BW" + bytes(0x50)  # an extender whose 0x3C doesn't point at the module
    mz_at = len(stub) + 6
    le_rel = 0x80
    le_hdr = bytearray(0xB0)
    le_hdr[0:4] = b"LE\0\0"
    struct.pack_into("<HH", le_hdr, 8, 2, 1)  # 386, OS/2-style
    page_size = 0x1000
    objects = struct.pack("<IIIIII", len(code), 0x10000, 0x2045, 1, 1, 0) + \
        struct.pack("<IIIIII", 0x100, 0x20000, 0x2043, 2, 1, 0)
    page_map = bytes([0, 0, 1, 0]) + bytes([0, 0, 2, 0])
    records = b"".join(bytes([0x07, 0x10]) + struct.pack("<h", src) + bytes([2]) + struct.pack("<I", dst)
                       for src, dst in fixups)
    fixup_pages = struct.pack("<III", 0, len(records), len(records))
    tables = bytearray()
    obj_off = len(le_hdr)
    tables += objects
    pmap_off = obj_off + len(tables)
    tables += page_map
    fpt_off = obj_off + len(tables)
    tables += fixup_pages
    frt_off = obj_off + len(tables)
    tables += records
    data_rel = le_rel + len(le_hdr) + len(tables)
    struct.pack_into("<I", le_hdr, 0x14, 2)  # pages
    struct.pack_into("<II", le_hdr, 0x18, 1, 0)  # entry: object 1, offset 0
    struct.pack_into("<II", le_hdr, 0x28, page_size, 0x100)  # page size, last page's bytes
    struct.pack_into("<II", le_hdr, 0x40, obj_off, 2)
    struct.pack_into("<I", le_hdr, 0x48, pmap_off)
    struct.pack_into("<II", le_hdr, 0x68, fpt_off, frt_off)
    struct.pack_into("<I", le_hdr, 0x80, data_rel)  # from the module's MZ header, as DOS/4GW's are
    mz = bytearray(le_rel)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, le_rel)
    module = bytes(mz) + bytes(le_hdr) + bytes(tables) + code.ljust(page_size, b"\0") + bytes(0x100)
    return stub + bytes(6) + module


def test_a_bound_module_is_found_and_its_pages_and_fixups_read():
    code = bytes.fromhex("eb78") + bytes(8) + bytes.fromhex("a1") + struct.pack("<I", 0x10) + bytes(4)
    data = _bound(code, [(11, 0x10)])  # mov eax,[data+0x10]: the field holds the offset in the data object
    mod = le.parse(data)
    assert [(o.base, o.executable) for o in mod.objects] == [(0x10000, True), (0x20000, False)]
    assert mod.entry == 0x10000 and mod.read(0x10000, 2) == b"\xeb\x78", "pages from the module's MZ header"
    assert [(f.source, f.kind, f.target) for f in mod.fixups] == [(0x1000B, le.OFFSET32, 0x20010)]
    mod.relocated()
    assert struct.unpack("<I", mod.read(0x1000B, 4))[0] == 0x20010


def test_what_a_dos_game_never_has_is_refused():
    data = bytearray(_bound(bytes(16), []))
    at = data.find(b"LE\0\0")
    struct.pack_into("<I", data, at + 0x74, 1)  # an import module
    with pytest.raises(le.LEError, match="imports"):
        le.parse(bytes(data))
