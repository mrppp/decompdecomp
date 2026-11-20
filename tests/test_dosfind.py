"""Functions of a 32-bit DOS game found from its code and fixups: a synthetic LE module (tests/test_le.py builds it)."""

import struct

from decompnet import dosfind, le
from .test_le import _bound


def test_starts_come_from_the_entry_calls_data_pointers_and_what_follows_a_function():
    base = 0x10000
    code = bytearray(0x60)
    code[0x00:0x05] = b"\xe8" + struct.pack("<i", 0x20 - 0x05)  # entry: call 0x10020
    code[0x05] = 0xC3  # ret
    code[0x06:0x08] = b"\x8b\xc0"  # Watcom's filler: mov eax,eax
    code[0x08:0x0A] = b"\x40\xc3"  # a function only computed calls reach: inc eax; ret (right after the entry)
    code[0x20:0x22] = b"\x40\xc3"  # called: inc eax; ret
    code[0x40:0x42] = b"\x48\xc3"  # pointed to from data: dec eax; ret
    data = _bound(bytes(code), [])
    mod = le.parse(data)
    mod.fixups.append(le.Fixup(0x20000, le.OFFSET32, base + 0x40, 1))  # (a table of function pointers in data)
    found = dosfind.find(mod)
    assert found.starts == {base: "entry", base + 0x20: "call", base + 0x40: "data pointer",
                            base + 0x08: "after a function"}
    assert found.functions == [(base, 6), (base + 0x08, 2), (base + 0x20, 2), (base + 0x40, 2)]
    assert not found.unclear and not found.cut


def test_a_code_pointer_to_a_variable_is_no_function():
    """A hand-written library keeps variables in its code object, and `mov eax, offset var` reads like a pointer."""
    base = 0x10000
    code = bytearray(0x40)
    code[0x00:0x05] = b"\xb8" + struct.pack("<I", base + 0x30)  # mov eax, offset var (fixed up)
    code[0x05] = 0xC3
    mod = le.parse(_bound(bytes(code), []))
    mod.fixups.append(le.Fixup(base + 0x01, le.OFFSET32, base + 0x30, 1))
    found = dosfind.find(mod)
    assert base + 0x30 not in found.starts, "zeros there: a variable"
