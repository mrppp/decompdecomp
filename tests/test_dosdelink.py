"""A 32-bit DOS game's functions cut into ELF32 objects: a synthetic LE module (tests/test_le.py builds it)."""

import struct

from decompnet import dosdelink, dosfind, le, omf

from .test_le import _bound


def test_calls_data_and_conventions_become_what_watcom_objects_say():
    base = 0x10000
    code = bytearray(0x40)
    code[0x00:0x05] = b"\xa1" + struct.pack("<I", 0x20010)  # mov eax, [data+0x10] (fixed up)
    code[0x05:0x0A] = b"\xe8" + struct.pack("<i", 0x20 - 0x0A)  # call 0x10020
    code[0x0A] = 0xC3
    code[0x20:0x26] = b"\x55\x89\xe5\x8b\x45\x08"  # push ebp; mov ebp, esp (Watcom's 89 E5); mov eax, [ebp+8]
    code[0x26:0x28] = b"\x5d\xc3"  # pop ebp; ret
    code[0x30:0x36] = b"\x55\x89\xe5\x8b\x45\x08"  # the same, then pop ebp; ret 4: __stdcall
    code[0x36:0x3A] = b"\x5d\xc2\x04\x00"
    mod = le.parse(_bound(bytes(code), [(1, 0x10)]))
    mod.relocated()
    fns = {f.addr: f for f in dosdelink.functions(mod, dosfind.find(mod).functions)}
    caller, callee = fns[base], fns[base + 0x20]
    assert (caller.convention, callee.convention) == ("register", "stack")
    assert (caller.symbol, callee.symbol) == ("func_00010000_", "_func_00010020")
    assert fns[base + 0x30].symbol == "_func_00010030@4"  # (it takes its argument off as it returns)
    assert caller.relocs == [(1, omf.R_386_32, "_D_00020010", 0), (6, omf.R_386_PC32, "_func_00010020", 0)]
    obj = dosdelink.elf(mod, sorted(fns.values(), key=lambda f: f.addr))
    assert obj[:4] == b"\x7fELF"
    text = obj[obj.find(code[0:1] + b"\0\0\0\0"):][:12]  # the caller's bytes, fields holding their addends
    assert text[1:5] == b"\0\0\0\0" and struct.unpack("<i", text[6:10])[0] == -4


def test_source_files_are_runs_of_neighbouring_functions():
    fns = [dosdelink.Function(a, 0x100, f"func_{a:08X}") for a in (0x10000, 0x10100, 0x10200, 0x12000)]
    assert list(dosdelink.units(fns)) == ["text_00010000", "text_00012000"], "a big hole starts another file"
