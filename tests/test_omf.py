"""OMF objects (Watcom's) converted to ELF32 for objdiff: the objects are OpenWatcom 2's output for watcom_flat.c,
`wcc386 -zq -bt=dos -mf -oxt -6r` (and the same with `* 3` changed to `* 5`)."""

import struct
from pathlib import Path

import pytest

from decompnet import omf

DATA = Path(__file__).parent / "data" / "omf"


def test_a_watcom_object_becomes_an_elf32_object_with_its_names_and_fixups():
    mod = omf.parse((DATA / "watcom_flat.obj").read_bytes())
    assert [(s.name, s.klass) for s in mod.segments][0] == ("_TEXT", "CODE")
    assert [(n, off) for n, seg, off, _ in mod.publics if seg == 0] == [("add_scaled_", 0), ("sum_squares_", 32)]
    kinds = sorted(r[1] for r in mod.segments[0].relocs)
    assert kinds == [omf.R_386_32, omf.R_386_PC32], "a call (self-relative) and a data reference (offset)"
    elf = omf.convert((DATA / "watcom_flat.obj").read_bytes())
    assert elf[:4] == b"\x7fELF" and elf[4] == 1 and struct.unpack_from("<H", elf, 18)[0] == 3  # ELF32, EM_386


def test_objdiff_reads_the_converted_objects_function_by_function(tmp_path):
    from decompnet import toolchains
    try:
        objdiff = toolchains.binary("objdiff-cli")
    except Exception:
        pytest.skip("needs objdiff-cli")
    if not objdiff or not Path(objdiff).exists():
        pytest.skip("needs objdiff-cli")
    import json
    import subprocess
    for name in ("watcom_flat", "watcom_flat_changed"):
        (tmp_path / f"{name}.o").write_bytes(omf.convert((DATA / f"{name}.obj").read_bytes()))

    def percent(left, right, symbol):
        out = subprocess.run([str(objdiff), "diff", "-1", str(tmp_path / left), "-2", str(tmp_path / right), "-o", "-",
                              "--format", "json", symbol], capture_output=True, text=True, check=True).stdout
        return next(s.get("match_percent") for s in json.loads(out)["right"]["symbols"] if s["name"] == symbol)
    assert percent("watcom_flat.o", "watcom_flat.o", "add_scaled_") == 100.0
    assert percent("watcom_flat.o", "watcom_flat_changed.o", "add_scaled_") < 100.0, "the * 3 -> * 5 is seen"
    assert percent("watcom_flat.o", "watcom_flat_changed.o", "sum_squares_") == 100.0, "and nothing else"


def test_what_isnt_flat_32_bit_code_is_refused_not_converted_wrongly():
    data = bytearray((DATA / "watcom_flat.obj").read_bytes())
    at = 0
    while at < len(data):  # make the first FIXUPP's first fixup a 16-bit offset (location 1)
        kind, length = data[at], struct.unpack_from("<H", data, at + 1)[0]
        if kind & 0xFE == 0x9C and data[at + 3] & 0x80:
            data[at + 3] = (data[at + 3] & ~0x3C) | (1 << 2)
            break
        at += 3 + length
    with pytest.raises(omf.OMFError, match="32-bit offset"):
        omf.parse(bytes(data))
