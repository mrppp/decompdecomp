"""An Xbox 360 image's own function table (.pdata), and the base-image layout it tells apart.

Synthetic PE images only; the real checks were made by hand on two games' images: .pdata listed 27,923 and 104,828
functions, 98-99% beginning with mflr r12 and every one ending on blr, a tail-call b or a call that never returns.
"""

import struct

from decompnet.consoles.xbox360 import pdata, scratch

BASE = 0x82000000
MFLR = 0x7D8802A6
BLR = 0x4E800020
TEXT_VA, TEXT_RAW = 0x2000, 0x1A00  # .text's address and the file offset the section table gives (like XexTool's)
PDATA_VA = 0x1000
IMAGE_SIZE = 0x4000


def _pe(sections, image_size=IMAGE_SIZE, header_size=0x400) -> bytearray:
    """A PowerPC PE header with `sections` [(name, va, vsize, raw, rsize, flags)]; the rest is up to the caller."""
    out = bytearray(header_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x80)
    out[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", out, 0x84, scratch.PE_MACHINE_PPC, len(sections))
    struct.pack_into("<H", out, 0x94, 0xE0)  # SizeOfOptionalHeader
    opt = 0x98
    struct.pack_into("<I", out, opt + 16, TEXT_VA)  # entry
    struct.pack_into("<I", out, opt + 28, BASE)
    struct.pack_into("<II", out, opt + 56, image_size, header_size)
    for index, (name, va, vsize, raw, rsize, flags) in enumerate(sections):
        at = opt + 0xE0 + index * 40
        out[at:at + 8] = name.encode().ljust(8, b"\0")
        struct.pack_into("<IIII", out, at + 8, vsize, va, rsize, raw)
        struct.pack_into("<I", out, at + 36, flags)
    return out


SECTIONS = [(".pdata", PDATA_VA, 0x18, PDATA_VA, 0x200, 0x40000000),
            (".text", TEXT_VA, 0x100, TEXT_RAW, 0x200, 0x60000020)]
FUNCS = [(BASE + TEXT_VA, 0x10), (BASE + TEXT_VA + 0x10, 0x20), (BASE + TEXT_VA + 0x30, 0x8)]


def _table() -> bytes:
    return b"".join(struct.pack(">II", start, (length // 4) << 8 | 2) for start, length in FUNCS)


def _code() -> bytes:
    code = bytearray(0x100)
    for start, length in FUNCS:
        at = start - BASE - TEXT_VA
        struct.pack_into(">I", code, at, MFLR)
        struct.pack_into(">I", code, at + length - 4, BLR)
    return bytes(code)


def memory_layout_image() -> bytes:
    """What XexTool writes: every section at its address, the section table still naming file offsets."""
    image = _pe(SECTIONS)
    image.extend(bytes(IMAGE_SIZE - len(image)))
    image[PDATA_VA:PDATA_VA + 0x18] = _table()
    image[TEXT_VA:TEXT_VA + 0x100] = _code()
    return bytes(image)


def file_layout_image() -> bytes:
    """A real file layout: each section at the file offset its table entry gives."""
    image = _pe(SECTIONS)
    image.extend(bytes(TEXT_RAW + 0x200 - len(image)))
    image[PDATA_VA:PDATA_VA + 0x18] = _table()
    image[TEXT_RAW:TEXT_RAW + 0x100] = _code()
    return bytes(image)


def test_the_table_lists_each_function_with_its_length():
    assert pdata.entries(_table()) == FUNCS
    assert pdata.entries(_table() + bytes(8)) == FUNCS  # empty entries are not functions


def test_a_xextool_image_is_read_in_memory_layout_and_a_real_file_one_in_file_layout():
    assert pdata.memory_layout(memory_layout_image()) is True
    assert pdata.memory_layout(file_layout_image()) is False


def test_a_memory_layout_base_image_maps_its_code_at_its_address():
    """Mapped as a file layout, XexTool's .text landed (text va - raw) bytes away: every target was cut wrong."""
    mapped = scratch.read_base_image(memory_layout_image())["image"]
    assert struct.unpack_from(">I", mapped, TEXT_VA)[0] == MFLR
    assert pdata.functions(mapped, BASE, log=lambda line: None) == FUNCS


def test_a_file_layout_base_image_still_maps_by_its_section_table_and_keeps_its_header():
    mapped = scratch.read_base_image(file_layout_image())["image"]
    assert struct.unpack_from(">I", mapped, TEXT_VA)[0] == MFLR
    assert mapped[:2] == b"MZ", "the header is mapped too: it is how .pdata is found"
    assert pdata.functions(mapped, BASE, log=lambda line: None) == FUNCS


def test_a_table_that_does_not_describe_the_code_is_not_trusted():
    """A mis-mapped image's table names other bytes; cutting functions there would make every target wrong."""
    shifted = bytearray(memory_layout_image())
    shifted[TEXT_VA:TEXT_VA + 0x100] = bytes(0x100)
    shifted[TEXT_VA + 0x5E0:TEXT_VA + 0x5E0 + 0x100] = _code()  # the code somewhere else
    said = []
    assert pdata.functions(bytes(shifted), BASE, log=said.append) is None
    assert said and "doesn't match its code" in said[0]


def test_overlapping_or_out_of_code_entries_are_left_out():
    image = bytearray(memory_layout_image())
    extra = struct.pack(">II", BASE + TEXT_VA + 0x14, (0x8 // 4) << 8) + struct.pack(">II", BASE + 0x10, 1 << 8)
    image[PDATA_VA:PDATA_VA + 0x28] = _table() + extra
    struct.pack_into("<I", image, 0x98 + 0xE0 + 8, 0x28)  # .pdata's vsize now covers them
    assert pdata.functions(bytes(image), BASE, log=lambda line: None) == FUNCS


def test_analysis_fills_gaps_lends_names_and_its_fragments_are_dropped():
    table = [{"name": f"FUN_{a:08x}", "addr": a, "size": n} for a, n in FUNCS]
    analysed = [
        {"name": "FUN_82002000", "addr": BASE + TEXT_VA, "size": 0x8},  # same start: the table's length stands
        {"name": "Update", "addr": BASE + TEXT_VA + 0x10, "size": 0x20},  # same start, a real name: taken
        {"name": "FUN_82002018", "addr": BASE + TEXT_VA + 0x18, "size": 0x8},  # inside a table function: a piece
        {"name": "FUN_82002040", "addr": BASE + TEXT_VA + 0x40, "size": 0x10},  # past every table function: a leaf
        {"name": "FUN_82002034", "addr": BASE + TEXT_VA + 0x34, "size": 0x10},  # runs into the next start: dropped
    ]
    merged, added, dropped = pdata.merge(table, analysed)
    assert [(row["addr"] - BASE, row["size"], row["name"]) for row in merged] == [
        (TEXT_VA, 0x10, "FUN_82002000"), (TEXT_VA + 0x10, 0x20, "Update"), (TEXT_VA + 0x30, 0x8, "FUN_82002030"),
        (TEXT_VA + 0x40, 0x10, "FUN_82002040")]
    assert (added, dropped) == (1, 2)
    assert pdata.merge(table, None) == (table, 0, 0)


def test_the_import_takes_its_functions_from_the_table_without_ghidra(tmp_path, monkeypatch):
    """With no function map and no Ghidra, the import used to fail; the image's own table is enough."""
    import json

    from decompnet.forks import ghidra

    game = tmp_path / "Game.bin"
    game.write_bytes(memory_layout_image())
    monkeypatch.setattr(ghidra, "available", lambda: False)
    monkeypatch.setattr(scratch, "_run", lambda cmd, root, what, log: (True, ""))
    logs = []
    root = tmp_path / "project"
    try:
        scratch.create(root, game, log=logs.append)
    except Exception:  # noqa: BLE001  a later build step may refuse a synthetic game; what create() wrote counts
        pass
    cfg = json.loads(next((root / "config").glob("*/functions.json")).read_text(encoding="utf-8"))
    got = sorted((fn["addr"], fn["size"], fn["name"]) for fns in cfg["units"].values() for fn in fns)
    assert got == [(a, n, f"FUN_{a:08x}") for a, n in FUNCS]
    assert any("function table (.pdata) lists 3 functions" in line for line in logs)
    assert any("from the code between them alone" in line for line in logs), "where they come from without Ghidra is said"


def _project(tmp_path, units):
    """A project made by an earlier import: its config (functions in `units`) and its image."""
    import json

    root = tmp_path / "proj"
    (root / "config" / "game").mkdir(parents=True)
    (root / "orig").mkdir()
    (root / "orig" / "game.xex").write_bytes(memory_layout_image())
    (root / "src" / "auto").mkdir(parents=True)
    info = {"target_format_version": 4, "elf": "orig/game.xex", "sha1": "", "image_base": BASE, "entry": BASE + TEXT_VA,
            "text": {"va": BASE, "offset": 0, "size": IMAGE_SIZE},
            "units": {u: [{"name": n, "addr": a, "offset": a - BASE, "size": s, "relocs": []} for n, a, s in fns]
                      for u, fns in units.items()}}
    (root / "config" / "game" / "functions.json").write_text(json.dumps(info), encoding="utf-8")
    return root


def _units(root):
    import json

    info = json.loads((root / "config" / "game" / "functions.json").read_text(encoding="utf-8"))
    return {u: [(f["name"], f["addr"] - BASE, f["size"]) for f in fns] for u, fns in info["units"].items()}


def test_a_reimport_takes_the_table_and_keeps_matched_functions_names_and_files(tmp_path, monkeypatch):
    """An older import's analysis (fragments, a wrong length) gives way to the table; a matched function keeps its
    extent, a function the project named keeps its name, and each stays in the file that held it."""
    from decompnet.forks import ghidra

    monkeypatch.setattr(ghidra, "available", lambda: False)
    a, b, c = (start for start, _ in FUNCS)
    root = _project(tmp_path, {"text_82002000": [
        ("Init", a, 0x8),                   # named by polishing; the old analysis cut it short
        ("FUN_82002018", a + 0x18, 0x8),    # a fragment of the table's second function
        ("Matched", c, 0x8),                # matched: stays as it is
    ]})
    said = scratch.reanalyse_functions(root, "game", keep={"Matched"}, log=lambda line: None)
    assert said and "3 matched" not in said and "1 matched kept" in said
    assert _units(root) == {"text_82002000": [("Init", TEXT_VA, 0x10), (f"FUN_{b:08x}", TEXT_VA + 0x10, 0x20),
                                              ("Matched", TEXT_VA + 0x30, 0x8)]}
    assert scratch.reanalyse_functions(root, "game", keep={"Matched"}, log=lambda line: None) is None, "nothing left to change"


def test_a_reimport_gives_code_no_file_held_files_of_its_own(tmp_path, monkeypatch):
    from decompnet.forks import ghidra

    monkeypatch.setattr(ghidra, "available", lambda: False)
    c = FUNCS[2][0]
    root = _project(tmp_path, {"text_82002030": [("FUN_82002030", c, 0x8)]})  # no file before the first two
    scratch.reanalyse_functions(root, "game", log=lambda line: None)
    got = _units(root)
    assert got["text_82002030"] == [("FUN_82002030", TEXT_VA + 0x30, 0x8)]
    [new_unit] = [u for u in got if u != "text_82002030"]
    assert [n for n, _, _ in got[new_unit]] == [f"FUN_{FUNCS[0][0]:08x}", f"FUN_{FUNCS[1][0]:08x}"]
    assert (root / "src" / "auto" / f"{new_unit}.c").read_text(encoding="utf-8").endswith('#include "common.h"\n')


def test_a_reimport_refuses_an_image_whose_table_does_not_match_its_code(tmp_path, monkeypatch):
    import pytest

    from decompnet.forks import ghidra
    from decompnet.forks.project import ForkError

    monkeypatch.setattr(ghidra, "available", lambda: False)
    root = _project(tmp_path, {"text_82002000": [("FUN_82002000", FUNCS[0][0], 0x10)]})
    image = bytearray((root / "orig" / "game.xex").read_bytes())
    image[TEXT_VA:TEXT_VA + 0x100] = bytes(0x100)  # the code isn't where the table says (a mis-mapped image)
    (root / "orig" / "game.xex").write_bytes(bytes(image))
    with pytest.raises(ForkError, match="start a new project"):
        scratch.reanalyse_functions(root, "game", log=lambda line: None)


def test_the_console_offers_reimport():
    from decompnet.consoles.xbox360 import XBOX360

    assert XBOX360.reimports is True


def _leaf_image(words_at: dict[int, list[int]], data: list[int] = ()) -> bytes:
    """A memory-layout image whose .text (0x100 bytes at TEXT_VA) holds `words_at` {offset: [words]}, and whose
    .rdata holds `data` (code addresses, as a vtable does)."""
    sections = SECTIONS + [(".rdata", 0x3000, 0x40, 0x3000, 0x40, 0x40000040)]
    image = _pe(sections)
    image.extend(bytes(IMAGE_SIZE - len(image)))
    for offset, words in words_at.items():
        for i, w in enumerate(words):
            struct.pack_into(">I", image, TEXT_VA + offset + 4 * i, w)
    for i, v in enumerate(data):
        struct.pack_into(">I", image, 0x3000 + 4 * i, v)
    return bytes(image)


ADDI = 0x38630001  # addi r3,r3,1
BEQ_8 = 0x41820008  # beq +8
B_BACK_4 = 0x4BFFFFFC  # b -4


def test_leaf_functions_between_table_functions_are_found_where_they_end():
    """A leaf function (no frame, no calls) has no .pdata entry: the code between table functions is cut after each
    return or jump that nothing before it jumps past, padding skipped."""
    known = [(BASE + TEXT_VA, 0x10)]
    image = _leaf_image({
        0x10: [ADDI, BLR],  # a leaf
        0x18: [0, 0],  # padding
        0x20: [BEQ_8, BLR, ADDI, BLR],  # an early return: the beq jumps past the first blr, so one function
        0x30: [ADDI, B_BACK_4],  # ends on a jump back (a tail call to the code before it)
    })
    assert pdata.leaves(image, BASE, known, log=lambda *_: None) == [
        (BASE + TEXT_VA + 0x10, 8), (BASE + TEXT_VA + 0x20, 16), (BASE + TEXT_VA + 0x30, 8)]


def test_code_with_no_clear_end_before_a_named_start_is_left_out():
    """A start that something names (here a vtable entry) is never inside a found function: code that runs past one
    without ending is not cut on a guess, and the named function itself is still found."""
    named = BASE + TEXT_VA + 0x18
    image = _leaf_image({0x10: [ADDI, ADDI], 0x18: [ADDI, BLR]}, data=[named])
    assert pdata.leaves(image, BASE, [(BASE + TEXT_VA, 0x10)], log=lambda *_: None) == [(named, 8)]


def test_import_thunks_and_exception_handler_words_are_not_leaf_functions():
    thunk = [0x3D608200, 0x816B0010, pdata.MTCTR_R11, pdata.BCTR]  # lis r11 / lwz r11 / mtctr r11 / bctr
    unpatched = [0x01000034, 0x02000034, pdata.MTCTR_R11, pdata.BCTR]  # as the file holds it: two import records
    handler = [BASE + 0x3000, BASE + 0x3010]  # an exception handler and its data, before the function they serve
    lines = []
    image = _leaf_image({0x10: thunk, 0x20: unpatched, 0x30: handler})
    assert pdata.leaves(image, BASE, [(BASE + TEXT_VA, 0x10), (BASE + TEXT_VA + 0x38, 0x10)], log=lines.append) == []
    assert not lines, "addresses before a function aren't reported as code with no clear end"


def test_a_switch_keeps_its_cases():
    """A switch ends its dispatch with bctr (a bounds check, then a table lookup): the cases after it are its own."""
    switch = [0x2803_0003, 0x4181_0014, 0x7D6B_182E, 0x7D69_03A6, pdata.BCTR, ADDI, BLR]  # cmplwi, bgt, lwzx, ...
    image = _leaf_image({0x10: switch})
    assert pdata.leaves(image, BASE, [(BASE + TEXT_VA, 0x10)], log=lambda *_: None) == [(BASE + TEXT_VA + 0x10, 28)]


def test_a_reimport_keeps_each_function_in_its_file_when_files_interleave(tmp_path, monkeypatch):
    """After one reimport a file's code can reach past another's (one game had 196 such files). Assigning functions
    by the first file whose span held them moved 451 of them away from the file with their C."""
    from decompnet.forks import ghidra

    monkeypatch.setattr(ghidra, "available", lambda: False)
    a, b, c = (start for start, _ in FUNCS)
    root = _project(tmp_path, {"outer": [(f"FUN_{a:08x}", a, 0x10), (f"FUN_{c:08x}", c, 0x8)],
                               "inner": [(f"FUN_{b:08x}", b, 0x10)]})  # the table says 0x20: a new extent
    scratch.reanalyse_functions(root, "game", log=lambda line: None)
    got = _units(root)
    assert [n for n, _, _ in got["inner"]] == [f"FUN_{b:08x}"]
    assert [n for n, _, _ in got["outer"]] == [f"FUN_{a:08x}", f"FUN_{c:08x}"]


def test_a_reimport_adds_the_leaf_functions_between_table_functions(tmp_path, monkeypatch):
    """A leaf function in the code between table functions joins the file of the function before it."""
    from decompnet.forks import ghidra

    monkeypatch.setattr(ghidra, "available", lambda: False)
    root = _project(tmp_path, {"text_82002000": [(f"FUN_{a:08x}", a, n) for a, n in FUNCS]})
    image = bytearray((root / "orig" / "game.xex").read_bytes())
    leaf = BASE + TEXT_VA + 0x38
    struct.pack_into(">II", image, TEXT_VA + 0x38, ADDI, BLR)
    (root / "orig" / "game.xex").write_bytes(bytes(image))
    said = scratch.reanalyse_functions(root, "game", log=lambda line: None)
    assert "1 leaf functions found" in said
    assert _units(root)["text_82002000"][-1] == (f"FUN_{leaf:08x}", 0x38 + TEXT_VA, 8)
