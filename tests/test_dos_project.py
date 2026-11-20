"""A DOS project's config edits (consoles/dos/project.py), its drafts (drafts.py) and its rebuild tool, on a
synthetic project: no game, no compiler."""

import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

from decompnet import omf
from decompnet.app.twins import _watcom_c_name
from decompnet.consoles.dos import DOS, drafts, project
from decompnet.forks.project import ForkError

BASE = 0x10000
TOOLS = Path(drafts.__file__).parent / "project_template" / "tools"


def _tool(name: str):
    """A project tool as a project runs it (its omf2elf.py is decompnet/omf.py, copied in)."""
    sys.modules.setdefault("omf2elf", omf)
    spec = importlib.util.spec_from_file_location(f"dos_tool_{name}", TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rebuild = _tool("rebuild")


def _project(tmp_path):
    """Three neighbouring functions: f1 calls f2 and reads a global; f2 has a jump table (a label in itself); f3
    takes f2's address, 4 bytes in. The code image holds them relocated, as a loaded game's does."""
    code = bytearray(0x40)
    # f1 at 0x10000 (16 bytes): call f2 (PC32 at 1), mov eax,[D_00020000] (abs at 6), ret
    code[0:5] = b"\xe8" + struct.pack("<i", 0x10 - 5)
    code[5:10] = b"\xa1" + struct.pack("<I", 0x20000)
    code[10] = 0xC3
    # f2 at 0x10010 (16 bytes): jmp [table], with the table's address at 2: the table at 0x1001C
    code[0x10:0x12] = b"\xff\x24"
    struct.pack_into("<I", code, 0x12, 0x1001C)
    code[0x16] = 0xC3
    # f3 at 0x10020 (8 bytes): mov eax, f2+4
    code[0x20] = 0xB8
    struct.pack_into("<I", code, 0x21, 0x10014)
    code[0x25] = 0xC3
    root = tmp_path / "proj"
    (root / "orig").mkdir(parents=True)
    (root / "orig" / "g.code.bin").write_bytes(bytes(code))
    (root / "config" / "g").mkdir(parents=True)
    info = {"format": 1, "image": "orig/g.code.bin", "sha1": "", "code_base": BASE, "units": {"text_00010000": [
        {"name": "func_00010000", "symbol": "func_00010000_", "convention": "register", "addr": 0x10000, "size": 16,
         "relocs": [[1, 2, "func_00010010_", 0], [6, 1, "_D_00020000", 0]]},
        {"name": "func_00010010", "symbol": "func_00010010_", "convention": "register", "addr": 0x10010, "size": 16,
         "relocs": [[2, 1, None, 0xC]]},
        {"name": "func_00010020", "symbol": "_func_00010020", "convention": "stack", "addr": 0x10020, "size": 8,
         "relocs": [[1, 1, "func_00010010_", 4]]},
    ]}}
    (root / "config" / "g" / "functions.json").write_text(json.dumps(info), encoding="utf-8")
    return root


def _info(root):
    return json.loads((root / "config" / "g" / "functions.json").read_text(encoding="utf-8"))


def test_a_real_name_is_kept_by_address_and_given_back_to_the_build(tmp_path):
    root = _project(tmp_path)
    assert project.rename(root, "g", "func_00010010_", "dispatch")
    assert project.rename(root, "g", "_func_00010020", "helper")
    assert project.rename(root, "g", "D_00020000", "counter")
    info = _info(root)
    assert info["names"] == {"func_00010010": "dispatch", "func_00010020": "helper", "D_00020000": "counter"}
    # what Watcom calls each real name -> the symbol the targets have, by its convention
    assert project.names_for_build(info) == {"dispatch_": "func_00010010_", "_helper": "_func_00010020",
                                             "_counter": "_D_00020000"}
    assert project.rename(root, "g", "dispatch", "dispatch") == {}  # (named so already)
    with pytest.raises(ForkError):
        project.rename(root, "g", "func_00010000", "dispatch")  # another symbol's name
    with pytest.raises(ForkError):
        project.rename(root, "g", "func_00099999", "nowhere")


def test_compile_renames_back_the_way_the_project_does():
    compile_tool = _tool("compile")
    info = {"units": {"u": [{"name": "func_00010010", "convention": "register"},
                            {"name": "func_00010020", "convention": "stack"}]},
            "names": {"func_00010010": "dispatch", "func_00010020": "helper", "D_00020000": "counter"}}
    assert compile_tool.names_for_build(info) == project.names_for_build(info)


def test_a_source_file_divides_at_a_function(tmp_path):
    root = _project(tmp_path)
    project.split(root, "g", "src/auto/text_00010000.c", "func_00010010", "src/auto/second.c")
    units = _info(root)["units"]
    assert list(units) == ["text_00010000", "second"]
    assert [f["name"] for f in units["second"]] == ["func_00010010", "func_00010020"]
    with pytest.raises(ForkError):
        project.split(root, "g", "src/auto/second.c", "func_00010010", "src/auto/third.c")  # (its first)


def test_a_join_then_a_cut_is_the_project_it_was(tmp_path):
    root = _project(tmp_path)
    before = _info(root)
    project.join(root, "g", "func_00010000", "func_00010010", keep=set())
    joined = _info(root)["units"]["text_00010000"]
    first = joined[0]
    assert first["size"] == 32 and [f["name"] for f in joined] == ["func_00010000", "func_00010020"]
    # its call into what was f2 is its own branch now; f2's table label is the joined function's, 16 bytes on
    assert [1, 2, "func_00010010_", 0] not in first["relocs"] and [18, 1, None, 0x1C] in first["relocs"]
    assert joined[1]["relocs"] == [[1, 1, "func_00010000_", 0x14]]  # f3's pointer: into the joined function
    project.cut(root, "g", "func_00010000_", 0x10010, keep=set())
    after = _info(root)["units"]["text_00010000"]
    assert [(f["name"], f["size"]) for f in after] == [(f["name"], f["size"]) for f in before["units"]["text_00010000"]]
    assert after[1]["relocs"] == before["units"]["text_00010000"][1]["relocs"]
    assert after[2]["relocs"] == before["units"]["text_00010000"][2]["relocs"]
    with pytest.raises(ForkError):
        project.join(root, "g", "func_00010000", "func_00010010", keep={"func_00010010_"})


def test_the_rebuild_puts_every_function_back_and_tells_a_wrong_one(tmp_path):
    root = _project(tmp_path)
    info = _info(root)
    code = (root / info["image"]).read_bytes()
    target = root / "build" / "g" / "target"
    target.mkdir(parents=True)
    delink = _tool("delink")
    (target / "text_00010000.o").write_bytes(delink.elf(info["units"]["text_00010000"], code, BASE))
    report = rebuild.rebuild(root / "config" / "g" / "functions.json", root / "build" / "g", root)
    assert report["identical"] and report["image"] == code and not report["c"]
    # a compiled object defining f3 with the wrong constant: it differs, and the rest still comes from the targets
    data = bytearray(b"\xb8\x00\x00\x00\x00\xc3\x90\x90")
    seg = omf.Segment("_TEXT", "CODE", 8, 16, data)
    struct.pack_into("<I", data, 1, 8)
    seg.relocs.append((1, omf.R_386_32, ("ext", 0)))
    obj = omf.to_elf(omf.Module([seg], [("_func_00010020", 0, 0, True)], ["func_00010010_"]))
    (root / "build" / "g" / "src" / "auto").mkdir(parents=True)
    (root / "build" / "g" / "src" / "auto" / "text_00010000.o").write_bytes(obj)
    report = rebuild.rebuild(root / "config" / "g" / "functions.json", root / "build" / "g", root)
    assert not report["identical"] and report["differ"] == ["func_00010020"]


def test_flag_variants_try_the_processor_and_optimisation_not_the_convention():
    variants = DOS.flag_variants(["-zq", "-bt=dos", "-mf", "-5r", "-ox"])
    assert variants[0] == ["-zq", "-bt=dos", "-mf", "-5r", "-ox"]
    assert ["-zq", "-bt=dos", "-mf", "-3r", "-ox"] in variants
    assert ["-zq", "-bt=dos", "-mf", "-5r", "-os"] in variants
    assert not any("-5s" in v or "-3s" in v for v in variants)


def test_a_ghidra_draft_becomes_the_projects_c():
    draft = """
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int __regparm3 func_00010079_(int param_1,int param_2)

{
  int unaff_EBX;

  if (param_2 <= param_1) {
    if (unaff_EBX < param_1) {
      param_1 = unaff_EBX + __D_00020000;
    }
    _func_00010020(&_D_00020010);
    return param_1;
  }
  return param_2;
}
"""
    assert "func_00010079(" in drafts.adapt(draft) and "WARNING" not in drafts.adapt(draft)
    prelude, definition = drafts.compilable(draft, "func_00010079_", {"func_00010020"})
    assert definition.startswith("int func_00010079(int param_1, int param_2, int param_3)")  # ebx: the third
    assert "unaff" not in definition
    assert "int __cdecl func_00010020();" in prelude
    assert "extern undefined4 D_00020000;" in prelude and "extern undefined1 D_00020010;" in prelude
    # three register arguments as Ghidra read them: its third is GCC's ecx, not Watcom's ebx
    assert drafts.compilable("int __regparm3 func_00010000_(int a,int b,int c)\n{\n  return a;\n}", "func_00010000_",
                             set()) is None


def test_twins_read_watcom_names_as_c_writes_them():
    assert _watcom_c_name("func_0001A2B0_") == "func_0001A2B0"
    assert _watcom_c_name("_func_0001A2B0") == "func_0001A2B0"
    assert _watcom_c_name("_D_0001A2B0") == "D_0001A2B0"
    assert _watcom_c_name("_TEXT") == "_TEXT"
