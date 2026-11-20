"""A 32-bit DOS project from the user's own copy of the game: what Dos.create_project makes.

The game's LE module (decompnet.le) is read and relocated as its loader would; its functions are found from code and
fixups (decompnet.dosfind) and cut into source files with their relocations (decompnet.dosdelink). The project keeps:
  orig/VERSION.exe        the user's copy (hard-linked where possible; never committed)
  orig/VERSION.code.bin   its code object as loaded, which tools/delink.py cuts the targets from
  config/VERSION/functions.json  every function: address, size, Watcom symbol, convention, relocations
  src/auto/<file>.c       one per source file, for agents to write into; include/common.h the types
  tools/                  project_template's, and decompnet/omf.py as tools/omf2elf.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from ... import dosdelink, dosfind, le
from ...forks.project import ForkError

TEMPLATE = Path(__file__).parent / "project_template"
OMF = Path(__file__).resolve().parents[2] / "omf.py"
TOOLS = ("tools/configure.py", "tools/compile.py", "tools/delink.py")
TYPES_H = """\
/* Types for this decompilation (32-bit x86, Watcom C). Agents add structs and prototypes here or in new headers.
 * The game's functions are func_XXXXXXXX and its data D_XXXXXXXX (their addresses): write them with those names
 * and the build gives them the original's symbols. A function in Watcom's stack convention (functions.json says
 * "stack") is declared __cdecl. */
#ifndef COMMON_H
#define COMMON_H
typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
#endif
"""


def game_info(game: Path) -> dict:
    data = game.read_bytes()
    info: dict = {"platform": "dos", "id": re.sub(r"[^A-Za-z0-9_.-]+", "_", game.stem.lower()) or "game",
            "title": game.stem, "sha1": hashlib.sha1(data).hexdigest()}
    try:
        mod = le.parse(data)
    except le.LEError as e:
        raise ForkError(f"{game.name} isn't a 32-bit DOS/4GW program decompdecomp can read: {e}") from None
    info["entry_point"] = mod.entry
    info["objects"] = [{"base": o.base, "size": o.size, "code": o.executable} for o in mod.objects]
    return info


def write_tools(root: Path) -> list[str]:
    """Bring a project's tools up to the template (and tools/omf2elf.py up to decompnet/omf.py)."""
    changed = []
    for rel in TOOLS:
        src, dest = TEMPLATE / rel, root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or dest.read_bytes() != src.read_bytes():
            shutil.copyfile(src, dest)
            changed.append(rel)
    dest = root / "tools" / "omf2elf.py"
    if not dest.exists() or dest.read_bytes() != OMF.read_bytes():
        shutil.copyfile(OMF, dest)
        changed.append("tools/omf2elf.py")
    return changed


def _ninja() -> str:
    """The ninja bundled next to this interpreter (the app's), or the one on PATH."""
    bundled = Path(sys.executable).with_name("ninja")
    if bundled.is_file():
        return str(bundled)
    if found := shutil.which("ninja"):
        return found
    raise ForkError("ninja is needed to cut the project's target objects; install it and try again")


def _run(cmd: list[str], root: Path, what: str, log) -> None:
    run = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if run.returncode != 0:
        raise ForkError(f"{what} failed:\n{(run.stdout + run.stderr)[-2000:]}")


def create(root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
    """Make the project in `root` (which mustn't exist yet) from the user's copy `game`."""
    if root.exists():
        raise ForkError(f"{root} exists already")
    info = game_info(game)
    version = info["id"]
    data = game.read_bytes()
    mod = le.parse(data)
    mod.relocated()
    code = [o for o in mod.objects if o.executable]
    if not code:
        raise ForkError(f"{game.name} has no code object")
    log(f"reading {game.name}: {len(mod.objects)} objects, {len(mod.fixups)} fixups, entry {mod.entry:#x}")
    found = dosfind.find(mod)
    fns = dosdelink.functions(mod, found.functions)
    groups = dosdelink.units(fns)
    covered = sum(f.size for f in fns) / sum(o.size for o in code)
    log(f"{len(fns)} functions ({covered:.0%} of the code) in {len(groups)} source files")
    main = max(code, key=lambda o: o.size)
    if any(not (main.base <= f.addr < main.base + main.size) for f in fns):
        fns = [f for f in fns if main.base <= f.addr < main.base + main.size]  # (one code object: a stub's left out)
        groups = dosdelink.units(fns)

    root.mkdir(parents=True)
    (root / "orig").mkdir()
    original = root / "orig" / f"{version}.exe"
    try:
        os.link(game, original)  # never a second copy of a large game where a link will do
    except OSError:
        shutil.copyfile(game, original)
    image = root / "orig" / f"{version}.code.bin"
    image.write_bytes(main.data)
    (root / "include").mkdir()
    (root / "include" / "common.h").write_text(TYPES_H, encoding="utf-8")
    shutil.copyfile(TEMPLATE / "README", root / "README.template")
    write_tools(root)
    conf = root / "config" / version
    conf.mkdir(parents=True)
    (conf / "functions.json").write_text(json.dumps({
        "format": 1, "image": f"orig/{version}.code.bin", "sha1": hashlib.sha1(main.data).hexdigest(),
        "code_base": main.base, "entry": mod.entry,
        "units": {u: [{"name": f.name, "symbol": f.symbol, "convention": f.convention, "addr": f.addr,
                       "size": f.size, "relocs": f.relocs} for f in group] for u, group in groups.items()},
    }, indent=1), encoding="utf-8")
    for u, group in groups.items():
        src = root / "src" / "auto" / f"{u}.c"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(f"/* {len(group)} function{'s' if len(group) != 1 else ''} from 0x{group[0].addr:08X}, found "
                       "from the game's code and fixups. */\n#include \"common.h\"\n", encoding="utf-8")
    chosen = compiler or "openwatcom-2.0"
    (root / ".decomp.wtf.json").write_text(json.dumps({
        "created": "from scratch", "platform": "dos", "version": version, "compiler": chosen,
        "game": {"what": "your own copy of the game's DOS/4GW program", "path": f"orig/{version}.exe",
                 "sha1": info["sha1"]},
        "setup": [["python", "tools/configure.py", version], ["ninja", "prepare"]],
    }, indent=2), encoding="utf-8")
    (root / ".gitignore").write_text("orig/\nbuild/\nbuild.ninja\n.ninja_*\nobjdiff.json\n__pycache__/\n.decomp-wtf/\n",
                                     encoding="utf-8")
    (root / "README.md").write_text(
        f"# {info['title']} decompilation\n\n"
        "Started from scratch with decompdecomp: functions were found from the game's own code and the fixups its "
        "DOS/4GW module lists, and objdiff compares each source file with the original.\n\n"
        f"1. Your copy of the program is `orig/{version}.exe` (never commit it).\n"
        f"2. `python tools/configure.py {version}` and `ninja` build it with OpenWatcom.\n"
        "3. Decompiled code goes in `src/`; `objdiff.json` shows each function's progress.\n", encoding="utf-8")
    _run([sys.executable, "tools/configure.py", version], root, "the first build", log)
    _run([_ninja(), "prepare-targets"], root, "cutting the targets", log)
    missing = [u for u in groups if not (root / "build" / version / "target" / f"{u}.o").is_file()]
    if missing:
        raise ForkError(f"delink finished without writing every target object (e.g. {', '.join(missing[:3])})")
    log(f"{len(groups)} source files for agents to write into")
    return {"platform": "dos", "id": version, "title": info["title"], "compiler": chosen, "sources": len(groups),
            "sha1": info["sha1"]}
