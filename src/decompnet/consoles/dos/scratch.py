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

from ... import dosdelink, dosfind, le, watcomlib
from ...forks.project import ForkError

TEMPLATE = Path(__file__).parent / "project_template"
OMF = Path(__file__).resolve().parents[2] / "omf.py"
TOOLS = ("tools/configure.py", "tools/compile.py", "tools/delink.py", "tools/rebuild.py")
TYPES_H = """\
/* Types for this decompilation (32-bit x86, Watcom C). Agents add structs and prototypes here or in new headers.
 * The game's functions are func_XXXXXXXX and its data D_XXXXXXXX (their addresses): write them with those names
 * and the build gives them the original's symbols. A function in Watcom's stack convention (functions.json says
 * "stack") is declared __cdecl, or __stdcall where it says "pops" (its symbol _func_XXXXXXXX@8).
 * Watcom 9.5 and 10.x are C89 compilers: declare a function before you call it, declarations at the start of a
 * block, no long long, bool or inline (guide "watcom"). */
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


def library_folders(compiler: str = "") -> list[Path]:
    """The user's Watcom copies whose libraries to look for in a game: the one the project builds with first."""
    from ... import kits
    copies = sorted(kits.compilers(("watcom",)), key=lambda c: c.version != compiler)
    return list(dict.fromkeys(Path(c.exe).parent.parent for c in copies))


def apply_library(info: dict, code: bytes, folders: list[Path], log=print) -> int:
    """Mark the game's functions that are Watcom's library code (watcomlib.identify, with the libraries of the
    copy among `folders` the game matches most: the Watcom that linked it): each gets "library" (set aside:
    generated_functions) and its real name, and the library's data its names, where no other symbol has them yet.
    Returns how many functions."""
    fns = [fn for fns in info["units"].values() for fn in fns]
    found, data, folder = {}, {}, None
    for candidate in folders:
        libs = watcomlib.load(candidate)
        if libs:
            f, d = watcomlib.identify(fns, code, info["code_base"], libs)
            if len(f) > len(found):
                found, data, folder = f, d, candidate
    names = dict(info.get("names") or {})
    taken = set(names.values())
    for fn in fns:
        lf = found.get(fn["symbol"])
        if lf is None:
            fn.pop("library", None)
            continue
        fn["library"] = f"{lf.library}: {lf.name}"
        real = watcomlib.c_name(lf.name)
        if fn["name"] not in names and real not in taken:
            names[fn["name"]] = real
            taken.add(real)
    for sym, ext in data.items():
        key, real = sym.lstrip("_"), watcomlib.c_name(ext)
        if key not in names and real not in taken:
            names[key] = real
            taken.add(real)
    info["names"] = dict(sorted(names.items()))
    if found and folder is not None:
        log(f"{len(found)} functions are Watcom's C library (your copy at {folder}), set aside and named; "
            f"{len(data)} of the library's data named")
    return len(found)


def require_compiler() -> None:
    """OpenWatcom 2, which every project builds with, installed: the import card's "Install the missing compiler"
    or Setup's Compilers & tools installs it (a pinned download, toolchains.toml), never the import by itself."""
    from ... import toolchains
    if toolchains.installed("openwatcom-2.0") is None:
        raise ForkError("DOS projects build with OpenWatcom C 2.0, which isn't installed: tick \"Install the missing "
                        "compiler first\" on the import, or install it in Setup (Compilers & tools), then import again")


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
    require_compiler()
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
    main = _main_object(mod)
    # the largest code object only (a second one's code is an address to it: D_XXXXXXXX), before the relocations
    # are named, so no relocation names a function the project doesn't have
    fns = dosdelink.functions(mod, [f for f in found.functions if main.base <= f[0] < main.base + main.size])
    groups = dosdelink.units(fns)
    covered = sum(f.size for f in fns) / main.size
    log(f"{len(fns)} functions ({covered:.0%} of the code) in {len(groups)} source files")

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
    config = {
        "format": 1, "image": f"orig/{version}.code.bin", "sha1": hashlib.sha1(main.data).hexdigest(),
        "code_base": main.base, "entry": mod.entry,
        "units": {u: [{"name": f.name, "symbol": f.symbol, "convention": f.convention, **({"pops": f.pops} if f.pops else {}),
                       "addr": f.addr, "size": f.size, "relocs": [list(r) for r in f.relocs]} for f in group]
                  for u, group in groups.items()},
    }
    apply_library(config, main.data, library_folders(compiler or ""), log)
    (conf / "functions.json").write_text(json.dumps(config, indent=1), encoding="utf-8")
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
        "3. Decompiled code goes in `src/`; `objdiff.json` shows each function's progress.\n"
        "4. `ninja rebuild` puts the game's code back together from the project and checks it against your copy.\n", encoding="utf-8")
    _run([sys.executable, "tools/configure.py", version], root, "the first build", log)
    _run([_ninja(), "prepare-targets"], root, "cutting the targets", log)
    missing = [u for u in groups if not (root / "build" / version / "target" / f"{u}.o").is_file()]
    if missing:
        raise ForkError(f"delink finished without writing every target object (e.g. {', '.join(missing[:3])})")
    log(f"{len(groups)} source files for agents to write into")
    if shutil.which("git"):  # the project's history: every match a commit (.gitignore keeps orig/ and build/ out)
        for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                    ["git", "-c", "user.name=decompdecomp", "-c", "user.email=noreply@decompdecomp.invalid", "commit",
                     "-q", "-m", f"Start the {info['title']} decompilation (decompdecomp, OpenWatcom)"]):
            subprocess.run(cmd, cwd=root, capture_output=True)
    return {"platform": "dos", "id": version, "title": info["title"], "compiler": chosen, "sources": len(groups),
            "sha1": info["sha1"]}


def check_code(root: Path, version: str, log=print) -> dict:
    """The rebuild check: the game's code object rebuilt from the project (tools/rebuild.py: every function from what
    src/ compiles to where that defines it, else from its delinked target, relocations filled in), compared with
    the user's copy byte for byte: {"identical", "detail", "what"}. A join or cut that took the wrong bytes comes out
    different too."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("dos_rebuild", root / "tools" / "rebuild.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    report = tool.rebuild(Path("config") / version / "functions.json", Path("build") / version, root)
    if not report["identical"]:
        differ = report["differ"] or ["the code outside its functions"]
        detail = (f"{len(differ)} functions rebuilt from the project differ from your copy: "
                  f"{', '.join(differ[:8])}{'…' if len(differ) > 8 else ''}")
        log(f"note: {detail}")
        return {"identical": False, "detail": detail}
    c, n = len(report["c"]), report["functions"]
    log(f"the game's code rebuilt from the project ({c:,} of its {n:,} functions from C) is your copy, byte for byte")
    return {"identical": True, "detail": f"identical: the code object ({report['size']:,} bytes); its {n:,} functions "
                                         f"({report['bytes']:,} bytes), {c:,} of them from C",
            "what": "The game's code, rebuilt from the project,"}


def _main_object(mod):
    code = [o for o in mod.objects if o.executable]
    return max(code, key=lambda o: o.size)


def reanalyse(root: Path, version: str, matched: set[str], log=print) -> str | None:
    """The project's functions found again as an import finds them now (from its own copy, orig/VERSION.exe), every
    matched function kept as it is, and every other one in the source file whose code it's in (a new one: its
    neighbour's file), so the C in the files stays where it was. Real names, cut-off parts set aside and per-file
    flags are kept. Returns what changed, as a sentence, or None."""
    path = root / "config" / version / "functions.json"
    info = json.loads(path.read_text(encoding="utf-8"))
    mod = le.parse((root / "orig" / f"{version}.exe").read_bytes())
    mod.relocated()
    main = _main_object(mod)
    if hashlib.sha1(main.data).hexdigest() != info["sha1"]:
        raise ForkError(f"orig/{version}.exe isn't the copy this project was made from")
    old = {fn["addr"]: (unit, fn) for unit, fns in info["units"].items() for fn in fns}
    kept = {a: (u, fn) for a, (u, fn) in old.items() if {fn["name"], fn["symbol"]} & matched}
    found = [f for f in dosfind.find(mod).functions if main.base <= f[0] < main.base + main.size]

    def inside_kept(a: int, n: int) -> bool:
        return any(k < a + n and a < k + fn["size"] for k, (_, fn) in kept.items())
    spans = sorted([(a, n) for a, n in found if a not in kept and not inside_kept(a, n)]
                   + [(a, fn["size"]) for a, (_, fn) in kept.items()])
    fns = {f.addr: f for f in dosdelink.functions(mod, spans)}
    order = list(info["units"])
    units: dict[str, list] = {u: [] for u in order}
    last = order[0]
    for a, n in spans:
        f = fns[a]
        entry = {"name": f.name, "symbol": f.symbol, "convention": f.convention, **({"pops": f.pops} if f.pops else {}),
                 "addr": a, "size": n, "relocs": [list(r) for r in f.relocs]}
        if a in old:
            last, before = old[a]
            for key in ("set_aside", "generated"):
                if key in before:
                    entry[key] = before[key]
            if a in kept:  # its symbol and relocations as they were: its C names them
                entry = before
        units[last].append(entry)
    units = {u: group for u, group in units.items() if group}
    library_before = {fn["symbol"]: fn.get("library") for _, fn in old.values()}
    names_before = dict(info.get("names") or {})
    new_info = {**info, "units": units}
    manifest = json.loads((root / ".decomp.wtf.json").read_text(encoding="utf-8"))
    apply_library(new_info, main.data, library_folders(manifest.get("compiler", "")), log)
    library_after = {fn["symbol"]: fn.get("library") for group in units.values() for fn in group}
    before = {(fn["addr"], fn["size"], fn["symbol"], json.dumps(fn["relocs"])) for _, fn in old.values()}
    after = {(fn["addr"], fn["size"], fn["symbol"], json.dumps(fn["relocs"])) for group in units.values() for fn in group}
    if before == after and library_before == library_after and names_before == new_info.get("names", {}):
        return None
    info = new_info
    new_addrs = {fn["addr"] for group in units.values() for fn in group}
    added = len(new_addrs - set(old))
    gone = len(set(old) - new_addrs)
    changed = len(after - before) - added
    path.write_text(json.dumps(info, indent=1), encoding="utf-8")
    for u in units:  # a file only the new analysis has (none yet: new functions join their neighbour's)
        src = root / "src" / "auto" / f"{u}.c"
        if not src.exists():
            src.write_text('#include "common.h"\n', encoding="utf-8")
    library = sum(1 for v in library_after.values() if v)
    sentence = (f"{len(new_addrs):,} functions found again: {added} new, {gone} gone, {max(changed, 0)} with other "
                f"extents or references; {len(kept)} matched kept as they were"
                + (f"; {library} are Watcom's C library, set aside" if library else ""))
    log(sentence)
    return sentence
