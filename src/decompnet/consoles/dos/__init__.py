"""32-bit DOS games: protected-mode programs bound to the DOS/4GW extender, written in Watcom C (x86, PROJECT mode).

A game is an MZ program with an LE module behind it (decompnet.le). decompdecomp finds its functions from its code and
fixups (decompnet.dosfind), cuts them into one ELF32 object per source file with relocations named as Watcom's
compiler would (decompnet.dosdelink), and builds the C with OpenWatcom (toolchains.toml's openwatcom-2.0), whose OMF
objects decompnet.omf turns into ELF, so objdiff judges each function. 16-bit (real-mode) DOS games aren't read:
objdiff's x86 is 32/64-bit only.

Files:
  __init__.py       the console: its facts, sniffing an executable, and the parts the app asks for
  scratch.py        a project from the user's copy: config/VERSION/functions.json, orig/, src/ and the build
  project.py        the edits the app makes to a project's config: real names, splits, joins, cuts, ranges
  drafts.py         Ghidra's drafts in the project's C (briefs), and made compilable (autopilot)
  project_template/ what every project gets: tools/configure.py, compile.py, delink.py, rebuild.py (omf2elf.py is
                    decompnet/omf.py, copied in)

A Watcom of the user's own (kits/watcom.py: 9.5 to 11.0, Open Watcom 1.x) can build any source file instead, through
wine: the old compilers keep registers OpenWatcom 2 doesn't.

Its demo game is projects/demo-dos (a homemade program built with OpenWatcom into an LE executable).
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import BETA, PROJECT, REBUILD_CHECK, Compiler, Console


def _functions_json(fp, version: str) -> dict:
    path = Path(fp.root) / "config" / version / "functions.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


class Dos(Console):
    id = "dos"
    name = "DOS (32-bit, DOS/4GW)"
    short = "DOS"
    status = BETA
    arch = "x86"
    big_endian = False
    mode = PROJECT
    layout = "LE + objdiff"
    compilers = (Compiler("openwatcom-2.0", "OpenWatcom C 2.0", "32-bit DOS/4GW games of the mid-1990s",
                          guess="Watcom"),)
    compiler_config = (".decomp.wtf.json", "config/**/*")
    guides = ("x86",)
    compiler_guide = ""
    m2c = ""  # m2c has no x86 target
    ram = (0x10000, 0x1000000)  # a DOS/4GW game's objects are linked low (code at 0x10000 is common)
    demo = "demo-dos"
    demo_tools = ("openwatcom-2.0", "objdiff-cli")
    packs = (("openwatcom-2.0", "OpenWatcom C 2.0, the compiler DOS projects build with (free and open source)"),)
    own_features = frozenset({REBUILD_CHECK})

    def sniff(self, head: bytes, file) -> bool:
        """An MZ program with an LE module behind it (bound to DOS/4GW): the MZ header, then an LE header whose
        processor and system fields make sense, within the first 2 MB (DOS/4GW's own program comes first)."""
        if head[:2] != b"MZ":
            return False
        try:
            data = Path(file).read_bytes()[:0x200000] if isinstance(file, (str, Path)) else bytes(file)[:0x200000]
        except OSError:
            return False
        from ...le import LEError, header_offset
        try:
            header_offset(data)
        except LEError:
            return False
        return True

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
        from . import scratch
        return scratch.create(root, game, compiler=compiler, log=log)

    def game_info(self, game: Path) -> dict:
        from . import scratch
        return scratch.game_info(game)

    # Watcom C of the user's own (kits/watcom.py: 9.5 to 11.0, Open Watcom 1.x), per source file beside OpenWatcom 2
    kits = ("watcom",)

    def tool_args(self) -> list[str]:
        """configure.py's --own for each Watcom of the user's own: VERSION=RUNNER,EXE,HEADERS..."""
        from ... import kits
        return [arg for c in kits.compilers(self.kits)
                for arg in ("--own", ",".join([f"{c.version}={c.runner or 'none'}", str(c.exe), *map(str, c.includes)]))]

    def build_env(self) -> dict[str, str]:
        """wine and the app's prefix, for a Watcom of the user's own (a Windows program) to build a file with."""
        from ... import kits, wine
        return wine.build_env(always=True) if kits.compilers(self.kits) else {}

    def file_compiler(self, fp, source: str) -> str | None:
        """The compiler a source file builds with: its own (the manifest's dos_compilers_map), else the project's."""
        manifest = fp.manifest or {}
        return (manifest.get("dos_compilers_map") or {}).get(source) or manifest.get("compiler") or "openwatcom-2.0"

    def set_file_compiler(self, fp, source: str, compiler: str) -> str:
        if compiler not in {c.id for c in self.compilers}:
            from ...forks.project import ForkError
            raise ForkError(f"{compiler} isn't a compiler DOS projects have here (Setup: Watcom C, your own copy)")
        manifest = fp.manifest or {}
        own = dict(manifest.get("dos_compilers_map") or {})
        if compiler == (manifest.get("compiler") or "openwatcom-2.0"):
            own.pop(source, None)
        else:
            own[source] = compiler
        fp.update_manifest(dos_compilers_map=own)
        return ".decomp.wtf.json"

    def set_own_compiler(self, fp, compiler: str, sources: list[str]) -> list[str]:
        """`compiler` the project's, each of `sources` keeping the one it builds with."""
        manifest = fp.manifest or {}
        keep = {s: self.file_compiler(fp, s) for s in sources}
        own = {s: c for s, c in keep.items() if c != compiler}
        fp.update_manifest(compiler=compiler, dos_compilers_map=own)
        return [".decomp.wtf.json"] if manifest != fp.manifest else []

    def real_names(self, fp, version: str) -> dict[str, str]:
        """How the source spells each function: Watcom's register convention spells C's `f` as `f_` (its stack
        convention's `_f` the engine already reads), or the real name polishing gave it (functions.json's names)."""
        info = _functions_json(fp, version)
        names = info.get("names") or {}
        out = {}
        for fns in info.get("units", {}).values():
            for fn in fns:
                c = names.get(fn["name"], fn["name"])
                if c != fn["symbol"]:
                    out[fn["symbol"]] = c
        return out

    # The game's names are its addresses: a real name is kept by address in functions.json's "names", and the report
    # keeps the address symbol (tools/compile.py renames a compiled object's real-named symbols back to it)
    renames_in_report = False
    splits_sources = True  # a source file is a unit of functions.json
    DEFAULT_FLAGS = ("-zq", "-bt=dos", "-mf", "-5r", "-ox")
    # What search_flags tries: the processor Watcom tuned for (a game's code changes with it: one function matched
    # with -5r or -4r, came out 77% with -3r) and how hard it optimised (-os: 48%). The calling convention (-5s) is
    # left alone: it renames every symbol the targets were cut with.
    CPUS = ("-5r", "-4r", "-3r", "-6r")
    # how hard it optimised, each a set of flags: -ox has -s in it (no stack checks), -os and -ot alone would check
    # the stack in every function
    OPTIMISATIONS = (("-ox",), ("-oneatx",), ("-otexan",), ("-os", "-s"), ("-ot", "-s"))
    OPTIMISING = frozenset({"-ox", "-oneatx", "-otexan", "-os", "-ot", "-s"})

    def _version(self, fp) -> str:
        return (fp.manifest or {}).get("version") or ""

    def rename_symbol(self, fp, version: str, old: str, new: str) -> dict:
        from . import project
        return project.rename(Path(fp.root), version, old, new)

    def rename_pattern(self, old: str) -> str:
        """func_0001A2B0 however the source spells it (the report's func_0001A2B0_ or _func_0001A2B0 is func_0001A2B0
        there); a real name given before as itself."""
        import re

        from . import project
        key = project.address_key(old)
        return rf"\b{re.escape(key)}\b" if key else rf"\b{re.escape(old)}\b"

    def split_source(self, fp, version: str, source: str, at: str, new: str) -> dict:
        from . import project
        return project.split(Path(fp.root), version, source, at, new)

    def join_functions(self, fp, first: str, last: str, keep: set[str], log=print) -> str:
        from . import project
        return project.join(Path(fp.root), self._version(fp), first, last, keep)

    def file_flags(self, fp, source: str) -> list[str] | None:
        """A source file's Watcom flags: its own (the manifest's dos_flags_map), else the project's."""
        from . import project
        manifest = fp.manifest or {}
        own = project.flags_of(manifest, source)
        return own or (manifest.get("dos_flags") or " ".join(self.DEFAULT_FLAGS)).split()

    def set_file_flags(self, fp, source: str, flags: list[str]) -> str:
        manifest = fp.manifest or {}
        default = (manifest.get("dos_flags") or " ".join(self.DEFAULT_FLAGS)).split()
        own = dict(manifest.get("dos_flags_map") or {})
        if list(flags) == default:
            own.pop(source, None)
        else:
            own[source] = " ".join(flags)
        fp.update_manifest(dos_flags_map=own)
        return ".decomp.wtf.json"

    def flag_variants(self, flags: list[str]) -> list[list[str]]:
        """A file's flags first, then: another processor, another optimisation, and a stack frame kept (-of), alone
        and for size (a shareware game's __stdcall library: -os -of -s)."""
        out = [list(flags)]

        def add(variant: list[str]) -> None:
            if variant not in out:
                out.append(variant)
        rest = [f for f in flags if f not in self.OPTIMISING]
        frame = [] if "-of" in flags else ["-of"]
        add([*flags, *frame])
        add([*[f for f in rest if f != "-of"], "-os", "-s", "-of"])
        for cpu in self.CPUS:
            add([cpu if f in self.CPUS else f for f in flags] + ([] if any(f in self.CPUS for f in flags) else [cpu]))
        for opt in self.OPTIMISATIONS:
            add([*rest, *opt])
        return out

    def file_ranges(self, fp) -> dict[str, list[tuple[int, int]]]:
        from . import project
        version = self._version(fp)
        return project.ranges(Path(fp.root), version) if version else {}

    def generated_functions(self, fp, version: str) -> dict[str, str]:
        """The parts cut off a function that agents said aren't code (project.cut's set_aside): set aside."""
        return {fn["symbol"]: fn["set_aside"] for fns in _functions_json(fp, version).get("units", {}).values()
                for fn in fns if fn.get("set_aside")}

    def structs(self, fp):
        """guess_struct's layouts: every function's code read in its own convention (project.structs)."""
        from . import project
        version = self._version(fp)
        return project.structs(Path(fp.root), version) if version else None

    # Ghidra's drafts of its target objects (drafts.py): briefs show them, autopilot tries them made compilable
    own_drafts = True
    own_tools = frozenset({"redraft", "search_flags"})

    def prepare_drafts(self, fp) -> str | None:
        from .drafts import GHIDRA_H, GHIDRA_HEADER
        path = Path(fp.root) / "include" / GHIDRA_HEADER
        if path.exists():
            return None
        path.write_text(GHIDRA_H, encoding="utf-8")
        return path.relative_to(fp.root).as_posix()

    def adapt_draft(self, text: str) -> str:
        from .drafts import adapt
        return adapt(text)

    def compilable_draft(self, fp, symbol: str, draft: str, known: str = "") -> tuple[str, str] | None:
        from .drafts import compilable
        info = _functions_json(fp, self._version(fp))
        stack = {fn["name"]: "__stdcall" if fn.get("pops") else "__cdecl" for fns in info.get("units", {}).values()
                 for fn in fns if fn.get("convention") == "stack"}
        return compilable(draft, symbol, stack, known)

    reimports = True  # the analysis again, from the project's own copy, matches kept (scratch.reanalyse)

    def reimport(self, net, slug: str, game: Path, log=print) -> str | None:
        """The functions found again as an import finds them now, from the project's own copy of the game (the one
        it judges against: `game` isn't read again), every match, note and name kept (forkengine.reanalyse sets the
        project up again, checks the rebuild, and takes the change back if either fails)."""
        from . import scratch
        _, fp, _ = net.forks.get(slug)
        version = self._version(fp)
        if changed := scratch.write_tools(Path(fp.root)):
            log(f"updated this project's build tools ({', '.join(changed)})")
        matched = {r["name"] for r in net.project_store(slug).all(
            "SELECT name FROM functions WHERE project_id=? AND status='matched'", net.project_row(slug)["id"])}
        log("finding this project's functions again from its own copy of the game")
        return net.forks.reanalyse(slug, lambda fp: scratch.reanalyse(Path(fp.root), version, matched, log=log),
                                   log=log)

    def check_rebuild(self, fp, version: str, log=print) -> dict:
        """The game's code rebuilt from what the project builds now (scratch.check_code)."""
        from . import scratch
        fp.run(["ninja", "prepare"], log=lambda *_: None, timeout=600)
        return scratch.check_code(Path(fp.root), version, log=log)

    def on_start(self, net, slug: str, log=print) -> None:
        """A project made before gets the tools it lacks (rebuild.py, the real-name renaming in compile.py)."""
        from . import scratch
        _, fp, _ = net.forks.get(slug)
        if scratch.write_tools(Path(fp.root)) and (version := self._version(fp)):
            fp.run(["python", "tools/configure.py", version], log=lambda *_: None, timeout=120)

    def cut_function(self, fp, symbol: str, at: int, keep: set[str], why: str = "") -> str:
        from . import project
        return project.cut(Path(fp.root), self._version(fp), symbol, at, keep, why)

    def function_extent(self, fp, symbol: str) -> tuple[int, int] | None:
        version = (fp.manifest or {}).get("version") or ""
        for fns in _functions_json(fp, version).get("units", {}).values():
            for fn in fns:
                if symbol in (fn["symbol"], fn["name"]):
                    return fn["addr"], fn["size"]
        return None


DOS = Dos()
