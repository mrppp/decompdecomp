"""32-bit DOS games: protected-mode programs bound to the DOS/4GW extender, written in Watcom C (x86, PROJECT mode).

A game is an MZ program with an LE module behind it (decompnet.le). decompdecomp finds its functions from its code and
fixups (decompnet.dosfind), cuts them into one ELF32 object per source file with relocations named as Watcom's
compiler would (decompnet.dosdelink), and builds the C with OpenWatcom (toolchains.toml's openwatcom-2.0), whose OMF
objects decompnet.omf turns into ELF, so objdiff judges each function. 16-bit (real-mode) DOS games aren't read:
objdiff's x86 is 32/64-bit only.

Files:
  __init__.py       the console: its facts, sniffing an executable, and the parts the app asks for
  scratch.py        a project from the user's copy: config/VERSION/functions.json, orig/, src/ and the build
  project_template/ what every project gets: tools/configure.py, compile.py, delink.py (omf2elf.py is
                    decompnet/omf.py, copied in)

Its demo game is projects/demo-dos (a homemade program built with OpenWatcom into an LE executable).
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import BETA, PROJECT, Compiler, Console


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
    compiler_config = (".decomp.wtf.json",)
    guides = ("x86",)
    compiler_guide = ""
    m2c = ""  # m2c has no x86 target
    ram = (0x10000, 0x1000000)  # a DOS/4GW game's objects are linked low (code at 0x10000 is common)
    demo = "demo-dos"
    demo_tools = ("openwatcom-2.0", "objdiff-cli")

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

    def tool_args(self) -> list[str]:
        return []

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

    def function_extent(self, fp, symbol: str) -> tuple[int, int] | None:
        version = (fp.manifest or {}).get("version") or ""
        for fns in _functions_json(fp, version).get("units", {}).values():
            for fn in fns:
                if symbol in (fn["symbol"], fn["name"]):
                    return fn["addr"], fn["size"]
        return None


DOS = Dos()
