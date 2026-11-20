"""Build Demo Quest DOS, a 32-bit DOS/4GW program (an MZ program with an LE module), made only from code we may share:
the same Demo Quest game as the N64 demo (CC0, ../demo-n64/original) and a start-up file (dosmain.c), compiled with
OpenWatcom (-5r -ox, a Pentium-era game's flags) and linked by its own linker for DOS/4GW, with its stub, as a game
of the mid-1990s was. It writes build/demo.json: the game, and every function's address by its C name.

    uv run python projects/demo-dos/build.py    ->  build/demoquest.exe (+ build/demoquest.map, build/demo.json)

Needs the openwatcom-2.0 toolchain (decompnet toolchain install openwatcom-2.0).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GAME = HERE.parent / "demo-n64" / "original"
BUILD = HERE / "build"
FLAGS = ["-zq", "-bt=dos", "-mf", "-5r", "-ox"]


def main() -> None:
    from decompnet import le, toolchains

    if not toolchains.installed("openwatcom-2.0"):
        sys.exit("needs the openwatcom-2.0 toolchain: decompnet toolchain install openwatcom-2.0")
    watcom = toolchains.path("openwatcom-2.0")
    env = dict(os.environ, WATCOM=str(watcom), INCLUDE=str(watcom / "h"),
               PATH=os.pathsep.join([str(watcom / "binl64"), os.environ.get("PATH", "")]))
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir()
    for src in (GAME / "game.c", GAME / "game.h", HERE / "dosmain.c"):
        shutil.copyfile(src, BUILD / src.name)
    for src in ("game.c", "dosmain.c"):
        obj = src.replace(".c", ".obj")  # (named: on Linux it would be .o)
        subprocess.run([str(watcom / "binl64" / "wcc386"), *FLAGS, src, f"-fo={obj}"], cwd=BUILD, env=env, check=True)
    subprocess.run([str(watcom / "binl64" / "wlink"), "system", "dos4g", "name", "demoquest.exe",
                    "file", "dosmain.obj,game.obj", "option", "map=demoquest.map,quiet"],
                   cwd=BUILD, env=env, check=True)
    mod = le.parse((BUILD / "demoquest.exe").read_bytes())
    symbols = {}
    for line in (BUILD / "demoquest.map").read_text(encoding="latin-1").splitlines():
        m = re.match(r"([0-9a-f]{4}):([0-9a-f]{8})[+*]?\s+(\S+)$", line.strip())
        if m and int(m.group(1), 16) <= len(mod.objects):
            obj = mod.objects[int(m.group(1), 16) - 1]
            if obj.executable:
                name = m.group(3)
                c = name[:-1] if name.endswith("_") else name[1:] if name.startswith("_") else name
                symbols[c] = obj.base + int(m.group(2), 16)
    (BUILD / "demo.json").write_text(json.dumps({"game": "demoquest.exe", "symbols": symbols}, indent=1),
                                     encoding="utf-8")
    print(f"build/demoquest.exe: {len(symbols)} code symbols")


if __name__ == "__main__":
    main()
