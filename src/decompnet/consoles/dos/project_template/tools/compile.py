#!/usr/bin/env python3
"""Compile one source file with Watcom's wcc386 and write it as the ELF object objdiff reads.

    python tools/compile.py --compiler wcc386 --include include --output OUT.o --source FILE.c -- FLAGS...

wcc386 writes OMF; tools/omf2elf.py (decompnet.omf, copied in by decompdecomp) turns it into ELF32. WATCOM and
INCLUDE are set from the compiler's own install (its h/ beside binl64/) unless already set. A Watcom of your own
(--runner wine: a Windows wcc386.exe on Linux or macOS) runs through wine, in the prefix decompdecomp gives it
($DECOMPNET_WINE, $DECOMPNET_WINE_PREFIX), its paths as Windows reads them (Z: and backslashes). Standard library only.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import omf2elf  # noqa: E402


def windows(path: Path) -> str:
    """A path as a Windows program under wine reads it: wine's Z: is /."""
    return "Z:" + str(Path(path).resolve()).replace("/", "\\")


def names_for_build(info: dict) -> dict:
    """{the symbol Watcom gives a real name: the address symbol the targets have} (decompnet's
    consoles/dos/project.py names_for_build, kept here so the project needs nothing of decompdecomp's)."""
    out = {}
    conventions = {fn["name"]: fn.get("convention", "register") for fns in info["units"].values() for fn in fns}
    for key, real in (info.get("names") or {}).items():
        if key.startswith("func_"):
            stack = conventions.get(key) == "stack"
            out[f"_{real}" if stack else f"{real}_"] = f"_{key}" if stack else f"{key}_"
        else:
            out[f"_{real}"] = f"_{key}"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler", required=True)
    ap.add_argument("--include", default="include")
    ap.add_argument("--output", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--config", default="", help="functions.json: its real names are renamed back to the targets'")
    ap.add_argument("--runner", default="none", help="none, or wine: a Windows compiler on Linux or macOS")
    ap.add_argument("--system-include", action="append", default=[], help="the compiler's own headers")
    ap.add_argument("flags", nargs="*")
    args = ap.parse_args()
    env = dict(os.environ)
    home = Path(args.compiler).resolve().parent.parent  # .../binl64/wcc386 -> the install
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        obj = Path(tmp) / "out.obj"
        if args.runner == "wine":
            wine = env.get("DECOMPNET_WINE") or shutil.which("wine")
            if not wine:
                sys.stderr.write(f"{args.source}: this Watcom is a Windows program, run through wine, and this "
                                 "computer has none\n")
                return 1
            if env.get("DECOMPNET_WINE_PREFIX"):
                env["WINEPREFIX"] = env["DECOMPNET_WINE_PREFIX"]
            env.update(WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=", WATCOM=windows(home))
            headers = ";".join(windows(Path(p).resolve()) for p in (args.include, *args.system_include))
            cmd = [wine, args.compiler, *args.flags, f"-i={headers}", windows(Path(args.source).resolve()),
                   f"-fo={windows(obj)}"]
        else:
            if (home / "h").is_dir():
                env.setdefault("WATCOM", str(home))
                env["INCLUDE"] = os.pathsep.join(p for p in (args.include, str(home / "h"), env.get("INCLUDE", ""))
                                                 if p)
            cmd = [args.compiler, *args.flags, f"-i={args.include}", args.source, f"-fo={obj}"]
        run = subprocess.run(cmd, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        sys.stdout.write(run.stdout)
        sys.stderr.write(run.stderr)
        if run.returncode != 0 or not obj.is_file():
            return run.returncode or 1
        try:
            module = omf2elf.parse(obj.read_bytes())
            if args.config:  # a real name (Foo_) is the address symbol the target has (func_0001A2B0_) again
                back = names_for_build(json.loads(Path(args.config).read_text(encoding="utf-8")))
                module.publics = [(back.get(n, n), *rest) for n, *rest in module.publics]
                module.externs = [back.get(n, n) for n in module.externs]
            elf = omf2elf.to_elf(module)
        except omf2elf.OMFError as e:
            sys.stderr.write(f"{args.source}: Watcom's object couldn't be read: {e}\n")
            return 1
    out.write_bytes(elf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
