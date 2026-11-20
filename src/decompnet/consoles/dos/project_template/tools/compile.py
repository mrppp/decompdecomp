#!/usr/bin/env python3
"""Compile one source file with Watcom's wcc386 and write it as the ELF object objdiff reads.

    python tools/compile.py --compiler wcc386 --include include --output OUT.o --source FILE.c -- FLAGS...

wcc386 writes OMF; tools/omf2elf.py (decompnet.omf, copied in by decompdecomp) turns it into ELF32. WATCOM and
INCLUDE are set from the compiler's own install (its h/ beside binl64/) unless already set. Standard library only.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import omf2elf  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler", required=True)
    ap.add_argument("--include", default="include")
    ap.add_argument("--output", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("flags", nargs="*")
    args = ap.parse_args()
    env = dict(os.environ)
    home = Path(args.compiler).resolve().parent.parent  # .../binl64/wcc386 -> the install
    if (home / "h").is_dir():
        env.setdefault("WATCOM", str(home))
        env["INCLUDE"] = os.pathsep.join(p for p in (args.include, str(home / "h"), env.get("INCLUDE", "")) if p)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        obj = Path(tmp) / "out.obj"
        run = subprocess.run([args.compiler, *args.flags, f"-i={args.include}", args.source, f"-fo={obj}"],
                             env=env, capture_output=True, text=True)
        sys.stdout.write(run.stdout)
        sys.stderr.write(run.stderr)
        if run.returncode != 0 or not obj.is_file():
            return run.returncode or 1
        try:
            elf = omf2elf.convert(obj.read_bytes())
        except omf2elf.OMFError as e:
            sys.stderr.write(f"{args.source}: Watcom's object couldn't be read: {e}\n")
            return 1
    out.write_bytes(elf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
