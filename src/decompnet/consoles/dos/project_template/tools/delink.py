#!/usr/bin/env python3
"""Cut the game's functions out of your copy into one ELF32 object per source file, for objdiff.

    python tools/delink.py config/VERSION/functions.json OUT_DIR

functions.json (written by decompdecomp from the game's LE module) gives each function's address, size, symbol and
relocations: every address the game's loader fixes up, and every call out of the function, become relocations as
in a compiled object, so a function matches whatever names the C uses. Each function gets a section of its own.
The bytes come from orig/VERSION.code.bin, the game's code object as loaded (its SHA-1 is checked). Standard
library only.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import omf2elf  # noqa: E402


def elf(functions: list[dict], code: bytes, base: int) -> bytes:
    segments, publics, externs = [], [], []
    for i, fn in enumerate(functions):
        data = bytearray(code[fn["addr"] - base:fn["addr"] - base + fn["size"]])
        seg = omf2elf.Segment(f"_TEXT_{fn['symbol']}", "CODE", fn["size"], 16, data)
        for off, rtype, name, addend in fn["relocs"]:
            value = addend - 4 if rtype == omf2elf.R_386_PC32 else addend
            struct.pack_into("<i" if value < 0 else "<I", data, off, value)
            if name is None:
                seg.relocs.append((off, rtype, ("seg", i)))
                continue
            if name not in externs:
                externs.append(name)
            seg.relocs.append((off, rtype, ("ext", externs.index(name))))
        segments.append(seg)
        publics.append((fn["symbol"], i, 0, True))
    return omf2elf.to_elf(omf2elf.Module(segments, publics, externs))


def main() -> None:
    config, out = Path(sys.argv[1]), Path(sys.argv[2])
    info = json.loads(config.read_text(encoding="utf-8"))
    code = Path(info["image"]).read_bytes()
    if hashlib.sha1(code).hexdigest() != info["sha1"]:
        sys.exit(f"{info['image']} isn't the copy this project was made from (its SHA-1 should be {info['sha1']})")
    out.mkdir(parents=True, exist_ok=True)
    for unit, functions in info["units"].items():
        obj = elf(functions, code, info["code_base"])
        path = out / f"{unit}.o"
        if not path.exists() or path.read_bytes() != obj:  # unchanged objects keep their time: nothing rebuilds
            path.write_bytes(obj)


if __name__ == "__main__":
    main()
