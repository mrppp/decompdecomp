#!/usr/bin/env python3
"""Rebuild the game's code object from the project and compare it with your copy, byte for byte.

    python tools/rebuild.py config/VERSION/functions.json build/VERSION [OUT]

Every function's code is put back at its address: from what its source file compiles to (build/VERSION/src/auto)
where that is the game's code (its C matches), else from the delinked target (build/VERSION/target): C still being
worked on doesn't make the rebuild differ, and the targets' relocations, cuts and joins are what's checked. Each relocation is filled in
with the address its symbol names: a function's (functions.json), the game's data D_XXXXXXXX's own address, a place
in the function itself. The result is compared with orig/VERSION.code.bin. A function whose C compiles longer or
shorter than the original, or calls something that isn't one of the game's symbols, comes out different. Prints a
JSON report: identical, the functions that differ, how many came from C. Standard library only.
"""

from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

R_386_32, R_386_PC32 = 1, 2
DATA = re.compile(r"_D_([0-9A-Fa-f]{8})$")


def read_elf(data: bytes) -> tuple[list[dict], list[dict]]:
    """An ELF32 relocatable object's sections ({name, data, relocs}) and symbols ({name, value, section, defined})."""
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise ValueError("not an ELF32 object")
    shoff, = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    heads = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * shentsize) for i in range(shnum)]
    names = heads[shstrndx]

    def string(table, at: int) -> str:
        start = table[4] + at
        return data[start:data.index(b"\0", start)].decode("latin-1")

    sections = [{"name": string(names, h[0]), "data": data[h[4]:h[4] + h[5]] if h[1] != 8 else b"", "relocs": []}
                for h in heads]
    symbols: list[dict] = []
    for h in heads:
        if h[1] == 2:  # SHT_SYMTAB
            strtab = heads[h[6]]
            for k in range(h[5] // 16):
                name, value, _, _, _, shndx = struct.unpack_from("<IIIBBH", data, h[4] + k * 16)
                symbols.append({"name": string(strtab, name), "value": value, "section": shndx,
                                "defined": 0 < shndx < 0xFF00})
    for h in heads:
        if h[1] == 9:  # SHT_REL
            for k in range(h[5] // 8):
                off, rinfo = struct.unpack_from("<II", data, h[4] + k * 8)
                sections[h[7]]["relocs"].append((off, rinfo & 0xFF, rinfo >> 8))
    return sections, symbols


def placed(path: Path) -> dict[str, tuple[bytes, list, list[dict], int, int]]:
    """Each function symbol an object defines -> (its section's bytes, relocations, symbols, its offset, its end)."""
    if not path.is_file():
        return {}
    sections, symbols = read_elf(path.read_bytes())
    out = {}
    for i, s in enumerate(sections):
        here = sorted((sym["value"], sym["name"]) for sym in symbols if sym["defined"] and sym["section"] == i
                      and sym["name"] and not sym["name"].startswith("."))
        for k, (value, name) in enumerate(here):
            end = here[k + 1][0] if k + 1 < len(here) else len(s["data"])
            out[name] = (s["data"], s["relocs"], symbols, value, end)
    return out


def rebuild(config: Path, build: Path, root: Path = Path(".")) -> dict:
    info = json.loads((root / config).read_text(encoding="utf-8"))
    original = (root / info["image"]).read_bytes()
    base = info["code_base"]
    image = bytearray(original)
    address = {fn["symbol"]: fn["addr"] for fns in info["units"].values() for fn in fns}
    differ, from_c, total, size = [], [], 0, 0
    for unit, fns in info["units"].items():
        compiled = placed(root / build / "src" / "auto" / f"{unit}.o")
        target = placed(root / build / "target" / f"{unit}.o")
        for fn in fns:
            total += 1
            size += fn["size"]
            want = original[fn["addr"] - base:fn["addr"] - base + fn["size"]]
            code = _placed_code(fn, compiled.get(fn["symbol"]), address)
            own = code == want
            if not own:
                code = _placed_code(fn, target.get(fn["symbol"]), address)
            if code is None:
                differ.append(fn["name"])
                continue
            image[fn["addr"] - base:fn["addr"] - base + fn["size"]] = code
            if code != want:
                differ.append(fn["name"])
            elif own:
                from_c.append(fn["name"])
    return {"identical": not differ and bytes(image) == original, "differ": differ, "c": from_c,
            "functions": total, "bytes": size, "size": len(original), "image": bytes(image)}


def _placed_code(fn: dict, found, address: dict[str, int]) -> bytes | None:
    """A function's code from an object, its relocations filled in for its address; None where it isn't there, its
    size isn't the function's, or it refers to something that isn't one of the game's symbols."""
    if found is None or found[4] - found[3] != fn["size"]:
        return None
    data, relocs, symbols, start, end = found
    code = bytearray(data[start:end])
    for off, rtype, k in relocs:
        if not start <= off < end:
            continue
        sym = symbols[k] if k < len(symbols) else {"name": ""}
        name = sym["name"]
        if name in address:
            s = address[name]
        elif m := DATA.fullmatch(name):
            s = int(m.group(1), 16)
        elif sym.get("defined"):  # a place in the object itself: this function's section, relative to it
            s = fn["addr"] - start + sym["value"]
        else:
            return None
        at = off - start
        addend, = struct.unpack_from("<i", code, at)
        value = s + addend - (fn["addr"] + at if rtype == R_386_PC32 else 0)
        struct.pack_into("<I", code, at, value & 0xFFFFFFFF)
    return bytes(code)


def main() -> None:
    report = rebuild(Path(sys.argv[1]), Path(sys.argv[2]))
    if len(sys.argv) > 3:
        Path(sys.argv[3]).write_bytes(report["image"])
    print(json.dumps({k: v for k, v in report.items() if k != "image"}, indent=1))
    sys.exit(0 if report["identical"] else 1)


if __name__ == "__main__":
    main()
