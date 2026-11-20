"""What a DOS project's config holds, and the edits the app makes to it: names, source files, joins, flags.

config/VERSION/functions.json is the project's account of the game: every function's address, size, Watcom symbol,
convention and relocations, by source file ("units"), and the real names polishing gave (its "names": func_XXXXXXXX
or D_XXXXXXXX -> a name). The target objects keep the address symbols (func_XXXXXXXX_, _D_XXXXXXXX), and
tools/compile.py gives a compiled object's renamed symbols those back (names_for_build), so objdiff still pairs a
renamed function with the original, and every call to it. The manifest's "dos_flags_map" holds a source file's own
Watcom flags, which tools/configure.py builds it with.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ...forks.project import ForkError

ADDRESS = re.compile(r"_?(func|D)_([0-9A-Fa-f]{8})_?(?:@\d+)?$")  # func_0001A2B0(_), _func_...(@8), D_..., _D_...


def config_path(root: Path, version: str) -> Path:
    return root / "config" / version / "functions.json"


def load(root: Path, version: str) -> tuple[Path, str, dict]:
    path = config_path(root, version)
    text = path.read_text(encoding="utf-8")
    return path, text, json.loads(text)


def save(path: Path, info: dict) -> None:
    path.write_text(json.dumps(info, indent=1), encoding="utf-8")


def address_key(name: str) -> str | None:
    """func_XXXXXXXX or D_XXXXXXXX for a symbol however it's spelt (Watcom's or C's), or None."""
    m = ADDRESS.fullmatch(name)
    return f"{m.group(1)}_{m.group(2).upper()}" if m else None


def _functions(info: dict):
    for unit, fns in info["units"].items():
        for fn in fns:
            yield unit, fn


def _find(info: dict, name: str):
    """(unit, function) by its C name, Watcom symbol or real name, else (None, None)."""
    real = {v: k for k, v in (info.get("names") or {}).items()}
    key = address_key(name) or real.get(name)
    for unit, fn in _functions(info):
        if name in (fn["name"], fn["symbol"]) or key == fn["name"]:
            return unit, fn
    return None, None


def rename(root: Path, version: str, old: str, new: str) -> dict:
    """Give `old` (a function or data, by any spelling, or a real name given before) the real name `new`."""
    if not re.fullmatch(r"[A-Za-z_]\w*", new):
        raise ForkError(f"{new} isn't a C name")
    path, text, info = load(root, version)
    names = dict(info.get("names") or {})
    key = address_key(old) or next((k for k, v in names.items() if v == old), None)
    if key is None or (key.startswith("func_") and _find(info, key)[1] is None):
        raise ForkError(f"{old} isn't one of the game's functions or data (func_<address>, D_<address>)")
    if names.get(key) == new:
        return {}
    if new in names.values() or address_key(new):
        raise ForkError(f"{new} names another of the game's symbols already: pick another name")
    names[key] = new
    save(path, {**info, "names": dict(sorted(names.items()))})
    return {path: text}


def names_for_build(info: dict) -> dict[str, str]:
    """{the symbol Watcom gives a real name: the address symbol the targets have}: what compile.py renames back.
    A function's symbol says how Watcom spells it (register: name_, __cdecl: _name, __stdcall: _name@8); data is
    _name."""
    out = {}
    symbols = {fn["name"]: fn["symbol"] for _, fn in _functions(info)}
    for key, real in (info.get("names") or {}).items():
        if key in symbols:  # (its symbol spells the name as its convention does: name_, _name, _name@8)
            out[symbols[key].replace(key, real)] = symbols[key]
        elif key.startswith("D_"):
            out[f"_{real}"] = f"_{key}"
    return out


def split(root: Path, version: str, source: str, at: str, new: str) -> dict:
    """Divide `source`'s unit at function `at`: it and those after it go to `new`'s, right after it."""
    path, text, info = load(root, version)
    unit = next((u for u in info["units"] if f"src/auto/{u}.c" == source), None)
    if unit is None:
        raise ForkError(f"{source} isn't one of the project's source files")
    m = re.fullmatch(r"src/auto/([A-Za-z0-9_]+)\.c", new)
    if m is None:
        raise ForkError(f"{new}: name it src/auto/<name>.c (letters, digits, _)")
    if m.group(1) in info["units"]:
        raise ForkError(f"{new} exists already: pick another new_name")
    fns = info["units"][unit]
    k = next((i for i, fn in enumerate(fns) if at in (fn["name"], fn["symbol"])), None)
    if not k:
        raise ForkError(f"{at} isn't one of {source}'s functions after its first")
    units = {}
    for u, group in info["units"].items():
        units[u] = group[:k] if u == unit else group
        if u == unit:
            units[m.group(1)] = group[k:]
    save(path, {**info, "units": units})
    return {path: text}


def join(root: Path, version: str, first: str, last: str, keep: set[str]) -> str:
    """Make one function of `first` to `last` (neighbours in one source file, none of them matched): its size
    reaches the last one's end, calls between them become its own branches, and a reference from elsewhere to a
    later one names the joined function, that far in."""
    path, _, info = load(root, version)
    unit, a = _find(info, first)
    unit_b, b = _find(info, last)
    if a is None or b is None or unit != unit_b:
        raise ForkError(f"{first} and {last} aren't functions of one source file")
    fns = info["units"][unit]
    i, j = fns.index(a), fns.index(b)
    if j <= i:
        raise ForkError(f"{last} doesn't come after {first}")
    joined = fns[i:j + 1]
    if any({fn["name"], fn["symbol"]} & keep for fn in joined):
        raise ForkError("a matched function can't be joined: its C would no longer be the whole function")
    gone = {fn["symbol"]: fn["addr"] for fn in joined[1:]}
    lo, hi = a["addr"], b["addr"] + b["size"]
    relocs = []
    for fn in joined:
        shift = fn["addr"] - lo
        for off, rtype, name, addend in fn["relocs"]:
            if name in gone or name == a["symbol"]:
                target = (gone.get(name, lo)) + addend
                if rtype == 2:  # a call or jump into the joined function: its own branch, no relocation
                    continue
                relocs.append([off + shift, rtype, None, target - lo])
            elif name is None:
                relocs.append([off + shift, rtype, None, addend + shift])
            else:
                relocs.append([off + shift, rtype, name, addend])
    merged = {**a, "size": hi - lo, "relocs": sorted(relocs)}
    info["units"][unit] = fns[:i] + [merged] + fns[j + 1:]
    for _, fn in _functions(info):  # elsewhere: a later piece's symbol names the joined function, that far in
        fn["relocs"] = [[off, rtype, a["symbol"], gone[name] - lo + addend] if name in gone else [off, rtype, name, addend]
                        for off, rtype, name, addend in fn["relocs"]]
    save(path, info)
    return f"{a['name']} now runs to 0x{hi:08X}, joining {', '.join(fn['name'] for fn in joined[1:])}"


def cut(root: Path, version: str, symbol: str, at: int, keep: set[str], why: str = "") -> str:
    """End `symbol`'s function at address `at`: the rest becomes a function of its own (func_<at>, in the same
    source file, right after it, with the relocations that fall in it), set aside when agents said it isn't code."""
    path, _, info = load(root, version)
    unit, fn = _find(info, symbol)
    if fn is None:
        raise ForkError(f"{symbol} isn't one of the game's functions")
    if {fn["name"], fn["symbol"]} & keep:
        raise ForkError(f"{fn['name']} matches: its C is the whole function, so it can't be cut")
    if not fn["addr"] < at < fn["addr"] + fn["size"]:
        raise ForkError(f"0x{at:08X} isn't inside {fn['name']} (0x{fn['addr']:08X}-0x{fn['addr'] + fn['size']:08X})")
    k = at - fn["addr"]
    name = f"func_{at:08X}"
    rest = {"name": name, "symbol": f"{name}_", "convention": "register", "addr": at, "size": fn["size"] - k,
            "relocs": []}
    kept = []
    for off, rtype, target, addend in fn["relocs"]:
        if off >= k:  # its own now; a label in the old function is the old function's, by name
            if target is None:
                target_at = fn["addr"] + addend
                if target_at >= at:
                    rest["relocs"].append([off - k, rtype, None, target_at - at])
                else:
                    rest["relocs"].append([off - k, rtype, fn["symbol"], addend])
            else:
                rest["relocs"].append([off - k, rtype, target, addend])
        elif target is None and fn["addr"] + addend >= at:
            kept.append([off, rtype, rest["symbol"], fn["addr"] + addend - at])
        else:
            kept.append([off, rtype, target, addend])
    if why:
        rest["set_aside"] = why
    group = info["units"][unit]
    i = group.index(fn)
    group[i] = {**fn, "size": k, "relocs": kept}
    group.insert(i + 1, rest)
    for _, other in _functions(info):  # elsewhere: a reference into the cut-off part names it
        if other is rest or other is group[i]:
            continue
        other["relocs"] = [[off, rtype, rest["symbol"], fn["addr"] + addend - at]
                           if target == fn["symbol"] and fn["addr"] + addend >= at else [off, rtype, target, addend]
                           for off, rtype, target, addend in other["relocs"]]
    save(path, info)
    return f"{fn['name']} now ends at 0x{at:08X}; {name} is a function of its own" + (f" ({why})" if why else "")


def flags_of(manifest: dict, source: str) -> list[str] | None:
    """A source file's own Watcom flags (the manifest's dos_flags_map), [] when it builds with the project's."""
    own = (manifest.get("dos_flags_map") or {}).get(source)
    return own.split() if own else []


def ranges(root: Path, version: str) -> dict[str, list[tuple[int, int]]]:
    _, _, info = load(root, version)
    return {f"src/auto/{u}.c": [(fns[0]["addr"], fns[-1]["addr"] + fns[-1]["size"])] for u, fns in info["units"].items()
            if fns}


_STRUCTS: dict = {}


def structs(root: Path, version: str):
    """The struct layouts every function's code shows (structs.recover over arch/x86_fields.py), each function read
    in its own convention (Watcom's registers, or the stack), with every name agents know its functions by. Cached
    by the config's and image's times; reading them is most of the time."""
    from ... import structs as structs_mod
    from ...arch import x86_fields

    path = config_path(root, version)
    _, _, info = load(root, version)
    image = root / info["image"]
    key = (str(path), path.stat().st_mtime_ns, image.stat().st_mtime_ns)
    if key in _STRUCTS:
        return _STRUCTS[key]
    code = image.read_bytes()
    base = info["code_base"]
    real = info.get("names") or {}
    fns = [fn for _, fn in _functions(info)]
    stack = {fn["addr"] for fn in fns if fn.get("convention") == "stack"}

    def read(addr: int, body: bytes, relocs: list, datum) -> structs_mod.Facts:
        abi = None if addr in stack else x86_fields.WATCOM
        return x86_fields.read_facts(addr, body, relocs, datum=datum, abi=abi)

    from ... import le
    try:
        exe = next((root / "orig").glob("*.exe"))
        spans = [(o.base, o.base + o.size) for o in le.parse(exe.read_bytes()).objects if not o.executable]
    except (StopIteration, OSError, le.LEError):
        spans = []

    def datum(addr: int) -> int | None:  # an address in the game's data objects is a datum of its own (D_<address>)
        return addr if any(lo <= addr < hi for lo, hi in spans) else None
    layouts = structs_mod.recover(((fn["addr"], code[fn["addr"] - base:fn["addr"] - base + fn["size"]], [])
                                   for fn in fns), read, datum)
    layouts.first_is_this = True  # (Watcom's eax: arg0 and `this` both)
    symbols: dict[str, int] = {}
    labels: dict[int, str] = {}
    for fn in fns:
        label = real.get(fn["name"], fn["name"])
        labels[fn["addr"]] = label
        for name in (fn["name"], fn["symbol"], label):
            symbols[name] = fn["addr"]
    data = {int(k[2:], 16): v for k, v in real.items() if k.startswith("D_")}
    layouts.labels, layouts.symbols = {**data, **labels}, symbols
    _STRUCTS.clear()
    _STRUCTS[key] = layouts
    return layouts
