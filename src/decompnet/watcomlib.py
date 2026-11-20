"""Watcom's C library in a DOS game: which of the game's functions are the library's, and what they're called.

A game linked with Watcom carries the functions of its runtime it uses (clib3r.lib: malloc_, sopen_, printf...;
math3r.lib, math387r.lib) byte for byte, their addresses filled in. The user's own Watcom (kits/watcom.py) has those
libraries: OMF libraries (a page-aligned run of object modules, omf.py reads each), whose code segments, cut at
their public symbols, are the functions. A game function is the library's when its code, its relocated fields
masked, is a library function's (the same length, give or take the alignment padding after it), and that library
function is found in one place only (a five-byte `jmp` is every library stub's twin: such small ones are named
only by the calls below). From those, every call and data reference the library function's object names is the
game's function or data at that place: names follow outwards (`sopen_` calls `__set_errno_`: so does the game's,
and the function it calls is that), each followed function checked against its library bytes too.

What a game was linked with decides what's found: the libraries of another Watcom version mostly differ.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import omf

MIN_BYTES = 12  # a function this small or smaller is named only by a call from a sure match
PAD = 16  # the alignment padding a function may have after its library code
# the libraries a game links, by the calling convention it was built with: register (-3r to -6r) or stack (-3s to
# -6s, whose symbols are _name: a 1994 game of Bullfrog's was), its C runtime, then its maths
LIBRARIES = {
    "register": ("lib386/dos/clib3r.lib", "lib386/math3r.lib", "lib386/math387r.lib", "lib386/dos/emu387.lib"),
    "stack": ("lib386/dos/clib3s.lib", "lib386/math3s.lib", "lib386/math387s.lib", "lib386/dos/emu387.lib"),
}
ENOUGH = 20  # matches that say which Watcom (and convention) linked a game, not a coincidence of small functions


@dataclass
class LibFunction:
    name: str  # its symbol: memcpy_ (register convention), _printf (stack)
    code: bytes  # its bytes, the fields its fixups fill in zeroed
    fixed: set[int]  # where those fields start
    refs: dict[int, str] = field(default_factory=dict)  # offset -> the external symbol a fixup there names
    library: str = ""


def modules(data: bytes):
    """The object modules of an OMF library, each as its bytes (LIBHDR's page size apart; the dictionary after)."""
    if not data or data[0] != 0xF0:
        raise ValueError("not an OMF library")
    page = struct.unpack_from("<H", data, 1)[0] + 3
    at = page
    while at + 3 <= len(data) and data[at] != 0xF1:
        start = at
        while at + 3 <= len(data):
            kind, n = data[at], struct.unpack_from("<H", data, at + 1)[0]
            at += 3 + n
            if kind in (0x8A, 0x8B):  # MODEND
                break
        yield data[start:at]
        at = (at + page - 1) // page * page


def functions(data: bytes, library: str = "") -> list[LibFunction]:
    """A library's functions: each module's code segments cut at their public symbols."""
    out = []
    for raw in modules(data):
        try:
            mod = omf.parse(raw)
        except (omf.OMFError, struct.error, IndexError, ValueError):
            continue  # (a module it can't read: none of its functions are found)
        by_seg: dict[int, list[tuple[int, str]]] = {}
        for name, seg, off, _ in mod.publics:
            if isinstance(seg, int) and 0 <= seg < len(mod.segments):
                by_seg.setdefault(seg, []).append((off, name))
        for seg, pubs in by_seg.items():
            s = mod.segments[seg]
            if s.klass.upper() != "CODE":
                continue
            masked = bytearray(s.data)
            for off, *_ in s.relocs:
                masked[off:off + 4] = bytes(4)
            pubs.sort()
            for k, (off, name) in enumerate(pubs):
                end = pubs[k + 1][0] if k + 1 < len(pubs) else len(s.data)
                fixed = {o - off for o, *_ in s.relocs if off <= o < end}
                refs = {o - off: mod.externs[t[1]] for o, _, t in s.relocs
                        if off <= o < end and t[0] == "ext" and t[1] < len(mod.externs)}
                out.append(LibFunction(name, bytes(masked[off:end]), fixed, refs, library))
    return out


@dataclass
class Match:
    """Which of the user's Watcom copies, and which convention's libraries, a game's library code is."""
    folder: Path
    convention: str  # "register" or "stack"
    found: dict  # game symbol -> LibFunction
    data: dict  # data symbol -> the library's name

    @property
    def sure(self) -> bool:
        return len(self.found) >= ENOUGH


def best(fns: list[dict], code: bytes, base: int, folders: list[Path]) -> Match | None:
    """The copy and convention whose libraries the game matches most (identify), or None where none matches."""
    out = None
    for folder in folders:
        for convention in LIBRARIES:
            libs = load(folder, convention)
            if libs:
                found, data = identify(fns, code, base, libs)
                if found and (out is None or len(found) > len(out.found)):
                    out = Match(folder, convention, found, data)
    return out


def load(folder: Path, convention: str = "register") -> list[LibFunction]:
    """The functions of a Watcom copy's libraries for a convention (LIBRARIES, found ignoring case)."""
    from .kits import find

    out = []
    for rel in LIBRARIES[convention]:
        path = find(folder, rel)
        if path is not None:
            out += functions(path.read_bytes(), path.name)
    return out


def _same(game: bytes, game_fixed, lib: LibFunction) -> bool:
    """Whether a game function's code is the library function's: equal with both one's and the other's fields
    masked, and what's after it (if anything) alignment padding."""
    n = len(lib.code)
    if not 0 <= len(game) - n <= PAD:
        return False
    if any(b not in (0, 0x90, 0xCC) for b in game[n:]):
        return False
    a, b = bytearray(game[:n]), bytearray(lib.code)
    for off in (*game_fixed, *lib.fixed):
        if off < n:
            a[off:off + 4] = b[off:off + 4] = bytes(4)
    return bytes(a) == bytes(b)


def identify(fns: list[dict], code: bytes, base: int,
             libs: list[LibFunction]) -> tuple[dict[str, LibFunction], dict[str, str]]:
    """The game's functions that are library code: ({their symbol: the library function},
    {a data symbol (_D_XXXXXXXX): the library's name for it}). `fns`: functions.json's entries; `code`: the code
    object they're in, at `base`."""
    by_len: dict[int, list[LibFunction]] = {}
    by_name: dict[str, LibFunction] = {}
    for lf in libs:
        by_len.setdefault(len(lf.code), []).append(lf)
        by_name.setdefault(lf.name, lf)
    game: dict[str, tuple[bytes, set[int], dict]] = {}
    for fn in fns:
        raw = bytearray(code[fn["addr"] - base:fn["addr"] - base + fn["size"]])
        fixed = {off for off, *_ in fn["relocs"]}
        for off in fixed:
            raw[off:off + 4] = bytes(4)
        game[fn["symbol"]] = (bytes(raw), fixed, fn)
    candidates: dict[str, set[str]] = {}  # game symbol -> library names it could be
    places: dict[str, set[str]] = {}  # library name -> game symbols
    for sym, (raw, fixed, _) in game.items():
        for n in range(len(raw), max(len(raw) - PAD, MIN_BYTES) - 1, -1):
            for lf in by_len.get(n, ()):
                if _same(raw, fixed, lf):
                    candidates.setdefault(sym, set()).add(lf.name)
                    places.setdefault(lf.name, set()).add(sym)
    names = {sym: next(iter(ls)) for sym, ls in candidates.items() if len(ls) == 1 and len(places[next(iter(ls))]) == 1}
    data: dict[str, str] = {}
    todo = list(names)
    while todo:  # follow calls and data references outwards from what's sure
        sym = todo.pop()
        lf = by_name.get(names[sym])
        fn = game[sym][2]
        relocs = {off: (target, addend) for off, _, target, addend in fn["relocs"]}
        for off, ext in (lf.refs if lf else {}).items():
            target, addend = relocs.get(off, (None, 0))
            if target is None or addend:
                continue
            if target in game and target not in names and ext in by_name:
                if _same(game[target][0], game[target][1], by_name[ext]):
                    names[target] = ext
                    todo.append(target)
            elif target.startswith("_D_") and target not in data:
                data[target] = ext
    return {sym: by_name[name] for sym, name in names.items()}, data


def c_name(symbol: str) -> str:
    """A Watcom symbol as C writes it: memcpy_ (register convention) and _printf (stack, data) are memcpy, printf."""
    if symbol.endswith("_"):  # (register convention; __CommonInit_'s leading underscores are its own)
        return symbol[:-1]
    return symbol[1:] if symbol.startswith("_") else symbol
