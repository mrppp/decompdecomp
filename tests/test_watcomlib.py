"""Watcom's library found in a game (watcomlib.py): an OMF library's modules and functions, identified in a game's
code by their bytes, then by the calls of what's sure. Synthetic: no Watcom file."""

import struct

from decompnet import omf, watcomlib
from decompnet.watcomlib import LibFunction


def _record(kind: int, body: bytes) -> bytes:
    data = bytes([kind]) + struct.pack("<H", len(body) + 1) + body
    return data + bytes([(-sum(data)) & 0xFF])


def _module(name: str, code: bytes) -> bytes:
    """An Easy OMF-386 module (as Watcom 9.5 wrote them): one CODE segment, one public at its start."""
    lnames = _record(0x96, b"\0" + bytes([5]) + b"_TEXT" + bytes([4]) + b"CODE")
    segdef = _record(0x98, bytes([0xA8]) + struct.pack("<I", len(code)) + bytes([2, 3, 1]))
    pubdef = _record(0x90, bytes([0, 1, len(name)]) + name.encode() + struct.pack("<I", 0) + b"\0")
    ledata = _record(0xA0, bytes([1]) + struct.pack("<I", 0) + code)
    return (_record(0x80, bytes([len(name)]) + name.encode()) + _record(0x88, b"\x80\xaa80386") + lnames + segdef
            + pubdef + ledata + _record(0x8A, b"\0"))


def _library(mods: list[bytes], page: int = 16) -> bytes:
    out = bytearray(_record(0xF0, bytes(page - 4)))  # LIBHDR: its length gives the page size
    for m in mods:
        out += m
        out += bytes((-len(out)) % page)
    return bytes(out + bytes([0xF1]))


def test_an_easy_omf_library_reads_as_its_functions():
    body = bytes.fromhex("31c0c3") + bytes(10)  # xor eax, eax; ret; then more of it
    lib = _library([_module("zero_", body), _module("other_", b"\x90" * 20)])
    assert len(list(watcomlib.modules(lib))) == 2
    fns = {f.name: f for f in watcomlib.functions(lib, "clib3r.lib")}
    assert fns["zero_"].code == body and fns["zero_"].library == "clib3r.lib"
    mod = omf.parse(next(iter(watcomlib.modules(lib))))
    assert mod.publics[0][2] == 0, "the PUBDEF's offset is 32-bit, as the COMENT says"


def test_a_game_function_is_the_librarys_when_its_bytes_are_and_calls_name_the_rest():
    # the game: a library function (16 bytes, calling a small helper at 5), the helper (6 bytes), a game function
    sure = bytes.fromhex("5589e5e8") + bytes(4) + bytes.fromhex("5dc3") + b"\x11" * 6
    helper = bytes.fromhex("b801000000c3")
    game_fn = bytes.fromhex("b802000000c3")
    code = sure + helper + game_fn
    fns = [
        {"name": "func_00010000", "symbol": "func_00010000_", "addr": 0x10000, "size": 16,
         "relocs": [[4, 2, "func_00010010_", 0], [10, 1, "_D_00020000", 0]]},
        {"name": "func_00010010", "symbol": "func_00010010_", "addr": 0x10010, "size": 6, "relocs": []},
        {"name": "func_00010016", "symbol": "func_00010016_", "addr": 0x10016, "size": 6, "relocs": []},
    ]
    libs = [
        LibFunction("memgrab_", bytes.fromhex("5589e5e8") + bytes(4) + bytes.fromhex("5dc3") + b"\x11" * 6, {4, 10},
                    {4: "helper_", 10: "__heapbase"}, "clib3r.lib"),
        LibFunction("helper_", helper, set(), {}, "clib3r.lib"),
        LibFunction("twin_", game_fn, set(), {}, "clib3r.lib"),  # small: by its bytes alone it names nothing
    ]
    found, data = watcomlib.identify(fns, code, 0x10000, libs)
    assert {sym: lf.name for sym, lf in found.items()} == {"func_00010000_": "memgrab_", "func_00010010_": "helper_"}
    assert data == {"_D_00020000": "__heapbase"}


def test_watcoms_symbols_read_as_c():
    assert watcomlib.c_name("memcpy_") == "memcpy"
    assert watcomlib.c_name("__CommonInit_") == "__CommonInit"
    assert watcomlib.c_name("___iob") == "__iob"
