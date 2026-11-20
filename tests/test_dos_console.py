"""The DOS console: what it recognises, and how its projects' symbols read as C (a synthetic LE module)."""

import json
from types import SimpleNamespace

from decompnet import consoles

from .test_le import _bound


def test_a_dos4gw_program_is_recognised_and_nothing_else_claims_it(tmp_path):
    game = tmp_path / "game.exe"
    game.write_bytes(_bound(bytes(16), []))
    assert consoles.identify(game).id == "dos"
    plain = tmp_path / "plain.exe"
    plain.write_bytes(b"MZ" + bytes(0x200))  # a 16-bit DOS program: no LE module
    assert not consoles.get("dos").sniff(plain.read_bytes()[:64], plain)


def test_watcoms_symbols_read_as_the_c_names(tmp_path):
    conf = tmp_path / "config" / "game"
    conf.mkdir(parents=True)
    (conf / "functions.json").write_text(json.dumps({"units": {"text_00010000": [
        {"name": "func_00010000", "symbol": "func_00010000_", "addr": 0x10000, "size": 8},
        {"name": "func_00010010", "symbol": "_func_00010010", "addr": 0x10010, "size": 8}]}}))
    fp = SimpleNamespace(root=tmp_path, manifest={"version": "game"})
    dos = consoles.get("dos")
    assert dos.real_names(fp, "game") == {"func_00010000_": "func_00010000", "_func_00010010": "func_00010010"}
    assert dos.function_extent(fp, "func_00010000_") == (0x10000, 8)
