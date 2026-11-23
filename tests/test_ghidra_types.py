"""A project's own types reach its Ghidra drafts (forks/ghidra.decompile_object, Console.draft_types)."""
from pathlib import Path

from decompnet import consoles
from decompnet.forks import ghidra


def test_ghidra_is_given_the_types_and_its_cache_tells_them_apart(tmp_path, monkeypatch):
    obj = tmp_path / "a.o"
    obj.write_bytes(b"\x7fELF object")
    given = []

    def run(binary, script, timeout, *, extra=()):
        given.append([Path(p).read_text() for p in extra])
        return [{"name": "func_00010000", "c": f"int f(void) {{ return {len(given)}; }}"}]
    monkeypatch.setattr(ghidra, "_run_script", run)
    monkeypatch.setattr(ghidra, "available", lambda: True)
    plain = ghidra.decompile_object(obj, tmp_path / "cache")
    typed = ghidra.decompile_object(obj, tmp_path / "cache", types=("typedef int T;", {"_D_000ADF6C": "T *"}))
    assert given == [[], ["typedef int T;", "_D_000ADF6C\tT *\n"]]
    assert plain != typed  # (the types are part of the cache key: a draft without them isn't reused)
    assert ghidra.decompile_object(obj, tmp_path / "cache", types=("typedef int T;", {"_D_000ADF6C": "T *"})) == typed
    assert len(given) == 2


def test_a_console_gives_no_types_unless_it_says_so():
    assert consoles.Console().draft_types(None) is None  # (drafts as before: Ghidra without the project's types)
