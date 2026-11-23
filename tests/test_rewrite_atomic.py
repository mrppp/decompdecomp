"""Source files are written whole and swapped in (forkengine._rewrite): two writers of one file at once used to leave
NUL bytes where one truncated it and the other wrote past its new end, and the file stopped building."""

import threading

from decompnet.app.forkengine import _rewrite


def test_two_writers_never_leave_nul_bytes(tmp_path):
    path = tmp_path / "unit.c"
    long, short = "int a;\n" * 2000, "int b;\n" * 10
    path.write_text(long)
    seen, stop = [], threading.Event()

    def write(text):
        while not stop.is_set():
            _rewrite(path, text)

    def read():
        while not stop.is_set():
            data = path.read_bytes()
            seen.append(b"\0" in data or data not in (long.encode(), short.encode()))
    threads = [threading.Thread(target=write, args=(t,)) for t in (long, short)] + [threading.Thread(target=read)]
    for t in threads:
        t.start()
    threading.Event().wait(1.5)
    stop.set()
    for t in threads:
        t.join()
    assert seen and not any(seen), "a reader saw NUL bytes or a mixed file"
    assert path.read_bytes() in (long.encode(), short.encode())
    assert not list(tmp_path.glob(".*.tmp")), "no temporary file is left behind"


def test_an_unchanged_file_is_only_touched(tmp_path):
    path = tmp_path / "unit.c"
    path.write_text("int a;\n")
    inode = path.stat().st_ino
    _rewrite(path, "int a;\n")
    assert path.stat().st_ino == inode and path.read_text() == "int a;\n"

def test_a_trial_takes_out_only_its_own_change(tmp_path):
    """A trial puts back the file it changed; an edit made during the trial elsewhere in the file stays, and one that
    overlaps the trial's change gives way to the text from before the trial."""
    from decompnet.app.forkengine import _put_back
    before = "int a;\nint b;\nint c;\nint d;\nint e;\nint f;\n"
    trial = before.replace("int b;", "int b_trial;")
    path = tmp_path / "unit.c"
    _rewrite(path, trial)
    assert _put_back(path, before, trial) and path.read_text() == before
    _rewrite(path, trial.replace("int f;", "int f_helper;"))
    assert _put_back(path, before, trial) and path.read_text() == before.replace("int f;", "int f_helper;")
    _rewrite(path, trial.replace("int b_trial;", "int b_helper;"))
    assert _put_back(path, before, trial) and path.read_text() == before
