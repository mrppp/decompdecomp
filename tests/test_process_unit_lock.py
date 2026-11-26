"""A unit's lock holds across processes: the app and its permuter worker (another process with its own engine on the
same project) take turns at a file, so a repair trial is never in the file while the app measures or edits it."""
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from decompnet.app import forkengine
from decompnet.app.forkengine import _lock_file, _ProcessLock

fcntl = pytest.importorskip("fcntl")


def _hold(path, seconds):
    """Another process holding `path`'s lock for `seconds`; returns once it has it."""
    code = textwrap.dedent(f"""
        import fcntl, sys, time
        f = open({str(path)!r}, "a+b")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        print("held", flush=True)
        time.sleep({seconds})
    """)
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "held"
    return p


def test_a_unit_held_by_another_process_waits_its_turn(tmp_path):
    path = _lock_file(tmp_path, "unit-src/auto/text_00010010.c")
    path.parent.mkdir(parents=True)
    other = _hold(path, 1.0)
    try:
        start = time.monotonic()
        with _ProcessLock(path):
            waited = time.monotonic() - start
    finally:
        other.wait()
    assert waited >= 0.5  # (it waited for the other process, not just for this one's threads)


def test_the_lock_is_reentrant_and_lets_go_of_the_file_at_the_last_release(tmp_path):
    path = _lock_file(tmp_path, "unit-a")
    lock = _ProcessLock(path)
    with lock:
        with lock:  # (compile_and_diff inside a trial run: the same thread again)
            assert lock.file is not None
        assert lock.file is not None
    assert lock.file is None
    other = _hold(path, 0)  # another process gets it at once now
    other.wait()


def test_threads_of_one_process_still_take_turns(tmp_path):
    lock, inside, most = _ProcessLock(_lock_file(tmp_path, "unit-a")), [0], [0]

    def work():
        for _ in range(20):
            with lock:
                inside[0] += 1
                most[0] = max(most[0], inside[0])
                time.sleep(0.001)
                inside[0] -= 1
    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert most[0] == 1


def test_the_engines_unit_lock_is_the_projects_file_lock(tmp_path):
    engine = forkengine.ForkEngine.__new__(forkengine.ForkEngine)
    engine._mlock, engine._unit_locks = threading.Lock(), {}
    lock = engine._unit_lock({"id": 1, "root": str(tmp_path)}, "src/auto/a.c")
    assert lock is engine._unit_lock({"id": 1, "root": str(tmp_path)}, "src/auto/a.c")
    assert lock.path.parent == tmp_path / ".decomp-wtf" / "locks"
    assert engine._unit_lock({"id": 2}, "src/auto/a.c").path is None  # (no folder: the process's own lock alone)
