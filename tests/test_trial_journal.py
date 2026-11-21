"""A trial's file is put back when the process that wrote it died mid-call (trial_journal): a deep pass's lanes,
killed after a Stop, left eleven of one game's files with half a function each, none building for two hours."""
import subprocess
import sys
import textwrap

from decompnet.app import trial_journal
from decompnet.app.forkengine import _rewrite

CHILD = textwrap.dedent('''
    import os, sys
    from pathlib import Path
    from decompnet.app import trial_journal
    from decompnet.app.forkengine import _rewrite
    folder, path = Path(sys.argv[1]), Path(sys.argv[2])
    @trial_journal.journaled
    def trial():
        before = path.read_text()
        after = before + "int half_a_function(\\n"
        _rewrite(path, after)
        trial_journal.note(folder, path, before, after)
        os._exit(0)  # killed mid-trial, before the original is written back
    trial()
''')


def die_mid_trial(folder, path):
    subprocess.run([sys.executable, '-c', CHILD, str(folder), str(path)], check=True)


def test_a_dead_process_trial_is_put_back(tmp_path):
    folder, path = tmp_path / 'trials', tmp_path / 'unit.c'
    path.write_text('int f(void) { return 1; }\n')
    die_mid_trial(folder, path)
    assert 'half_a_function' in path.read_text()
    assert trial_journal.recover(folder, _rewrite) == [path]
    assert path.read_text() == 'int f(void) { return 1; }\n'
    assert not list(folder.glob('*.json')), 'the note is dropped once handled'
    assert trial_journal.recover(folder, _rewrite) == []


def test_a_file_written_since_is_left_alone(tmp_path):
    folder, path = tmp_path / 'trials', tmp_path / 'unit.c'
    path.write_text('int f(void) { return 1; }\n')
    die_mid_trial(folder, path)
    path.write_text('int f(void) { return 2; }\n')  # an agent's later edit
    assert trial_journal.recover(folder, _rewrite) == []
    assert path.read_text() == 'int f(void) { return 2; }\n'
    assert not list(folder.glob('*.json'))


def test_a_call_that_returns_or_raises_leaves_no_note(tmp_path):
    folder, path = tmp_path / 'trials', tmp_path / 'unit.c'
    path.write_text('a\n')

    @trial_journal.journaled
    def trial(fail):
        _rewrite(path, 'b\n')
        trial_journal.note(folder, path, 'a\n', 'b\n')
        assert len(list(folder.glob('*.json'))) == 1
        _rewrite(path, 'a\n')
        if fail:
            raise ValueError
    trial(False)
    try:
        trial(True)
    except ValueError:
        pass
    assert not list(folder.glob('*.json'))


def test_a_live_process_trial_is_not_touched(tmp_path):
    folder, path = tmp_path / 'trials', tmp_path / 'unit.c'
    path.write_text('a\n')

    @trial_journal.journaled
    def trial():
        _rewrite(path, 'b\n')
        trial_journal.note(folder, path, 'a\n', 'b\n')
        assert trial_journal.recover(folder, _rewrite) == []  # this process's own trial, still running
        assert path.read_text() == 'b\n'
    trial()


def test_the_manifest_is_swapped_in_whole(tmp_path):
    """A reader never finds `.decomp.wtf.json` empty or half-written (the live overview once read it mid-write)."""
    import json
    import threading

    from decompnet.forks.project import write_manifest
    big, small = {'dos_flags_map': {f'src/{i}.c': '-ox' for i in range(3000)}}, {'dos_flags': '-ox'}
    write_manifest(tmp_path, big)
    stop, bad = threading.Event(), []

    def writer(m):
        while not stop.is_set():
            write_manifest(tmp_path, m)

    def reader():
        while not stop.is_set():
            try:
                json.loads((tmp_path / '.decomp.wtf.json').read_text(encoding='utf-8'))
            except ValueError:
                bad.append(1)
    threads = [threading.Thread(target=writer, args=(m,)) for m in (big, small)] + [threading.Thread(target=reader)]
    for t in threads:
        t.start()
    threading.Event().wait(1.5)
    stop.set()
    for t in threads:
        t.join()
    assert not bad
