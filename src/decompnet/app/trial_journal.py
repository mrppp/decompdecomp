"""Source a trial wrote into a project's file, put back when the process that wrote it died before it could.

A compile writes its C into the unit's file, builds, then writes the original back (forkengine). A process stopped
in between left its trial in the file: a deep pass's lanes, killed when they hadn't wound down 40 seconds after a
Stop with their builds queued behind sixteen helpers', left eleven of one game's files with half a function each
and no declarations, and every function in those files failed to build for two hours until they were found.

Each trial notes the file, the original's text and a digest of what it wrote, under the home's .decomp/trials, and
drops the note when its call returns. `recover` (at start, and when a deep pass's lanes close) puts the original
back where the note's process is gone and the file still holds exactly what that trial wrote; a file anything has
written since is left alone.
"""
from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path

log = logging.getLogger('decompdecomp')
_local = threading.local()
_dirs: set[Path] = set()  # the journals of this process's engines (one home in the app, a test's in tests)
CONTENT_DAYS = 2  # an original nothing refers to is kept this long (a trial may still be writing its note)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _started(pid: int) -> str:
    """When the process began (Linux: clock ticks since boot), so a reused pid isn't taken for the writer."""
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return ''


def _alive(pid: int, started: str) -> bool:
    if pid == os.getpid():
        return True  # (this process's own notes are live trials, or calls that are about to drop them)
    if os.name == 'nt':
        return True  # (no cheap check: notes stay until the writer's own call drops them)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return not started or _started(pid) in ('', started)


_SELF = (os.getpid(), _started(os.getpid()))


def note(folder: Path, path: Path, before: str, after: str) -> None:
    """Record a trial just written to `path` (its original `before`, its own text `after`), for this call."""
    stack = getattr(_local, 'stack', None)
    if stack is None:
        return  # (outside a journaled call: nothing would drop the note)
    try:
        folder.mkdir(parents=True, exist_ok=True)
        _dirs.add(folder)
        original = before.replace('\n', os.linesep).encode('utf-8')
        key = _digest(original)
        content = folder / f'{key}.orig'
        if not content.exists():
            tmp = folder / f'.{key}.{uuid.uuid4().hex}.tmp'
            tmp.write_bytes(original)
            os.replace(tmp, content)
        else:
            os.utime(content)
        entry = folder / f'{os.getpid()}-{uuid.uuid4().hex}.json'
        entry.write_text(json.dumps({'path': str(path), 'before': key,
                                     'after': _digest(after.replace('\n', os.linesep).encode('utf-8')),
                                     'pid': _SELF[0], 'started': _SELF[1]}), encoding='utf-8')
        stack.append(entry)
    except OSError as error:
        log.warning('trial journal: could not note %s: %s', path, error)


def journaled(method):
    """The notes a call takes are dropped when it returns or raises: only a process that dies mid-call leaves one."""
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        stack = getattr(_local, 'stack', None)
        if stack is None:
            stack = _local.stack = []
        mark = len(stack)
        try:
            return method(*args, **kwargs)
        finally:
            for entry in stack[mark:]:
                try:
                    entry.unlink(missing_ok=True)
                except OSError:
                    pass
            del stack[mark:]
    return wrapper


def recover(folder: Path, rewrite) -> list[Path]:
    """Put back the originals of trials whose process died mid-call; `rewrite(path, text)` writes a file whole.
    Returns the files restored."""
    restored = []
    try:
        entries = sorted(folder.glob('*.json'))
    except OSError:
        return restored
    for entry in entries:
        try:
            data = json.loads(entry.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue  # (being written)
        if _alive(int(data.get('pid', 0)), str(data.get('started', ''))):
            continue
        claim = entry.with_name(f'{entry.name}.{os.getpid()}.claim')
        try:
            os.replace(entry, claim)  # one recoverer per note, when the app and a lane look at once
        except OSError:
            continue
        try:
            path = Path(data['path'])
            original = folder / f"{data['before']}.orig"
            if path.is_file() and original.is_file() and _digest(path.read_bytes()) == data['after']:
                rewrite(path, original.read_bytes().decode('utf-8').replace(os.linesep, '\n'))
                restored.append(path)
                log.warning('trial journal: put back %s, which kept the trial of a process that stopped mid-call',
                            path)
        except (OSError, KeyError, UnicodeDecodeError) as error:
            log.warning('trial journal: could not put back %s: %s', data.get('path'), error)
        finally:
            claim.unlink(missing_ok=True)
    referenced = set()
    for entry in folder.glob('*.json'):
        try:
            referenced.add(json.loads(entry.read_text(encoding='utf-8'))['before'])
        except (OSError, ValueError, KeyError):
            return restored  # (a note being written: leave the originals until next time)
    cutoff = time.time() - CONTENT_DAYS * 86400
    for content in folder.glob('*.orig'):
        try:
            if content.stem not in referenced and content.stat().st_mtime < cutoff:
                content.unlink()
        except OSError:
            pass
    return restored
