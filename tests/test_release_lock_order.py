"""A release from inside the release tool's project lock never compiles: the tool left the function's best state
itself, before that lock (tools.py). A second leave_best under it took the source tree after the project lock, the
opposite of every compile's order, and two of a game's helpers deadlocked for ten hours."""

from types import SimpleNamespace
from unittest import mock

from decompnet.app import forkengine
from decompnet.app.forkengine import _BEST_LEFT, ForkEngine


def _release(left: bool) -> int:
    calls = []
    fake = SimpleNamespace(_fn=lambda slug, f: {"name": f}, net=SimpleNamespace(links={}),
                           leave_best=lambda *a: calls.append(a))
    token = _BEST_LEFT.set(left)
    try:
        with mock.patch.object(forkengine.Network, "release", return_value="released"):
            assert ForkEngine.release.__wrapped__(fake, None, "game", "func_00010000", "notes") == "released"
    finally:
        _BEST_LEFT.reset(token)
    return len(calls)


def test_the_release_tools_lock_means_no_second_leave_best():
    assert _release(left=False) == 1  # (a release from elsewhere leaves the best state itself)
    assert _release(left=True) == 0
