"""Repair handoffs after a release start at most once a gap on a project: one slot ran them back to back (181 an
hour on one game), and helpers' compiles and claims queued behind them for up to 19 minutes a call."""
import types

from decompnet.app import release_repairs


class _Jobs:
    def __init__(self):
        self.jobs, self.started = {}, []

    def start(self, kind, work, **kwargs):
        self.started.append(kind)
        jid = f"job{len(self.started)}"
        self.jobs[jid] = {"state": "running"}
        return jid


def _net():
    sweeps = types.SimpleNamespace(jobs=_Jobs(), active={})
    return types.SimpleNamespace(deep_sweeps=sweeps, links={}, project_row=lambda slug: {"id": 1})


def _fn(n):
    return {"id": n, "name": f"func_{n:08X}", "status": "open", "best_source": f"int f{n}(void) {{ return 0; }}",
            "best_score": 5, "project_id": 1}


def test_a_second_handoff_inside_the_gap_is_left_to_the_deep_pass(monkeypatch):
    from decompnet import candidate_scope, claim_stalls
    monkeypatch.setattr(candidate_scope, "key", lambda net, proj, fn: "scope")
    monkeypatch.setattr(claim_stalls, "repair_rules", lambda: ())
    clock = [1000.0]
    monkeypatch.setattr(release_repairs.time, "monotonic", lambda: clock[0])
    net = _net()
    assert "queued" in release_repairs.handoff(net, "game", _fn(1))
    said = release_repairs.handoff(net, "game", _fn(2))
    assert "skipped" in said and "next deep pass" in said
    assert "queued" in release_repairs.handoff(net, "other-game", _fn(3))  # (per project)
    clock[0] += 61
    assert "queued" in release_repairs.handoff(net, "game", _fn(4))
    assert net.deep_sweeps.jobs.started == ["CPU repair handoff"] * 3


def test_a_gap_of_zero_runs_them_as_before(monkeypatch):
    from decompnet import candidate_scope, claim_stalls
    monkeypatch.setattr(candidate_scope, "key", lambda net, proj, fn: "scope")
    monkeypatch.setattr(claim_stalls, "repair_rules", lambda: ())
    monkeypatch.setenv("DECOMP_HANDOFF_GAP_SECONDS", "0")
    net = _net()
    assert all("queued" in release_repairs.handoff(net, "game", _fn(n)) for n in (1, 2, 3))
