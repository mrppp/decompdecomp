"""A helper's own OpenCode database starts with the user's sign-ins, not the user's conversation history.

OpenCode 2 keeps provider sign-ins in its database, so a helper's database is seeded from the user's. A user's
database is mostly session history (several GB on a busy desktop): copying it whole gave every new helper its own
multi-GB copy of conversations it has no use for.
"""

import sqlite3
from pathlib import Path

import pytest

from decompnet.agents import opencode

SCHEMA = """
CREATE TABLE project (id TEXT PRIMARY KEY, path TEXT NOT NULL);
CREATE TABLE credential (id TEXT PRIMARY KEY, provider TEXT NOT NULL, secret TEXT NOT NULL);
CREATE TABLE migration (name TEXT PRIMARY KEY);
CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT REFERENCES project(id) ON DELETE CASCADE);
CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT REFERENCES session(id) ON DELETE CASCADE);
CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT REFERENCES message(id) ON DELETE CASCADE, data BLOB);
CREATE TABLE session_v2 (id TEXT PRIMARY KEY, project_id TEXT REFERENCES project(id) ON DELETE CASCADE);
CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT REFERENCES session_v2(id) ON DELETE CASCADE,
                              data BLOB);
CREATE TABLE added_by_a_later_opencode (id TEXT PRIMARY KEY, session_id TEXT REFERENCES session_v2(id));
CREATE INDEX part_message_idx ON part (message_id);
CREATE INDEX credential_provider_idx ON credential (provider);
"""
HISTORY = ("session", "message", "part", "session_v2", "session_message", "added_by_a_later_opencode")


@pytest.fixture
def user_database(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "user" / "opencode.db"
    path.parent.mkdir()
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA)
        db.execute("PRAGMA user_version = 7")
        db.execute("INSERT INTO project VALUES ('prj1', '/home/someone/game')")
        db.executemany("INSERT INTO credential VALUES (?, ?, ?)",
                       [("c1", "opencode-go", "key-one"), ("c2", "nvidia", "key-two")])
        db.executemany("INSERT INTO migration VALUES (?)", [("0001_init",), ("0002_sessions",)])
        db.execute("INSERT INTO kv VALUES ('theme', 'dark')")
        db.execute("INSERT INTO session VALUES ('s1', 'prj1')")
        db.execute("INSERT INTO message VALUES ('m1', 's1')")
        db.execute("INSERT INTO session_v2 VALUES ('v1', 'prj1')")
        db.execute("INSERT INTO added_by_a_later_opencode VALUES ('x1', 'v1')")
        # Two megabytes of conversation, the bulk of the file as in a real user's database.
        db.executemany("INSERT INTO part VALUES (?, 'm1', ?)", [(f"p{i}", bytes(100_000)) for i in range(10)])
        db.executemany("INSERT INTO session_message VALUES (?, 'v1', ?)",
                       [(f"sm{i}", bytes(100_000)) for i in range(10)])
    db.close()
    monkeypatch.setenv("OPENCODE_DB", str(path))
    return path


def rows(path: Path, query: str) -> list[tuple]:
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return db.execute(query).fetchall()
    finally:
        db.close()


def seed(tmp_path: Path) -> Path:
    target = tmp_path / "helper" / "opencode.db"
    target.parent.mkdir(exist_ok=True)
    opencode.Opencode().seed_database(target)
    return target


def test_helper_keeps_the_users_provider_sign_ins(user_database, tmp_path):
    target = seed(tmp_path)
    assert rows(target, "SELECT id, provider, secret FROM credential ORDER BY id") == [
        ("c1", "opencode-go", "key-one"), ("c2", "nvidia", "key-two")]


def test_helper_keeps_settings_and_applied_migrations(user_database, tmp_path):
    target = seed(tmp_path)
    assert rows(target, "SELECT name FROM migration ORDER BY name") == [("0001_init",), ("0002_sessions",)]
    assert rows(target, "SELECT key, value FROM kv") == [("theme", "dark")]
    assert rows(target, "SELECT id, path FROM project") == [("prj1", "/home/someone/game")]
    assert rows(target, "PRAGMA user_version") == [(7,)]


@pytest.mark.parametrize("table", HISTORY)
def test_helper_gets_none_of_the_users_conversations(user_database, tmp_path, table):
    """Sessions, and every table that hangs off one directly or through another, even one a later OpenCode adds."""
    target = seed(tmp_path)
    assert rows(target, f"SELECT count(*) FROM {table}") == [(0,)]


def test_helper_database_has_the_users_whole_schema(user_database, tmp_path):
    target = seed(tmp_path)
    schema = "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
    assert rows(target, schema) == rows(user_database, schema)


def test_helper_database_is_a_fraction_of_a_history_heavy_users(user_database, tmp_path):
    target = seed(tmp_path)
    assert user_database.stat().st_size > 2_000_000
    assert target.stat().st_size < 200_000


def test_existing_helper_database_is_left_alone(user_database, tmp_path):
    target = tmp_path / "helper" / "opencode.db"
    target.parent.mkdir()
    target.write_bytes(b"the helper's own sessions")
    opencode.Opencode().seed_database(target)
    assert target.read_bytes() == b"the helper's own sessions"


def test_no_user_database_means_no_helper_database(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENCODE_DB", str(tmp_path / "absent.db"))
    target = seed(tmp_path)
    assert not target.exists()


def test_unreadable_user_database_leaves_nothing_behind(tmp_path, monkeypatch):
    broken = tmp_path / "broken.db"
    broken.write_bytes(b"this is not a database at all" * 100)
    monkeypatch.setenv("OPENCODE_DB", str(broken))
    target = seed(tmp_path)
    assert list(target.parent.iterdir()) == []  # the session then starts empty, as before


def outgrown(tmp_path: Path, monkeypatch) -> Path:
    """A helper database past the size limit, with OpenCode's write-ahead files beside it."""
    monkeypatch.setattr(opencode, "HELPER_DATABASE_LIMIT", 1000)
    target = tmp_path / "helper" / "opencode.db"
    target.parent.mkdir()
    target.write_bytes(b"x" * 5000)
    for suffix in ("-wal", "-shm"):
        target.with_name(target.name + suffix).write_bytes(b"old")
    return target


def test_outgrown_helper_database_starts_again_from_the_users_sign_ins(user_database, tmp_path, monkeypatch):
    target = outgrown(tmp_path, monkeypatch)
    opencode.Opencode().seed_database(target)
    assert rows(target, "SELECT provider FROM credential ORDER BY id") == [("opencode-go",), ("nvidia",)]
    assert rows(target, "SELECT count(*) FROM session_message") == [(0,)]
    # The old database's write-ahead files would be replayed into the new one.
    assert sorted(p.name for p in target.parent.iterdir()) == ["opencode.db"]


def test_helper_database_at_the_limit_keeps_its_own_sessions(user_database, tmp_path, monkeypatch):
    monkeypatch.setattr(opencode, "HELPER_DATABASE_LIMIT", 5000)
    target = tmp_path / "helper" / "opencode.db"
    target.parent.mkdir()
    target.write_bytes(b"x" * 5000)
    opencode.Opencode().seed_database(target)
    assert target.read_bytes() == b"x" * 5000


def test_outgrown_helper_database_is_kept_when_there_is_nothing_to_start_from(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENCODE_DB", str(tmp_path / "absent.db"))
    target = outgrown(tmp_path, monkeypatch)
    opencode.Opencode().seed_database(target)
    assert target.read_bytes() == b"x" * 5000


def test_outgrown_helper_database_is_kept_when_the_users_cannot_be_read(tmp_path, monkeypatch):
    broken = tmp_path / "broken.db"
    broken.write_bytes(b"this is not a database at all" * 100)
    monkeypatch.setenv("OPENCODE_DB", str(broken))
    target = outgrown(tmp_path, monkeypatch)
    opencode.Opencode().seed_database(target)
    assert target.read_bytes() == b"x" * 5000
    assert sorted(p.name for p in target.parent.iterdir()) == ["opencode.db", "opencode.db-shm", "opencode.db-wal"]

