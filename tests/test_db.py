import sqlite3

import pytest

from yemu.storage.db import SCHEMA_VERSION, Database


def _legacy_db(path):
    """A database as created by YEMU before schema versioning."""
    c = sqlite3.connect(path)
    c.execute(
        "CREATE TABLE samples (id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, md5 TEXT, filename TEXT, "
        "file_type TEXT, size_bytes INTEGER, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    )
    c.execute(
        "CREATE TABLE analyses (id INTEGER PRIMARY KEY, sample_id INTEGER, started_at TIMESTAMP, "
        "finished_at TIMESTAMP, threat_score INTEGER, verdict TEXT, yara_matches TEXT, report_json TEXT)"
    )
    c.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, analysis_id INTEGER, event_type TEXT, "
        "timestamp REAL, severity TEXT, details TEXT)"
    )
    c.execute("INSERT INTO samples (sha256, filename) VALUES ('abc', 'old.bin')")
    c.execute(
        "INSERT INTO analyses (sample_id, started_at, finished_at, verdict) "
        "VALUES (1, '2026-01-01', '2026-01-01', 'clean')"
    )
    c.execute("INSERT INTO analyses (sample_id, started_at) VALUES (1, '2026-01-02')")
    c.commit()
    c.close()


@pytest.mark.asyncio
async def test_legacy_database_is_migrated(tmp_path):
    path = tmp_path / "legacy.db"
    _legacy_db(path)
    db = Database(path)
    await db.connect()
    try:
        assert await db.schema_version() == SCHEMA_VERSION
        rows = await db.get_recent_analyses()
        status = {r["id"]: r["status"] for r in rows}
        assert status == {1: "completed", 2: "interrupted"}
    finally:
        await db.close()

    # reconnecting must not re-run migrations
    db = Database(path)
    await db.connect()
    assert await db.schema_version() == SCHEMA_VERSION
    await db.close()


@pytest.mark.asyncio
async def test_bulk_events_and_status(tmp_path):
    db = Database(tmp_path / "new.db")
    await db.connect()
    try:
        sid = await db.add_sample("h", "m", "s.bin", "unknown", 3)
        aid = await db.create_analysis(sid, "2026-01-01 00:00:00", guest_os="vm", snapshot="clean-baseline")
        await db.add_events(aid, [("file", 2.0, "INFO", {"path": "/b"}), ("file", 1.0, "INFO", {"path": "/a"})])
        await db.update_analysis(aid, status="failed", error="boom", scoring={"yara_match": 40})
        details = await db.get_analysis_details(aid)
        assert (details["status"], details["error"], details["guest_os"]) == ("failed", "boom", "vm")
        events = await db.get_analysis_events(aid)
        assert [e["timestamp"] for e in events] == [1.0, 2.0]
    finally:
        await db.close()
