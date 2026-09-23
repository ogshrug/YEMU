import json
import logging
from datetime import datetime

import aiosqlite

from yemu import paths

SCHEMA_VERSION = 2

# (version, statements). Never edit a released migration; append a new one.
MIGRATIONS = [
    (
        1,
        [
            """CREATE TABLE IF NOT EXISTS samples (
              id INTEGER PRIMARY KEY,
              sha256 TEXT UNIQUE,
              md5 TEXT,
              filename TEXT,
              file_type TEXT,
              size_bytes INTEGER,
              first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS analyses (
              id INTEGER PRIMARY KEY,
              sample_id INTEGER REFERENCES samples(id),
              started_at TIMESTAMP,
              finished_at TIMESTAMP,
              threat_score INTEGER,
              verdict TEXT,
              yara_matches TEXT,
              report_json TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY,
              analysis_id INTEGER REFERENCES analyses(id),
              event_type TEXT,
              timestamp REAL,
              severity TEXT,
              details TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS iocs (
              id INTEGER PRIMARY KEY,
              analysis_id INTEGER REFERENCES analyses(id),
              ioc_type TEXT,
              value TEXT,
              confidence INTEGER
            )""",
        ],
    ),
    (
        2,
        [
            "ALTER TABLE analyses ADD COLUMN status TEXT",
            "ALTER TABLE analyses ADD COLUMN error TEXT",
            "ALTER TABLE analyses ADD COLUMN guest_os TEXT",
            "ALTER TABLE analyses ADD COLUMN snapshot TEXT",
            "ALTER TABLE analyses ADD COLUMN scoring TEXT",
            "UPDATE analyses SET status = CASE WHEN finished_at IS NULL THEN 'interrupted' ELSE 'completed' END",
            "CREATE INDEX IF NOT EXISTS idx_events_analysis ON events(analysis_id)",
            "CREATE INDEX IF NOT EXISTS idx_analyses_started ON analyses(started_at)",
        ],
    ),
]


def _ts(value):
    # store timestamps as text ourselves: sqlite3's implicit datetime adapter is deprecated
    return str(value) if isinstance(value, datetime) else value


class Database:
    def __init__(self, db_path=None):
        self.db_path = str(db_path or paths.db_path())
        self.conn = None
        self.logger = logging.getLogger(__name__)

    async def connect(self):
        try:
            self.conn = await aiosqlite.connect(self.db_path)
            self.conn.row_factory = aiosqlite.Row
            await self.conn.execute("PRAGMA journal_mode=WAL")  # GUI and CLI can share the DB
            await self.conn.execute("PRAGMA busy_timeout=5000")
            await self._migrate()
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            raise

    async def _migrate(self):
        """Apply MIGRATIONS newer than PRAGMA user_version, each in its own transaction."""
        assert self.conn is not None
        version = await self.schema_version()
        for target, statements in MIGRATIONS:
            if target <= version:
                continue
            try:
                for stmt in statements:
                    await self.conn.execute(stmt)
                await self.conn.execute(f"PRAGMA user_version = {target}")
                await self.conn.commit()
                self.logger.info(f"Database migrated to schema v{target}")
            except Exception:
                await self.conn.rollback()
                raise

    async def schema_version(self):
        assert self.conn is not None
        async with self.conn.execute("PRAGMA user_version") as cur:
            return (await cur.fetchone())[0]

    async def add_sample(self, sha256, md5, filename, file_type, size_bytes):
        if not self.conn:
            return None
        try:
            async with self.conn.execute(
                "INSERT OR IGNORE INTO samples (sha256, md5, filename, file_type, size_bytes) VALUES (?, ?, ?, ?, ?)",
                (sha256, md5, filename, file_type, size_bytes),
            ) as cursor:
                await self.conn.commit()
                if cursor.rowcount > 0:
                    return cursor.lastrowid

            async with self.conn.execute("SELECT id FROM samples WHERE sha256 = ?", (sha256,)) as cursor:
                row = await cursor.fetchone()
                return row['id'] if row else None
        except Exception as e:
            self.logger.error(f"Failed to add sample: {e}")
            return None

    async def create_analysis(self, sample_id, started_at, guest_os=None, snapshot=None):
        if not self.conn:
            return None
        try:
            async with self.conn.execute(
                "INSERT INTO analyses (sample_id, started_at, status, guest_os, snapshot) "
                "VALUES (?, ?, 'running', ?, ?)",
                (sample_id, _ts(started_at), guest_os, snapshot),
            ) as cursor:
                await self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Failed to create analysis: {e}")
            return None

    async def update_analysis(
        self,
        analysis_id,
        finished_at=None,
        threat_score=None,
        verdict=None,
        yara_matches=None,
        report_json=None,
        status=None,
        error=None,
        scoring=None,
    ):
        if not self.conn or not analysis_id:
            return
        try:
            fields = {
                "finished_at": _ts(finished_at) if finished_at is not None else None,
                "threat_score": threat_score,
                "verdict": verdict,
                "yara_matches": json.dumps(yara_matches) if yara_matches is not None else None,
                "report_json": json.dumps(report_json) if report_json is not None else None,
                "status": status,
                "error": str(error)[:2000] if error is not None else None,
                "scoring": json.dumps(scoring) if scoring is not None else None,
            }
            updates = {k: v for k, v in fields.items() if v is not None}
            if not updates:
                return
            query = "UPDATE analyses SET " + ", ".join(f"{k} = ?" for k in updates) + " WHERE id = ?"
            await self.conn.execute(query, (*updates.values(), analysis_id))
            await self.conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to update analysis: {e}")

    async def add_event(self, analysis_id, event_type, timestamp, severity, details):
        await self.add_events(analysis_id, [(event_type, timestamp, severity, details)])

    async def add_events(self, analysis_id, rows):
        """Bulk insert [(event_type, timestamp, severity, details), ...] in one transaction."""
        if not self.conn or not analysis_id or not rows:
            return
        try:
            await self.conn.executemany(
                "INSERT INTO events (analysis_id, event_type, timestamp, severity, details) VALUES (?, ?, ?, ?, ?)",
                [(analysis_id, t, ts, sev, json.dumps(d)) for t, ts, sev, d in rows],
            )
            await self.conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to add events: {e}")

    async def get_recent_analyses(self, limit=50):
        if not self.conn:
            return []
        try:
            async with self.conn.execute(
                """
                SELECT a.id, s.filename, a.started_at, a.verdict, a.threat_score, a.status
                FROM analyses a
                JOIN samples s ON a.sample_id = s.id
                ORDER BY a.started_at DESC
                LIMIT ?
            """,
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Failed to get recent analyses: {e}")
            return []

    async def get_analysis_details(self, analysis_id):
        if not self.conn or not analysis_id:
            return None
        try:
            async with self.conn.execute(
                """
                SELECT a.*, s.filename, s.sha256, s.md5, s.size_bytes, s.file_type
                FROM analyses a
                JOIN samples s ON a.sample_id = s.id
                WHERE a.id = ?
            """,
                (analysis_id,),
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.logger.error(f"Failed to get analysis details: {e}")
            return None

    async def get_analysis_events(self, analysis_id):
        if not self.conn or not analysis_id:
            return []
        try:
            async with self.conn.execute(
                """
                SELECT * FROM events WHERE analysis_id = ? ORDER BY timestamp ASC, id ASC
            """,
                (analysis_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Failed to get analysis events: {e}")
            return []

    async def close(self):
        if self.conn:
            try:
                await self.conn.close()
            except Exception as e:
                self.logger.error(f"Failed to close database: {e}")
