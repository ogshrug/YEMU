import aiosqlite
import json
import logging

class Database:
    def __init__(self, db_path="malware_sandbox.db"):
        self.db_path = db_path

    async def connect(self):
        self.conn = await aiosqlite.connect(self.db_path)
        self.conn.row_factory = aiosqlite.Row
        await self._create_tables()

    async def _create_tables(self):
        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS samples (
          id INTEGER PRIMARY KEY,
          sha256 TEXT UNIQUE,
          md5 TEXT,
          filename TEXT,
          file_type TEXT,
          size_bytes INTEGER,
          first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
          id INTEGER PRIMARY KEY,
          sample_id INTEGER REFERENCES samples(id),
          started_at TIMESTAMP,
          finished_at TIMESTAMP,
          threat_score INTEGER,
          verdict TEXT,
          yara_matches TEXT,
          report_json TEXT
        )""")

        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY,
          analysis_id INTEGER REFERENCES analyses(id),
          event_type TEXT,
          timestamp REAL,
          severity TEXT,
          details TEXT
        )""")

        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
          id INTEGER PRIMARY KEY,
          analysis_id INTEGER REFERENCES analyses(id),
          ioc_type TEXT,
          value TEXT,
          confidence INTEGER
        )""")
        await self.conn.commit()

    async def add_sample(self, sha256, md5, filename, file_type, size_bytes):
        async with self.conn.execute(
            "INSERT OR IGNORE INTO samples (sha256, md5, filename, file_type, size_bytes) VALUES (?, ?, ?, ?, ?)",
            (sha256, md5, filename, file_type, size_bytes)
        ) as cursor:
            await self.conn.commit()
            if cursor.rowcount > 0:
                return cursor.lastrowid

        async with self.conn.execute("SELECT id FROM samples WHERE sha256 = ?", (sha256,)) as cursor:
            row = await cursor.fetchone()
            return row['id'] if row else None

    async def create_analysis(self, sample_id, started_at):
        async with self.conn.execute(
            "INSERT INTO analyses (sample_id, started_at) VALUES (?, ?)",
            (sample_id, started_at)
        ) as cursor:
            await self.conn.commit()
            return cursor.lastrowid

    async def update_analysis(self, analysis_id, finished_at=None, threat_score=None, verdict=None, yara_matches=None, report_json=None):
        query = "UPDATE analyses SET "
        params = []
        updates = []
        if finished_at is not None:
            updates.append("finished_at = ?")
            params.append(finished_at)
        if threat_score is not None:
            updates.append("threat_score = ?")
            params.append(threat_score)
        if verdict is not None:
            updates.append("verdict = ?")
            params.append(verdict)
        if yara_matches is not None:
            updates.append("yara_matches = ?")
            params.append(json.dumps(yara_matches))
        if report_json is not None:
            updates.append("report_json = ?")
            params.append(json.dumps(report_json))

        if not updates:
            return

        query += ", ".join(updates)
        query += " WHERE id = ?"
        params.append(analysis_id)

        await self.conn.execute(query, tuple(params))
        await self.conn.commit()

    async def add_event(self, analysis_id, event_type, timestamp, severity, details):
        await self.conn.execute(
            "INSERT INTO events (analysis_id, event_type, timestamp, severity, details) VALUES (?, ?, ?, ?, ?)",
            (analysis_id, event_type, timestamp, severity, json.dumps(details))
        )
        await self.conn.commit()

    async def get_recent_analyses(self, limit=50):
        async with self.conn.execute("""
            SELECT a.id, s.filename, a.started_at, a.verdict, a.threat_score
            FROM analyses a
            JOIN samples s ON a.sample_id = s.id
            ORDER BY a.started_at DESC
            LIMIT ?
        """, (limit,)) as cursor:
            return await cursor.fetchall()

    async def get_analysis_details(self, analysis_id):
        async with self.conn.execute("""
            SELECT a.*, s.filename, s.sha256, s.md5, s.size_bytes, s.file_type
            FROM analyses a
            JOIN samples s ON a.sample_id = s.id
            WHERE a.id = ?
        """, (analysis_id,)) as cursor:
            return await cursor.fetchone()

    async def get_analysis_events(self, analysis_id):
        async with self.conn.execute("""
            SELECT * FROM events WHERE analysis_id = ? ORDER BY timestamp ASC
        """, (analysis_id,)) as cursor:
            return await cursor.fetchall()

    async def close(self):
        await self.conn.close()
