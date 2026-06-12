import aiosqlite
import json
import logging

class Database:
    def __init__(self, db_path=":memory:"):
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

    async def add_event(self, analysis_id, event_type, timestamp, severity, details):
        await self.conn.execute(
            "INSERT INTO events (analysis_id, event_type, timestamp, severity, details) VALUES (?, ?, ?, ?, ?)",
            (analysis_id, event_type, timestamp, severity, json.dumps(details))
        )
        await self.conn.commit()

    async def close(self):
        await self.conn.close()
