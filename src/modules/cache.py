"""
SQLite-based result cache for ultimate-osint.
Avoids redundant API calls and rate-limiting on repeated targets.
"""

import json
import sqlite3
import time
from pathlib import Path

CACHE_PATH = Path.home() / ".cache" / "ultimate-osint" / "cache.db"
DEFAULT_TTL = 86400  # 24 hours


class Cache:
    def __init__(self, path: Path = CACHE_PATH, ttl: int = DEFAULT_TTL):
        self.default_ttl = ttl
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS results (
                key         TEXT PRIMARY KEY,
                data        TEXT NOT NULL,
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL
            )
        """)
        self.conn.commit()
        self._purge()

    def _purge(self) -> None:
        self.conn.execute("DELETE FROM results WHERE expires_at < ?", (time.time(),))
        self.conn.commit()

    def _key(self, module: str, target: str) -> str:
        return f"{module}:{target.lower().strip()}"

    def get(self, module: str, target: str) -> dict | None:
        row = self.conn.execute(
            "SELECT data FROM results WHERE key = ? AND expires_at > ?",
            (self._key(module, target), time.time()),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def set(self, module: str, target: str, data: dict, ttl: int | None = None) -> None:
        now = time.time()
        self.conn.execute(
            "INSERT OR REPLACE INTO results (key, data, created_at, expires_at) VALUES (?,?,?,?)",
            (self._key(module, target), json.dumps(data, default=str), now, now + (ttl or self.default_ttl)),
        )
        self.conn.commit()

    def invalidate(self, module: str | None = None, target: str | None = None) -> int:
        if module and target:
            cur = self.conn.execute("DELETE FROM results WHERE key = ?", (self._key(module, target),))
        elif module:
            cur = self.conn.execute("DELETE FROM results WHERE key LIKE ?", (f"{module}:%",))
        else:
            cur = self.conn.execute("DELETE FROM results")
        self.conn.commit()
        return cur.rowcount

    def stats(self) -> dict:
        row = self.conn.execute("SELECT COUNT(*), MIN(created_at), MAX(expires_at) FROM results").fetchone()
        return {"entries": row[0], "oldest": row[1], "newest_expiry": row[2]}


# Module-level singleton
_cache = Cache()


def get_cache() -> Cache:
    return _cache
