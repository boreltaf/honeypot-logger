"""
SQLite logging module for honeypot events.
Handles all database operations.
"""

import sqlite3
import threading
from datetime import datetime
from config import DB_PATH


class HoneypotLogger:
    """Thread-safe SQLite logger for honeypot events."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        """Create a new connection (must be thread-local)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create tables if they don't exist."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER,
                    dest_port INTEGER NOT NULL,
                    protocol TEXT,
                    payload TEXT,
                    country TEXT DEFAULT 'Unknown',
                    city TEXT DEFAULT 'Unknown',
                    org TEXT DEFAULT 'Unknown'
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_source_ip
                ON events(source_ip)
            """)
            conn.commit()
            conn.close()

    def log_event(self, source_ip, source_port, dest_port, protocol,
                  payload="", country="Unknown", city="Unknown", org="Unknown"):
        """Insert a new connection event."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        with self._lock:
            conn = self._get_connection()
            conn.execute(
                """INSERT INTO events
                   (timestamp, source_ip, source_port, dest_port, protocol,
                    payload, country, city, org)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, source_ip, source_port, dest_port, protocol,
                 payload, country, city, org)
            )
            conn.commit()
            conn.close()

    def get_recent_events(self, limit=50):
        """Get the most recent events."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows

    def get_stats(self):
        """Get aggregated statistics."""
        with self._lock:
            conn = self._get_connection()
            stats = {}

            # Total events
            cursor = conn.execute("SELECT COUNT(*) as count FROM events")
            stats["total_events"] = cursor.fetchone()["count"]

            # Unique source IPs
            cursor = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) as count FROM events"
            )
            stats["unique_ips"] = cursor.fetchone()["count"]

            # Events per protocol
            cursor = conn.execute(
                "SELECT protocol, COUNT(*) as count FROM events "
                "GROUP BY protocol ORDER BY count DESC"
            )
            stats["by_protocol"] = [dict(row) for row in cursor.fetchall()]

            # Top attackers
            cursor = conn.execute(
                "SELECT source_ip, COUNT(*) as count, "
                "MAX(country) as country, MAX(city) as city "
                "FROM events GROUP BY source_ip "
                "ORDER BY count DESC LIMIT 10"
            )
            stats["top_attackers"] = [dict(row) for row in cursor.fetchall()]

            # Events per country
            cursor = conn.execute(
                "SELECT country, COUNT(*) as count FROM events "
                "GROUP BY country ORDER BY count DESC"
            )
            stats["by_country"] = [dict(row) for row in cursor.fetchall()]

            # Events in last 24 hours
            cursor = conn.execute(
                "SELECT COUNT(*) as count FROM events "
                "WHERE timestamp >= datetime('now', '-1 day')"
            )
            stats["last_24h"] = cursor.fetchone()["count"]

            conn.close()
            return stats

    def get_events_since(self, event_id):
        """Get all events newer than the given ID (for live polling)."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC",
                (event_id,)
            )
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows

    def get_latest_event_id(self):
        """Get the highest event ID."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT MAX(id) as max_id FROM events")
            result = cursor.fetchone()["max_id"]
            conn.close()
            return result or 0

    def clear_events(self):
        """Delete all events (for dashboard clear button)."""
        with self._lock:
            conn = self._get_connection()
            conn.execute("DELETE FROM events")
            conn.commit()
            conn.close()