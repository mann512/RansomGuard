import json, sqlite3, threading
from contextlib import contextmanager
from datetime import datetime, timezone
from . import config
class Database:
    def __init__(self, path=None):
        self.path = str(path or config.DB_PATH)
        self._lock = threading.Lock()
        self._init_schema()
    @contextmanager
    def _conn(self):
        with self._lock:
            conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn; conn.commit()
            except Exception:
                conn.rollback(); raise
            finally: conn.close()
    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, severity TEXT NOT NULL, score INTEGER NOT NULL, reason TEXT NOT NULL, affected_files TEXT NOT NULL, process_info TEXT, stopped INTEGER DEFAULT 0, restored INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT NOT NULL, backup_path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, timestamp TEXT NOT NULL, phase TEXT DEFAULT 'forensic', alert_id INTEGER);
            """)
    def _now(self): return datetime.now(timezone.utc).isoformat()
    def add_alert(self, severity, score, reason, affected_files, process_info=None, stopped=False):
        with self._conn() as conn:
            cur = conn.execute("INSERT INTO alerts (timestamp, severity, score, reason, affected_files, process_info, stopped) VALUES (?, ?, ?, ?, ?, ?, ?)", (self._now(), severity, score, reason, json.dumps(affected_files), json.dumps(process_info) if process_info else None, 1 if stopped else 0))
            return cur.lastrowid
    def update_alert_process(self, alert_id, process_info, stopped):
        with self._conn() as conn: conn.execute("UPDATE alerts SET process_info=?, stopped=? WHERE id=?", (json.dumps(process_info) if process_info else None, 1 if stopped else 0, alert_id))
    def list_alerts(self, limit=100):
        with self._conn() as conn: rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._alert_row(r) for r in rows]
    def get_alert(self, alert_id):
        with self._conn() as conn: row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return self._alert_row(row) if row else None
    def mark_restored(self, alert_id):
        with self._conn() as conn: conn.execute("UPDATE alerts SET restored=1 WHERE id=?", (alert_id,))
    def _alert_row(self, row):
        d = dict(row)
        d["affected_files"] = json.loads(d["affected_files"]) if d["affected_files"] else []
        d["process_info"] = json.loads(d["process_info"]) if d["process_info"] else None
        d["stopped"] = bool(d["stopped"]); d["restored"] = bool(d["restored"])
        return d
    def add_backup(self, original_path, backup_path, sha256, size, phase="forensic", alert_id=None):
        with self._conn() as conn: conn.execute("INSERT INTO backups (original_path, backup_path, sha256, size, timestamp, phase, alert_id) VALUES (?, ?, ?, ?, ?, ?, ?)", (original_path, backup_path, sha256, size, self._now(), phase, alert_id))
    def latest_snapshot_for_path(self, original_path):
        with self._conn() as conn: row = conn.execute("SELECT * FROM backups WHERE original_path=? AND phase='snapshot' ORDER BY id DESC LIMIT 1", (original_path,)).fetchone()
        return dict(row) if row else None
    def backups_for_alert(self, alert_id):
        with self._conn() as conn: rows = conn.execute("SELECT * FROM backups WHERE alert_id=? ORDER BY id ASC", (alert_id,)).fetchall()
        return [dict(r) for r in rows]
    def stats(self):
        with self._conn() as conn:
            return {"total_alerts": conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"], "total_backups": conn.execute("SELECT COUNT(*) c FROM backups").fetchone()["c"], "restored": conn.execute("SELECT COUNT(*) c FROM alerts WHERE restored=1").fetchone()["c"]}