"""SQLite storage layer."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, source TEXT NOT NULL, src_ip TEXT NOT NULL,
    user TEXT, result TEXT, action TEXT, dst_port INTEGER,
    http_status INTEGER, path TEXT, raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL, title TEXT NOT NULL, score INTEGER NOT NULL,
    severity TEXT NOT NULL, src_ip TEXT NOT NULL, user TEXT,
    start_ts TEXT NOT NULL, end_ts TEXT NOT NULL, description TEXT,
    mitre TEXT, evidence TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(src_ip);
"""

VALID_STATUS = ("open", "investigating", "resolved")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: str, reset: bool = False) -> None:
    conn = connect(path)
    if reset:
        conn.executescript("DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS alerts;")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def insert_events(path: str, events: List[Event]) -> None:
    conn = connect(path)
    conn.executemany(
        "INSERT INTO events (ts, source, src_ip, user, result, action, dst_port, http_status, path, raw)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(e.ts.isoformat(), e.source, e.src_ip, e.user, e.result, e.action,
          e.dst_port, e.http_status, e.path, e.raw) for e in events])
    conn.commit()
    conn.close()


def _row_to_event(r: sqlite3.Row) -> Event:
    return Event(id=r["id"], ts=datetime.fromisoformat(r["ts"]), source=r["source"],
                 src_ip=r["src_ip"], user=r["user"], result=r["result"], action=r["action"],
                 dst_port=r["dst_port"], http_status=r["http_status"], path=r["path"], raw=r["raw"] or "")


def fetch_events(path: str) -> List[Event]:
    conn = connect(path)
    rows = conn.execute("SELECT * FROM events ORDER BY ts, id").fetchall()
    conn.close()
    return [_row_to_event(r) for r in rows]


def fetch_events_by_ids(path: str, ids: List[int]) -> List[Event]:
    if not ids:
        return []
    conn = connect(path)
    marks = ",".join("?" * len(ids))
    rows = conn.execute(f"SELECT * FROM events WHERE id IN ({marks}) ORDER BY ts, id", ids).fetchall()
    conn.close()
    return [_row_to_event(r) for r in rows]


def count_events(path: str) -> Dict[str, int]:
    conn = connect(path)
    rows = conn.execute("SELECT source, COUNT(*) c FROM events GROUP BY source").fetchall()
    conn.close()
    return {r["source"]: r["c"] for r in rows}


def replace_alerts(path: str, alerts: List[Alert]) -> None:
    """Analysis is idempotent: every run replaces the previous alert set."""
    conn = connect(path)
    conn.execute("DELETE FROM alerts")
    conn.executemany(
        "INSERT INTO alerts (rule, title, score, severity, src_ip, user, start_ts, end_ts,"
        " description, mitre, evidence, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [(a.rule, a.title, a.score, a.severity, a.src_ip, a.user, a.start_ts.isoformat(),
          a.end_ts.isoformat(), a.description, a.mitre, json.dumps(a.evidence), a.status)
         for a in alerts])
    conn.commit()
    conn.close()


def _row_to_alert(r: sqlite3.Row) -> Alert:
    return Alert(id=r["id"], rule=r["rule"], title=r["title"], score=r["score"], src_ip=r["src_ip"],
                 user=r["user"], start_ts=datetime.fromisoformat(r["start_ts"]),
                 end_ts=datetime.fromisoformat(r["end_ts"]), description=r["description"] or "",
                 mitre=r["mitre"] or "", evidence=json.loads(r["evidence"]), status=r["status"])


def fetch_alerts(path: str, severity: str = "", rule: str = "", status: str = "",
                 q: str = "", src_ip: str = "") -> List[Alert]:
    sql, args = "SELECT * FROM alerts WHERE 1=1", []
    if severity:
        sql += " AND severity = ?"; args.append(severity)
    if rule:
        sql += " AND rule = ?"; args.append(rule)
    if status:
        sql += " AND status = ?"; args.append(status)
    if src_ip:
        sql += " AND src_ip = ?"; args.append(src_ip)
    if q:
        sql += " AND (src_ip LIKE ? OR IFNULL(user,'') LIKE ? OR title LIKE ?)"
        args += [f"%{q}%"] * 3
    sql += " ORDER BY score DESC, start_ts DESC"
    conn = connect(path)
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return [_row_to_alert(r) for r in rows]


def get_alert(path: str, alert_id: int) -> Optional[Alert]:
    conn = connect(path)
    r = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    return _row_to_alert(r) if r else None


def set_status(path: str, alert_id: int, status: str) -> bool:
    if status not in VALID_STATUS:
        return False
    conn = connect(path)
    cur = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    conn.close()
    return cur.rowcount > 0
