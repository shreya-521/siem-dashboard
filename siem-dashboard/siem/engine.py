"""Orchestrates ingestion -> correlation -> storage."""
from __future__ import annotations

import os
from typing import Dict, List

from . import db
from .models import Alert, Event
from .parser import parse_file
from .rules import SINGLE_RULES, multi_stage


def analyze(events: List[Event]) -> List[Alert]:
    """Run every rule (events must carry ids so alerts can reference evidence)."""
    events = sorted(events, key=lambda e: (e.ts, e.id or 0))
    alerts: List[Alert] = []
    for rule in SINGLE_RULES:
        alerts.extend(rule(events))
    alerts.extend(multi_stage(alerts))
    alerts.sort(key=lambda a: (-a.score, a.start_ts))
    return alerts


def ingest_directory(db_path: str, log_dir: str, reset: bool = True) -> Dict[str, int]:
    """Parse auth.log / firewall.log / web.log from a directory into the database."""
    db.init_db(db_path, reset=reset)
    total, skipped = 0, 0
    for name in ("auth.log", "firewall.log", "web.log"):
        p = os.path.join(log_dir, name)
        if os.path.exists(p):
            evs, bad = parse_file(p)
            db.insert_events(db_path, evs)
            total += len(evs)
            skipped += bad
    return {"ingested": total, "skipped": skipped}


def run_analysis(db_path: str) -> List[Alert]:
    """Load events from the DB, correlate, and persist alerts."""
    alerts = analyze(db.fetch_events(db_path))
    db.replace_alerts(db_path, alerts)
    return alerts
