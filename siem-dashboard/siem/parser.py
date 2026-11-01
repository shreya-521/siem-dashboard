"""Log ingestion: parse raw text lines into normalised Event objects.

Line format (one event per line):
    <ISO-8601 timestamp> <source> key=value key=value ...

Examples:
    2026-10-30T09:15:02 auth service=sshd src=10.0.1.5 user=alice result=FAIL
    2026-10-30T09:15:02 firewall src=203.0.113.7 dst=10.0.0.5 dst_port=22 action=DENY
    2026-10-30T09:15:02 web src=10.0.1.8 method=GET path=/login status=401
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

from .models import Event

KV = re.compile(r"(\w+)=(\S+)")
VALID_SOURCES = {"auth", "firewall", "web"}
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def parse_line(line: str) -> Optional[Event]:
    """Return an Event, or None if the line is blank/malformed."""
    line = line.strip()
    if not line:
        return None
    parts = line.split(None, 2)
    if len(parts) < 3:
        return None
    ts_raw, source, rest = parts
    if source not in VALID_SOURCES:
        return None
    try:
        ts = datetime.fromisoformat(ts_raw)
    except ValueError:
        return None
    fields = dict(KV.findall(rest))
    src = fields.get("src")
    if not src or not IPV4.match(src):
        return None

    ev = Event(ts=ts, source=source, src_ip=src, user=fields.get("user"), raw=line)
    try:
        if source == "auth":
            result = fields.get("result", "").upper()
            if result not in ("SUCCESS", "FAIL"):
                return None
            ev.result = result
        elif source == "firewall":
            action = fields.get("action", "").upper()
            if action not in ("ALLOW", "DENY"):
                return None
            ev.action = action
            ev.dst_port = int(fields["dst_port"])
        else:  # web
            ev.http_status = int(fields["status"])
            ev.path = fields.get("path", "/")
    except (KeyError, ValueError):
        return None
    return ev


def parse_lines(lines: Iterable[str]) -> Tuple[List[Event], int]:
    """Parse many lines. Returns (events, number_of_malformed_lines_skipped)."""
    events, skipped = [], 0
    for line in lines:
        if not line.strip():
            continue
        ev = parse_line(line)
        if ev is None:
            skipped += 1
        else:
            events.append(ev)
    return events, skipped


def parse_file(path: str) -> Tuple[List[Event], int]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)
