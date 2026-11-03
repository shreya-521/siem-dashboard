"""Synthetic log generator. All data is fictional: IPs come from RFC1918 and the
RFC5737 documentation ranges, usernames are made up.

It produces a normal working day of noise plus a set of *planted* scenarios so the
detection rules can be verified against a known ground truth (see SCENARIOS).
"""
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from urllib.parse import quote

USERS = {"alice": "10.0.1.11", "bob": "10.0.1.12", "carol": "10.0.1.13",
         "dave": "10.0.1.14", "erin": "10.0.1.15", "admin": "10.0.1.5"}
SERVER = "10.0.0.5"

# Ground truth used by the tests and the README.
SCENARIOS = {
    "multi_stage": "198.51.100.23",   # scan -> brute force -> success => Critical
    "brute_only": "203.0.113.50",     # brute force on 'bob', never succeeds
    "scan_only": "203.0.113.77",      # port scan only
    "web_attacker": "192.0.2.44",     # SQLi / traversal / XSS
    "off_hours_internal": "10.0.1.99",  # admin login at 23:42 from inside
    "slow_guesser": "203.0.113.9",    # 3 fails over 30 min -> must NOT alert
    "typo_user": "10.0.1.11",         # alice: 2 typos then success -> must NOT alert
}

Line = Tuple[datetime, str]


def _auth(ts, ip, user, ok) -> Line:
    return ts, (f"{ts.isoformat()} auth service=sshd src={ip} user={user} "
                f"result={'SUCCESS' if ok else 'FAIL'}")


def _fw(ts, ip, port, allow) -> Line:
    return ts, (f"{ts.isoformat()} firewall src={ip} dst={SERVER} dst_port={port} "
                f"action={'ALLOW' if allow else 'DENY'}")


def _web(ts, ip, path, status) -> Line:
    return ts, f"{ts.isoformat()} web src={ip} method=GET path={path} status={status}"


def generate(day: datetime, seed: int = 42) -> Dict[str, List[str]]:
    rng = random.Random(seed)
    day = day.replace(hour=0, minute=0, second=0, microsecond=0)
    at = lambda h, m=0, s=0: day + timedelta(hours=h, minutes=m, seconds=s)
    auth: List[Line] = []
    fw: List[Line] = []
    web: List[Line] = []

    # ---- Background noise -------------------------------------------------
    for user, ip in USERS.items():
        for _ in range(rng.randint(1, 3)):
            auth.append(_auth(at(rng.randint(8, 16), rng.randint(0, 59), rng.randint(0, 59)), ip, user, True))
        for _ in range(rng.randint(15, 30)):
            t = at(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
            fw.append(_fw(t, ip, rng.choice([53, 80, 443, 443, 8080]), True))
        for _ in range(rng.randint(20, 40)):
            t = at(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
            web.append(_web(t, ip, rng.choice(["/", "/home", "/api/items", "/static/app.js", "/reports"]),
                            rng.choice([200, 200, 200, 304])))

    # ---- Benign decoys (rules must stay quiet) ------------------------------
    auth += [_auth(at(9, 0, 10), "10.0.1.11", "alice", False),
             _auth(at(9, 0, 25), "10.0.1.11", "alice", False),
             _auth(at(9, 0, 40), "10.0.1.11", "alice", True)]          # typo_user
    auth += [_auth(at(10, 0), "203.0.113.9", "carol", False),
             _auth(at(10, 15), "203.0.113.9", "carol", False),
             _auth(at(10, 30), "203.0.113.9", "dave", False)]          # slow_guesser

    # ---- Scenario 1: multi-stage attack (198.51.100.23) ---------------------
    atk = SCENARIOS["multi_stage"]
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080,
             8443, 9200, 5900, 6379, 27017, 11211, 2049]
    for k, p in enumerate(ports):
        fw.append(_fw(at(2, 10, 0) + timedelta(seconds=k * 1.5), atk, p, p == 22))
    for k in range(12):
        auth.append(_auth(at(2, 14, 0) + timedelta(seconds=k * 5), atk, "admin", False))
    auth.append(_auth(at(2, 15, 10), atk, "admin", True))               # compromise + off-hours admin

    # ---- Scenario 2: brute force only (203.0.113.50 -> bob) ------------------
    for k in range(8):
        auth.append(_auth(at(13, 30, 0) + timedelta(seconds=k * 9), SCENARIOS["brute_only"], "bob", False))

    # ---- Scenario 3: port scan only (203.0.113.77) ---------------------------
    for k, p in enumerate(range(1000, 1015)):
        fw.append(_fw(at(15, 20, 0) + timedelta(seconds=k * 2), SCENARIOS["scan_only"], p, False))

    # ---- Scenario 4: web attacker (192.0.2.44) -------------------------------
    for k, path in enumerate(["/search?q=" + quote("' OR 1=1--"),
                              "/download?file=" + quote("../../etc/passwd"),
                              "/comment?text=" + quote("<script>alert(1)</script>"),
                              "/search?q=" + quote("x' UNION SELECT password FROM users--")]):
        web.append(_web(at(14, 5, 0) + timedelta(seconds=k * 20), SCENARIOS["web_attacker"], path, 404 if k % 2 else 500))

    # ---- Scenario 5: internal admin login at 23:42 ---------------------------
    auth.append(_auth(at(23, 42, 5), SCENARIOS["off_hours_internal"], "admin", True))

    out = {}
    for name, lines in (("auth", auth), ("firewall", fw), ("web", web)):
        out[name] = [text for _, text in sorted(lines, key=lambda x: x[0])]
    # Two deliberately corrupted lines to exercise the parser's error handling.
    out["auth"].insert(5, "### corrupted entry ###")
    out["web"].insert(7, "2026-13-45T99:99:99 web src=not-an-ip status=abc")
    return out


def write_logs(out_dir: str, day: datetime = datetime(2026, 10, 30), seed: int = 42) -> Dict[str, int]:
    os.makedirs(out_dir, exist_ok=True)
    data = generate(day, seed)
    counts = {}
    for name, lines in data.items():
        with open(os.path.join(out_dir, f"{name}.log"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
        counts[name] = len(lines)
    return counts
