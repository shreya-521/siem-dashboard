"""Correlation rules.

Each single-source rule takes a chronologically sorted list of Events and
returns a list of Alerts. `multi_stage` then correlates *across* the alerts
produced by the other rules, which is what turns isolated detections into an
incident narrative.

All thresholds are module-level constants so they are easy to tune and test.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Callable, Dict, List
from urllib.parse import unquote

from .models import Alert, Event, is_internal

# ---- Tunable thresholds -------------------------------------------------
BRUTE_THRESHOLD = 5                       # failed logins ...
BRUTE_WINDOW = timedelta(seconds=120)     # ... within this window
COMPROMISE_FAILS = 3                      # failures before a success ...
COMPROMISE_WINDOW = timedelta(minutes=5)  # ... within this lookback
SCAN_PORTS = 10                           # distinct ports ...
SCAN_WINDOW = timedelta(seconds=60)       # ... within this window
WORK_START, WORK_END = 8, 18              # working hours [08:00, 18:00)
PRIVILEGED_USERS = {"admin", "root", "administrator"}
WEB_GAP = timedelta(minutes=5)            # hits closer than this are one burst
MULTI_STAGE_SPAN = timedelta(hours=1)     # max gap between attack stages

WEB_SIGNATURES = {
    "SQL injection": ["' or ", "union select", "1=1", "--"],
    "Path traversal": ["../", "..\\", "/etc/passwd"],
    "XSS": ["<script", "javascript:", "onerror="],
}

MITRE = {
    "brute_force": "T1110 Brute Force",
    "compromise": "T1078 Valid Accounts",
    "port_scan": "T1046 Network Service Discovery",
    "off_hours_admin": "T1078 Valid Accounts",
    "web_attack": "T1190 Exploit Public-Facing Application",
    "multi_stage": "TA0001-TA0006 Initial Access / Credential Access chain",
}


def _by_ip(events: List[Event], pred: Callable[[Event], bool]) -> Dict[str, List[Event]]:
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if pred(e):
            grouped[e.src_ip].append(e)
    return grouped


def _fmt(ts) -> str:
    return ts.strftime("%H:%M:%S")


# ---- Rule 1: brute force ------------------------------------------------
def brute_force(events: List[Event]) -> List[Alert]:
    """>= BRUTE_THRESHOLD failed logins from one IP within BRUTE_WINDOW.

    A continuing attack (each failure within the window of the previous one)
    is merged into a single alert instead of firing repeatedly.
    """
    alerts: List[Alert] = []
    for ip, evs in _by_ip(events, lambda e: e.source == "auth" and e.result == "FAIL").items():
        i, n = 0, len(evs)
        while i < n:
            j = i
            while j + 1 < n and evs[j + 1].ts - evs[i].ts <= BRUTE_WINDOW:
                j += 1
            if j - i + 1 >= BRUTE_THRESHOLD:
                k = j
                while k + 1 < n and evs[k + 1].ts - evs[k].ts <= BRUTE_WINDOW:
                    k += 1
                burst = evs[i:k + 1]
                users = sorted({e.user for e in burst if e.user})
                score = 70 + min(15, len(burst) - BRUTE_THRESHOLD)
                alerts.append(Alert(
                    rule="brute_force", title="Brute-force login attempt", score=score, src_ip=ip,
                    user=users[0] if len(users) == 1 else None,
                    start_ts=burst[0].ts, end_ts=burst[-1].ts, mitre=MITRE["brute_force"],
                    description=(f"{len(burst)} failed logins from {ip} between {_fmt(burst[0].ts)} "
                                 f"and {_fmt(burst[-1].ts)} targeting: {', '.join(users) or 'unknown'}."),
                    evidence=[e.id for e in burst if e.id is not None]))
                i = k + 1
            else:
                i += 1
    return alerts


# ---- Rule 2: probable account compromise --------------------------------
def compromise(events: List[Event]) -> List[Alert]:
    """A successful login shortly after >= COMPROMISE_FAILS failures from the same IP."""
    alerts: List[Alert] = []
    for ip, evs in _by_ip(events, lambda e: e.source == "auth").items():
        for idx, e in enumerate(evs):
            if e.result != "SUCCESS":
                continue
            fails = [p for p in evs[:idx]
                     if p.result == "FAIL" and e.ts - p.ts <= COMPROMISE_WINDOW]
            if len(fails) >= COMPROMISE_FAILS:
                alerts.append(Alert(
                    rule="compromise", title="Successful login after repeated failures", score=85,
                    src_ip=ip, user=e.user, start_ts=fails[0].ts, end_ts=e.ts, mitre=MITRE["compromise"],
                    description=(f"Account '{e.user}' logged in successfully from {ip} at {_fmt(e.ts)} "
                                 f"after {len(fails)} failures in the previous "
                                 f"{int(COMPROMISE_WINDOW.total_seconds() // 60)} minutes. "
                                 "Credentials may be compromised."),
                    evidence=[x.id for x in fails + [e] if x.id is not None]))
    return alerts


# ---- Rule 3: port scan --------------------------------------------------
def port_scan(events: List[Event]) -> List[Alert]:
    """One IP touching >= SCAN_PORTS distinct destination ports within SCAN_WINDOW."""
    alerts: List[Alert] = []
    for ip, evs in _by_ip(events, lambda e: e.source == "firewall").items():
        i, n = 0, len(evs)
        while i < n:
            j = i
            while j + 1 < n and evs[j + 1].ts - evs[i].ts <= SCAN_WINDOW:
                j += 1
            if len({e.dst_port for e in evs[i:j + 1]}) >= SCAN_PORTS:
                k = j
                while k + 1 < n and evs[k + 1].ts - evs[k].ts <= SCAN_WINDOW:
                    k += 1
                burst = evs[i:k + 1]
                ports = {e.dst_port for e in burst}
                score = 40 + min(30, len(ports) - SCAN_PORTS)
                alerts.append(Alert(
                    rule="port_scan", title="Port scan detected", score=score, src_ip=ip,
                    start_ts=burst[0].ts, end_ts=burst[-1].ts, mitre=MITRE["port_scan"],
                    description=(f"{ip} probed {len(ports)} distinct ports in "
                                 f"{int((burst[-1].ts - burst[0].ts).total_seconds())}s "
                                 f"({sum(1 for e in burst if e.action == 'DENY')} denied)."),
                    evidence=[e.id for e in burst if e.id is not None]))
                i = k + 1
            else:
                i += 1
    return alerts


# ---- Rule 4: off-hours privileged login ---------------------------------
def off_hours_admin(events: List[Event]) -> List[Alert]:
    """Privileged account login outside working hours. External source IPs score higher."""
    alerts: List[Alert] = []
    for e in events:
        if (e.source == "auth" and e.result == "SUCCESS" and e.user
                and e.user.lower() in PRIVILEGED_USERS
                and not (WORK_START <= e.ts.hour < WORK_END)):
            external = not is_internal(e.src_ip)
            alerts.append(Alert(
                rule="off_hours_admin", title="Privileged login outside working hours",
                score=75 if external else 55, src_ip=e.src_ip, user=e.user, start_ts=e.ts, end_ts=e.ts,
                mitre=MITRE["off_hours_admin"],
                description=(f"Privileged account '{e.user}' logged in at {_fmt(e.ts)} from "
                             f"{'EXTERNAL' if external else 'internal'} address {e.src_ip} "
                             f"(working hours are {WORK_START:02d}:00-{WORK_END:02d}:00)."),
                evidence=[e.id] if e.id is not None else []))
    return alerts


# ---- Rule 5: web attack signatures --------------------------------------
def web_attack(events: List[Event]) -> List[Alert]:
    """Requests containing SQL-injection, path-traversal or XSS patterns."""
    alerts: List[Alert] = []
    hits = defaultdict(list)
    for e in events:
        if e.source != "web" or not e.path:
            continue
        decoded = unquote(e.path).lower()
        for name, sigs in WEB_SIGNATURES.items():
            if any(s in decoded for s in sigs):
                hits[e.src_ip].append((e, name))
                break
    for ip, items in hits.items():
        group = [items[0]]
        groups = []
        for prev, cur in zip(items, items[1:]):
            if cur[0].ts - prev[0].ts <= WEB_GAP:
                group.append(cur)
            else:
                groups.append(group); group = [cur]
        groups.append(group)
        for g in groups:
            kinds = sorted({k for _, k in g})
            alerts.append(Alert(
                rule="web_attack", title="Malicious web request patterns", score=45 + min(15, len(g) * 3),
                src_ip=ip, start_ts=g[0][0].ts, end_ts=g[-1][0].ts, mitre=MITRE["web_attack"],
                description=f"{len(g)} suspicious web request(s) from {ip}: {', '.join(kinds)}.",
                evidence=[e.id for e, _ in g if e.id is not None]))
    return alerts


# ---- Rule 6: multi-stage correlation ------------------------------------
def multi_stage(alerts: List[Alert]) -> List[Alert]:
    """Port scan -> brute force -> successful login from the same IP => Critical incident.

    Works on alerts, not raw events: this is cross-rule correlation.
    """
    by_ip: Dict[str, Dict[str, List[Alert]]] = defaultdict(lambda: defaultdict(list))
    for a in alerts:
        by_ip[a.src_ip][a.rule].append(a)

    out: List[Alert] = []
    for ip, rules in by_ip.items():
        for scan in sorted(rules.get("port_scan", []), key=lambda a: a.start_ts):
            brute = next((b for b in sorted(rules.get("brute_force", []), key=lambda a: a.start_ts)
                          if b.start_ts >= scan.start_ts and b.start_ts - scan.end_ts <= MULTI_STAGE_SPAN), None)
            if not brute:
                continue
            comp = next((c for c in sorted(rules.get("compromise", []), key=lambda a: a.end_ts)
                         if c.end_ts >= brute.start_ts and c.end_ts - brute.end_ts <= MULTI_STAGE_SPAN), None)
            if not comp:
                continue
            evidence = sorted(set(scan.evidence + brute.evidence + comp.evidence))
            out.append(Alert(
                rule="multi_stage", title="Multi-stage attack: scan -> brute force -> compromise",
                score=100, src_ip=ip, user=comp.user, start_ts=scan.start_ts, end_ts=comp.end_ts,
                mitre=MITRE["multi_stage"],
                description=(f"{ip} performed reconnaissance (port scan at {_fmt(scan.start_ts)}), then a "
                             f"brute-force attack at {_fmt(brute.start_ts)}, then logged in as "
                             f"'{comp.user}' at {_fmt(comp.end_ts)}. Treat as an active intrusion."),
                evidence=evidence))
            break  # one incident per IP is enough
    return out


SINGLE_RULES = [brute_force, compromise, port_scan, off_hours_admin, web_attack]
