"""Incident report generation (Markdown)."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import List, Optional

from .models import SEVERITY_ORDER, Alert, Event, severity_label

RECOMMENDATIONS = {
    "multi_stage": ["Isolate the affected host(s) and block the source IP at the perimeter immediately.",
                    "Force a password reset and revoke active sessions for the compromised account.",
                    "Review all activity by the account after the successful login for persistence or data access.",
                    "Preserve logs and begin formal incident response procedures."],
    "compromise": ["Reset credentials for the affected account and invalidate sessions.",
                   "Enable multi-factor authentication."],
    "brute_force": ["Block or rate-limit the source IP.",
                    "Enforce account lockout thresholds and MFA."],
    "port_scan": ["Block the source IP and review exposed services.",
                  "Close unnecessary ports and tighten firewall rules."],
    "off_hours_admin": ["Confirm with the account owner that the login was legitimate.",
                        "Restrict privileged logins to approved hours/networks."],
    "web_attack": ["Review web application input validation and deploy a WAF rule.",
                   "Check application logs for any successful exploitation."],
}


def _order(a: Alert):
    return (-a.score, a.start_ts)


def build_incident_report(ip: str, alerts: List[Alert], events: List[Event],
                          now: Optional[datetime] = None) -> str:
    now = now or datetime.now()
    alerts = sorted(alerts, key=lambda a: a.start_ts)
    top = max(alerts, key=lambda a: a.score)
    first, last = min(a.start_ts for a in alerts), max(a.end_ts for a in alerts)
    rules = sorted({a.rule for a in alerts})
    lines = [
        f"# Incident Report: {ip}", "",
        f"*Generated {now.strftime('%Y-%m-%d %H:%M')} by the Security Event Correlation Dashboard "
        "(synthetic data).*", "",
        "## Summary", "",
        f"| Field | Value |", "|---|---|",
        f"| Source IP | `{ip}` |",
        f"| Overall severity | **{severity_label(top.score)}** (score {top.score}/100) |",
        f"| First activity | {first.strftime('%Y-%m-%d %H:%M:%S')} |",
        f"| Last activity | {last.strftime('%Y-%m-%d %H:%M:%S')} |",
        f"| Alerts | {len(alerts)} ({', '.join(rules)}) |",
        f"| Supporting log events | {len(events)} |", "",
        f"**Assessment:** {top.description}", "",
        "## Timeline", "", "| Time | Severity | Rule | Detail | Status |", "|---|---|---|---|---|",
    ]
    for a in alerts:
        lines.append(f"| {a.start_ts.strftime('%H:%M:%S')} | {a.severity} | {a.rule} | "
                     f"{a.description.replace('|', '/')} | {a.status} |")
    lines += ["", "## MITRE ATT&CK mapping", ""]
    for m in sorted({a.mitre for a in alerts if a.mitre}):
        lines.append(f"- {m}")
    lines += ["", "## Evidence (first 25 log events)", "", "```"]
    lines += [e.raw for e in events[:25]]
    if len(events) > 25:
        lines.append(f"... and {len(events) - 25} more")
    lines += ["```", "", "## Recommended actions", ""]
    seen = []
    for rule in sorted(rules, key=lambda r: list(RECOMMENDATIONS).index(r) if r in RECOMMENDATIONS else 99):
        for rec in RECOMMENDATIONS.get(rule, []):
            if rec not in seen:
                seen.append(rec)
    lines += [f"{i}. {r}" for i, r in enumerate(seen, 1)]
    lines += ["", "---", "*Findings are produced by rule-based detection and require analyst validation.*", ""]
    return "\n".join(lines)
