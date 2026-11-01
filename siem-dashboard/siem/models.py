"""Core data structures shared by every layer of the pipeline."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip: str) -> bool:
    """True for RFC1918 addresses. (Documentation ranges such as 203.0.113.0/24 count as external.)"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS)


def severity_label(score: int) -> str:
    """Map a 0-100 score to a label."""
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


@dataclass
class Event:
    """A normalised log event (auth, firewall or web)."""
    ts: datetime
    source: str                       # auth | firewall | web
    src_ip: str
    user: Optional[str] = None
    result: Optional[str] = None      # auth: SUCCESS | FAIL
    action: Optional[str] = None      # firewall: ALLOW | DENY
    dst_port: Optional[int] = None
    http_status: Optional[int] = None
    path: Optional[str] = None
    raw: str = ""
    id: Optional[int] = None


@dataclass
class Alert:
    """Output of a correlation rule."""
    rule: str
    title: str
    score: int
    src_ip: str
    start_ts: datetime
    end_ts: datetime
    description: str
    mitre: str = ""
    user: Optional[str] = None
    evidence: List[int] = field(default_factory=list)   # event ids
    status: str = "open"
    id: Optional[int] = None

    @property
    def severity(self) -> str:
        return severity_label(self.score)
