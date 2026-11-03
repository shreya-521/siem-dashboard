# Incident Report: 198.51.100.23

*Generated 2026-10-31 18:34 by the Security Event Correlation Dashboard (synthetic data).*

## Summary

| Field | Value |
|---|---|
| Source IP | `198.51.100.23` |
| Overall severity | **Critical** (score 100/100) |
| First activity | 2026-10-30 02:10:00 |
| Last activity | 2026-10-30 02:15:10 |
| Alerts | 5 (brute_force, compromise, multi_stage, off_hours_admin, port_scan) |
| Supporting log events | 38 |

**Assessment:** 198.51.100.23 performed reconnaissance (port scan at 02:10:00), then a brute-force attack at 02:14:00, then logged in as 'admin' at 02:15:10. Treat as an active intrusion.

## Timeline

| Time | Severity | Rule | Detail | Status |
|---|---|---|---|---|
| 02:10:00 | Critical | multi_stage | 198.51.100.23 performed reconnaissance (port scan at 02:10:00), then a brute-force attack at 02:14:00, then logged in as 'admin' at 02:15:10. Treat as an active intrusion. | open |
| 02:10:00 | Medium | port_scan | 198.51.100.23 probed 25 distinct ports in 36s (24 denied). | open |
| 02:14:00 | High | compromise | Account 'admin' logged in successfully from 198.51.100.23 at 02:15:10 after 12 failures in the previous 5 minutes. Credentials may be compromised. | open |
| 02:14:00 | High | brute_force | 12 failed logins from 198.51.100.23 between 02:14:00 and 02:14:55 targeting: admin. | open |
| 02:15:10 | High | off_hours_admin | Privileged account 'admin' logged in at 02:15:10 from EXTERNAL address 198.51.100.23 (working hours are 08:00-18:00). | open |

## MITRE ATT&CK mapping

- T1046 Network Service Discovery
- T1078 Valid Accounts
- T1110 Brute Force
- TA0001-TA0006 Initial Access / Credential Access chain

## Evidence (first 25 log events)

```
2026-10-30T02:10:00 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=21 action=DENY
2026-10-30T02:10:01.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=22 action=ALLOW
2026-10-30T02:10:03 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=23 action=DENY
2026-10-30T02:10:04.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=25 action=DENY
2026-10-30T02:10:06 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=53 action=DENY
2026-10-30T02:10:07.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=80 action=DENY
2026-10-30T02:10:09 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=110 action=DENY
2026-10-30T02:10:10.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=139 action=DENY
2026-10-30T02:10:12 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=143 action=DENY
2026-10-30T02:10:13.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=443 action=DENY
2026-10-30T02:10:15 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=445 action=DENY
2026-10-30T02:10:16.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=993 action=DENY
2026-10-30T02:10:18 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=995 action=DENY
2026-10-30T02:10:19.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=1433 action=DENY
2026-10-30T02:10:21 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=3306 action=DENY
2026-10-30T02:10:22.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=3389 action=DENY
2026-10-30T02:10:24 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=5432 action=DENY
2026-10-30T02:10:25.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=8080 action=DENY
2026-10-30T02:10:27 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=8443 action=DENY
2026-10-30T02:10:28.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=9200 action=DENY
2026-10-30T02:10:30 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=5900 action=DENY
2026-10-30T02:10:31.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=6379 action=DENY
2026-10-30T02:10:33 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=27017 action=DENY
2026-10-30T02:10:34.500000 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=11211 action=DENY
2026-10-30T02:10:36 firewall src=198.51.100.23 dst=10.0.0.5 dst_port=2049 action=DENY
... and 13 more
```

## Recommended actions

1. Isolate the affected host(s) and block the source IP at the perimeter immediately.
2. Force a password reset and revoke active sessions for the compromised account.
3. Review all activity by the account after the successful login for persistence or data access.
4. Preserve logs and begin formal incident response procedures.
5. Reset credentials for the affected account and invalidate sessions.
6. Enable multi-factor authentication.
7. Block or rate-limit the source IP.
8. Enforce account lockout thresholds and MFA.
9. Block the source IP and review exposed services.
10. Close unnecessary ports and tighten firewall rules.
11. Confirm with the account owner that the login was legitimate.
12. Restrict privileged logins to approved hours/networks.

---
*Findings are produced by rule-based detection and require analyst validation.*
