import unittest
from datetime import datetime, timedelta

from siem import rules
from siem.engine import analyze
from siem.models import Event, is_internal, severity_label

T0 = datetime(2026, 10, 30, 12, 0, 0)
_next_id = [0]


def ev(offset_s, source="auth", ip="203.0.113.5", **kw):
    _next_id[0] += 1
    return Event(ts=T0 + timedelta(seconds=offset_s), source=source, src_ip=ip, id=_next_id[0], **kw)


def fail(t, ip="203.0.113.5", user="bob"):
    return ev(t, "auth", ip, user=user, result="FAIL")


def ok(t, ip="203.0.113.5", user="bob", base=None):
    e = ev(t, "auth", ip, user=user, result="SUCCESS")
    if base:
        e.ts = base + timedelta(seconds=t)
    return e


def probe(t, port, ip="203.0.113.5"):
    return ev(t, "firewall", ip, dst_port=port, action="DENY")


class SeverityTests(unittest.TestCase):
    def test_labels(self):
        self.assertEqual([severity_label(s) for s in (0, 39, 40, 69, 70, 89, 90, 100)],
                         ["Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"])

    def test_internal_detection(self):
        self.assertTrue(is_internal("10.1.2.3") and is_internal("192.168.0.9") and is_internal("172.16.5.5"))
        self.assertFalse(is_internal("203.0.113.9") or is_internal("8.8.8.8") or is_internal("garbage"))


class BruteForceTests(unittest.TestCase):
    def test_fires_at_threshold(self):
        a = rules.brute_force([fail(i * 10) for i in range(5)])      # 5 fails in 40s
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].rule, "brute_force")
        self.assertEqual(a[0].severity, "High")
        self.assertEqual(len(a[0].evidence), 5)

    def test_below_threshold_is_silent(self):
        self.assertEqual(rules.brute_force([fail(i * 10) for i in range(4)]), [])

    def test_outside_window_is_silent(self):
        # 5 failures, but 60s apart -> never 5 inside any 120s window
        self.assertEqual(rules.brute_force([fail(i * 60) for i in range(5)]), [])

    def test_different_ips_not_mixed(self):
        evs = [fail(i * 5, ip="1.1.1.1") for i in range(3)] + [fail(i * 5 + 1, ip="2.2.2.2") for i in range(3)]
        self.assertEqual(rules.brute_force(evs), [])

    def test_long_attack_is_one_alert(self):
        self.assertEqual(len(rules.brute_force([fail(i * 20) for i in range(30)])), 1)

    def test_successes_ignored(self):
        self.assertEqual(rules.brute_force([ok(i) for i in range(10)]), [])

    def test_two_separate_bursts(self):
        evs = [fail(i * 5) for i in range(5)] + [fail(3600 + i * 5) for i in range(5)]
        self.assertEqual(len(rules.brute_force(evs)), 2)


class CompromiseTests(unittest.TestCase):
    def test_success_after_failures(self):
        a = rules.compromise([fail(0), fail(10), fail(20), ok(30)])
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].score, 85)

    def test_typo_does_not_alert(self):
        self.assertEqual(rules.compromise([fail(0), fail(10), ok(20)]), [])

    def test_old_failures_expire(self):
        self.assertEqual(rules.compromise([fail(0), fail(10), fail(20), ok(1000)]), [])

    def test_other_ip_success_ignored(self):
        self.assertEqual(rules.compromise([fail(0), fail(5), fail(10), ok(15, ip="9.9.9.9")]), [])


class PortScanTests(unittest.TestCase):
    def test_scan_detected(self):
        a = rules.port_scan([probe(i, 1000 + i) for i in range(10)])
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].rule, "port_scan")

    def test_repeated_same_port_is_not_scan(self):
        self.assertEqual(rules.port_scan([probe(i, 443) for i in range(50)]), [])

    def test_nine_ports_is_silent(self):
        self.assertEqual(rules.port_scan([probe(i, 1000 + i) for i in range(9)]), [])

    def test_slow_scan_is_silent(self):
        self.assertEqual(rules.port_scan([probe(i * 30, 1000 + i) for i in range(10)]), [])


class OffHoursTests(unittest.TestCase):
    def _login(self, hour, user="admin", ip="203.0.113.5"):
        return Event(ts=datetime(2026, 10, 30, hour, 30), source="auth", src_ip=ip, user=user,
                     result="SUCCESS", id=1)

    def test_night_admin_login(self):
        a = rules.off_hours_admin([self._login(2)])
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].score, 75)           # external

    def test_internal_scores_lower(self):
        self.assertEqual(rules.off_hours_admin([self._login(23, ip="10.0.1.9")])[0].score, 55)

    def test_working_hours_ok(self):
        self.assertEqual(rules.off_hours_admin([self._login(9), self._login(17)]), [])

    def test_boundaries(self):
        self.assertEqual(len(rules.off_hours_admin([self._login(7)])), 1)
        self.assertEqual(len(rules.off_hours_admin([self._login(18)])), 1)

    def test_normal_user_ignored(self):
        self.assertEqual(rules.off_hours_admin([self._login(3, user="alice")]), [])


class WebAttackTests(unittest.TestCase):
    def _w(self, t, path):
        return ev(t, "web", "192.0.2.44", path=path, http_status=200)

    def test_sqli_detected_even_when_url_encoded(self):
        a = rules.web_attack([self._w(0, "/search?q=%27%20OR%201%3D1--")])
        self.assertEqual(len(a), 1)
        self.assertIn("SQL injection", a[0].description)

    def test_traversal_and_xss(self):
        a = rules.web_attack([self._w(0, "/f?x=../../etc/passwd"), self._w(5, "/c?t=<script>alert(1)</script>")])
        self.assertEqual(len(a), 1)                 # grouped into one burst
        self.assertEqual(len(a[0].evidence), 2)

    def test_benign_paths(self):
        self.assertEqual(rules.web_attack([self._w(0, "/"), self._w(1, "/api/items?id=5")]), [])


class MultiStageTests(unittest.TestCase):
    def _chain(self, ip="198.51.100.1", skip=None):
        evs = [probe(i, 2000 + i, ip) for i in range(12)]
        evs += [fail(100 + i * 5, ip, "admin") for i in range(6)]
        evs += [ok(140, ip, "admin")]
        if skip == "scan":
            evs = [e for e in evs if e.source != "firewall"]
        if skip == "brute":
            evs = [e for e in evs if e.result != "FAIL"]
        return evs

    def test_full_chain_is_critical(self):
        alerts = analyze(self._chain())
        ms = [a for a in alerts if a.rule == "multi_stage"]
        self.assertEqual(len(ms), 1)
        self.assertEqual((ms[0].severity, ms[0].score), ("Critical", 100))
        self.assertEqual(alerts[0].rule, "multi_stage")          # sorted to the top
        self.assertGreater(len(ms[0].evidence), 15)

    def test_missing_scan_no_multi_stage(self):
        self.assertFalse([a for a in analyze(self._chain(skip="scan")) if a.rule == "multi_stage"])

    def test_missing_compromise_no_multi_stage(self):
        evs = [e for e in self._chain() if e.result != "SUCCESS"]
        self.assertFalse([a for a in analyze(evs) if a.rule == "multi_stage"])

    def test_stages_from_different_ips_not_correlated(self):
        evs = ([probe(i, 2000 + i, "1.1.1.1") for i in range(12)]
               + [fail(100 + i * 5, "2.2.2.2", "admin") for i in range(6)] + [ok(140, "2.2.2.2", "admin")])
        self.assertFalse([a for a in analyze(evs) if a.rule == "multi_stage"])

    def test_stages_too_far_apart(self):
        evs = [probe(i, 2000 + i, "1.1.1.1") for i in range(12)]
        evs += [fail(7200 + i * 5, "1.1.1.1", "admin") for i in range(6)] + [ok(7240, "1.1.1.1", "admin")]
        self.assertFalse([a for a in analyze(evs) if a.rule == "multi_stage"])


if __name__ == "__main__":
    unittest.main()
