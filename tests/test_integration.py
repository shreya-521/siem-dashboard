"""End-to-end: generator -> parser -> SQLite -> correlation -> Flask dashboard."""
import os
import shutil
import tempfile
import unittest
from datetime import datetime

from app import create_app
from siem import db, engine, generator, reporting
from siem.generator import SCENARIOS


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.log_dir = os.path.join(cls.tmp, "logs")
        cls.db = os.path.join(cls.tmp, "t.db")
        generator.write_logs(cls.log_dir)
        cls.stats = engine.ingest_directory(cls.db, cls.log_dir)
        cls.alerts = engine.run_analysis(cls.db)
        cls.client = create_app(cls.db).test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def rules_for(self, ip):
        return {a.rule for a in self.alerts if a.src_ip == ip}


class PipelineTests(Base):

    def test_malformed_lines_skipped_not_crashing(self):
        self.assertEqual(self.stats["skipped"], 2)
        self.assertGreater(self.stats["ingested"], 400)

    def test_generator_is_deterministic(self):
        a = generator.generate(datetime(2026, 10, 30), seed=1)
        b = generator.generate(datetime(2026, 10, 30), seed=1)
        self.assertEqual(a, b)

    def test_multi_stage_attacker_found(self):
        self.assertEqual(self.rules_for(SCENARIOS["multi_stage"]),
                         {"port_scan", "brute_force", "compromise", "off_hours_admin", "multi_stage"})

    def test_single_stage_scenarios(self):
        self.assertEqual(self.rules_for(SCENARIOS["brute_only"]), {"brute_force"})
        self.assertEqual(self.rules_for(SCENARIOS["scan_only"]), {"port_scan"})
        self.assertEqual(self.rules_for(SCENARIOS["web_attacker"]), {"web_attack"})
        self.assertEqual(self.rules_for(SCENARIOS["off_hours_internal"]), {"off_hours_admin"})

    def test_no_false_positives_on_decoys(self):
        self.assertEqual(self.rules_for(SCENARIOS["slow_guesser"]), set())
        self.assertEqual(self.rules_for("10.0.1.11"), set())     # alice's typos
        flagged = {a.src_ip for a in self.alerts}
        self.assertEqual(flagged, {SCENARIOS[k] for k in
                                   ("multi_stage", "brute_only", "scan_only", "web_attacker", "off_hours_internal")})

    def test_only_one_critical(self):
        crit = [a for a in self.alerts if a.severity == "Critical"]
        self.assertEqual([a.rule for a in crit], ["multi_stage"])

    def test_analysis_is_idempotent(self):
        before = len(db.fetch_alerts(self.db))
        engine.run_analysis(self.db)
        self.assertEqual(len(db.fetch_alerts(self.db)), before)

    def test_evidence_links_resolve_to_real_events(self):
        for a in db.fetch_alerts(self.db):
            self.assertEqual(len(db.fetch_events_by_ids(self.db, a.evidence)), len(a.evidence))
            self.assertTrue(a.evidence)


class DashboardTests(Base):
    """HTTP-level checks against the Flask app."""

    def test_dashboard_renders(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Multi-stage attack", r.data)

    def test_filter_by_severity(self):
        r = self.client.get("/?severity=Critical")
        self.assertIn(b"198.51.100.23", r.data)
        self.assertNotIn(b"203.0.113.50", r.data)

    def test_search_filter(self):
        r = self.client.get("/?q=203.0.113.77")
        self.assertIn(b"Port scan", r.data)
        self.assertNotIn(b"Brute-force", r.data)

    def test_alert_detail_and_404(self):
        first = db.fetch_alerts(self.db)[0]
        self.assertEqual(self.client.get(f"/alerts/{first.id}").status_code, 200)
        self.assertEqual(self.client.get("/alerts/99999").status_code, 404)

    def test_status_update(self):
        a = db.fetch_alerts(self.db, rule="port_scan")[0]
        r = self.client.post(f"/alerts/{a.id}/status", data={"status": "resolved"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(db.get_alert(self.db, a.id).status, "resolved")
        self.assertEqual(self.client.post(f"/alerts/{a.id}/status", data={"status": "hacked"}).status_code, 400)
        db.set_status(self.db, a.id, "open")

    def test_incident_pages_and_report_download(self):
        self.assertEqual(self.client.get("/incidents").status_code, 200)
        self.assertEqual(self.client.get("/incidents/198.51.100.23").status_code, 200)
        self.assertEqual(self.client.get("/incidents/1.2.3.4").status_code, 404)
        r = self.client.get("/incidents/198.51.100.23/report.md")
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers["Content-Disposition"])
        text = r.data.decode()
        self.assertIn("# Incident Report: 198.51.100.23", text)
        self.assertIn("Critical", text)
        self.assertIn("Recommended actions", text)

    def test_api_stats(self):
        j = self.client.get("/api/stats").get_json()
        self.assertEqual(j["by_severity"]["Critical"], 1)
        self.assertEqual(j["total_alerts"], len(self.alerts))

    def test_reanalyse_endpoint(self):
        self.assertEqual(self.client.post("/analyze").status_code, 302)

    def test_log_content_is_html_escaped(self):
        """A malicious log line must not become live HTML in the dashboard (stored XSS check)."""
        tmp = tempfile.mkdtemp()
        try:
            p = os.path.join(tmp, "x.db")
            db.init_db(p)
            lines = ["2026-10-30T12:00:%02d web src=192.0.2.9 method=GET path=/x?q=<script>alert(1)</script> status=200" % i
                     for i in range(2)]
            from siem.parser import parse_lines
            db.insert_events(p, parse_lines(lines)[0])
            engine.run_analysis(p)
            r = create_app(p).test_client().get("/incidents/192.0.2.9")
            self.assertEqual(r.status_code, 200)
            self.assertNotIn(b"<script>alert(1)</script>", r.data)
            self.assertIn(b"&lt;script&gt;", r.data)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
