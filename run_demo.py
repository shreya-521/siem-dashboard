"""One-command setup: generate synthetic logs, ingest them, run correlation, write sample report."""
import os
import sys
from datetime import datetime

from siem import db, engine, generator, reporting

BASE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE, "data", "logs")
DB_PATH = os.path.join(BASE, "data", "siem.db")


def main():
    counts = generator.write_logs(LOG_DIR)
    print("Generated logs:", counts)
    stats = engine.ingest_directory(DB_PATH, LOG_DIR)
    print(f"Ingested {stats['ingested']} events ({stats['skipped']} malformed lines skipped)")
    alerts = engine.run_analysis(DB_PATH)
    print(f"Correlation produced {len(alerts)} alerts:")
    for a in db.fetch_alerts(DB_PATH):
        print(f"  [{a.severity:<8}] {a.score:>3}  {a.rule:<16} {a.src_ip:<15} {a.description[:70]}")
    crit = next((a for a in alerts if a.rule == "multi_stage"), None)
    if crit:
        alerts_ip = db.fetch_alerts(DB_PATH, src_ip=crit.src_ip)
        ids = sorted({i for a in alerts_ip for i in a.evidence})
        report = reporting.build_incident_report(crit.src_ip, alerts_ip, db.fetch_events_by_ids(DB_PATH, ids))
        out = os.path.join(BASE, "docs", "sample_incident_report.md")
        with open(out, "w") as fh:
            fh.write(report)
        print("Sample incident report written to", os.path.relpath(out, BASE))
    print("\nNext: python app.py   ->  http://127.0.0.1:5000")


if __name__ == "__main__":
    sys.exit(main())
