"""Flask dashboard for the Security Event Correlation & Incident Response project."""
import os
from collections import Counter, defaultdict

from flask import (Flask, Response, abort, jsonify, redirect, render_template, request, url_for)

from siem import db, engine, reporting
from siem.models import SEVERITY_ORDER, severity_label

BASE = os.path.dirname(os.path.abspath(__file__))
RULE_LABELS = {"multi_stage": "Multi-stage attack", "brute_force": "Brute force",
               "compromise": "Account compromise", "port_scan": "Port scan",
               "off_hours_admin": "Off-hours admin login", "web_attack": "Web attack"}


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.environ.get("SIEM_DB", os.path.join(BASE, "data", "siem.db"))
    path = lambda: app.config["DB_PATH"]

    @app.context_processor
    def helpers():
        return {"rule_labels": RULE_LABELS, "severities": SEVERITY_ORDER}

    @app.route("/")
    def dashboard():
        f = {k: request.args.get(k, "").strip() for k in ("severity", "rule", "status", "q")}
        everything = db.fetch_alerts(path())
        shown = db.fetch_alerts(path(), **f)
        sev = Counter(a.severity for a in everything)
        rules = Counter(a.rule for a in everything)
        hourly = [0] * 24
        for a in everything:
            hourly[a.start_ts.hour] += 1
        return render_template(
            "dashboard.html", alerts=shown, total=len(everything),
            sev_counts={s: sev.get(s, 0) for s in SEVERITY_ORDER}, rule_counts=rules,
            open_count=sum(1 for a in everything if a.status != "resolved"),
            hourly=hourly, max_hourly=max(hourly) or 1, events=db.count_events(path()), f=f)

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        alert = db.get_alert(path(), alert_id) or abort(404)
        return render_template("alert.html", a=alert, events=db.fetch_events_by_ids(path(), alert.evidence))

    @app.post("/alerts/<int:alert_id>/status")
    def alert_status(alert_id):
        if not db.set_status(path(), alert_id, request.form.get("status", "")):
            abort(400)
        return redirect(request.form.get("next") or url_for("alert_detail", alert_id=alert_id))

    @app.route("/incidents")
    def incidents():
        groups = defaultdict(list)
        for a in db.fetch_alerts(path()):
            groups[a.src_ip].append(a)
        rows = [{"ip": ip, "alerts": al, "score": max(a.score for a in al),
                 "severity": severity_label(max(a.score for a in al)),
                 "first": min(a.start_ts for a in al), "last": max(a.end_ts for a in al),
                 "rules": sorted({a.rule for a in al}),
                 "open": sum(1 for a in al if a.status != "resolved")} for ip, al in groups.items()]
        rows.sort(key=lambda r: (-r["score"], r["first"]))
        return render_template("incidents.html", rows=rows)

    def _incident(ip):
        alerts = db.fetch_alerts(path(), src_ip=ip)
        if not alerts:
            abort(404)
        ids = sorted({i for a in alerts for i in a.evidence})
        return alerts, db.fetch_events_by_ids(path(), ids)

    @app.route("/incidents/<ip>")
    def incident_detail(ip):
        alerts, events = _incident(ip)
        return render_template("incident.html", ip=ip, alerts=sorted(alerts, key=lambda a: a.start_ts),
                               events=events, score=max(a.score for a in alerts),
                               severity=severity_label(max(a.score for a in alerts)))

    @app.route("/incidents/<ip>/report.md")
    def incident_report(ip):
        alerts, events = _incident(ip)
        body = reporting.build_incident_report(ip, alerts, events)
        return Response(body, mimetype="text/markdown", headers={
            "Content-Disposition": f"attachment; filename=incident_{ip.replace('.', '_')}.md"})

    @app.post("/analyze")
    def analyze():
        engine.run_analysis(path())
        return redirect(url_for("dashboard"))

    @app.route("/api/stats")
    def api_stats():
        alerts = db.fetch_alerts(path())
        return jsonify(total_alerts=len(alerts),
                       by_severity=dict(Counter(a.severity for a in alerts)),
                       by_rule=dict(Counter(a.rule for a in alerts)),
                       events=db.count_events(path()))

    return app


if __name__ == "__main__":
    application = create_app()
    if not os.path.exists(application.config["DB_PATH"]):
        raise SystemExit("No database found. Run `python run_demo.py` first.")
    application.run(debug=False)
