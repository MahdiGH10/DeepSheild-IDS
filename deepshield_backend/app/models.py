from datetime import datetime
from .extensions import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    attack_type = db.Column(db.String(64), nullable=False)
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    severity = db.Column(db.String(32), nullable=False, default="Informational")
    source = db.Column(db.String(128), nullable=False, default="unknown")
    target = db.Column(db.String(128), nullable=False, default="unknown")
    indicators = db.Column(db.Text, nullable=False, default="[]")
    risk_explanation = db.Column(db.Text, nullable=False, default="No explanation yet.")
    status = db.Column(db.String(32), nullable=False, default="new")
    analyst_notes = db.Column(db.Text, nullable=True)
    protocol = db.Column(db.String(16), nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)


class TrafficEvent(db.Model):
    __tablename__ = "traffic_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    attack_type = db.Column(db.String(64), nullable=False, default="normal")
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    source = db.Column(db.String(128), nullable=False, default="sensor")


class AutomationRun(db.Model):
    __tablename__ = "automation_runs"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    status = db.Column(db.String(32), nullable=False, default="queued")
    format = db.Column(db.String(16), nullable=False, default="json")
    retry_count = db.Column(db.Integer, nullable=False, default=0)
    request_payload = db.Column(db.Text, nullable=True)
    response_status = db.Column(db.Integer, nullable=True)
    response_payload = db.Column(db.Text, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    alert = db.relationship("Alert", backref="automation_runs")


class IncidentEvent(db.Model):
    __tablename__ = "incident_events"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    event_type = db.Column(db.String(32), nullable=False, default="status-change")
    message = db.Column(db.Text, nullable=False, default="")
    actor = db.Column(db.String(64), nullable=False, default="analyst")
    from_status = db.Column(db.String(32), nullable=True)
    to_status = db.Column(db.String(32), nullable=True)

    alert = db.relationship("Alert", backref="incident_events")
