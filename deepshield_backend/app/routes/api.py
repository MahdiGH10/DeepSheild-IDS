import json
import os
import random
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..models import Alert, AutomationRun, IncidentEvent, TrafficEvent
from ..services.automation import (
    build_html_dispatch_attachment_fields,
    dispatch_to_n8n,
    render_report,
)
from ..services.llm import interpret_alert_with_llm
from ..services.predictor import predictor_service

api_bp = Blueprint("api", __name__)

_DISPATCH_WORKERS = max(1, int(os.getenv("IDS_DISPATCH_WORKERS", "2")))
_DISPATCH_EXECUTOR = ThreadPoolExecutor(max_workers=_DISPATCH_WORKERS, thread_name_prefix="deepshield-dispatch")

ALLOWED_INCIDENT_STATUSES = {
    "new",
    "acknowledged",
    "investigating",
    "escalated",
    "resolved",
    "closed",
    "informational",
}

ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "new": {"acknowledged", "investigating", "escalated", "resolved", "closed"},
    "acknowledged": {"investigating", "escalated", "resolved", "closed"},
    "investigating": {"escalated", "resolved", "closed"},
    "escalated": {"investigating", "resolved", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
    "informational": {"closed"},
}


def _parse_optional_network(payload: dict) -> tuple[str | None, int | None]:
    raw_proto = payload.get("protocol")
    proto = str(raw_proto).strip()[:16] if raw_proto not in (None, "") else None
    dst_port: int | None = None
    if payload.get("dst_port") is not None:
        try:
            dst_port = int(payload.get("dst_port"))
            if dst_port < 0 or dst_port > 65535:
                dst_port = None
        except (TypeError, ValueError):
            dst_port = None
    return proto, dst_port


def _serialize_alert(row: Alert) -> dict:
    unknown_attack = _is_unidentified_attack_type(row.attack_type)
    return {
        "id": row.id,
        "timestamp": row.timestamp.isoformat() + "Z",
        "attack_type": row.attack_type,
        "confidence": row.confidence,
        "severity": row.severity,
        "source": row.source,
        "target": row.target,
        "status": row.status,
        "analyst_notes": row.analyst_notes,
        "indicators": json.loads(row.indicators or "[]"),
        "risk_explanation": row.risk_explanation,
        "protocol": getattr(row, "protocol", None),
        "dst_port": getattr(row, "dst_port", None),
        "unknown_attack": unknown_attack,
        "emergency_level": "HIGH_URGENCY" if unknown_attack else None,
    }


def _log_incident_event(
    *,
    alert_id: int,
    event_type: str,
    message: str,
    actor: str = "analyst",
    from_status: str | None = None,
    to_status: str | None = None,
) -> None:
    event = IncidentEvent(
        alert_id=alert_id,
        event_type=event_type,
        message=message,
        actor=actor,
        from_status=from_status,
        to_status=to_status,
    )
    db.session.add(event)


def _serialize_incident_event(evt: IncidentEvent) -> dict:
    return {
        "id": evt.id,
        "alert_id": evt.alert_id,
        "created_at": evt.created_at.isoformat() + "Z",
        "event_type": evt.event_type,
        "message": evt.message,
        "actor": evt.actor,
        "from_status": evt.from_status,
        "to_status": evt.to_status,
    }


def _serialize_automation_run(run: AutomationRun) -> dict:
    return {
        "id": run.id,
        "alert_id": run.alert_id,
        "created_at": run.created_at.isoformat() + "Z",
        "status": run.status,
        "format": run.format,
        "retry_count": run.retry_count,
        "response_status": run.response_status,
        "error_message": run.error_message,
        "request_payload": run.request_payload,
        "response_payload": run.response_payload,
    }


def _build_report_payload(
    *,
    alert: Alert,
    include_timeline: bool,
    include_interpretation: bool,
) -> dict:
    report_payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "alert": {
            "id": alert.id,
            "attack_type": alert.attack_type,
            "confidence": alert.confidence,
            "severity": alert.severity,
            "source": alert.source,
            "target": alert.target,
            "status": alert.status,
        },
        "indicators": json.loads(alert.indicators or "[]"),
        "risk_explanation": alert.risk_explanation,
        "analyst_notes": alert.analyst_notes,
    }

    if include_timeline:
        events = (
            IncidentEvent.query.filter(IncidentEvent.alert_id == alert.id)
            .order_by(IncidentEvent.created_at.asc())
            .all()
        )
        report_payload["timeline"] = [_serialize_incident_event(evt) for evt in events]

    if include_interpretation:
        llm_payload = {
            "id": alert.id,
            "attack_type": alert.attack_type,
            "confidence": alert.confidence,
            "severity": alert.severity,
            "source": alert.source,
            "target": alert.target,
            "indicators": json.loads(alert.indicators or "[]"),
            "risk_explanation": alert.risk_explanation,
            "status": alert.status,
        }
        report_payload["interpretation"] = interpret_alert_with_llm(llm_payload)

    if _normalize_severity(alert.severity) == "critical" and _is_unidentified_attack_type(alert.attack_type):
        report_payload["unidentified_attack"] = True
        report_payload["emergency_level"] = "HIGH_URGENCY"
        report_payload["recommended_actions"] = [
            "Declare high-urgency unknown attack response and assign a senior analyst immediately.",
            "Isolate the affected target segment from non-essential internal routes.",
            "Block or rate-limit the source path at the perimeter while preserving packet captures.",
            "Capture volatile evidence: recent flows, process list, auth logs, DNS queries, and outbound connections.",
            "Open an incident bridge and notify SOC lead, network owner, and incident response contact.",
            "Treat this as a potential zero-day or custom toolchain until classification is confirmed.",
        ]
        report_payload["attack_logs"] = _build_attack_logs_for_alert(alert)

    return report_payload


ATTACK_PROFILE_FEATURES: dict[str, list[str]] = {
    "dos": ["Flow Duration", "Total Fwd Packets", "Fwd Packet Length Mean", "Flow Bytes/s", "SYN Flag Count"],
    "ddos": ["Flow Packets/s", "Bwd Packet Length Mean", "Total Backward Packets", "ACK Flag Count", "Subflow Fwd Packets"],
    "portscan": ["Destination Port", "Flow Packets/s", "Bwd IAT Mean", "Fwd PSH Flags", "URG Flag Count"],
    "infiltration": ["Init_Win_bytes_forward", "Fwd Header Length", "Idle Min", "Packet Length Variance", "Down/Up Ratio"],
    "heartbleed": ["Packet Length Std", "Bwd Packet Length Max", "Flow IAT Std", "Fwd Segment Size Avg", "Active Mean"],
    "r2l": ["Failed Logins", "Login Attempts", "Service Requests", "Dst Host Count", "Srv Count"],
    "u2r": ["su_attempted", "num_root", "root_shell", "num_compromised", "logged_in"],
}


def _pick_profile_features(attack_type: str) -> list[str]:
    normalized = (attack_type or "").lower()
    for key, value in ATTACK_PROFILE_FEATURES.items():
        if key in normalized:
            return value
    return ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s", "Packet Length Mean", "Bwd Packet Length Std"]


def _build_shap_payload(attack_type: str) -> dict:
    features = _pick_profile_features(attack_type)
    shap_values: list[float] = []
    feature_values: list[int] = []
    for idx, _feature in enumerate(features):
        if idx < 3:
            base = 0.20 + random.random() * 0.75
        else:
            base = -0.65 + random.random() * 0.95
        shap_values.append(round(max(-1.0, min(1.0, base)), 3))
        feature_values.append(int((idx + 1) * (random.random() * 5000 + 200)))

    return {
        "features": features,
        "shap_values": shap_values,
        "feature_values": feature_values,
    }


def _resolve_shap_result_path(alert_id: int) -> Path:
    configured = (os.getenv("IDS_SHAP_RESULT_PATH", "") or "").strip()
    if configured:
        base = Path(configured).expanduser().resolve()
        if base.suffix:
            return base
        return base / f"alert_{alert_id}.json"

    instance_dir = Path(current_app.instance_path).resolve()
    return instance_dir / "shap_results" / f"alert_{alert_id}.json"


def _write_shap_result(alert_id: int, payload: dict) -> str:
    target = _resolve_shap_result_path(alert_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(target)


def _load_shap_result(alert_id: int) -> tuple[dict | None, str | None]:
    target = _resolve_shap_result_path(alert_id)
    if not target.exists():
        return None, None
    try:
        return json.loads(target.read_text(encoding="utf-8")), str(target)
    except Exception:
        return None, str(target)


def _require_analyst_api_key():
    expected = (os.getenv("IDS_ANALYST_API_KEY", "") or "").strip()
    if not expected:
        return None
    provided = (request.headers.get("x-api-key", "") or "").strip()
    if provided != expected:
        return jsonify({"error": "Missing or invalid analyst API key."}), 401
    return None


def _as_bool(env_value: str | None, default: bool = False) -> bool:
    if env_value is None:
        return default
    return str(env_value).strip().lower() in {"1", "true", "yes", "on"}


def _attack_family_key(attack_type: str | None) -> str:
    normalized = (attack_type or "").strip().lower()
    if predictor_service._is_benign_label(normalized):
        return "baseline"
    if "ddos" in normalized or "dos" in normalized:
        return "dos"
    if "portscan" in normalized:
        return "probe"
    if "heartbleed" in normalized or "infiltration" in normalized:
        return "u2r"
    if "ftp-patator" in normalized or "ssh-patator" in normalized or "brute force" in normalized or "sql injection" in normalized or "xss" in normalized:
        return "r2l"
    if "bot" in normalized:
        return "botnet"
    return normalized or "unknown"


_SEVERITY_ORDER: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_ACTIVE_INCIDENT_STATUSES = ["new", "acknowledged", "investigating", "escalated"]

_KNOWN_ATTACK_TOKENS: tuple[str, ...] = (
    "ddos",
    "dos",
    "portscan",
    "bot",
    "heartbleed",
    "infiltration",
    "ftp-patator",
    "ssh-patator",
    "brute force",
    "sql injection",
    "xss",
    "web attack",
    "u2r",
    "r2l",
    "probe",
)


def _normalize_severity(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    return normalized if normalized in _SEVERITY_ORDER else "informational"


def _is_unidentified_attack_type(attack_type: str | None) -> bool:
    normalized = (attack_type or "").strip().lower()
    if not normalized or predictor_service._is_benign_label(normalized):
        return False
    return not any(token in normalized for token in _KNOWN_ATTACK_TOKENS)


def _build_attack_logs_for_alert(alert: Alert, limit: int = 25) -> list[dict]:
    window_minutes = max(5, int(os.getenv("IDS_UNIDENTIFIED_LOG_WINDOW_MINUTES", "15")))
    since = alert.timestamp - timedelta(minutes=window_minutes)

    rows = (
        TrafficEvent.query.filter(
            TrafficEvent.timestamp >= since,
            TrafficEvent.source == alert.source,
        )
        .order_by(TrafficEvent.timestamp.desc())
        .limit(max(1, limit))
        .all()
    )

    return [
        {
            "timestamp": row.timestamp.isoformat() + "Z",
            "attack_type": row.attack_type,
            "confidence": row.confidence,
            "source": row.source,
        }
        for row in rows
    ]


def _is_mail_eligible_for_alert(alert: Alert) -> tuple[bool, str | None]:
    min_severity = _normalize_severity(os.getenv("IDS_EMAIL_MIN_SEVERITY", "high"))
    alert_severity = _normalize_severity(alert.severity)

    if _SEVERITY_ORDER.get(alert_severity, 0) >= _SEVERITY_ORDER.get(min_severity, 3):
        return True, None

    reason = (
        f"Dispatch skipped by policy: alert severity '{alert.severity}' is below "
        f"mail threshold '{min_severity}'."
    )
    return False, reason


def _check_auto_dispatch_rate_limit(alert: Alert) -> tuple[bool, str | None]:
    cooldown_seconds = max(0, int(os.getenv("IDS_AUTO_MAIL_COOLDOWN_SECONDS", "180")))
    max_per_window = max(1, int(os.getenv("IDS_AUTO_MAIL_MAX_PER_WINDOW", "3")))
    window_seconds = max(cooldown_seconds, int(os.getenv("IDS_AUTO_MAIL_WINDOW_SECONDS", "900")))

    now = datetime.utcnow()
    baseline = now - timedelta(seconds=window_seconds)

    recent_query = (
        AutomationRun.query.join(Alert, AutomationRun.alert_id == Alert.id)
        .filter(
            AutomationRun.created_at >= baseline,
            AutomationRun.status.in_(["queued", "delivered"]),
            Alert.attack_type == alert.attack_type,
            Alert.source == alert.source,
            Alert.target == alert.target,
        )
        .order_by(AutomationRun.created_at.desc())
    )

    latest = recent_query.first()
    if cooldown_seconds > 0 and latest:
        elapsed = (now - latest.created_at).total_seconds()
        if elapsed < cooldown_seconds:
            remaining = int(cooldown_seconds - elapsed)
            reason = (
                "Dispatch skipped by anti-spam cooldown: "
                f"attack '{alert.attack_type}' from '{alert.source}' to '{alert.target}' "
                f"must wait {remaining}s before next email."
            )
            return True, reason

    count_in_window = recent_query.count()
    if count_in_window >= max_per_window:
        reason = (
            "Dispatch skipped by anti-spam window cap: "
            f"already sent/queued {count_in_window} emails in last {window_seconds}s "
            f"for '{alert.attack_type}' from '{alert.source}' to '{alert.target}'."
        )
        return True, reason

    return False, None


def _check_global_attack_type_mail_limit(alert: Alert) -> tuple[bool, str | None]:
    """
    Limit auto-dispatch to at most one email per attack family within a cooldown window,
    regardless of source/target. Stops n8n spam when many alerts share the same family
    (e.g. simulator randomizing endpoints each event). Disable with IDS_AUTO_MAIL_GLOBAL_ATTACK_TYPE_LIMIT=0.
    """
    if not _as_bool(os.getenv("IDS_AUTO_MAIL_GLOBAL_ATTACK_TYPE_LIMIT", "1"), default=True):
        return False, None

    cooldown_seconds = max(30, int(os.getenv("IDS_AUTO_MAIL_GLOBAL_ATTACK_TYPE_COOLDOWN_SECONDS", "600")))
    now = datetime.utcnow()
    baseline = now - timedelta(seconds=cooldown_seconds)
    family = _attack_family_key(alert.attack_type)

    if family == "baseline":
        return True, "Auto dispatch skipped: baseline traffic is not eligible for email notifications."

    recent_runs = (
        AutomationRun.query.join(Alert, AutomationRun.alert_id == Alert.id)
        .filter(
            AutomationRun.created_at >= baseline,
            AutomationRun.status.in_(["queued", "delivered"]),
            Alert.id != alert.id,
        )
        .order_by(AutomationRun.created_at.desc())
        .all()
    )

    prev = next((run for run in recent_runs if _attack_family_key(run.alert.attack_type) == family), None)
    if not prev:
        return False, None

    elapsed = (now - prev.created_at).total_seconds()
    remaining = max(0, int(cooldown_seconds - elapsed))
    reason = (
        "Auto dispatch skipped: global attack-family mail limit — "
        f"family '{family}' was already notified within the last {cooldown_seconds}s "
        f"(retry in ~{remaining}s). Set IDS_AUTO_MAIL_GLOBAL_ATTACK_TYPE_LIMIT=0 to disable."
    )
    return True, reason


def _already_dispatched_for_active_signature(alert: Alert) -> tuple[bool, str | None]:
    existing = (
        AutomationRun.query.join(Alert, AutomationRun.alert_id == Alert.id)
        .filter(
            Alert.id != alert.id,
            Alert.attack_type == alert.attack_type,
            Alert.source == alert.source,
            Alert.target == alert.target,
            Alert.status.in_(_ACTIVE_INCIDENT_STATUSES),
            AutomationRun.status.in_(["queued", "delivered"]),
        )
        .order_by(AutomationRun.created_at.desc())
        .first()
    )

    if not existing:
        return False, None

    reason = (
        "Dispatch skipped by one-time policy: "
        f"an email was already queued/sent for active threat signature "
        f"'{alert.attack_type}' from '{alert.source}' to '{alert.target}' (run_id={existing.id})."
    )
    return True, reason


def _automation_run_request_payload_snapshot(dispatch_payload: dict) -> str:
    """Persist dispatch metadata without large base64 blobs."""
    lean = {
        k: v
        for k, v in dispatch_payload.items()
        if k not in {"attachment_pdf_base64", "attachment_log_base64", "attachment_html_report_base64"}
    }
    if dispatch_payload.get("attachment_html_report_base64"):
        lean["_attachment_html_included"] = True
    if dispatch_payload.get("attachment_pdf_base64"):
        lean["_attachment_pdf_included"] = True
    if dispatch_payload.get("attachment_log_base64"):
        lean["_attachment_log_included"] = True
    return json.dumps(lean, default=str)


def _dispatch_report_for_alert(
    *,
    alert: Alert,
    format_type: str,
    include_timeline: bool,
    include_interpretation: bool,
) -> tuple[AutomationRun, dict]:
    report_payload = _build_report_payload(
        alert=alert,
        include_timeline=include_timeline,
        include_interpretation=include_interpretation,
    )
    rendered_content, content_type = render_report(report_payload, format_type)

    dispatch_payload = {
        "format": format_type,
        "content_type": content_type,
        "report_payload": report_payload,
        "rendered_content": rendered_content,
    }
    if str(format_type).lower() == "html":
        dispatch_payload.update(build_html_dispatch_attachment_fields(report_payload))

    run = AutomationRun(alert_id=alert.id, format=format_type, status="queued")
    run.request_payload = _automation_run_request_payload_snapshot(dispatch_payload)
    db.session.add(run)
    db.session.commit()

    dispatch_result = dispatch_to_n8n(dispatch_payload)
    run.status = "delivered" if dispatch_result.get("ok") else "failed"
    run.retry_count = int(dispatch_result.get("attempts") or 0)
    run.error_message = dispatch_result.get("error")
    run.response_status = dispatch_result.get("response_status")
    run.response_payload = dispatch_result.get("response_body")
    db.session.commit()
    return run, dispatch_result


def _run_queued_dispatch(
    app,
    *,
    alert_id: int,
    run_id: int,
    format_type: str,
    include_timeline: bool,
    include_interpretation: bool,
    reason: str | None,
) -> None:
    with app.app_context():
        run = AutomationRun.query.get(run_id)
        alert = Alert.query.get(alert_id)
        if not run or not alert:
            return

        eligible, ineligible_reason = _is_mail_eligible_for_alert(alert)
        if not eligible:
            run.status = "skipped"
            run.retry_count = 0
            run.error_message = ineligible_reason
            db.session.commit()

            _log_incident_event(
                alert_id=alert.id,
                event_type="automation-dispatch-skipped",
                message=ineligible_reason or "Auto dispatch skipped by severity policy.",
                actor="system",
            )
            db.session.commit()
            return

        try:
            report_payload = _build_report_payload(
                alert=alert,
                include_timeline=include_timeline,
                include_interpretation=include_interpretation,
            )
            rendered_content, content_type = render_report(report_payload, format_type)

            dispatch_payload = {
                "format": format_type,
                "content_type": content_type,
                "report_payload": report_payload,
                "rendered_content": rendered_content,
            }
            if str(format_type).lower() == "html":
                dispatch_payload.update(build_html_dispatch_attachment_fields(report_payload))

            run.request_payload = _automation_run_request_payload_snapshot(dispatch_payload)
            db.session.commit()

            dispatch_result = dispatch_to_n8n(dispatch_payload)
            run.status = "delivered" if dispatch_result.get("ok") else "failed"
            run.retry_count = int(dispatch_result.get("attempts") or 0)
            run.error_message = dispatch_result.get("error")
            run.response_status = dispatch_result.get("response_status")
            run.response_payload = dispatch_result.get("response_body")

            _log_incident_event(
                alert_id=alert.id,
                event_type="automation-dispatch",
                message=(
                    f"Auto dispatch attempted after escalation ({reason or 'policy'}): "
                    f"status={run.status}, retries={run.retry_count}, response_status={run.response_status}"
                ),
                actor="system",
            )
            db.session.commit()
        except Exception as exc:
            run.status = "failed"
            run.error_message = str(exc)[:2000]
            db.session.commit()

            _log_incident_event(
                alert_id=alert.id,
                event_type="automation-dispatch",
                message=(
                    f"Auto dispatch failed unexpectedly after escalation ({reason or 'policy'}): "
                    f"{str(exc)[:240]}"
                ),
                actor="system",
            )
            db.session.commit()


def _apply_auto_escalation_policy(alert: Alert) -> tuple[str, str | None]:
    """
    Returns (result, reason)
      - result: "escalated" | "no-escalation"
    """
    if alert.status in {"escalated", "resolved", "closed", "informational"}:
        return "no-escalation", None

    severity = (alert.severity or "").strip().lower()
    if severity in {"critical", "high"}:
        old_status = alert.status
        alert.status = "escalated"
        reason = "auto-escalated: critical severity" if severity == "critical" else "auto-escalated: high severity"
        _log_incident_event(
            alert_id=alert.id,
            event_type="auto-escalation",
            message=f"Auto escalation triggered ({reason}).",
            actor="system",
            from_status=old_status,
            to_status="escalated",
        )
        db.session.commit()
        return "escalated", reason

    return "no-escalation", None


def _maybe_auto_dispatch_on_escalation(alert: Alert, reason: str | None) -> dict | None:
    if alert.status != "escalated":
        return None
    if not _as_bool(os.getenv("IDS_AUTO_DISPATCH_ON_ESCALATION", "1"), default=True):
        return None

    eligible, ineligible_reason = _is_mail_eligible_for_alert(alert)
    if not eligible:
        _log_incident_event(
            alert_id=alert.id,
            event_type="automation-dispatch-skipped",
            message=ineligible_reason or "Auto dispatch skipped by severity policy.",
            actor="system",
        )
        db.session.commit()
        return {
            "status": "skipped",
            "mode": "policy",
            "reason": ineligible_reason,
        }

    duplicate_dispatched, duplicate_reason = _already_dispatched_for_active_signature(alert)
    if duplicate_dispatched:
        _log_incident_event(
            alert_id=alert.id,
            event_type="automation-dispatch-skipped",
            message=duplicate_reason or "Auto dispatch skipped by one-time policy.",
            actor="system",
        )
        db.session.commit()
        return {
            "status": "skipped",
            "mode": "one-time",
            "reason": duplicate_reason,
        }

    global_limited, global_reason = _check_global_attack_type_mail_limit(alert)
    if global_limited:
        _log_incident_event(
            alert_id=alert.id,
            event_type="automation-dispatch-skipped",
            message=global_reason or "Auto dispatch skipped by global attack-type limit.",
            actor="system",
        )
        db.session.commit()
        return {
            "status": "skipped",
            "mode": "attack-type-limit",
            "reason": global_reason,
        }

    limited, rate_limit_reason = _check_auto_dispatch_rate_limit(alert)
    if limited:
        _log_incident_event(
            alert_id=alert.id,
            event_type="automation-dispatch-skipped",
            message=rate_limit_reason or "Auto dispatch skipped by anti-spam policy.",
            actor="system",
        )
        db.session.commit()
        return {
            "status": "skipped",
            "mode": "rate-limit",
            "reason": rate_limit_reason,
        }

    format_type = os.getenv("IDS_AUTO_DISPATCH_FORMAT", "html").strip().lower() or "html"
    if format_type not in {"json", "markdown", "html"}:
        format_type = "html"

    include_timeline = _as_bool(os.getenv("IDS_AUTO_DISPATCH_INCLUDE_TIMELINE", "1"), default=True)
    include_interpretation = _as_bool(os.getenv("IDS_AUTO_DISPATCH_INCLUDE_INTERPRETATION", "1"), default=True)

    run = AutomationRun(alert_id=alert.id, format=format_type, status="queued")
    db.session.add(run)
    db.session.commit()

    _log_incident_event(
        alert_id=alert.id,
        event_type="automation-dispatch-queued",
        message=f"Auto dispatch queued after escalation ({reason or 'policy'}): run_id={run.id}",
        actor="system",
    )
    db.session.commit()

    app_obj = current_app._get_current_object()
    _DISPATCH_EXECUTOR.submit(
        _run_queued_dispatch,
        app_obj,
        alert_id=alert.id,
        run_id=run.id,
        format_type=format_type,
        include_timeline=include_timeline,
        include_interpretation=include_interpretation,
        reason=reason,
    )

    return {
        "run_id": run.id,
        "status": "queued",
        "mode": "async",
    }


@api_bp.get("/")
def root():
    return jsonify({"name": "DeepShield API", "status": "ok"})


@api_bp.get("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "model_loaded": predictor_service.model_loaded,
            "model_runtime": predictor_service.runtime,
            "model_load_errors": predictor_service.load_errors,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    )


@api_bp.post("/predict")
def predict():
    payload = request.get_json(silent=True) or {}
    features = payload.get("features")
    source = payload.get("source", "sensor")
    target = payload.get("target", "asset")

    validated_features, validation_error = predictor_service.validate_features(features)
    if validation_error:
        return (
            jsonify(
                {
                    "error": validation_error,
                    "expected_feature_count": predictor_service.expected_feature_count,
                }
            ),
            400,
        )

    result = predictor_service.predict(validated_features)
    proto, dst_port = _parse_optional_network(payload)

    alert = Alert(
        attack_type=result["attack_type"],
        confidence=result["confidence"],
        severity=result["severity"],
        source=source,
        target=target,
        indicators=json.dumps(result["indicators"]),
        risk_explanation=result["risk_explanation"],
        status="new" if not predictor_service._is_benign_label(result["attack_type"]) else "informational",
        protocol=proto,
        dst_port=dst_port,
    )
    db.session.add(alert)
    db.session.commit()

    db.session.add(
        TrafficEvent(
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            source=source,
        )
    )
    db.session.commit()

    return jsonify({"alert_id": alert.id, "expected_feature_count": predictor_service.expected_feature_count, **result})


@api_bp.post("/ingest/traffic-event")
def ingest_traffic_event():
    payload = request.get_json(silent=True) or {}
    attack_type = str(payload.get("attack_type", "normal"))
    confidence = float(payload.get("confidence", 0.0))
    source = str(payload.get("source", "sensor"))

    event = TrafficEvent(attack_type=attack_type, confidence=confidence, source=source)
    db.session.add(event)
    db.session.commit()

    escalation_reason = None
    automation_result = None

    if not predictor_service._is_benign_label(attack_type):
        severity = predictor_service._severity_for_attack(attack_type, confidence)
        indicators = predictor_service._indicators_for_attack(attack_type)
        risk_explanation = f"Live telemetry flagged {attack_type} behavior."

        if _is_unidentified_attack_type(attack_type):
            severity = "Critical"
            indicators = [
                "Unknown/undocumented attack signature detected",
                "Pattern does not match approved attack taxonomy",
                "Immediate analyst triage required",
                "High-urgency emergency workflow activated",
                "Preserve telemetry and isolate target path immediately",
            ]
            risk_explanation = (
                f"Live telemetry flagged an unidentified attack pattern '{attack_type}'. "
                "Classified as Critical/high-urgency emergency for immediate cybersec investigation. "
                "Analyst action is required now: isolate the target path, preserve evidence, and escalate to incident response."
            )

        proto, dst_port = _parse_optional_network(payload)
        alert = Alert(
            attack_type=attack_type,
            confidence=confidence,
            severity=severity,
            source=source,
            target=str(payload.get("target", "asset")),
            indicators=json.dumps(indicators),
            risk_explanation=risk_explanation,
            status="new",
            protocol=proto,
            dst_port=dst_port,
        )
        db.session.add(alert)
        db.session.commit()

        escalation_result, escalation_reason = _apply_auto_escalation_policy(alert)
        if escalation_result == "escalated":
            automation_result = _maybe_auto_dispatch_on_escalation(alert, escalation_reason)

    response = {"status": "accepted"}
    if escalation_reason:
        response["escalation_reason"] = escalation_reason
    if automation_result:
        response["automation"] = automation_result
    return jsonify(response)


@api_bp.get("/alerts")
def list_alerts():
    limit = min(int(request.args.get("limit", 100)), 500)
    rows = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return jsonify([_serialize_alert(row) for row in rows])


@api_bp.get("/alerts/<int:alert_id>")
def get_alert(alert_id: int):
    row = Alert.query.get_or_404(alert_id)
    return jsonify(_serialize_alert(row))


@api_bp.patch("/alerts/<int:alert_id>")
def patch_alert(alert_id: int):
    row = Alert.query.get_or_404(alert_id)
    payload = request.get_json(silent=True) or {}

    new_status = payload.get("status")
    notes = payload.get("analyst_notes")
    actor = str(payload.get("actor", "analyst"))

    if notes is not None:
        row.analyst_notes = str(notes)[:4000]

    if new_status is not None:
        new_status = str(new_status)
        if new_status not in ALLOWED_INCIDENT_STATUSES:
            return jsonify({"error": f"Unsupported status '{new_status}'."}), 400
        allowed = ALLOWED_STATUS_TRANSITIONS.get(row.status, set())
        if new_status != row.status and new_status not in allowed:
            return (
                jsonify(
                    {
                        "error": f"Invalid transition from '{row.status}' to '{new_status}'.",
                        "allowed_next": sorted(list(allowed)),
                    }
                ),
                400,
            )

        old_status = row.status
        row.status = new_status
        if old_status != new_status:
            _log_incident_event(
                alert_id=row.id,
                event_type="status-change",
                message=f"Status changed from {old_status} to {new_status}.",
                actor=actor,
                from_status=old_status,
                to_status=new_status,
            )

    db.session.commit()
    return jsonify(_serialize_alert(row))


def _transition(alert_id: int, target_status: str):
    row = Alert.query.get_or_404(alert_id)
    allowed = ALLOWED_STATUS_TRANSITIONS.get(row.status, set())
    if target_status not in allowed:
        return (
            jsonify(
                {
                    "error": f"Invalid transition from '{row.status}' to '{target_status}'.",
                    "allowed_next": sorted(list(allowed)),
                }
            ),
            400,
        )
    old_status = row.status
    row.status = target_status
    _log_incident_event(
        alert_id=row.id,
        event_type="status-change",
        message=f"Status changed from {old_status} to {target_status}.",
        actor="analyst",
        from_status=old_status,
        to_status=target_status,
    )
    db.session.commit()
    return jsonify(_serialize_alert(row))


@api_bp.post("/incidents/<int:alert_id>/acknowledge")
def acknowledge_incident(alert_id: int):
    return _transition(alert_id, "acknowledged")


@api_bp.post("/incidents/<int:alert_id>/investigate")
def investigate_incident(alert_id: int):
    return _transition(alert_id, "investigating")


@api_bp.post("/incidents/<int:alert_id>/escalate")
def escalate_incident(alert_id: int):
    return _transition(alert_id, "escalated")


@api_bp.post("/incidents/<int:alert_id>/resolve")
def resolve_incident(alert_id: int):
    return _transition(alert_id, "resolved")


@api_bp.post("/incidents/<int:alert_id>/close")
def close_incident(alert_id: int):
    return _transition(alert_id, "closed")


@api_bp.get("/incidents/<int:alert_id>/timeline")
def incident_timeline(alert_id: int):
    Alert.query.get_or_404(alert_id)
    events = IncidentEvent.query.filter(IncidentEvent.alert_id == alert_id).order_by(IncidentEvent.created_at.asc()).all()
    return jsonify(
        [_serialize_incident_event(evt) for evt in events]
    )


@api_bp.get("/reports/incidents/<int:alert_id>/preview")
def preview_report(alert_id: int):
    alert = Alert.query.get_or_404(alert_id)
    format_type = str(request.args.get("format", "markdown")).lower()
    include_timeline = str(request.args.get("include_timeline", "1")).lower() not in {"0", "false", "no"}
    include_interpretation = str(request.args.get("include_interpretation", "0")).lower() in {"1", "true", "yes"}

    if format_type not in {"json", "markdown", "html"}:
        return jsonify({"error": "Unsupported format"}), 400

    report_payload = _build_report_payload(
        alert=alert,
        include_timeline=include_timeline,
        include_interpretation=include_interpretation,
    )

    rendered_content, content_type = render_report(report_payload, format_type)
    return jsonify(
        {
            "format": format_type,
            "content_type": content_type,
            "report_payload": report_payload,
            "rendered_content": rendered_content,
        }
    )


@api_bp.get("/dashboard/realtime")
def dashboard_realtime():
    window_seconds = min(max(int(request.args.get("window_seconds", 120)), 30), 3600)
    since = datetime.utcnow() - timedelta(seconds=window_seconds)
    events = TrafficEvent.query.filter(TrafficEvent.timestamp >= since).order_by(TrafficEvent.timestamp.asc()).all()

    points = [
        {
            "ts": e.timestamp.isoformat() + "Z",
            "attack_type": e.attack_type,
            "confidence": e.confidence,
            "source": e.source,
        }
        for e in events
    ]

    counts = Counter(e.attack_type for e in events)
    return jsonify(
        {
            "window_seconds": window_seconds,
            "points": points,
            "attack_breakdown": dict(counts),
            "total_events": len(points),
        }
    )


@api_bp.get("/ops/posture")
def ops_posture():
    now = datetime.utcnow()
    recent_window = now - timedelta(seconds=90)
    recent_events = (
        TrafficEvent.query.filter(TrafficEvent.timestamp >= recent_window)
        .order_by(TrafficEvent.timestamp.desc())
        .all()
    )

    recent_total = len(recent_events)
    recent_attack_like = sum(1 for e in recent_events if not predictor_service._is_benign_label(e.attack_type))

    if recent_total == 0:
        simulation_state = "idle"
    elif recent_attack_like == 0:
        simulation_state = "baseline"
    else:
        simulation_state = "attack-active"

    active_alerts = Alert.query.filter(Alert.status.in_(["new", "acknowledged", "investigating", "escalated"])).count()
    latest_event = recent_events[0].timestamp.isoformat() + "Z" if recent_events else None
    latest_run = AutomationRun.query.order_by(AutomationRun.created_at.desc()).first()
    webhook_url = (os.getenv("IDS_N8N_WEBHOOK_URL", "") or "").strip()
    webhook_secret = (os.getenv("IDS_N8N_WEBHOOK_SECRET", "") or "").strip()
    n8n_configured = bool(webhook_url and webhook_secret and "your-n8n-instance" not in webhook_url)

    return jsonify(
        {
            "services_ready": True,
            "backend_status": "healthy",
            "model_loaded": predictor_service.model_loaded,
            "model_load_errors": predictor_service.load_errors,
            "simulation_state": simulation_state,
            "recent_event_count": recent_total,
            "recent_attack_like_count": recent_attack_like,
            "active_alerts": active_alerts,
            "last_event_at": latest_event,
            "n8n_configured": n8n_configured,
            "latest_automation_run": (
                {
                    "id": latest_run.id,
                    "alert_id": latest_run.alert_id,
                    "status": latest_run.status,
                    "format": latest_run.format,
                    "retry_count": latest_run.retry_count,
                    "response_status": latest_run.response_status,
                    "error_message": latest_run.error_message,
                    "created_at": latest_run.created_at.isoformat() + "Z",
                }
                if latest_run
                else None
            ),
            "timestamp": now.isoformat() + "Z",
        }
    )


@api_bp.post("/alerts/<int:alert_id>/interpretation")
def interpretation(alert_id: int):
    alert = Alert.query.get_or_404(alert_id)
    payload = {
        "id": alert.id,
        "attack_type": alert.attack_type,
        "confidence": alert.confidence,
        "severity": alert.severity,
        "source": alert.source,
        "target": alert.target,
        "indicators": json.loads(alert.indicators or "[]"),
        "risk_explanation": alert.risk_explanation,
        "status": alert.status,
    }
    result = interpret_alert_with_llm(payload)
    return jsonify(result)


@api_bp.post("/alerts/<int:alert_id>/shap-sync")
def shap_sync(alert_id: int):
    auth_error = _require_analyst_api_key()
    if auth_error:
        return auth_error
    alert = Alert.query.get_or_404(alert_id)
    payload = _build_shap_payload(alert.attack_type)
    output_path = _write_shap_result(alert.id, payload)
    return jsonify(
        {
            "attack_type": alert.attack_type,
            "output_path": output_path,
            "shap": payload,
        }
    )


@api_bp.get("/alerts/<int:alert_id>/shap-result")
def shap_result(alert_id: int):
    auth_error = _require_analyst_api_key()
    if auth_error:
        return auth_error

    alert = Alert.query.get_or_404(alert_id)
    payload, output_path = _load_shap_result(alert.id)
    if not payload:
        payload = _build_shap_payload(alert.attack_type)
        output_path = _write_shap_result(alert.id, payload)

    return jsonify(
        {
            "attack_type": alert.attack_type,
            "output_path": output_path,
            "shap": payload,
        }
    )


@api_bp.post("/automation/incidents/<int:alert_id>/dispatch-report")
def dispatch_report(alert_id: int):
    alert = Alert.query.get_or_404(alert_id)
    body = request.get_json(silent=True) or {}
    format_type = str(body.get("format", "json")).lower()
    include_timeline = bool(body.get("include_timeline", True))
    include_interpretation = bool(body.get("include_interpretation", False))
    if format_type not in {"json", "markdown", "html"}:
        return jsonify({"error": "Unsupported format"}), 400

    eligible, ineligible_reason = _is_mail_eligible_for_alert(alert)
    if not eligible:
        run = AutomationRun(alert_id=alert.id, format=format_type, status="skipped")
        run.retry_count = 0
        run.error_message = ineligible_reason
        run.request_payload = json.dumps(
            {
                "format": format_type,
                "include_timeline": include_timeline,
                "include_interpretation": include_interpretation,
                "skipped_by_policy": True,
                "reason": ineligible_reason,
            },
            default=str,
        )
        db.session.add(run)

        _log_incident_event(
            alert_id=alert.id,
            event_type="automation-dispatch-skipped",
            message=ineligible_reason or "Manual dispatch skipped by severity policy.",
            actor="analyst",
        )
        db.session.commit()

        return jsonify(
            {
                "run_id": run.id,
                "status": "skipped",
                "error": ineligible_reason,
                "reason": ineligible_reason,
                "retry_count": 0,
                "response_status": None,
            }
        )

    run, dispatch_result = _dispatch_report_for_alert(
        alert=alert,
        format_type=format_type,
        include_timeline=include_timeline,
        include_interpretation=include_interpretation,
    )

    return jsonify(
        {
            "run_id": run.id,
            "status": run.status,
            "error": run.error_message,
            "reason": run.error_message,
            "retry_count": run.retry_count,
            "response_status": run.response_status,
        }
    )


@api_bp.get("/automation/incidents/<int:alert_id>/runs")
def get_automation_runs(alert_id: int):
    Alert.query.get_or_404(alert_id)
    runs = AutomationRun.query.filter(AutomationRun.alert_id == alert_id).order_by(AutomationRun.created_at.desc()).all()
    return jsonify([_serialize_automation_run(run) for run in runs])
