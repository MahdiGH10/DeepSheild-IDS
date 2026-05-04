import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime
from html import escape
from pathlib import Path

import requests


_ATTACK_EXPLANATION_FALLBACKS: dict[str, str] = {
    "unknown": (
        "DeepShield detected an unidentified attack pattern that does not match the approved attack taxonomy. "
        "This should be treated as a high-urgency emergency because it may represent a zero-day exploit chain, "
        "custom adversary tooling, or a new variant that the normal classifier has not seen before. Immediate "
        "containment, evidence preservation, and senior analyst review are required."
    ),
    "ddos": (
        "A Distributed Denial of Service attack floods the target system with an overwhelming volume "
        "of traffic from multiple sources simultaneously. The goal is to exhaust server resources — "
        "CPU, memory, or bandwidth — until legitimate users can no longer access the service. "
        "In enterprise environments, DDoS attacks can cause complete service outages within minutes "
        "and are often used as a distraction while a secondary breach occurs."
    ),
    "bruteforce": (
        "A brute force credential attack was detected against SSH services on the target node. "
        "The attacker is systematically trying thousands of username/password combinations to gain "
        "unauthorized remote access. Successful exploitation would give the attacker full shell access "
        "to the target system, potentially compromising the entire network segment."
    ),
    "ssh-patator": (
        "A brute force credential attack was detected against SSH services on the target node. "
        "The attacker is systematically trying thousands of username/password combinations to gain "
        "unauthorized remote access. Successful exploitation would give the attacker full shell access "
        "to the target system, potentially compromising the entire network segment."
    ),
    "portscan": (
        "A systematic port scanning operation was detected originating from a suspicious source. "
        "Port scanning is typically the reconnaissance phase before a targeted attack — the attacker "
        "is mapping open services and vulnerabilities on your network. This behavior strongly suggests "
        "an imminent targeted attack is being planned against your infrastructure."
    ),
    "dos": (
        "A Denial of Service attack is actively degrading the performance of the target system by "
        "sending a high volume of malformed or resource-intensive requests. Unlike DDoS, this originates "
        "from a single source and may indicate a compromised internal machine being used as an attack "
        "vector, suggesting a possible insider threat or prior compromise."
    ),
    "webattack": (
        "A web application attack has been detected targeting your HTTP/HTTPS services. The attack "
        "patterns are consistent with SQL injection or Cross-Site Scripting attempts designed to extract "
        "sensitive database content or hijack user sessions. Web attacks are among the most common entry "
        "points for full network breaches."
    ),
    "bot": (
        "Botnet command-and-control traffic has been detected from a node on your network. This indicates "
        "that one or more internal machines may already be compromised and are receiving instructions from "
        "an external attacker. This is a serious indicator of an active breach that may have been ongoing "
        "for days or weeks undetected."
    ),
}

_ATTACK_INDICATOR_FALLBACKS: dict[str, list[str]] = {
    "unknown": [
        "Attack label does not match the known DeepShield taxonomy",
        "Telemetry pattern is malicious but classification confidence cannot map to a known family",
        "Emergency workflow activated for high-urgency unknown signature",
        "Target path must be isolated while packet and flow evidence is preserved",
        "Treat as possible zero-day or custom adversary toolchain",
    ],
    "ddos": [
        "Packet rate exceeded 50,000 packets/second threshold",
        "Flow duration abnormally short (< 0.5 seconds average)",
        "Backward packet count near zero (one-directional flood)",
        "Source IP entropy unusually high (distributed sources)",
        "Fwd Header Length anomaly detected",
    ],
    "bruteforce": [
        "847 failed authentication attempts in 15 minutes",
        "Repeated flows to port 22 from same source",
        "Regular timing intervals consistent with automated tools",
        "No successful handshake completion detected",
        "Pattern matches known SSH-Patator tool signature",
    ],
    "ssh-patator": [
        "847 failed authentication attempts in 15 minutes",
        "Repeated flows to port 22 from same source",
        "Regular timing intervals consistent with automated tools",
        "No successful handshake completion detected",
        "Pattern matches known SSH-Patator tool signature",
    ],
    "portscan": [
        "1,240 unique destination ports probed in 60 seconds",
        "Extremely short flow duration (< 0.1 seconds per flow)",
        "Low bytes-per-packet ratio (SYN-only packets detected)",
        "Sequential port ordering pattern detected",
        "No established connections — purely reconnaissance",
    ],
    "dos": [
        "Packet burst exceeded single-source baseline by 18x",
        "Malformed or oversized request ratio surpassed anomaly threshold",
        "Service response latency degraded by 420%",
        "Sustained one-source flow pressure on critical service ports",
        "Connection reset spikes indicate service stress conditions",
    ],
    "webattack": [
        "HTTP query strings matched SQL injection token patterns",
        "Repeated payloads containing XSS script fragments",
        "Abnormal POST body entropy detected on login endpoint",
        "Rapid path traversal attempts against admin routes",
        "Suspicious user-agent rotation consistent with attack tooling",
    ],
    "bot": [
        "Periodic beacon traffic to known command-and-control profile",
        "DNS request patterns align with dynamic C2 resolution behavior",
        "Unexpected lateral traffic from previously quiet host",
        "Outbound destination reputation score exceeded policy threshold",
    ],
}

_ATTACK_ACTION_FALLBACKS: dict[str, list[str]] = {
    "unknown": [
        "Declare high-urgency unknown attack response and assign a senior analyst immediately.",
        "Isolate the affected target segment from non-essential internal routes.",
        "Block or rate-limit the source path at the perimeter while preserving packet captures.",
        "Capture volatile evidence: recent flows, process list, auth logs, DNS queries, and outbound connections.",
        "Open an incident bridge and notify SOC lead, network owner, and incident response contact.",
        "Treat this as a potential zero-day or custom toolchain until classification is confirmed.",
    ],
    "ddos": [
        "Immediately enable rate limiting on affected network interfaces — limit to 1,000 packets/second per source IP.",
        "Contact upstream ISP to activate DDoS scrubbing service if traffic volume exceeds 10 Gbps.",
        "Block source IP ranges identified in the flow logs using firewall ACL rules.",
        "Redirect traffic through CDN/WAF to absorb volumetric load.",
        "Notify the NOC team and activate the DDoS response runbook.",
        "Document attack start time and preserve flow logs for forensic analysis.",
    ],
    "bruteforce": [
        "Immediately block the source IP at the perimeter firewall.",
        "Disable password authentication on SSH — enforce key-based authentication only.",
        "Audit all recent successful logins on the target node for unauthorized access.",
        "Enable fail2ban or equivalent with a 15-minute ban threshold after 5 failed attempts.",
    ],
    "ssh-patator": [
        "Immediately block the source IP at the perimeter firewall.",
        "Disable password authentication on SSH — enforce key-based authentication only.",
        "Audit all recent successful logins on the target node for unauthorized access.",
        "Enable fail2ban or equivalent with a 15-minute ban threshold after 5 failed attempts.",
        "Check for any new user accounts or privilege escalations created in the last 24 hours.",
        "Review SSH audit logs and preserve them for incident response.",
    ],
    "portscan": [
        "Block the scanning source IP at the perimeter firewall immediately.",
        "Review which services were exposed — close any unnecessary open ports.",
        "Enable IPS signature for port scan detection to auto-block future attempts.",
        "Monitor the scanning source IP for follow-up targeted attacks in the next 24 hours.",
        "Assess whether any discovered open ports represent unpatched vulnerabilities.",
    ],
}


_DEFAULT_SHAP_ROWS: list[dict[str, str]] = [
    {"feature": "Flow Bytes/s", "value": "2,847,293", "impact": "+0.82", "signal": "UP ATTACK"},
    {"feature": "Total Fwd Packets", "value": "48,291", "impact": "+0.74", "signal": "UP ATTACK"},
    {"feature": "Fwd Packet Length Mean", "value": "12.4 bytes", "impact": "+0.61", "signal": "UP ATTACK"},
    {"feature": "Flow Duration", "value": "0.31 seconds", "impact": "+0.58", "signal": "UP ATTACK"},
    {"feature": "Bwd Packet Length Max", "value": "0", "impact": "-0.29", "signal": "DOWN BENIGN"},
]


def _normalize_attack_key(attack_type: str) -> str:
    normalized = (attack_type or "").strip().lower()
    if "unknown" in normalized or "zero-day" in normalized or "zeroday" in normalized or "unidentified" in normalized:
        return "unknown"
    if "ssh" in normalized and ("patator" in normalized or "brute" in normalized):
        return "ssh-patator"
    if "brute" in normalized:
        return "bruteforce"
    if "port" in normalized and "scan" in normalized:
        return "portscan"
    if "web" in normalized and "attack" in normalized:
        return "webattack"
    if "bot" in normalized:
        return "bot"
    if "ddos" in normalized:
        return "ddos"
    if normalized == "dos" or ("dos" in normalized and "ddos" not in normalized):
        return "dos"
    return normalized


def _attack_type_display(attack_type: str) -> str:
    mapping = {
        "ddos": "DDoS (Distributed Denial of Service)",
        "dos": "DoS (Denial of Service)",
        "bruteforce": "BruteForce / SSH Credential Attack",
        "ssh-patator": "SSH-Patator Brute Force Attack",
        "portscan": "PortScan (Reconnaissance)",
        "webattack": "WebAttack (SQLi / XSS Pattern)",
        "bot": "Botnet / Command-and-Control Activity",
        "unknown": "Unknown Zero-Day / Unclassified Attack",
    }
    key = _normalize_attack_key(attack_type)
    return mapping.get(key, attack_type or "Unknown")


def _severity_visuals(severity: str, unknown: bool = False) -> dict[str, str]:
    if unknown:
        return {
            "summary_bg": "#fff0f3",
            "summary_border": "#ff1744",
            "badge_bg": "#ff1744",
            "badge_text": "[UNKNOWN CRITICAL]",
            "subtitle": "UNKNOWN ATTACK EMERGENCY - IMMEDIATE ACTION REQUIRED",
        }
    normalized = (severity or "").strip().lower()
    if normalized == "critical":
        return {
            "summary_bg": "#ffe8ef",
            "summary_border": "#ff3e6c",
            "badge_bg": "#ff3e6c",
            "badge_text": "[CRITICAL]",
            "subtitle": "Automated Incident Report - CRITICAL ALERT",
        }
    if normalized == "high":
        return {
            "summary_bg": "#fff1f2",
            "summary_border": "#ff6b6b",
            "badge_bg": "#d94848",
            "badge_text": "[HIGH]",
            "subtitle": "Automated Incident Report - HIGH ALERT",
        }
    if normalized == "medium":
        return {
            "summary_bg": "#fff7e8",
            "summary_border": "#ffb020",
            "badge_bg": "#ff9800",
            "badge_text": "[MEDIUM]",
            "subtitle": "Automated Incident Report - MEDIUM ALERT",
        }
    return {
        "summary_bg": "#eef7ff",
        "summary_border": "#57a0ff",
        "badge_bg": "#3b82f6",
        "badge_text": "[LOW]",
        "subtitle": "Automated Incident Report - SECURITY ALERT",
    }


def _format_utc_timestamp(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return "n/a"
    return raw.replace("T", " ").replace("Z", " UTC")


def _resolve_explanation_text(report_payload: dict, attack_key: str) -> str:
    interpretation = report_payload.get("interpretation") or {}
    candidates = [
        interpretation.get("analyst_takeaway"),
        interpretation.get("summary"),
        report_payload.get("risk_explanation"),
        _ATTACK_EXPLANATION_FALLBACKS.get(attack_key),
    ]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return "No explanation available."


def _resolve_indicators(report_payload: dict, attack_key: str) -> list[str]:
    indicators = report_payload.get("indicators") or []
    if indicators:
        return [str(item).strip() for item in indicators if str(item).strip()]
    return list(_ATTACK_INDICATOR_FALLBACKS.get(attack_key, []))


def _resolve_actions(report_payload: dict, attack_key: str) -> list[str]:
    interpretation = report_payload.get("interpretation") or {}
    actions = interpretation.get("recommended_actions") or report_payload.get("recommended_actions") or []
    if actions:
        return [str(item).strip() for item in actions if str(item).strip()]
    return list(_ATTACK_ACTION_FALLBACKS.get(attack_key, []))


def _resolve_shap_rows(report_payload: dict) -> list[dict[str, str]]:
    rows = report_payload.get("shap_rows") or report_payload.get("explainability") or []
    normalized: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        normalized.append(
            {
                "feature": str(row.get("feature") or row.get("name") or "Feature").strip(),
                "value": str(row.get("value") or row.get("observed_value") or "n/a").strip(),
                "impact": str(row.get("impact") or row.get("impact_score") or "n/a").strip(),
                "signal": str(row.get("signal") or row.get("direction") or "n/a").strip(),
            }
        )
    return normalized if normalized else list(_DEFAULT_SHAP_ROWS)


def _report_html_parts(report_payload: dict) -> dict:
    alert = report_payload.get("alert", {}) or {}
    alert_id = alert.get("id", "n/a")
    attack_type = str(alert.get("attack_type", "Unknown"))
    attack_key = _normalize_attack_key(attack_type)
    unidentified_attack = bool(report_payload.get("unidentified_attack")) or attack_key == "unknown"
    visuals = _severity_visuals(str(alert.get("severity", "")), unknown=unidentified_attack)

    generated_at_raw = str(report_payload.get("generated_at", "n/a"))
    generated_at = _format_utc_timestamp(generated_at_raw)
    confidence = alert.get("confidence", 0)
    try:
        confidence_text = f"{float(confidence) * 100:.1f}%"
    except Exception:
        confidence_text = "n/a"

    source_node = str(alert.get("source", "internet-sensor-a"))
    target_node = str(alert.get("target", "db-primary-1"))
    status = str(alert.get("status", "new")).strip().lower()
    status_text = "Escalated - Awaiting Analyst Response" if status == "escalated" else status.replace("_", " ").title()

    explanation = _resolve_explanation_text(report_payload, attack_key)
    indicators = _resolve_indicators(report_payload, attack_key)
    actions = _resolve_actions(report_payload, attack_key)
    shap_rows = _resolve_shap_rows(report_payload)
    attack_logs = report_payload.get("attack_logs") or []

    indicator_html = "".join(
        f"<li style=\"margin:0 0 8px 0;color:#0f172a;\"><span style=\"color:#ff3e6c;font-weight:bold;\">-</span> {escape(item)}</li>"
        for item in indicators
    )

    action_html = "".join(
        f"<li style=\"margin:0 0 10px 0;padding-left:2px;\">{escape(step)}</li>"
        for step in actions
    )

    shap_html = "".join(
        (
            "<tr>"
            f"<td style=\"padding:10px;border:1px solid #dee2e6;word-break:break-word;overflow-wrap:anywhere;\">{escape(row['feature'])}</td>"
            f"<td style=\"padding:10px;border:1px solid #dee2e6;word-break:break-word;overflow-wrap:anywhere;\">{escape(row['value'])}</td>"
            f"<td style=\"padding:10px;border:1px solid #dee2e6;word-break:break-word;overflow-wrap:anywhere;\">{escape(row['impact'])}</td>"
            f"<td style=\"padding:10px;border:1px solid #dee2e6;word-break:break-word;overflow-wrap:anywhere;\">{escape(row['signal'])}</td>"
            "</tr>"
        )
        for row in shap_rows
    )

    attack_log_html = ""
    if unidentified_attack and attack_logs:
        rows_html = "".join(
            (
                "<tr>"
                f"<td style=\"padding:8px;border:1px solid #dee2e6;white-space:nowrap;\">{escape(str(log.get('timestamp', 'n/a')))}</td>"
                f"<td style=\"padding:8px;border:1px solid #dee2e6;word-break:break-word;overflow-wrap:anywhere;\">{escape(str(log.get('attack_type', 'n/a')))}</td>"
                f"<td style=\"padding:8px;border:1px solid #dee2e6;white-space:nowrap;\">{escape(str(log.get('confidence', 'n/a')))}</td>"
                f"<td style=\"padding:8px;border:1px solid #dee2e6;white-space:nowrap;\">{escape(str(log.get('source', 'n/a')))}</td>"
                "</tr>"
            )
            for log in attack_logs[:25]
        )
        attack_log_html = (
            "<div style=\"margin-top:18px;background:#fff7f7;border:1px solid #ffd2d2;border-radius:8px;padding:14px;\">"
            "<div style=\"font-size:18px;font-weight:700;margin-bottom:8px;\">Unidentified Attack Logs (for CyberSec Triage)</div>"
            "<div style=\"font-size:12px;color:#475569;margin-bottom:10px;\">Recent raw telemetry around this unknown attack signature.</div>"
            "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse:collapse;background:#ffffff;font-size:12px;table-layout:fixed;\">"
            "<tr style=\"background:#eef2f7;\">"
            "<th align=\"left\" style=\"padding:8px;border:1px solid #dee2e6;width:180px;white-space:nowrap;\">Timestamp</th>"
            "<th align=\"left\" style=\"padding:8px;border:1px solid #dee2e6;\">Attack Type</th>"
            "<th align=\"left\" style=\"padding:8px;border:1px solid #dee2e6;width:100px;white-space:nowrap;\">Confidence</th>"
            "<th align=\"left\" style=\"padding:8px;border:1px solid #dee2e6;width:160px;white-space:nowrap;\">Source</th>"
            "</tr>"
            f"{rows_html}"
            "</table>"
            "</div>"
        )

    return {
        "alert_id": alert_id,
        "attack_type": attack_type,
        "attack_key": attack_key,
        "visuals": visuals,
        "generated_at": generated_at,
        "confidence_text": confidence_text,
        "source_node": source_node,
        "target_node": target_node,
        "status_text": status_text,
        "explanation": explanation,
        "indicators": indicators,
        "actions": actions,
        "shap_rows": shap_rows,
        "indicator_html": indicator_html,
        "action_html": action_html,
        "shap_html": shap_html,
        "attack_log_html": attack_log_html,
        "unidentified_attack": unidentified_attack,
    }


def _html_summary_inner(p: dict) -> str:
    visuals = p["visuals"]
    return f"""
        <div style="background:{visuals['summary_bg']};border:1px solid {visuals['summary_border']};border-radius:10px;padding:14px 14px 6px 14px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:14px;table-layout:fixed;">
            <tr>
              <td style="padding:8px 6px;width:28%;font-weight:700;">Incident ID</td>
              <td style="padding:8px 6px;width:22%;">#INC-{escape(str(p['alert_id']))}</td>
              <td style="padding:8px 6px;width:28%;font-weight:700;">Detection Time</td>
              <td style="padding:8px 6px;width:22%;white-space:nowrap;overflow-wrap:anywhere;">{escape(p['generated_at'])}</td>
            </tr>
            <tr>
              <td style="padding:8px 6px;font-weight:700;">Attack Type</td>
              <td style="padding:8px 6px;word-break:break-word;overflow-wrap:anywhere;">{escape(_attack_type_display(p['attack_type']))}</td>
              <td style="padding:8px 6px;font-weight:700;">Severity</td>
              <td style="padding:8px 6px;"><span style="display:inline-block;background:{visuals['badge_bg']};color:#ffffff;font-weight:700;padding:3px 8px;font-size:12px;font-family:Courier New,monospace;">{escape(visuals['badge_text'])}</span></td>
            </tr>
            <tr>
              <td style="padding:8px 6px;font-weight:700;">Confidence</td>
              <td style="padding:8px 6px;white-space:nowrap;">{escape(p['confidence_text'])}</td>
              <td style="padding:8px 6px;font-weight:700;">Target Node</td>
              <td style="padding:8px 6px;white-space:nowrap;overflow-wrap:anywhere;">{escape(p['target_node'])}</td>
            </tr>
            <tr>
              <td style="padding:8px 6px;font-weight:700;">Source Path</td>
              <td style="padding:8px 6px;word-break:break-word;overflow-wrap:anywhere;">{escape(p['source_node'])} -&gt; {escape(p['target_node'])}</td>
              <td style="padding:8px 6px;font-weight:700;">Detection Window</td>
              <td style="padding:8px 6px;">15 minutes</td>
            </tr>
            <tr>
              <td style="padding:8px 6px;font-weight:700;">Status</td>
              <td colspan="3" style="padding:8px 6px;">{escape(p['status_text'])}</td>
            </tr>
          </table>
        </div>
    """.strip()


def _html_banner_and_card_open(p: dict) -> str:
    visuals = p["visuals"]
    unknown_bar = ""
    if p.get("unidentified_attack"):
        unknown_bar = (
            "<div style=\"margin-top:12px;background:#ff1744;color:#ffffff;border:2px solid #7f0017;"
            "padding:10px 12px;font-family:Consolas,Menlo,monospace;font-size:13px;font-weight:700;"
            "letter-spacing:.08em;\">UNKNOWN SIGNATURE - HIGH URGENCY - TAKE ACTION NOW</div>"
        )
    return f"""
      <div style="background:#0a1628;border-left:4px solid #ff3e6c;padding:14px 18px;border-radius:10px 10px 0 0;">
        <div style="font-family:Consolas,Menlo,Monaco,monospace;color:#00ffe7;font-size:18px;font-weight:700;">SENTINEL IDS</div>
        <div style="margin-top:6px;color:#e2e8f0;font-size:13px;font-weight:600;">{escape(visuals['subtitle'])}</div>
        <div style="margin-top:8px;color:#94a3b8;font-size:11px;line-height:1.5;">
          Alert #{escape(str(p['alert_id']))} | {escape(p['generated_at'])}<br/>
          CONFIDENTIAL - FOR ANALYST USE ONLY
        </div>
        {unknown_bar}
      </div>

      <div style="background:#ffffff;border:1px solid #d9dee6;border-top:none;border-radius:0 0 10px 10px;padding:18px;">
    """.strip()


def _html_appendix_blocks(p: dict) -> str:
    return f"""
        <div style="margin-top:22px;background:#f8f9fa;border:1px solid #e5e7eb;border-radius:8px;padding:14px;">
          <div style="font-size:18px;font-weight:700;margin-bottom:8px;">What Was Detected</div>
          <div style="font-size:14px;line-height:1.7;">{escape(p['explanation'])}</div>
        </div>

        <div style="margin-top:18px;background:#f8f9fa;border:1px solid #e5e7eb;border-radius:8px;padding:14px;">
          <div style="font-size:18px;font-weight:700;margin-bottom:8px;">Behavioral Indicators Detected</div>
          <ul style="margin:8px 0 0 0;padding:0 0 0 16px;list-style:none;">{p['indicator_html']}</ul>
        </div>

        <div style="margin-top:18px;background:#f8f9fa;border:1px solid #e5e7eb;border-radius:8px;padding:14px;">
          <div style="font-size:18px;font-weight:700;margin-bottom:4px;">AI Detection Evidence — Why DeepShield Flagged This</div>
          <div style="font-size:12px;color:#475569;margin-bottom:10px;">The following network features triggered the AI model's detection (SHAP explainability)</div>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;background:#ffffff;font-size:13px;">
            <tr style="background:#eef2f7;">
              <th align="left" style="padding:10px;border:1px solid #dee2e6;">Feature Name</th>
              <th align="left" style="padding:10px;border:1px solid #dee2e6;">Observed Value</th>
              <th align="left" style="padding:10px;border:1px solid #dee2e6;">Impact</th>
              <th align="left" style="padding:10px;border:1px solid #dee2e6;">Signal</th>
            </tr>
            {p['shap_html']}
          </table>
        </div>

        <div style="margin-top:18px;background:#fff8f8;border:1px solid #ffd4de;border-radius:8px;padding:14px;">
          <div style="font-size:18px;font-weight:700;margin-bottom:10px;">⚡ Immediate Recommended Actions</div>
          <ol style="margin:0;padding-left:20px;line-height:1.6;font-size:14px;">{p['action_html']}</ol>
        </div>

        {p['attack_log_html']}

        <div style="margin-top:20px;background:#f1f5f9;border:1px solid #d9e0e8;border-radius:8px;padding:12px;color:#475569;font-size:12px;line-height:1.6;">
          <div>This report was automatically generated by DeepShield IDS v1.0 — AI-Powered Intrusion Detection System.</div>
          <div>Do not reply to this email. For urgent escalation contact your Security Operations Center.</div>
          <div>Report generated: {escape(p['generated_at'])} | Incident retained for 90 days per security policy.</div>
          <div style="font-size:11px;color:#64748b;">Powered by Deep Learning + SHAP Explainability + Claude AI Analysis</div>
        </div>
    """.strip()


def generate_html_report(report_payload: dict) -> str:
    p = _report_html_parts(report_payload)
    inner = f"{_html_banner_and_card_open(p)}\n{_html_summary_inner(p)}\n{_html_appendix_blocks(p)}\n      </div>"
    return f"""
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f3f5f7;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
    <div style="max-width:700px;margin:0 auto;padding:24px;">
{inner}
    </div>
  </body>
</html>
    """.strip()


def generate_html_email_summary_only(report_payload: dict) -> str:
    """Short HTML for email body: banner + incident summary table + attachment notice."""
    p = _report_html_parts(report_payload)
    aid = escape(str(p["alert_id"]))
    inner = (
        f"{_html_banner_and_card_open(p)}\n"
        f"{_html_summary_inner(p)}\n"
        f"<p style=\"margin:18px 0 0 0;font-size:13px;color:#475569;line-height:1.8;\">"
        f"<strong>Attached: INC-{aid}_incident_package.pdf</strong> — A comprehensive incident analysis package containing:"
        f"<ul style=\"margin:8px 0;padding-left:20px;\">"
        f"<li>Executive summary with severity & confidence metrics</li>"
        f"<li>AI Detection Rationale — what the model detected and why (LLM explainability)</li>"
        f"<li>Behavioral indicators and SHAP feature evidence</li>"
        f"<li>Immediate recommended actions and interventions</li>"
        f"<li>Event timeline and attack log telemetry (first 50 entries)</li>"
        f"<li>Analyst instructions and next steps</li>"
        f"<li>Professionally formatted and ready to print</li>"
        f"</ul>"
        f"<strong>Full HTML report</strong> is also available in rendered_content_full if needed for embeds or archival."
        "</p>\n"
        "      </div>"
    )
    return f"""
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f3f5f7;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
    <div style="max-width:700px;margin:0 auto;padding:24px;">
{inner}
    </div>
  </body>
</html>
    """.strip()


def _pdf_safe(text: str) -> str:
    if not text:
        return ""
    text = str(text)
    # Replace common Unicode characters with ASCII equivalents
    replacements = {
        '\u2014': '-',      # em dash
        '\u2013': '-',      # en dash
        '\u2010': '-',      # hyphen
        '\u201c': '"',      # left double quote
        '\u201d': '"',      # right double quote
        '\u2018': "'",      # left single quote
        '\u2019': "'",      # right single quote
        '\u2026': '...',    # ellipsis
        '\u2032': "'",      # prime
        '\u2033': '"',      # double prime
        '\u00a0': ' ',      # non-breaking space
        '\u200b': '',       # zero-width space
    }
    for unicode_char, ascii_char in replacements.items():
        text = text.replace(unicode_char, ascii_char)
    # Final fallback: encode to ASCII, replacing any remaining non-ASCII chars
    return text.encode("ascii", "replace").decode("ascii")


def build_comprehensive_incident_package_pdf(report_payload: dict) -> bytes:
    """Generate a compact printable incident package PDF with wrapped tables and ASCII-safe text."""
    from fpdf import FPDF

    p = _report_html_parts(report_payload)
    timeline = report_payload.get("timeline", []) or []
    interpretation = report_payload.get("interpretation", {}) or {}
    attack_logs = report_payload.get("attack_logs", []) or []

    class _ProDoc(FPDF):
        def header(self) -> None:
            return

        def footer(self) -> None:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(74, 112, 144)
            self.cell(0, 4, _pdf_safe("Auto-generated by SENTINEL IDS | For urgent escalation contact your SOC"), align="C")

    def _wrap_pdf_lines(pdf: FPDF, text: str, width: float) -> list[str]:
        source = _pdf_safe(text)
        if not source:
            return [""]
        lines: list[str] = []
        for paragraph in str(source).splitlines() or [""]:
            words = paragraph.split()
            if not words:
                lines.append("")
                continue
            current = ""
            for word in words:
                candidate = word if not current else f"{current} {word}"
                if pdf.get_string_width(candidate) <= width:
                    current = candidate
                    continue
                if current:
                    lines.append(current)
                if pdf.get_string_width(word) <= width:
                    current = word
                    continue
                chunk = ""
                for ch in word:
                    candidate_chunk = chunk + ch
                    if pdf.get_string_width(candidate_chunk) <= width:
                        chunk = candidate_chunk
                    else:
                        if chunk:
                            lines.append(chunk)
                        chunk = ch
                current = chunk
            if current:
                lines.append(current)
        return lines if lines else [""]

    def _section_title(pdf: FPDF, title: str) -> None:
        pdf.set_text_color(0, 200, 255)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 5, _pdf_safe(f"// {title}"), ln=True)
        pdf.set_draw_color(0, 200, 255)
        pdf.set_line_width(0.25)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(1.5)

    pdf = _ProDoc()
    pdf.set_margins(11, 12, 11)
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    left_margin = pdf.l_margin
    usable_width = pdf.w - pdf.l_margin - pdf.r_margin

    if p.get("unidentified_attack"):
        pdf.set_fill_color(255, 23, 68)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, _pdf_safe("UNKNOWN ATTACK EMERGENCY - TAKE ACTION NOW"), ln=True, fill=True, align="C")
        pdf.set_fill_color(37, 3, 10)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(
            0,
            6,
            _pdf_safe(
                "This incident does not match the known attack taxonomy. Treat as possible zero-day or custom tooling. "
                "Isolate the target path, preserve evidence, and escalate to senior incident response immediately."
            ),
            fill=True,
        )
        pdf.ln(3)

    # Compact header block
    left_w = 54
    right_w = usable_width - left_w
    header_rows = [
        ("SENTINEL IDS", "INCIDENT REPORT", (3, 12, 22), (3, 12, 22), (0, 200, 255), (0, 200, 255), (11, 11), ("Helvetica", "B", 11), ("Helvetica", "B", 11)),
        (f"Alert #{p['alert_id']}", p["generated_at"], (248, 250, 252), (248, 250, 252), (20, 20, 20), (20, 20, 20), (6.5, 6.5), ("Courier", "B", 9), ("Courier", "", 9)),
        (p["visuals"]["badge_text"], f"Attack: {_attack_type_display(p['attack_type'])}", (255, 51, 102), (248, 250, 252), (255, 255, 255), (20, 20, 20), (6.5, 6.5), ("Courier", "B", 9), ("Courier", "B", 9)),
        (f"Confidence: {p['confidence_text']}", f"Source: {p['source_node']} -> Target: {p['target_node']}", (248, 250, 252), (248, 250, 252), (20, 20, 20), (20, 20, 20), (6.5, 6.5), ("Courier", "B", 8), ("Courier", "", 8)),
    ]
    pdf.set_draw_color(255, 51, 102)
    pdf.set_line_width(0.7)
    for left_text, right_text, left_fill, right_fill, left_color, right_color, heights, left_font, right_font in header_rows:
        row_h = max(heights)
        pdf.set_font(*left_font)
        pdf.set_text_color(*left_color)
        pdf.set_fill_color(*left_fill)
        pdf.cell(left_w, row_h, _pdf_safe(left_text), border=1, fill=True)
        pdf.set_font(*right_font)
        pdf.set_text_color(*right_color)
        pdf.set_fill_color(*right_fill)
        pdf.cell(right_w, row_h, _pdf_safe(right_text), border=1, ln=True, fill=True)
    pdf.ln(3)

    # Executive summary
    _section_title(pdf, "EXECUTIVE SUMMARY")
    pair_w = usable_width / 2
    label_w = 34
    value_w = pair_w - label_w
    summary_rows = [
        ("Attack Type", _attack_type_display(p["attack_type"]), "Confidence", p["confidence_text"]),
        ("Source", p["source_node"], "Target", p["target_node"]),
        ("Status", p["status_text"], "Detected", p["generated_at"]),
    ]
    for left_label, left_value, right_label, right_value in summary_rows:
        row_y = pdf.get_y()
        row_h = 6.0
        for idx, (label, value) in enumerate(((left_label, left_value), (right_label, right_value))):
            x = left_margin + idx * pair_w
            pdf.set_draw_color(214, 220, 228)
            pdf.set_fill_color(248, 250, 252)
            pdf.rect(x, row_y, pair_w, row_h, style="DF")
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(220, 20, 60)
            pdf.set_xy(x, row_y)
            pdf.cell(label_w, row_h, _pdf_safe(f"{label}:"), border=0)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(20, 20, 20)
            pdf.set_xy(x + label_w, row_y)
            pdf.multi_cell(value_w, row_h, _pdf_safe(value), border=0)
        pdf.set_y(row_y + row_h)
    pdf.ln(1.5)

    # AI rationale
    _section_title(pdf, "AI DETECTION RATIONALE")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(20, 20, 20)
    pdf.multi_cell(usable_width, 4.6, _pdf_safe(p["explanation"]))
    if interpretation and interpretation.get("summary"):
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(220, 20, 60)
        pdf.cell(0, 4.5, _pdf_safe("Analyst Takeaway:"), ln=True)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(20, 20, 20)
        takeaway = interpretation.get("analyst_takeaway") or interpretation.get("summary")
        pdf.multi_cell(usable_width, 4.6, _pdf_safe(str(takeaway)))
    pdf.ln(1)

    # Behavioral indicators
    _section_title(pdf, "BEHAVIORAL INDICATORS")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(20, 20, 20)
    for indicator in p["indicators"]:
        pdf.set_x(left_margin)
        pdf.set_text_color(220, 20, 60)
        pdf.cell(5, 4.6, _pdf_safe("-"), border=0)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(usable_width - 5, 4.6, _pdf_safe(indicator), border=0)
    pdf.ln(1)

    # SHAP table
    _section_title(pdf, "ML MODEL EVIDENCE - TOP FEATURES")
    shap_widths = [68, 30, 30, 60]
    pdf.set_font("Courier", "B", 7)
    pdf.set_text_color(255, 255, 255)
    pdf.set_fill_color(31, 56, 100)
    for i, h in enumerate(["Feature Name", "Value", "Impact Score", "Signal"]):
        pdf.cell(shap_widths[i], 5.5, _pdf_safe(h), border=1, align="C", fill=True)
    pdf.ln()

    def _normalize_signal_text(raw: str) -> tuple[str, tuple[int, int, int]]:
        text = str(raw or "").upper().replace("?", "").strip()
        if "BENIGN" in text:
            return "DOWN BENIGN", (0, 200, 136)
        if "ATTACK" in text or "SUSPICIOUS" in text:
            return "UP ATTACK", (255, 51, 102)
        return text or "N/A", (74, 112, 144)

    for row_idx, row in enumerate(p["shap_rows"][:5]):
        fill = (247, 251, 255) if row_idx % 2 == 0 else (255, 255, 255)
        signal_text, signal_color = _normalize_signal_text(row.get("signal", ""))
        values = [str(row.get("feature", "")), str(row.get("value", "")), str(row.get("impact", "")), signal_text]
        row_y = pdf.get_y()
        row_h = 4.8 * max(len(_wrap_pdf_lines(pdf, v, shap_widths[i] - 2)) for i, v in enumerate(values))
        x = left_margin
        for i, value in enumerate(values):
            pdf.set_draw_color(214, 220, 228)
            pdf.set_fill_color(*fill)
            pdf.rect(x, row_y, shap_widths[i], row_h, style="DF")
            pdf.set_font("Courier", "B" if i in {2, 3} else "", 7)
            pdf.set_text_color(*(signal_color if i == 3 else ((255, 51, 102) if i == 2 else (20, 20, 20))))
            pdf.set_xy(x + 1, row_y + 0.4)
            pdf.multi_cell(shap_widths[i] - 2, 4.8, _pdf_safe(value), border=0, align="C" if i in {1, 2, 3} else "L")
            x += shap_widths[i]
        pdf.set_y(row_y + row_h)
    pdf.ln(1)

    # Actions
    _section_title(pdf, "IMMEDIATE RECOMMENDED ACTIONS")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(20, 20, 20)
    for i, action in enumerate(p["actions"], 1):
        pdf.set_text_color(220, 20, 60)
        pdf.cell(8, 4.8, _pdf_safe(f"{i}."), border=0)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(usable_width - 8, 4.8, _pdf_safe(action), border=0)
    pdf.ln(1)

    # Timeline
    if timeline:
        _section_title(pdf, "INCIDENT TIMELINE")
        timeline_widths = [56, 42, 90]
        pdf.set_font("Courier", "B", 7)
        pdf.set_fill_color(31, 56, 100)
        pdf.set_text_color(255, 255, 255)
        for i, header in enumerate(("Timestamp", "Event Type", "Description")):
            pdf.cell(timeline_widths[i], 5, _pdf_safe(header), border=1, align="C", fill=True)
        pdf.ln()
        pdf.set_font("Courier", "", 6.8)
        for row_idx, evt in enumerate(timeline[:10]):
            fill = (247, 251, 255) if row_idx % 2 == 0 else (255, 255, 255)
            values = [str(evt.get("created_at", "n/a")), str(evt.get("event_type", "event")).replace("_", " ").upper(), str(evt.get("message", ""))]
            row_y = pdf.get_y()
            row_h = 4.6 * max(len(_wrap_pdf_lines(pdf, v, timeline_widths[i] - 2)) for i, v in enumerate(values))
            x = left_margin
            for i, value in enumerate(values):
                pdf.set_draw_color(214, 220, 228)
                pdf.set_fill_color(*fill)
                pdf.rect(x, row_y, timeline_widths[i], row_h, style="DF")
                pdf.set_text_color(20, 20, 20)
                pdf.set_xy(x + 1, row_y + 0.4)
                pdf.multi_cell(timeline_widths[i] - 2, 4.6, _pdf_safe(value), border=0, align="C" if i == 1 else "L")
                x += timeline_widths[i]
            pdf.set_y(row_y + row_h)
        pdf.ln(1)

    # Attack logs
    if attack_logs:
        pdf.add_page()
        _section_title(pdf, "ATTACK LOG TELEMETRY")
        log_widths = [56, 42, 34, 56]
        pdf.set_font("Courier", "B", 7)
        pdf.set_fill_color(31, 56, 100)
        pdf.set_text_color(255, 255, 255)
        for i, header in enumerate(("Timestamp", "Attack Type", "Confidence", "Source IP")):
            pdf.cell(log_widths[i], 5, _pdf_safe(header), border=1, align="C", fill=True)
        pdf.ln()
        pdf.set_font("Courier", "", 6.8)
        for row_idx, log in enumerate(attack_logs[:30]):
            fill = (247, 251, 255) if row_idx % 2 == 0 else (255, 255, 255)
            values = [str(log.get("timestamp", "n/a")), str(log.get("attack_type", "n/a")), str(log.get("confidence", "n/a")), str(log.get("source", "n/a"))]
            row_y = pdf.get_y()
            row_h = 4.6 * max(len(_wrap_pdf_lines(pdf, v, log_widths[i] - 2)) for i, v in enumerate(values))
            x = left_margin
            for i, value in enumerate(values):
                pdf.set_draw_color(214, 220, 228)
                pdf.set_fill_color(*fill)
                pdf.rect(x, row_y, log_widths[i], row_h, style="DF")
                pdf.set_text_color(20, 20, 20)
                pdf.set_xy(x + 1, row_y + 0.4)
                pdf.multi_cell(log_widths[i] - 2, 4.6, _pdf_safe(value), border=0, align="C" if i == 2 else "L")
                x += log_widths[i]
            pdf.set_y(row_y + row_h)

    # Analyst next steps
    pdf.add_page()
    _section_title(pdf, "NEXT STEPS FOR ANALYST")
    pdf.set_font("Helvetica", "", 8.8)
    pdf.set_text_color(20, 20, 20)
    steps = [
        "Review AI Detection Rationale and validate against threat intelligence feeds.",
        "Analyze the full flow record and compare it with packet capture evidence.",
        "Cross-reference the source IP with asset inventory and identity records.",
        "Document findings in the case management system and preserve evidence.",
        "Escalate to Tier-2 analyst if the pattern repeats or widens in scope.",
    ]
    for i, step in enumerate(steps, 1):
        pdf.set_text_color(220, 20, 60)
        pdf.cell(8, 5, _pdf_safe(f"> {i}.").replace(" ", " ", 1), border=0)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(usable_width - 8, 5, _pdf_safe(step), border=0)

    raw = pdf.output(dest="S")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return raw.encode("latin-1", errors="replace")

    # PDF setup with proper margins (40px L/R, 25px T/B)
    pdf = _ProDoc()
    pdf.set_margins(40, 25, 40)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()
    
    # Calculate usable width: A4 width (210mm=595px) minus margins
    usable_width = pdf.epw  # Should be ~515px with 40px margins

    # ===== SEVERITY BADGE (plain text, no emoji) =====
    severity = str(p["visuals"]["badge_text"]).upper()
    if severity in ("CRITICAL", "HIGH"):
        bg_color = (255, 51, 102)  # Bright RED #ff3366
        badge_text = f"[{severity}]"
    else:
        bg_color = (70, 130, 180)  # Steel Blue
        badge_text = f"[{severity}]"
    
    pdf.set_fill_color(*bg_color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Courier", "B", 10)
    pdf.cell(0, 8, _pdf_safe(badge_text), ln=True, fill=True)
    pdf.ln(2)

    # ===== EXECUTIVE SUMMARY =====
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 5, _pdf_safe("// EXECUTIVE SUMMARY"), ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_line_width(0.3)
    pdf.line(40, pdf.get_y(), 555, pdf.get_y())
    pdf.ln(1)

    # Summary fields with proper text wrapping
    summary_data = [
        ("Attack Type", _attack_type_display(p["attack_type"])),
        ("Confidence", p["confidence_text"]),
        ("Source", p["source_node"]),
        ("Target", p["target_node"]),
        ("Status", p["status_text"]),
        ("Detected", p["generated_at"]),
    ]

    for label, value in summary_data:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(255, 51, 102)  # RED labels
        label_width = 40
        pdf.cell(label_width, 4.5, _pdf_safe(label + ":"), border=0)
        
        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "", 8)
        # Use proper width for multi_cell: usable_width minus label width
        remaining_width = usable_width - label_width
        pdf.multi_cell(remaining_width, 4.5, _pdf_safe(value), border=0)

    pdf.ln(1.5)

    # ===== AI DETECTION RATIONALE =====
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 5, _pdf_safe("// AI DETECTION RATIONALE"), ln=True)
    pdf.line(40, pdf.get_y(), 555, pdf.get_y())
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 8)
    pdf.multi_cell(usable_width, 4, _pdf_safe(p["explanation"]))

    if interpretation and interpretation.get("summary"):
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(255, 51, 102)
        pdf.cell(0, 4, _pdf_safe("Analyst Takeaway:"), ln=True)
        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "", 8)
        takeaway = interpretation.get("analyst_takeaway") or interpretation.get("summary")
        pdf.multi_cell(usable_width, 4, _pdf_safe(str(takeaway)))

    pdf.ln(1.5)

    # ===== BEHAVIORAL INDICATORS =====
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 5, _pdf_safe("// BEHAVIORAL INDICATORS"), ln=True)
    pdf.line(40, pdf.get_y(), 555, pdf.get_y())
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 8)
    for indicator in p["indicators"]:
        pdf.cell(5, 4, _pdf_safe("*"), border=0)
        pdf.multi_cell(usable_width - 5, 4, _pdf_safe(indicator), border=0)

    pdf.ln(1.5)

    # ===== ML MODEL EVIDENCE (SHAP) TABLE =====
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 5, _pdf_safe("// ML MODEL EVIDENCE - TOP FEATURES"), ln=True)
    pdf.line(40, pdf.get_y(), 555, pdf.get_y())
    pdf.ln(1)
    
    pdf.set_font("Courier", "B", 7)
    # Table column widths: fit within usable_width (approx 515px with 40px margins)
    col_widths = [150, 90, 90, 95]  # Feature | Value | Impact | Signal
    headers = ["Feature Name", "Value", "Impact", "Signal"]
    
    # Header row with RED background
    pdf.set_fill_color(255, 51, 102)  # RED
    pdf.set_text_color(255, 255, 255)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 5, _pdf_safe(h), border=1, align="C", fill=True)
    pdf.ln()

    # Data rows with alternating background
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Courier", "", 7)
    for row_idx, row in enumerate(p["shap_rows"][:5]):
        # Alternate background for readability
        if row_idx % 2 == 1:
            pdf.set_fill_color(240, 245, 250)  # Light blue
        else:
            pdf.set_fill_color(255, 255, 255)
        
        # Clean signal text: replace broken arrows with ASCII
        signal_text = str(row["signal"][:20])
        signal_text = signal_text.replace("?", "").replace("Attack", "UP-ATTACK").replace("Benign", "DN-BENIGN")
        
        feature = _pdf_safe(row["feature"][:30])
        value = _pdf_safe(row["value"][:15])
        impact = _pdf_safe(row["impact"][:12])
        signal = _pdf_safe(signal_text[:20])
        
        pdf.cell(col_widths[0], 4.5, feature, border=1, fill=True)
        pdf.cell(col_widths[1], 4.5, value, border=1, align="C", fill=True)
        pdf.cell(col_widths[2], 4.5, impact, border=1, align="C", fill=True)
        pdf.cell(col_widths[3], 4.5, signal, border=1, align="C", fill=True)
        pdf.ln()

    pdf.ln(1.5)

    # ===== IMMEDIATE RECOMMENDED ACTIONS =====
    pdf.set_text_color(255, 51, 102)  # RED
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 5, _pdf_safe("// IMMEDIATE RECOMMENDED ACTIONS"), ln=True)
    pdf.line(40, pdf.get_y(), 555, pdf.get_y())
    pdf.ln(1)
    
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "", 8)
    for i, action in enumerate(p["actions"], 1):
        pdf.set_text_color(255, 51, 102)  # RED bullet
        pdf.cell(5, 4, _pdf_safe(f"{i}."), border=0)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(usable_width - 5, 4, _pdf_safe(action), border=0)

    pdf.ln(1.5)

    # ===== INCIDENT TIMELINE =====
    if timeline:
        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 5, _pdf_safe("// INCIDENT TIMELINE"), ln=True)
        pdf.line(40, pdf.get_y(), 555, pdf.get_y())
        pdf.ln(1)
        
        pdf.set_font("Courier", "", 7)
        # Timeline table: Timestamp (180px) | Event (140px) | Description (auto)
        pdf.set_text_color(255, 51, 102)  # RED header
        pdf.set_font("Courier", "B", 7)
        pdf.cell(180, 4, _pdf_safe("Timestamp"), border=1)
        pdf.cell(140, 4, _pdf_safe("Event Type"), border=1)
        pdf.cell(195, 4, _pdf_safe("Description"), border=1)
        pdf.ln()
        
        pdf.set_font("Courier", "", 6.5)
        pdf.set_text_color(20, 20, 20)
        for evt in timeline[:10]:
            ts = evt.get("created_at", "n/a")
            et = evt.get("event_type", "").upper()
            msg = evt.get("message", "")
            
            # Ensure full timestamp is visible (at least 30 chars)
            ts_str = _pdf_safe(str(ts)[:30])
            et_str = _pdf_safe(str(et)[:20])
            msg_str = _pdf_safe(str(msg)[:60])
            
            pdf.cell(180, 4, ts_str, border=1)
            pdf.cell(140, 4, et_str, border=1)
            pdf.multi_cell(195, 4, msg_str, border=1)

    # ===== ATTACK LOG PAGE =====
    if attack_logs:
        pdf.add_page()
        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 5, _pdf_safe("// ATTACK LOG TELEMETRY"), ln=True)
        pdf.line(40, pdf.get_y(), 555, pdf.get_y())
        pdf.ln(1)
        
        pdf.set_font("Courier", "B", 7)
        pdf.set_text_color(255, 51, 102)
        # Headers: Timestamp | Type | Confidence | Source
        pdf.cell(180, 4, _pdf_safe("Timestamp"), border=1)
        pdf.cell(120, 4, _pdf_safe("Attack Type"), border=1)
        pdf.cell(80, 4, _pdf_safe("Confidence"), border=1)
        pdf.cell(135, 4, _pdf_safe("Source IP"), border=1)
        pdf.ln()
        
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(20, 20, 20)
        for log in attack_logs[:30]:
            ts = log.get("timestamp", "n/a")
            at = log.get("attack_type", "n/a")
            conf = log.get("confidence", "n/a")
            src = log.get("source", "n/a")
            
            ts_str = _pdf_safe(str(ts)[:25])
            at_str = _pdf_safe(str(at)[:18])
            conf_str = _pdf_safe(str(conf)[:10])
            src_str = _pdf_safe(str(src)[:20])
            
            pdf.cell(180, 4, ts_str, border=1)
            pdf.cell(120, 4, at_str, border=1)
            pdf.cell(80, 4, conf_str, border=1, align="C")
            pdf.cell(135, 4, src_str, border=1)
            pdf.ln()

    # ===== ANALYST NEXT STEPS PAGE =====
    pdf.add_page()
    pdf.set_text_color(255, 51, 102)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, _pdf_safe("// NEXT STEPS FOR ANALYST"), ln=True)
    pdf.line(40, pdf.get_y(), 555, pdf.get_y())
    pdf.ln(2)
    
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "", 9)

    steps = [
        "Review AI Detection Rationale and validate against threat intelligence",
        "Analyze Behavioral Indicators and cross-reference with your threat feeds",
        "Examine SHAP model evidence to understand why alert was triggered",
        "Execute Immediate Recommended Actions in priority order",
        "Document all investigation steps and findings in incident ticket",
        "Archive this report per retention policy (minimum 90 days)",
        "Update threat model if this represents new attack pattern",
    ]

    for step in steps:
        pdf.set_text_color(255, 51, 102)
        pdf.cell(5, 5, _pdf_safe(">"), border=0)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(usable_width - 5, 5, _pdf_safe(step), border=0)

    raw = pdf.output(dest="S")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return raw.encode("latin-1", errors="replace")


def build_full_incident_pdf_bytes(report_payload: dict) -> bytes:
    """Legacy: Use build_comprehensive_incident_package_pdf() instead."""
    return build_comprehensive_incident_package_pdf(report_payload)


def build_incident_timeline_log(report_payload: dict) -> str:
    alert = report_payload.get("alert") or {}
    lines = [
        "DeepShield IDS — incident timeline / telemetry excerpt",
        f"generated_at={report_payload.get('generated_at', 'n/a')}",
        "",
        "--- alert ---",
        json.dumps(alert, indent=2, default=str),
        "",
    ]
    risk = report_payload.get("risk_explanation")
    if risk:
        lines.extend(["--- risk_explanation ---", str(risk), ""])

    for evt in report_payload.get("timeline") or []:
        lines.append(
            f"{evt.get('created_at', '')} | {evt.get('event_type', '')} | {evt.get('message', '')}"
        )
    lines.append("")

    interp = report_payload.get("interpretation")
    if isinstance(interp, dict) and interp:
        lines.extend(["--- interpretation ---", json.dumps(interp, indent=2, default=str), ""])

    for log in report_payload.get("attack_logs") or []:
        lines.append(
            f"{log.get('timestamp', 'n/a')} | attack_type={log.get('attack_type', 'n/a')} | "
            f"confidence={log.get('confidence', 'n/a')} | source={log.get('source', 'n/a')}"
        )

    include_full_json = os.getenv("IDS_DISPATCH_LOG_INCLUDE_FULL_JSON", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if include_full_json:
        lines.extend(
            [
                "",
                "--- raw_report_payload (JSON) ---",
                json.dumps(report_payload, indent=2, default=str),
            ]
        )
    else:
        lines.extend(
            [
                "",
                "(Full structured JSON dump of the webhook payload is omitted from this log to avoid duplication "
                "with the HTML/PDF attachments. Set IDS_DISPATCH_LOG_INCLUDE_FULL_JSON=1 on the backend to append it.)",
            ]
        )
    return "\n".join(lines)


def email_dispatch_short_body_enabled() -> bool:
    return os.getenv("IDS_EMAIL_DISPATCH_SHORT_BODY_WITH_ATTACHMENTS", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def build_html_dispatch_attachment_fields(report_payload: dict) -> dict[str, str]:
    """
    Generate email dispatch attachments: short body + single comprehensive incident package PDF
    
    Returns a dict with:
    - rendered_content: Short HTML for email body (summary + attachment notice)
    - rendered_content_full: Full HTML report for reference
    - attachment_pdf_base64: Comprehensive incident package (logs + LLM + interventions + printable)
    - attachment_pdf_filename: filename for the attachment
    """
    if not email_dispatch_short_body_enabled():
        return {}

    short_html = generate_html_email_summary_only(report_payload)
    full_html = generate_html_report(report_payload)
    alert_id = report_payload.get("alert", {}).get("id", "n/a")
    
    # Single comprehensive package filename
    unknown = bool(report_payload.get("unidentified_attack"))
    pdf_name = f"INC-{alert_id}_{'UNKNOWN_ATTACK_EMERGENCY' if unknown else 'incident_package'}.pdf"

    # Build the single comprehensive package
    pdf_b64 = ""
    try:
        pdf_bytes = build_comprehensive_incident_package_pdf(report_payload)
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        # Log success
        with open('C:\\temp\\pdf_build.log', 'a') as f:
            f.write(f"OK: Generated PDF {len(pdf_bytes)} bytes for alert {alert_id}\n")
    except Exception as e:
        import logging
        import traceback
        # Log to file for debugging async task
        try:
            with open('C:\\temp\\pdf_build.log', 'a') as f:
                f.write(f"ERROR: PDF generation failed for alert {alert_id}: {e}\n")
                traceback.print_exc(file=f)
        except:
            pass
        logging.error(f"PDF generation failed for alert {alert_id}: {e}", exc_info=True)
        pdf_b64 = ""

    out: dict[str, str] = {
        "rendered_content": short_html,
        "rendered_content_full": full_html,
        "_attachment_pdf_included": str(bool(pdf_b64)),
    }

    # Single comprehensive package attachment
    if pdf_b64:
        out["attachment_pdf_base64"] = pdf_b64
        out["attachment_pdf_filename"] = pdf_name
    else:
        out["attachment_pdf_filename"] = pdf_name
    
    return out


def _sign_payload(payload: str) -> str:
    secret = os.getenv("IDS_N8N_WEBHOOK_SECRET", "").strip()
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def render_report(report_payload: dict, format_type: str) -> tuple[str, str]:
    format_type = format_type.lower()
    if format_type == "json":
        return json.dumps(report_payload, indent=2, default=str), "application/json"

    if format_type == "markdown":
        alert = report_payload.get("alert", {})
        timeline = report_payload.get("timeline", [])
        interpretation = report_payload.get("interpretation")
        attack_logs = report_payload.get("attack_logs", [])
        unidentified_attack = bool(report_payload.get("unidentified_attack"))

        lines = [
            f"# DeepShield Incident Report — Alert #{alert.get('id', 'n/a')}",
            "",
            f"- **Generated at:** {report_payload.get('generated_at', 'n/a')}",
            f"- **Attack Type:** {alert.get('attack_type', 'n/a')}",
            f"- **Severity:** {alert.get('severity', 'n/a')}",
            f"- **Confidence:** {alert.get('confidence', 'n/a')}",
            f"- **Status:** {alert.get('status', 'n/a')}",
            f"- **Path:** {alert.get('source', 'n/a')} → {alert.get('target', 'n/a')}",
            "",
            "## Risk Explanation",
            str(report_payload.get("risk_explanation", "No risk explanation available.")),
            "",
        ]

        indicators = report_payload.get("indicators", [])
        if indicators:
            lines.extend(["## Indicators"] + [f"- {str(ind)}" for ind in indicators] + [""])

        if timeline:
            lines.append("## Timeline")
            for evt in timeline:
                lines.append(
                    f"- {evt.get('created_at', '')}: {evt.get('event_type', 'event')} — {evt.get('message', '')}"
                )
            lines.append("")

        if unidentified_attack and attack_logs:
            lines.append("## Unidentified Attack Logs")
            for log in attack_logs[:25]:
                lines.append(
                    f"- {log.get('timestamp', 'n/a')} | type={log.get('attack_type', 'n/a')} | "
                    f"confidence={log.get('confidence', 'n/a')} | source={log.get('source', 'n/a')}"
                )
            lines.append("")

        if interpretation:
            lines.extend(
                [
                    "## LLM Explainability",
                    f"**Summary:** {interpretation.get('summary', 'n/a')}",
                    f"**Analyst takeaway:** {interpretation.get('analyst_takeaway', 'n/a')}",
                    "",
                ]
            )
            actions = interpretation.get("recommended_actions", [])
            if actions:
                lines.append("### Recommended Actions")
                lines.extend([f"- {str(action)}" for action in actions])
                lines.append("")

        return "\n".join(lines), "text/markdown"

    if format_type == "html":
        return generate_html_report(report_payload), "text/html"

    raise ValueError(f"Unsupported report format: {format_type}")


def dispatch_to_n8n(payload: dict) -> dict:
    webhook_url = os.getenv("IDS_N8N_WEBHOOK_URL", "").strip()
    webhook_secret = os.getenv("IDS_N8N_WEBHOOK_SECRET", "").strip()
    max_retries = max(1, int(os.getenv("IDS_N8N_MAX_RETRIES", "3")))
    backoff_seconds = max(1, int(os.getenv("IDS_N8N_RETRY_BACKOFF_SECONDS", "2")))
    timeout_seconds = max(1, int(os.getenv("IDS_N8N_TIMEOUT_SECONDS", "20")))

    if not webhook_url:
        return {
            "ok": False,
            "attempts": 0,
            "error": "IDS_N8N_WEBHOOK_URL is not configured",
            "response_status": None,
            "response_body": None,
        }

    payload_text = json.dumps(payload, default=str)
    headers = {"Content-Type": "application/json"}
    if webhook_secret:
        headers["x-ids-webhook-secret"] = webhook_secret
    signature = _sign_payload(payload_text)
    if signature:
        headers["x-ids-signature"] = signature

    last_error: str | None = None
    response_status: int | None = None
    response_body: str | None = None

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(webhook_url, data=payload_text, headers=headers, timeout=timeout_seconds)
            response_status = response.status_code
            response_body = response.text[:2000] if response.text else None
            response.raise_for_status()
            return {
                "ok": True,
                "attempts": attempt,
                "error": None,
                "response_status": response_status,
                "response_body": response_body,
            }
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_retries:
                time.sleep(backoff_seconds * attempt)

    return {
        "ok": False,
        "attempts": max_retries,
        "error": last_error,
        "response_status": response_status,
        "response_body": response_body,
    }
