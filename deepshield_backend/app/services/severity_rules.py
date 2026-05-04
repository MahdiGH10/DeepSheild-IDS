"""
Single source of truth for attack-class → SOC severity mapping used by PredictorService
and by the attack simulator menu. Keep thresholds aligned with product expectations.
"""


def is_benign_label(label: str) -> bool:
    normalized = str(label).strip().lower()
    return normalized in {"benign", "normal", "normal traffic"}


def severity_and_explanation(attack_type: str, confidence: float) -> tuple[str, str]:
    """
    Returns (severity, one-line justification) matching the historical DeepShield policy.
    """
    attack_lower = str(attack_type).lower()
    conf = float(confidence)

    if is_benign_label(attack_type):
        return (
            "Informational",
            "Benign or normal-traffic label — no attack severity tier.",
        )

    if "unknown" in attack_lower or "zero-day" in attack_lower or "zeroday" in attack_lower or "unidentified" in attack_lower:
        return (
            "Critical",
            f"Unknown/unclassified attack signature: Critical high-urgency emergency until analyst classification (p={conf:.2f}).",
        )

    if "heartbleed" in attack_lower or "infiltration" in attack_lower:
        facet = (
            "Heartbleed (TLS heartbeat / memory exposure)"
            if "heartbleed" in attack_lower
            else "Infiltration (lateral movement / pivot risk)"
        )
        if conf >= 0.60:
            return (
                "Critical",
                f"{facet}: Critical when model confidence ≥ 0.60 (same branch in engine; p={conf:.2f}).",
            )
        return (
            "High",
            f"{facet}: below Critical threshold 0.60 → High (p={conf:.2f}).",
        )

    if "sql injection" in attack_lower or "xss" in attack_lower or "brute force" in attack_lower:
        if conf >= 0.65:
            return (
                "High",
                "Web exploit (SQLi, XSS, brute force): High when confidence ≥ 0.65 "
                f"(application-layer impact; p={conf:.2f}).",
            )
        return (
            "Medium",
            "Web exploit branch: Medium when confidence < 0.65 "
            f"(lower certainty on exploit; p={conf:.2f}).",
        )

    if "patator" in attack_lower:
        if conf >= 0.70:
            return (
                "High",
                "Credential / service brute-force (*Patator): High when confidence ≥ 0.70 "
                f"(p={conf:.2f}).",
            )
        return (
            "Medium",
            "*Patator pattern: Medium when confidence < 0.70 "
            f"(p={conf:.2f}).",
        )

    if "ddos" in attack_lower or "dos" in attack_lower:
        if conf >= 0.70:
            return (
                "High",
                "DoS / DDoS (substring match on 'dos' or 'ddos'): High when confidence ≥ 0.70 "
                f"(availability impact; p={conf:.2f}).",
            )
        return (
            "Medium",
            "DoS / DDoS branch: Medium when confidence < 0.70 "
            f"(p={conf:.2f}).",
        )

    if "bot" in attack_lower or "portscan" in attack_lower:
        if conf >= 0.70:
            return (
                "High",
                "Bot or port scan: High when confidence ≥ 0.70 "
                f"(C2 or reconnaissance signal; p={conf:.2f}).",
            )
        return (
            "Medium",
            "Bot / portscan branch: Medium when confidence < 0.70 "
            f"(p={conf:.2f}).",
        )

    if attack_lower in {"u2r", "r2l"}:
        if conf >= 0.75:
            return (
                "Critical",
                "Rare U2R/R2L exact labels: Critical when confidence ≥ 0.75 "
                f"(privilege / remote-to-local abuse; p={conf:.2f}).",
            )
        return (
            "High",
            "U2R/R2L exact labels: High when confidence < 0.75 "
            f"(p={conf:.2f}).",
        )

    if attack_lower in {"dos", "ddos", "probe"}:
        if conf >= 0.70:
            return (
                "High",
                "Compact class labels dos/ddos/probe: High when confidence ≥ 0.70 "
                f"(p={conf:.2f}).",
            )
        return (
            "Medium",
            "Compact dos/ddos/probe labels: Medium when confidence < 0.70 "
            f"(p={conf:.2f}).",
        )

    return (
        "Medium",
        f"Default policy: Medium when no higher-specific rule matched (p={conf:.2f}).",
    )


def severity_for_attack(attack_type: str, confidence: float) -> str:
    return severity_and_explanation(attack_type, confidence)[0]
