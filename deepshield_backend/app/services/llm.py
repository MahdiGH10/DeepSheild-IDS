import hashlib
import json
import os
import time

import requests


_CACHE: dict[str, tuple[float, dict]] = {}


def _fallback(reason: str) -> dict:
    return {
        "summary": "DeepShield fallback interpretation generated because external LLM is unavailable or misconfigured.",
        "analyst_takeaway": "Validate source/target, indicators, and confidence before escalation.",
        "recommended_actions": [
            "Correlate with neighboring telemetry for the same source and target.",
            "Contain quickly when critical assets or repeated events are involved.",
            "Document analyst notes and decision rationale.",
        ],
        "provider": "fallback",
        "model": "none",
        "confidence_note": reason,
    }


def _sanitize_alert_payload(alert_payload: dict) -> dict:
    allowed_keys = {
        "id",
        "attack_type",
        "confidence",
        "severity",
        "source",
        "target",
        "indicators",
        "risk_explanation",
        "status",
    }
    sanitized: dict = {}
    for key in allowed_keys:
        value = alert_payload.get(key)
        if isinstance(value, str):
            sanitized[key] = value.replace("{", "(").replace("}", ")")[:500]
        elif isinstance(value, list):
            sanitized[key] = [str(v)[:120] for v in value][:20]
        else:
            sanitized[key] = value
    return sanitized


def _cache_key(payload: dict, model_name: str) -> str:
    canonical = json.dumps({"payload": payload, "model": model_name}, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _cache_get(key: str, ttl_seconds: int) -> dict | None:
    item = _CACHE.get(key)
    if not item:
        return None
    created_at, value = item
    if time.time() - created_at > ttl_seconds:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: dict) -> None:
    if len(_CACHE) > 256:
        oldest_key = next(iter(_CACHE.keys()))
        _CACHE.pop(oldest_key, None)
    _CACHE[key] = (time.time(), value)


def _extract_json_object(text: str) -> dict | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:].strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = stripped[start : end + 1]
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def interpret_alert_with_llm(alert_payload: dict) -> dict:
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    model_name = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
    timeout = int(os.getenv("IDS_LLM_TIMEOUT_SECONDS", "30"))
    ttl_seconds = int(os.getenv("IDS_LLM_CACHE_TTL_SECONDS", "900"))

    if not api_key:
        return _fallback("OPENROUTER_API_KEY not set. Configure env key for live explainability.")

    safe_payload = _sanitize_alert_payload(alert_payload)
    key = _cache_key(safe_payload, model_name)
    cached = _cache_get(key, ttl_seconds)
    if cached is not None:
        return cached

    system_prompt = (
        "You are a senior SOC analyst assistant. "
        "Return ONLY valid JSON with keys: summary, analyst_takeaway, recommended_actions."
    )
    user_prompt = (
        "Given this DeepShield alert payload, generate concise incident explainability for a SOC analyst. "
        "recommended_actions must be an array of 3 to 5 short actionable strings.\\n"
        f"payload={json.dumps(safe_payload, default=str)}"
    )

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.15,
                "max_tokens": 320,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        body = response.json()
        content = str(body.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()

        parsed = _extract_json_object(content)
        if parsed is None:
            result = {
                "summary": content[:900] if content else "Interpretation generated without structured JSON.",
                "analyst_takeaway": "Treat this explanation as advisory and validate with telemetry.",
                "recommended_actions": [
                    "Validate indicators and event timeline.",
                    "Contain if critical assets are impacted.",
                    "Record analyst findings for incident traceability.",
                ],
                "provider": "openrouter",
                "model": model_name,
                "confidence_note": "Unstructured output received from provider.",
            }
            _cache_set(key, result)
            return result

        actions = parsed.get("recommended_actions")
        if not isinstance(actions, list):
            actions = [
                "Validate indicators and timeline context.",
                "Contain affected systems if risk is high.",
                "Document evidence and next analyst action.",
            ]

        result = {
            "summary": str(parsed.get("summary", "No summary provided."))[:900],
            "analyst_takeaway": str(parsed.get("analyst_takeaway", "Use analyst judgement for final decision."))[:400],
            "recommended_actions": [str(a)[:180] for a in actions][:5],
            "provider": "openrouter",
            "model": model_name,
            "confidence_note": "LLM-generated explanation; analyst validation required.",
        }
        _cache_set(key, result)
        return result
    except requests.Timeout:
        return _fallback("OpenRouter timeout. Fallback response returned.")
    except requests.RequestException as exc:
        return _fallback(f"OpenRouter request failed: {str(exc)[:180]}")
    except Exception as exc:
        return _fallback(f"Unexpected LLM parsing/runtime issue: {str(exc)[:180]}")
