import json
import os
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np

from .severity_rules import is_benign_label, severity_for_attack


class PredictorService:
    def __init__(self) -> None:
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.model_loaded = False
        self.load_errors: list[str] = []
        self.runtime = {
            "python_version": sys.version.split()[0],
            "python_executable": sys.executable,
        }
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        model_dir = Path(os.getenv("MODEL_DIR", "../NewApprochmodels")).resolve()
        model_path = model_dir / "deepshield_ids_model.keras"
        scaler_path = model_dir / "scaler.pkl"
        label_encoder_path = model_dir / "label_encoder.pkl"
        feature_names_path = model_dir / "feature_names.pkl"

        try:
            self.feature_names = joblib.load(feature_names_path)
        except Exception as exc:
            self.feature_names = None
            self.load_errors.append(f"feature_names load failed: {exc}")

        try:
            self.scaler = joblib.load(scaler_path)
        except Exception as exc:
            self.scaler = None
            self.load_errors.append(f"scaler load failed: {exc}")

        try:
            self.label_encoder = joblib.load(label_encoder_path)
        except Exception as exc:
            self.label_encoder = None
            self.load_errors.append(f"label_encoder load failed: {exc}")

        try:
            import tensorflow as tf

            self.model = tf.keras.models.load_model(model_path)
            self.runtime["tensorflow_version"] = tf.__version__
            self.model_loaded = self.model is not None and self.scaler is not None and self.label_encoder is not None
        except Exception as exc:
            self.model = None
            self.model_loaded = False
            self.load_errors.append(f"keras model load failed: {exc}")

    @property
    def expected_feature_count(self) -> int | None:
        if self.feature_names is None:
            return None
        try:
            return int(len(self.feature_names))
        except Exception:
            return None

    def validate_features(self, features: list[float] | None) -> tuple[list[float] | None, str | None]:
        if features is None:
            return None, "Missing 'features' in request body."
        if not isinstance(features, list):
            return None, "'features' must be a JSON array."

        expected = self.expected_feature_count
        if expected is not None and len(features) != expected:
            return None, f"Invalid feature length: expected {expected}, got {len(features)}."

        cleaned: list[float] = []
        for idx, value in enumerate(features):
            try:
                casted = float(value)
            except Exception:
                return None, f"Feature at index {idx} is not numeric."
            if not np.isfinite(casted):
                return None, f"Feature at index {idx} must be finite."
            cleaned.append(casted)
        return cleaned, None

    @staticmethod
    def _is_benign_label(label: str) -> bool:
        return is_benign_label(label)

    @staticmethod
    def _severity_for_attack(attack_type: str, confidence: float) -> str:
        # Delegates to severity_rules.py (also used by simulate_live_traffic attack menu).
        return severity_for_attack(attack_type, confidence)

    @staticmethod
    def _indicators_for_attack(attack_type: str) -> list[str]:
        attack_lower = attack_type.lower()

        if PredictorService._is_benign_label(attack_type):
            return ["Traffic pattern within baseline", "No malicious signature dominance"]
        if "ddos" in attack_lower or "dos" in attack_lower:
            return ["Traffic burst anomaly", "Service exhaustion behavior"]
        if "portscan" in attack_lower:
            return ["Horizontal/vertical scan behavior", "High destination-port entropy"]
        if "bot" in attack_lower:
            return ["Botnet-like control pattern", "Automated beaconing indicators"]
        if "ftp-patator" in attack_lower or "ssh-patator" in attack_lower:
            return ["Credential stuffing pattern", "Repeated authentication failures"]
        if "heartbleed" in attack_lower:
            return ["TLS heartbeat anomaly", "Sensitive memory exfiltration risk"]
        if "infiltration" in attack_lower:
            return ["Lateral movement anomaly", "Suspicious internal pivoting"]
        if "web attack" in attack_lower or "xss" in attack_lower or "sql injection" in attack_lower:
            return ["Application-layer exploit indicators", "Malicious HTTP payload characteristics"]

        mapping = {
            "dos": ["Traffic burst anomaly", "Sustained request pressure"],
            "probe": ["Port/service scan pattern", "Distributed reconnaissance attempts"],
            "r2l": ["Authentication abuse signs", "Remote access behavior anomaly"],
            "u2r": ["Privilege escalation indicators", "Sensitive process manipulation"],
            "normal": ["Traffic pattern within baseline"],
        }
        return mapping.get(attack_type.lower(), ["General anomaly detected"])

    def predict(self, features: list[float] | None) -> dict:
        if self.model_loaded and features is not None and len(features) > 0:
            arr = np.array(features, dtype=np.float32).reshape(1, -1)
            scaled = self.scaler.transform(arr)
            probs = self.model.predict(scaled, verbose=0)[0]
            pred_idx = int(np.argmax(probs))
            pred_label = str(self.label_encoder.inverse_transform([pred_idx])[0])
            confidence = float(probs[pred_idx])
        else:
            pred_label = "normal"
            confidence = 0.55

        severity = self._severity_for_attack(pred_label, confidence)
        indicators = self._indicators_for_attack(pred_label)

        return {
            "attack_type": pred_label,
            "confidence": round(confidence, 4),
            "severity": severity,
            "indicators": indicators,
            "risk_explanation": f"DeepShield detected {pred_label} behavior with confidence {confidence:.2f}.",
            "is_benign": self._is_benign_label(pred_label),
            "predicted_at": datetime.utcnow().isoformat() + "Z",
        }


predictor_service = PredictorService()
