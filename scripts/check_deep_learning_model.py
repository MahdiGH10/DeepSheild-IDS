from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "deepshield_backend"

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

os.chdir(BACKEND)

from app.services.predictor import predictor_service  # noqa: E402


def main() -> int:
    status = {
        "model_loaded": predictor_service.model_loaded,
        "expected_feature_count": predictor_service.expected_feature_count,
        "runtime": predictor_service.runtime,
        "load_errors": predictor_service.load_errors,
    }
    print(json.dumps(status, indent=2))
    return 0 if predictor_service.model_loaded else 1


if __name__ == "__main__":
    raise SystemExit(main())
