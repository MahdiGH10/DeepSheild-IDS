# DeepShield Model Pipeline Report

## Purpose

DeepShield uses the saved artifacts in `NewApprochmodels/` to turn raw network-flow features into an IDS prediction. The backend loads these artifacts once when the Flask app starts, then reuses them for every `/predict` request.

## Model Artifacts Used

| Artifact | Backend role |
| --- | --- |
| `feature_names.pkl` | Defines the exact feature schema and expected feature count. The backend uses it to reject malformed requests before inference. |
| `scaler.pkl` | Applies the same normalization used during model training. This keeps live feature values in the numeric range the neural network expects. |
| `deepshield_ids_model.keras` | The trained deep learning classifier. It receives the scaled feature vector and outputs class probabilities. |
| `label_encoder.pkl` | Converts the model's predicted class index back into a readable attack label such as `Benign`, `Bot`, `DDoS`, or `PortScan`. |

## Backend Flow

1. The backend starts through `deepshield_backend/run.py`.
2. Flask creates the app in `deepshield_backend/app/__init__.py`.
3. `PredictorService` is initialized from `deepshield_backend/app/services/predictor.py`.
4. The service resolves `MODEL_DIR`, which defaults to `../NewApprochmodels`.
5. It loads:
   - `feature_names.pkl` with `joblib.load`
   - `scaler.pkl` with `joblib.load`
   - `label_encoder.pkl` with `joblib.load`
   - `deepshield_ids_model.keras` with `tf.keras.models.load_model`
6. The `/health` endpoint reports whether the Keras model is actually loaded.

## Prediction Request Flow

When a client sends `POST /predict`, the backend performs this sequence:

1. Reads the JSON body and extracts `features`.
2. Validates that `features` is a JSON array.
3. Checks the feature length against `len(feature_names.pkl)`.
4. Converts every feature to a finite float.
5. Converts the list into a NumPy array shaped as one sample.
6. Runs `scaler.transform(...)` so the input matches training-time scaling.
7. Runs `model.predict(...)` on the scaled feature vector.
8. Takes the highest-probability class with `np.argmax(...)`.
9. Uses `label_encoder.inverse_transform(...)` to recover the attack label.
10. Applies severity rules to map the label and confidence into `Informational`, `Low`, `Medium`, `High`, or `Critical`.
11. Stores the result as an alert and traffic event in SQLite.
12. Returns the prediction response to the frontend or API caller.

## Why All Four Files Must Stay Together

The Keras model alone is not enough. It only understands the numeric format it saw during training.

- If `feature_names.pkl` is missing, the backend cannot know whether the input vector has the correct number of fields.
- If `scaler.pkl` is missing, inference may run on raw values and predictions can become unreliable.
- If `label_encoder.pkl` is missing, the backend can get a class index but cannot reliably convert it to an attack name.
- If `deepshield_ids_model.keras` is missing, the backend falls back to a safe demo result instead of true deep learning inference.

## Current Local Verification

Current local check command:

```powershell
.\.venv\Scripts\python.exe scripts\check_deep_learning_model.py
```

Current result in this workspace:

```json
{
  "model_loaded": false,
  "expected_feature_count": 77,
  "runtime": {
    "python_version": "3.14.3"
  },
  "load_errors": [
    "keras model load failed: No module named 'tensorflow'"
  ]
}
```

This means the artifact paths are correct and the non-Keras artifacts load, but the local virtual environment is not TensorFlow-compatible. The current `.venv` uses Python 3.14.3, and TensorFlow is not installed for that runtime.

## Required Runtime

For local deep learning inference, use a 64-bit Python version supported by TensorFlow. Python 3.11 is the safest match for this project because the backend Dockerfile also uses Python 3.11.

Recommended local setup:

```powershell
Remove-Item .venv -Recurse -Force
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r deepshield_backend\requirements.txt
.\.venv\Scripts\python.exe scripts\check_deep_learning_model.py
```

Expected healthy result:

```json
{
  "model_loaded": true,
  "expected_feature_count": 77,
  "load_errors": []
}
```

## Operational Notes

- `/health` now exposes `model_loaded`, `model_runtime`, and `model_load_errors`.
- `/ops/posture` also exposes `model_loaded` and model load errors for the dashboard.
- If `model_loaded` is `false`, the backend does not perform neural-network inference and falls back to a benign demo result.
- Cloud deployment should use the Python 3.11 backend Docker image, which is compatible with the TensorFlow dependency declared in `deepshield_backend/requirements.txt`.

