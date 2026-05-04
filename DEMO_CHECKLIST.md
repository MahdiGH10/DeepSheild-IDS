# DeepShield Demo Checklist

## 1. Pre-flight

- [ ] `.env` exists in project root
- [ ] Backend dependencies are installed in `.venv`
- [ ] Frontend dependencies are installed in `uii-main/node_modules`
- [ ] Model artifacts exist in `NewApprochmodels/`

## 2. Launch

1. Run `launch_presentation.bat`.
2. Wait for backend, frontend, and benign simulator terminals.
3. Open `launch_attack_control.bat` when ready to inject an attack.

## 3. Unknown Attack Demo

1. In the red-team console, select option `15`.
2. Confirm the UI marks the alert as critical/high urgency.
3. Confirm automation prepares the unknown-attack emergency report.
