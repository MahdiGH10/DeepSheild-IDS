# DeepShield n8n Setup (Escalation Email)

## 1) Import workflow
- Open n8n.
- Import `deepshield_escalation_workflow.json`.

## 2) Configure SMTP node
- Open **Send Email** node.
- Replace placeholder SMTP credential with your valid SMTP credential.
- Ensure **Email Format** is **HTML** (the bundled workflow sets `"emailFormat": "html"`). If it is left on the n8n default **Text**, the node ignores the HTML body and recipients only see attachments with an empty message.
- Set **`DEEPSHIELD_FROM_EMAIL`** in the n8n environment to a sender address your SMTP allows (v2 node requires **From Email**). You can match it to your SMTP login; **`DEEPSHIELD_ANALYST_EMAIL`** is used as a fallback in the template when `DEEPSHIELD_FROM_EMAIL` is unset.

## 3) Configure the shared secret
Add in the backend `.env`:
- `IDS_N8N_WEBHOOK_SECRET=<same value as the workflow secret>`
- Optional: `DEEPSHIELD_ANALYST_EMAIL=soc-analyst@example.com`

Important: in n8n 2.16.1, the Code node sandbox blocks direct env-var access in this workflow. The validation step therefore uses the shared secret directly inside the node code and compares it to the `x-ids-webhook-secret` header. Keep the secret value in sync with the backend.

## 4) Activate webhook URL in backend .env
Set backend `.env`:
- `IDS_N8N_WEBHOOK_URL=<your n8n webhook production URL>`
- `IDS_N8N_WEBHOOK_SECRET=<same secret used in n8n env>`

## 5) Restart backend
Restart backend after env changes so auto-dispatch uses updated webhook settings.

## 6) Validate end-to-end
- Trigger repeated High or Critical incident.
- Confirm alert status becomes `escalated`.
- Confirm automation run is created at `/automation/incidents/{id}/runs`.
- Confirm n8n execution receives payload and email is sent.

## Payload fields n8n receives
- `format`
- `content_type`
- `report_payload` (incident metadata + timeline + optional interpretation)
- `rendered_content` (for HTML dispatches: short email body — banner + red summary table + attachment notice when `IDS_EMAIL_DISPATCH_SHORT_BODY_WITH_ATTACHMENTS` is enabled on the backend)
- `rendered_content_full` (optional) full HTML report for archival or alternate channels
- `attachment_html_report_base64`, `attachment_html_report_filename` (optional) **full styled HTML report** — open in a browser for the same dashboard-style layout as the mockup (header, red summary table, sections, SHAP table, actions, footer)
- `attachment_pdf_base64`, `attachment_pdf_filename` (optional) compact printable PDF summary of the same analyst content
- `attachment_log_base64`, `attachment_log_filename` (optional) plain-text timeline / excerpt (by default **does not** duplicate the entire `report_payload` JSON; set `IDS_DISPATCH_LOG_INCLUDE_FULL_JSON=1` on the backend to append it)

The bundled workflow adds **Prepare Email Attachments** (maps base64 into n8n binary keys `incident_html`, `incident_pdf`, and `incident_log`) and sets Send Email **Attachments** to `Object.keys($binary).join(',')`.

Set `IDS_EMAIL_DISPATCH_SHORT_BODY_WITH_ATTACHMENTS=0` in the backend `.env` to restore a single long HTML body in `rendered_content` with no attachment fields (legacy behavior).

## Notes
- Before n8n is configured, DeepShield still logs auto-dispatch attempts as failed (expected).
- Once configured, no code changes are required; dispatch switches to delivered automatically.
