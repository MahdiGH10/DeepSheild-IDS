export type LiveAlertItem = {
  id: number;
  timestamp: string;
  attack_type: string;
  confidence: number;
  severity: string;
  source: string;
  target: string;
  status: string;
  indicators: string[];
  risk_explanation: string;
  unknown_attack?: boolean;
  emergency_level?: string | null;
};

export type LiveRealtimePoint = {
  ts: string;
  attack_type: string;
  confidence: number;
  source: string;
};

export type LiveRealtimeResponse = {
  window_seconds: number;
  points: LiveRealtimePoint[];
  attack_breakdown: Record<string, number>;
  total_events: number;
};

export type LiveOpsPosture = {
  services_ready: boolean;
  backend_status: string;
  model_loaded: boolean;
  simulation_state: 'idle' | 'baseline' | 'attack-active';
  recent_event_count: number;
  recent_attack_like_count: number;
  active_alerts: number;
  n8n_configured: boolean;
  latest_automation_run: {
    id: number;
    alert_id: number;
    status: string;
    format: string;
    retry_count: number;
    error_message?: string | null;
    created_at: string;
  } | null;
  timestamp: string;
};

export type LiveAutomationRun = {
  id: number;
  alert_id: number;
  created_at: string;
  status: string;
  format: string;
  retry_count: number;
  response_status?: number | null;
  error_message?: string | null;
};

export type LiveShap = {
  attack_type: string;
  output_path: string;
  shap: {
    features: string[];
    shap_values: number[];
    feature_values: Array<number | string>;
  };
};

export type LiveInterpretation = {
  summary?: string;
  analyst_takeaway?: string;
  [key: string]: unknown;
};

export type LiveReportPreview = {
  rendered_content: string;
  content_type: string;
};

export type LiveDispatchResult = {
  run_id?: number;
  status: string;
  retry_count?: number;
  response_status?: number | null;
  error?: string | null;
  reason?: string | null;
};

// In production the frontend is served by nginx which proxies API paths to the internal
// backend service. Use a blank API_BASE to make requests relative (e.g. /alerts) so the
// browser calls the same host and nginx will proxy to the cluster-internal service name.
// For local development set VITE_API_BASE in an .env file to e.g. http://127.0.0.1:5000
const API_BASE = (import.meta.env.VITE_API_BASE ?? '').trim().replace(/\/+$/, '');
const ANALYST_API_KEY = (import.meta.env.VITE_ANALYST_API_KEY ?? '').trim();

function endpoint(path: string): string {
  return `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...(ANALYST_API_KEY ? { 'x-api-key': ANALYST_API_KEY } : {}),
    ...(init?.headers as Record<string, string> | undefined),
  };

  const res = await fetch(url, {
    cache: 'no-store',
    ...init,
    headers,
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Request failed (${res.status}) at ${url}${body ? `: ${body.slice(0, 120)}` : ''}`);
  }

  return res.json() as Promise<T>;
}

export function fetchLiveAlerts(limit = 100): Promise<LiveAlertItem[]> {
  return requestJson<LiveAlertItem[]>(endpoint(`/alerts?limit=${limit}`));
}

export function fetchLiveRealtime(windowSeconds = 120): Promise<LiveRealtimeResponse> {
  return requestJson<LiveRealtimeResponse>(endpoint(`/dashboard/realtime?window_seconds=${windowSeconds}`));
}

export function fetchLiveOpsPosture(): Promise<LiveOpsPosture> {
  return requestJson<LiveOpsPosture>(endpoint('/ops/posture'));
}

export function fetchLiveAutomationRuns(alertId: number): Promise<LiveAutomationRun[]> {
  return requestJson<LiveAutomationRun[]>(endpoint(`/automation/incidents/${alertId}/runs`));
}

export function fetchLiveShap(alertId: number): Promise<LiveShap> {
  return requestJson<LiveShap>(endpoint(`/alerts/${alertId}/shap-result`));
}

export function syncLiveShap(alertId: number): Promise<LiveShap> {
  return requestJson<LiveShap>(endpoint(`/alerts/${alertId}/shap-sync`), { method: 'POST' });
}

export function fetchLiveInterpretation(alertId: number): Promise<LiveInterpretation> {
  return requestJson<LiveInterpretation>(endpoint(`/alerts/${alertId}/interpretation`), { method: 'POST' });
}

export function fetchLiveReportPreview(
  alertId: number,
  format: 'json' | 'markdown' | 'html',
  includeTimeline = true,
  includeInterpretation = false
): Promise<LiveReportPreview> {
  const q = new URLSearchParams({
    format,
    include_timeline: includeTimeline ? '1' : '0',
    include_interpretation: includeInterpretation ? '1' : '0',
  });

  return requestJson<LiveReportPreview>(endpoint(`/reports/incidents/${alertId}/preview?${q.toString()}`));
}

export function dispatchLiveReport(
  alertId: number,
  format: 'json' | 'markdown' | 'html',
  includeTimeline = true,
  includeInterpretation = false
): Promise<LiveDispatchResult> {
  return requestJson<LiveDispatchResult>(endpoint(`/automation/incidents/${alertId}/dispatch-report`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      format,
      include_timeline: includeTimeline,
      include_interpretation: includeInterpretation,
    }),
  });
}
