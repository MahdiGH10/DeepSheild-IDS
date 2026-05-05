import { useEffect, useMemo, useState } from 'react';
import Header from './components/Header';
import HeroBriefing from './components/HeroBriefing';
import AlertQueue from './components/AlertQueue';
import TelemetryChart from './components/TelemetryChart';
import InvestigationWorkspace from './components/InvestigationWorkspace';
import OperationalHealth from './components/OperationalHealth';
import type { Alert, ThreatCategory, TelemetryPoint, ThreatBreakdown, SystemHealth, Severity, AlertStatus } from './types';
import { fetchLiveAlerts, fetchLiveOpsPosture, fetchLiveRealtime, type LiveAlertItem, type LiveOpsPosture, type LiveRealtimeResponse } from './lib/api';

const REFRESH_INTERVAL = 2000;

type GroupedAlert = Alert & {
  occurrenceCount: number;
  relatedAlerts: Alert[];
};

const BENIGN_LABELS = new Set(['benign', 'normal', 'normal traffic']);

function isBaselineLabel(value: string): boolean {
  return BENIGN_LABELS.has((value || '').trim().toLowerCase());
}

function confidenceToPercent(value: number): number {
  const confValue = Number(value) || 0;
  return Math.max(0, Math.min(100, confValue > 1 ? confValue : confValue * 100));
}

function normalizeAttackType(value: string): ThreatCategory {
  return value?.trim() || 'Unknown';
}

function mapSeverity(value: string): Severity {
  const normalized = value.toUpperCase();
  if (normalized.includes('CRIT')) return 'CRITICAL';
  if (normalized.includes('HIGH')) return 'HIGH';
  if (normalized.includes('LOW')) return 'LOW';
  return 'MEDIUM';
}

function mapStatus(value: string): AlertStatus {
  const normalized = value.toUpperCase();
  if (normalized.includes('INVEST')) return 'INVESTIGATING';
  if (normalized.includes('ESCAL')) return 'ESCALATED';
  if (normalized.includes('RESOL')) return 'RESOLVED';
  return 'ACTIVE';
}

function relTimeStamp(raw: string): Date {
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
}

function summarizeAutomationError(message?: string): string | undefined {
  if (!message) return undefined;
  const normalized = message.toLowerCase();
  if (normalized.includes('httpconnectionpool') || normalized.includes('connection refused')) {
    return 'n8n webhook unavailable';
  }
  if (normalized.includes('max retries exceeded')) {
    return 'automation retries exceeded';
  }
  if (normalized.includes('webhook')) {
    return 'automation webhook error';
  }
  return message.length > 72 ? `${message.slice(0, 69)}...` : message;
}

function mapAlert(item: LiveAlertItem): Alert {
  const confidence = confidenceToPercent(item.confidence);
  return {
    id: `INC-${item.id}`,
    backendId: item.id,
    attackType: normalizeAttackType(item.attack_type),
    source: item.source,
    target: item.target,
    confidence,
    severity: mapSeverity(item.severity),
    status: mapStatus(item.status),
    timestamp: relTimeStamp(item.timestamp),
    protocol: 'DeepShield Stream',
    port: 0,
    indicators: item.indicators?.length ? item.indicators : ['No indicators returned by backend.'],
    features: [],
    automationRuns: [],
    riskSummary: item.risk_explanation || 'Live backend alert without a textual risk explanation.',
    unknownAttack: Boolean(item.unknown_attack),
    emergencyLevel: item.emergency_level ?? null,
  };
}

function slugify(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'unknown';
}

function groupAlertsByType(alerts: Alert[]): GroupedAlert[] {
  const groups = new Map<string, Alert[]>();

  for (const alert of alerts) {
    const key = alert.attackType || 'Unknown';
    const existing = groups.get(key) ?? [];
    existing.push(alert);
    groups.set(key, existing);
  }

  return Array.from(groups.entries())
    .map(([attackType, items]) => {
      const relatedAlerts = [...items].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
      const latest = relatedAlerts[0];
      const uniqueIndicators = [...new Set(relatedAlerts.flatMap(a => a.indicators))];

      return {
        ...latest,
        id: `GROUP-${slugify(attackType)}`,
        attackType,
        backendId: latest.backendId,
        occurrenceCount: relatedAlerts.length,
        relatedAlerts,
        indicators: uniqueIndicators.length ? uniqueIndicators : latest.indicators,
        riskSummary:
          relatedAlerts.length > 1
            ? `${latest.riskSummary} (${relatedAlerts.length} alerts in this attack family)`
            : latest.riskSummary,
      };
    })
    .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
}

function toTelemetry(points: LiveRealtimeResponse['points']): TelemetryPoint[] {
  if (!points.length) return [];
  const parsedTimes = points.map(point => new Date(point.ts).getTime()).filter(Number.isFinite);
  const latestBackendTime = parsedTimes.length ? Math.max(...parsedTimes) : Date.now();
  const clockOffset = Date.now() - latestBackendTime;

  return points.map((point, index) => {
    const confidencePercent = confidenceToPercent(point.confidence);
    const backendTime = new Date(point.ts).getTime();
    const normalizedTime = Number.isFinite(backendTime)
      ? backendTime + clockOffset
      : Date.now() - (points.length - index - 1) * 700;

    return {
      t: normalizedTime,
      confidence: confidencePercent,
      intensity: Math.max(0.08, Math.min(1, confidencePercent / 100)),
      isAttack: !isBaselineLabel(point.attack_type),
    };
  });
}

function familyFromAttackType(value: string): ThreatCategory {
  const normalized = (value || '').trim().toLowerCase();
  if (isBaselineLabel(normalized)) return 'Baseline';
  if (normalized.includes('ddos') || normalized.includes('dos')) return 'DoS';
  if (normalized.includes('portscan')) return 'Probe';
  if (normalized.includes('heartbleed') || normalized.includes('infiltration')) return 'U2R';
  if (
    normalized.includes('ftp-patator') ||
    normalized.includes('ssh-patator') ||
    normalized.includes('brute force') ||
    normalized.includes('sql injection') ||
    normalized.includes('xss')
  ) {
    return 'R2L';
  }
  if (normalized.includes('bot')) return 'Botnet';
  return 'Other';
}

function breakdownFromRealtime(realtime: LiveRealtimeResponse): ThreatBreakdown[] {
  const entries = Object.entries(realtime.attack_breakdown);
  if (!entries.length) return [];
  const grouped = new Map<string, number>();

  for (const [category, count] of entries) {
    const family = familyFromAttackType(category);
    grouped.set(family, (grouped.get(family) ?? 0) + count);
  }

  const orderedFamilies: string[] = ['Baseline', 'DoS', 'Probe', 'R2L', 'U2R', 'Botnet', 'Other'];
  const counts = orderedFamilies
    .map(category => ({ category, count: grouped.get(category) ?? 0 }))
    .filter(item => item.count > 0 || item.category === 'Baseline');
  const max = Math.max(...counts.map(item => item.count), 1);

  return counts
    .sort((a, b) => {
      if (a.category === 'Baseline') return -1;
      if (b.category === 'Baseline') return 1;
      return b.count - a.count;
    })
    .map(({ category, count }): ThreatBreakdown => ({
      category,
      count,
      trend: count / max > 0.66 ? 'up' : count / max > 0.33 ? 'stable' : 'down',
    }));
}

function postureFromBackend(posture: LiveOpsPosture | null, totalEvents: number, avgConfidence: number): SystemHealth {
  const lastRunStatus = posture?.latest_automation_run?.status?.toUpperCase();
  const recentEventCount = posture?.recent_event_count ?? 0;
  const recentAttackLikeCount = posture?.recent_attack_like_count ?? 0;
  const attackShare = recentEventCount > 0 ? Math.round((recentAttackLikeCount / recentEventCount) * 100) : 0;

  return {
    modelStatus: posture?.model_loaded ? 'ONLINE' : posture ? 'FALLBACK' : 'OFFLINE',
    automationStatus: posture?.n8n_configured ? 'READY' : posture ? 'PARTIAL' : 'DOWN',
    avgConfidence,
    processedTotal: totalEvents,
    retryCount: posture?.latest_automation_run?.retry_count ?? 0,
    lastError: summarizeAutomationError(posture?.latest_automation_run?.error_message ?? undefined),
    lastRunStatus: lastRunStatus === 'SUCCESS'
      ? 'SUCCESS'
      : lastRunStatus === 'SKIPPED'
        ? 'SKIPPED'
        : 'FAILED',
    integrationReady: Boolean(posture?.services_ready),
    uptime: posture?.timestamp ? new Date(posture.timestamp).toLocaleTimeString() : 'Unavailable',
  };
}

export default function App() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<ThreatCategory | null>(null);
  const [backendAlerts, setBackendAlerts] = useState<Alert[]>([]);
  const [telemetry, setTelemetry] = useState<TelemetryPoint[]>([]);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [eventCount, setEventCount] = useState(0);
  const [opsPosture, setOpsPosture] = useState<LiveOpsPosture | null>(null);
  const [liveBreakdown, setLiveBreakdown] = useState<ThreatBreakdown[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const groupedAlerts = useMemo(() => groupAlertsByType(backendAlerts), [backendAlerts]);

  const alerts = useMemo(
    () => (filterCategory ? groupedAlerts.filter(a => a.attackType === filterCategory) : groupedAlerts),
    [groupedAlerts, filterCategory]
  );

  const selectedAlert = useMemo(
    () => alerts.find(a => a.id === selectedAlertId) ?? alerts[0] ?? null,
    [alerts, selectedAlertId]
  );

  useEffect(() => {
    if (!autoRefresh) return;

    let mounted = true;

    async function refresh() {
      try {
        const [alertsData, realtimeData, postureData] = await Promise.all([
          fetchLiveAlerts(80),
          // Use a smaller realtime window during benign-only demo so the chart reflects
          // the most recent simulator traffic (reduce noisy historical attack events).
          fetchLiveRealtime(120),
          fetchLiveOpsPosture(),
        ]);

        if (!mounted) return;

        const mappedAlerts = alertsData.map(mapAlert);
        const threatAlerts = mappedAlerts.filter(alert => !isBaselineLabel(alert.attackType));
        setBackendAlerts(threatAlerts);
        setTelemetry(toTelemetry(realtimeData.points));
        setLiveBreakdown(breakdownFromRealtime(realtimeData));
        setOpsPosture(postureData);
        setEventCount(realtimeData.total_events || postureData.recent_event_count || threatAlerts.length);
        setLastUpdated(new Date());
        setErrorMessage(null);

        const grouped = groupAlertsByType(threatAlerts);

        if (!selectedAlertId && grouped.length) {
          setSelectedAlertId(grouped[0].id);
        }
      } catch (err) {
        if (!mounted) return;
        setBackendAlerts([]);
        setTelemetry([]);
        setLiveBreakdown([]);
        setOpsPosture(null);
        setEventCount(0);
        setErrorMessage(err instanceof Error ? err.message : 'Unable to load live data from backend.');
      }
    }

    refresh();
    const interval = setInterval(refresh, REFRESH_INTERVAL);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [autoRefresh, selectedAlertId]);

  useEffect(() => {
    if (!alerts.length) {
      if (selectedAlertId !== null) setSelectedAlertId(null);
      return;
    }

    if (!selectedAlertId) {
      setSelectedAlertId(alerts[0].id);
      return;
    }

    if (!alerts.some(alert => alert.id === selectedAlertId)) {
      setSelectedAlertId(alerts[0].id);
    }
  }, [alerts, selectedAlertId]);

  const activeAlerts = useMemo(
    () => backendAlerts.filter(a => a.status === 'ACTIVE' || a.status === 'INVESTIGATING').length,
    [backendAlerts]
  );

  const avgConfidence = useMemo(() => {
    if (!telemetry.length) return 0;
    const total = telemetry.reduce((sum, p) => sum + p.confidence, 0);
    return Number((total / telemetry.length).toFixed(1));
  }, [telemetry]);

  const currentConfidence = telemetry.at(-1)?.confidence ?? 0;
  const simulationState = opsPosture?.simulation_state ?? (telemetry.some(p => p.isAttack) ? 'attack-active' : telemetry.length ? 'baseline' : 'idle');

  const dominantThreat = useMemo(() => {
    if (!liveBreakdown.length) return 'Benign';
    const nonBaseline = liveBreakdown.filter(b => b.category !== 'Baseline');
    const top = (nonBaseline.find(b => b.trend === 'up') ?? nonBaseline[0]) ?? liveBreakdown[0];
    return top.category;
  }, [liveBreakdown]);

  const handleFilterToggle = (cat: ThreatCategory) => {
    setFilterCategory(prev => (prev === cat ? null : cat));
  };

  const health = postureFromBackend(opsPosture, eventCount, avgConfidence);

  return (
    <div className="flex flex-col min-h-screen bg-[#070c12] text-slate-200 overflow-x-hidden">
      {/* Top mission header */}
      <Header
        activeAlerts={activeAlerts}
        lastUpdated={lastUpdated}
        autoRefresh={autoRefresh}
        onToggleRefresh={() => setAutoRefresh(v => !v)}
        dominantThreat={dominantThreat}
        currentConfidence={currentConfidence}
        simulationState={simulationState}
      />

      {/* Hero briefing */}
      <HeroBriefing
        dominantThreat={dominantThreat}
        activeAlerts={activeAlerts}
        filterCategory={filterCategory}
        currentConfidence={currentConfidence}
        simulationState={simulationState}
      />

      {errorMessage && (
        <div className="px-5 pb-2 text-[11px] text-amber-200">
          {errorMessage}
        </div>
      )}

      {/* Main 3-column command center */}
      <div className="flex flex-1 min-h-0 items-start">
        {/* Left rail: alert queue */}
        <div className="w-64 xl:w-72 shrink-0 flex flex-col h-[calc(100vh-9.125rem)] min-h-[24rem] overflow-hidden">
          <AlertQueue
            alerts={backendAlerts}
            selectedId={selectedAlertId}
            onSelect={setSelectedAlertId}
            filterCategory={filterCategory}
          />
        </div>

        {/* Center: telemetry + investigation */}
        <div className="flex-1 flex flex-col min-h-0 min-w-0 border-x border-slate-800">
          {/* Telemetry chart */}
          <TelemetryChart data={telemetry} />

          {/* Section divider */}
          <div className="px-5 py-2 border-b border-slate-800 bg-[#090e16] flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              Investigation Workspace
            </span>
            {selectedAlert && (
              <>
                <span className="text-slate-700 mx-1">—</span>
                <span className="text-[10px] font-mono text-slate-400">{selectedAlert.id}</span>
                <span className="text-[10px] font-mono text-slate-600">· {selectedAlert.attackType}</span>
              </>
            )}
          </div>

          {/* Investigation workspace */}
          <div className="flex-1 min-h-0 overflow-hidden bg-[#090e16]">
            <InvestigationWorkspace alert={selectedAlert} relatedAlerts={selectedAlert?.relatedAlerts ?? []} />
          </div>
        </div>

        {/* Right rail: operational health */}
        <div className="w-60 xl:w-64 shrink-0 flex flex-col min-h-0 overflow-hidden">
          <OperationalHealth
            health={health}
            breakdown={liveBreakdown}
            filterCategory={filterCategory}
            onFilterToggle={handleFilterToggle}
          />
        </div>
      </div>
    </div>
  );
}
