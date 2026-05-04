import { useEffect, useMemo, useState } from 'react';
import {
  MousePointerClick, ArrowRight, Cpu, FileText, Copy, Send, CheckCircle2,
  XCircle, MinusCircle, AlertTriangle, ShieldAlert, Network, ListChecks,
} from 'lucide-react';
import type { Alert, AlertStatus, Severity, AutomationRun } from '../types';
import ExplainabilityPanel from './ExplainabilityPanel';
import {
  dispatchLiveReport,
  fetchLiveAutomationRuns,
  fetchLiveInterpretation,
  fetchLiveReportPreview,
  fetchLiveShap,
  syncLiveShap,
  type LiveAutomationRun,
} from '../lib/api';

interface Props {
  alert: Alert | null;
  relatedAlerts?: Alert[];
}

function mapAutomationRun(run: LiveAutomationRun): AutomationRun {
  return {
    id: `RUN-${run.id}`,
    action: `Dispatch (${run.format})`,
    status: run.status?.toUpperCase() === 'SUCCESS' ? 'SUCCESS' : run.status?.toUpperCase() === 'SKIPPED' ? 'SKIPPED' : 'FAILED',
    timestamp: new Date(run.created_at),
    retries: run.retry_count ?? 0,
    note: run.error_message ?? undefined,
  };
}

function severityColor(s: Severity) {
  switch (s) {
    case 'CRITICAL': return 'text-red-300 bg-red-500/10 border-red-500/30';
    case 'HIGH':     return 'text-orange-300 bg-orange-500/10 border-orange-500/30';
    case 'MEDIUM':   return 'text-amber-300 bg-amber-500/10 border-amber-500/30';
    case 'LOW':      return 'text-slate-300 bg-slate-500/10 border-slate-500/30';
  }
}

function statusColor(s: AlertStatus) {
  switch (s) {
    case 'ACTIVE':        return 'text-red-300 bg-red-500/10 border-red-500/30';
    case 'INVESTIGATING': return 'text-cyan-300 bg-cyan-500/10 border-cyan-500/30';
    case 'ESCALATED':     return 'text-orange-300 bg-orange-500/10 border-orange-500/30';
    case 'RESOLVED':      return 'text-green-300 bg-green-500/10 border-green-500/30';
  }
}

function isUnknownEmergency(alert: Alert): boolean {
  return Boolean(alert.unknownAttack) || /unknown|zero-day|unidentified/i.test(alert.attackType);
}

function RunRow({ run }: { run: AutomationRun }) {
  const icon =
    run.status === 'SUCCESS' ? <CheckCircle2 size={12} className="text-green-400 shrink-0" /> :
    run.status === 'FAILED'  ? <XCircle size={12} className="text-red-400 shrink-0" /> :
                               <MinusCircle size={12} className="text-slate-500 shrink-0" />;

  const statusText = {
    SUCCESS: 'text-green-400',
    FAILED: 'text-red-400',
    SKIPPED: 'text-slate-500',
  }[run.status];

  const fmtT = (d: Date) => {
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`;
  };

  return (
    <div className="flex items-start gap-2 py-2 border-b border-slate-800/60 last:border-b-0">
      {icon}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-mono text-slate-300 truncate">{run.action}</span>
          <span className={`text-[9px] font-mono font-semibold uppercase ${statusText}`}>{run.status}</span>
          {run.retries > 0 && (
            <span className="text-[9px] font-mono text-slate-600">{run.retries} retries</span>
          )}
        </div>
        {run.note && (
          <p className="text-[10px] font-mono text-red-400/80 mt-0.5 truncate">{run.note}</p>
        )}
        <span className="text-[9px] font-mono text-slate-600">{fmtT(run.timestamp)}</span>
      </div>
    </div>
  );
}

function buildReport(alert: Alert): string {
  const pad2 = (n: number) => String(n).padStart(2, '0');
  const fmtDt = (d: Date) =>
    `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ` +
    `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())} UTC`;

  return [
    `DEEPSHIELD INCIDENT REPORT`,
    `Generated: ${fmtDt(new Date())}`,
    `─────────────────────────────────────────`,
    `Incident ID : ${alert.id}`,
    `Attack Type : ${alert.attackType}`,
    `Severity    : ${alert.severity}`,
    `Status      : ${alert.status}`,
    `Confidence  : ${alert.confidence}%`,
    ``,
    `NETWORK PATH`,
    `Source → Target : ${alert.source} → ${alert.target}`,
    `Protocol        : ${alert.protocol}  Port: ${alert.port || 'N/A'}`,
    ``,
    `RISK SUMMARY`,
    alert.riskSummary,
    ``,
    `INDICATORS`,
    ...alert.indicators.map(ind => `• ${ind}`),
    ``,
    `TOP MODEL FEATURES`,
    ...alert.features.map(f => `• ${f.name}: ${f.value} (weight: ${(f.weight * 100).toFixed(0)}%)`),
    ``,
    `AUTOMATION RUNS`,
    ...alert.automationRuns.map(r => `• [${r.status}] ${r.action}${r.note ? ` — ${r.note}` : ''}`),
    ``,
    `─────────────────────────────────────────`,
    `DeepShield AI-IDS v3.1 | Automated report — verify before external distribution`,
  ].join('\n');
}

export default function InvestigationWorkspace({ alert, relatedAlerts = [] }: Props) {
  const [showReport, setShowReport] = useState(false);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [explainLoading, setExplainLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dispatchStatus, setDispatchStatus] = useState<string | null>(null);
  const [reportFormat, setReportFormat] = useState<'markdown' | 'json' | 'html'>('markdown');
  const [reportPreview, setReportPreview] = useState('');
  const [interpretation, setInterpretation] = useState<{ summary?: string; analyst_takeaway?: string } | null>(null);
  const [automationRuns, setAutomationRuns] = useState<AutomationRun[]>([]);
  const [liveFeatures, setLiveFeatures] = useState(alert?.features ?? []);

  useEffect(() => {
    setShowReport(false);
    setCopied(false);
    setLoading(false);
    setExplainLoading(false);
    setError(null);
    setDispatchStatus(null);
    setReportPreview('');
    setInterpretation(null);
    setLiveFeatures(alert?.features ?? []);
    setAutomationRuns([]);

    if (!alert?.backendId) return;

    fetchLiveAutomationRuns(alert.backendId)
      .then((runs) => setAutomationRuns(runs.map(mapAutomationRun)))
      .catch(() => {
        setAutomationRuns([]);
      });
  }, [alert?.id, alert?.backendId]);

  const reportSource = useMemo(() => {
    if (!alert) return null;
    return {
      ...alert,
      features: liveFeatures,
      automationRuns: automationRuns.length ? automationRuns : alert.automationRuns,
    };
  }, [alert, liveFeatures, automationRuns]);

  const handleCopy = () => {
    if (!reportSource) return;
    navigator.clipboard.writeText(buildReport(reportSource)).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleGenerateExplainability = async () => {
    if (!alert?.backendId) return;

    setExplainLoading(true);
    setError(null);
    try {
      const [interpResult, shapResult] = await Promise.allSettled([
        fetchLiveInterpretation(alert.backendId),
        syncLiveShap(alert.backendId),
      ]);

      if (interpResult.status === 'fulfilled') {
        setInterpretation({
          summary: interpResult.value.summary,
          analyst_takeaway: interpResult.value.analyst_takeaway,
        });
      }

      const shapPayload = shapResult.status === 'fulfilled'
        ? shapResult.value
        : await fetchLiveShap(alert.backendId);

      const mapped = shapPayload.shap.features.map((name, idx) => ({
        name,
        weight: Math.min(1, Math.abs(Number(shapPayload.shap.shap_values[idx] ?? 0))),
        value: String(shapPayload.shap.feature_values[idx] ?? 'n/a'),
      }));

      setLiveFeatures(mapped);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Explainability generation failed.');
    } finally {
      setExplainLoading(false);
    }
  };

  useEffect(() => {
    if (!alert?.backendId) return;
    handleGenerateExplainability();
  }, [alert?.id, alert?.backendId]);

  const handlePreviewReport = async () => {
    if (!alert?.backendId) return;
    setLoading(true);
    setError(null);
    try {
      const preview = await fetchLiveReportPreview(alert.backendId, reportFormat, true, Boolean(interpretation));
      setReportPreview(preview.rendered_content || 'No preview content returned.');
      setShowReport(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report preview failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleDispatchReport = async () => {
    if (!alert?.backendId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await dispatchLiveReport(alert.backendId, reportFormat, true, Boolean(interpretation));
      setDispatchStatus(`Dispatch ${result.status}${result.retry_count ? ` (retries: ${result.retry_count})` : ''}${result.reason ? ` · ${result.reason}` : ''}`);
      const runs = await fetchLiveAutomationRuns(alert.backendId);
      setAutomationRuns(runs.map(mapAutomationRun));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Dispatch failed.');
    } finally {
      setLoading(false);
    }
  };

  const canDispatch = alert?.status === 'ACTIVE' || alert?.status === 'INVESTIGATING';
  const incidentHistory = relatedAlerts.length ? relatedAlerts : (alert ? [alert] : []);

  if (!alert) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-center px-6 py-12">
        <div className="w-12 h-12 rounded-xl border border-slate-800 bg-slate-900 flex items-center justify-center">
          <MousePointerClick size={20} className="text-slate-600" />
        </div>
        <div>
          <p className="text-sm font-semibold text-slate-400 mb-1">No Incident Selected</p>
          <p className="text-[11px] text-slate-600 leading-relaxed max-w-xs">
            Select an alert from the queue to open the investigation workspace and review indicators, model analysis, and automation history.
          </p>
        </div>
      </div>
    );
  }

  const report = reportSource ? buildReport(reportSource) : '';
  const unknownEmergency = isUnknownEmergency(alert);

  return (
    <div className="flex-1 overflow-y-auto px-5 py-5 space-y-5 scrollbar-thin">
      {unknownEmergency && (
        <section className="border border-red-400/60 bg-red-950/40 shadow-[0_0_24px_rgba(239,68,68,0.18)] rounded px-4 py-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div>
              <div className="text-[11px] font-mono font-bold tracking-[0.22em] uppercase text-red-200">
                Unknown Attack Emergency
              </div>
              <p className="mt-1 text-[11px] text-red-100/90 leading-relaxed">
                Unclassified signature detected. Isolate the target path, preserve telemetry, and escalate to incident response now.
              </p>
            </div>
            <span className="text-[10px] font-mono font-bold text-white bg-red-500 border border-red-200/60 px-2 py-1 rounded animate-pulse">
              TAKE ACTION FAST
            </span>
          </div>
        </section>
      )}

      {/* 1. Incident Identity */}
      <section>
        <SectionLabel icon={<ShieldAlert size={12} />} label="Incident" />
        <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2">
          <IdentityCell label="Incident" value={alert.id} mono />
          <IdentityCell label="Attack Type" value={alert.attackType} />
          <IdentityCell label="Confidence" value={`${alert.confidence}%`} mono
            valueClass={alert.confidence >= 90 ? 'text-red-300' : alert.confidence >= 75 ? 'text-orange-300' : 'text-amber-300'}
          />
          <div className="bg-[#0d1520] border border-slate-700/50 rounded px-3 py-2">
            <div className="text-[9px] font-mono uppercase text-slate-600 mb-1">Severity</div>
            <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border ${severityColor(alert.severity)}`}>
              {unknownEmergency ? 'UNKNOWN CRITICAL' : alert.severity}
            </span>
          </div>
        </div>
        <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2">
          <IdentityCell label="Status" valueNode={
            <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border ${statusColor(alert.status)}`}>
              {alert.status}
            </span>
          } />
          <IdentityCell label="Protocol / Port" value={`${alert.protocol} : ${alert.port || 'ANY'}`} mono />
        </div>
      </section>

      {/* 2. Network Path */}
      <section>
        <SectionLabel icon={<Network size={12} />} label="Path & Risk" />
        <div className="mt-3 bg-[#0d1520] border border-slate-700/50 rounded p-4">
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <code className="text-[11px] font-mono text-cyan-300 bg-cyan-500/8 px-2 py-1 rounded">{alert.source}</code>
            <ArrowRight size={14} className="text-slate-600" />
            <code className="text-[11px] font-mono text-orange-300 bg-orange-500/8 px-2 py-1 rounded">{alert.target}</code>
            <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-2 py-1 rounded">{alert.protocol}</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">{alert.riskSummary}</p>
        </div>
      </section>

      {/* 3. Indicators */}
      <section>
        <SectionLabel icon={<ListChecks size={12} />} label="Evidence" />
        <div className="mt-3 bg-[#0d1520] border border-slate-700/50 rounded divide-y divide-slate-800/60">
          {alert.indicators.map((ind, i) => (
            <div key={i} className="flex items-start gap-2.5 px-4 py-2.5">
              <AlertTriangle size={11} className="text-amber-400 mt-0.5 shrink-0" />
              <span className="text-[11px] font-mono text-slate-300 leading-relaxed">{ind}</span>
            </div>
          ))}
        </div>
      </section>

      {/* 3b. Incident Log */}
      <section>
        <SectionLabel icon={<FileText size={12} />} label="Incident Log" />
        <div className="mt-3 max-h-80 overflow-y-auto overscroll-contain scrollbar-thin bg-[#0d1520] border border-slate-700/50 rounded divide-y divide-slate-800/60">
          {incidentHistory.map((item, idx) => (
            <div key={`${item.id}-${idx}`} className="px-4 py-3 space-y-2">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] font-mono text-cyan-300 bg-cyan-500/8 px-2 py-0.5 rounded">{item.id}</span>
                  <span className="text-[10px] font-mono text-slate-500">{item.timestamp.toLocaleTimeString()}</span>
                </div>
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className={`text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded border ${severityColor(item.severity)}`}>{item.severity}</span>
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${statusColor(item.status)}`}>{item.status}</span>
                  <span className="text-[9px] font-mono text-slate-500">{item.confidence}% confidence</span>
                </div>
              </div>
              <div className="text-[11px] font-mono text-slate-400">
                <span className="text-slate-300">{item.source}</span>
                <span className="text-slate-700 mx-1">→</span>
                <span className="text-slate-300">{item.target}</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{item.riskSummary}</p>
              {item.indicators?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {item.indicators.slice(0, 4).map((indicator) => (
                    <span key={indicator} className="text-[9px] font-mono text-slate-500 bg-slate-800/70 px-1.5 py-0.5 rounded">
                      {indicator}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* 4. Explainability */}
      <section>
        <div className="flex items-center justify-between gap-3">
          <SectionLabel icon={<Cpu size={12} />} label="Explainability Analysis" />
          <span className={`text-[10px] font-mono px-2 py-1 rounded border ${
            explainLoading
              ? 'text-amber-300 bg-amber-500/10 border-amber-500/30'
              : liveFeatures.length
                ? 'text-cyan-300 bg-cyan-500/10 border-cyan-500/30'
                : 'text-slate-500 bg-slate-800 border-slate-700'
          }`}>
            {explainLoading ? 'Generating...' : liveFeatures.length ? 'Auto generated' : 'Pending'}
          </span>
        </div>
        {liveFeatures.length > 0 && (
          <ExplainabilityPanel features={liveFeatures} attackType={alert.attackType} />
        )}
        {interpretation?.summary && (
          <p className="mt-3 text-[11px] text-slate-400 leading-relaxed">{interpretation.summary}</p>
        )}
      </section>

      {/* 5. Report Preview */}
      <section>
        <div className="flex items-center justify-between">
          <SectionLabel icon={<FileText size={12} />} label="Report Preview" />
          <button
            onClick={handlePreviewReport}
            className={`text-[10px] font-mono px-3 py-1.5 rounded border transition-all ${
              showReport
                ? 'text-cyan-300 bg-cyan-500/10 border-cyan-500/30 hover:bg-cyan-500/20'
                : 'text-slate-400 bg-slate-800 border-slate-700 hover:border-slate-600'
            }`}
          >
            {loading ? 'Loading…' : showReport ? 'Refresh Report Preview' : 'Preview Report'}
          </button>
        </div>
        {showReport && (
          <pre className="mt-3 text-[10px] font-mono text-slate-400 bg-[#060a10] border border-slate-800 rounded p-4 overflow-x-auto leading-relaxed whitespace-pre-wrap">
            {reportPreview || report}
          </pre>
        )}
      </section>

      {/* 6. Automation Runs */}
      <section>
        <SectionLabel icon={<ListChecks size={12} />} label="Automation Runs" />
        <div className="mt-3 bg-[#0d1520] border border-slate-700/50 rounded px-4 py-1">
          {(automationRuns.length ? automationRuns : alert.automationRuns).length === 0 ? (
            <p className="text-[11px] text-slate-600 py-3 text-center">No automation runs recorded for this incident.</p>
          ) : (
            (automationRuns.length ? automationRuns : alert.automationRuns).map(run => <RunRow key={run.id} run={run} />)
          )}
        </div>
      </section>

      {/* Actions */}
      <section className="pb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-2 text-[11px] font-mono rounded border border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700 hover:border-slate-600 transition-all"
          >
            {copied ? <CheckCircle2 size={13} className="text-green-400" /> : <Copy size={13} />}
            {copied ? 'Copied' : 'Copy Report'}
          </button>

          {canDispatch ? (
            <button
              onClick={handleDispatchReport}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-2 text-[11px] font-mono rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 transition-all disabled:opacity-60 disabled:cursor-not-allowed"
            >
              <Send size={13} />
              {loading ? 'Dispatching…' : 'Dispatch Report'}
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <button disabled className="flex items-center gap-1.5 px-3 py-2 text-[11px] font-mono rounded border border-slate-800 bg-slate-900 text-slate-600 cursor-not-allowed">
                <Send size={13} />
                Dispatch Report
              </button>
              <span className="text-[10px] font-mono text-slate-600">
                Policy: dispatch only for ACTIVE or INVESTIGATING incidents
              </span>
            </div>
          )}
        </div>
      </section>

      <section className="pb-4">
        <div className="flex items-center gap-2 flex-wrap">
          <label className="text-[10px] font-mono text-slate-500">Report Format</label>
          <select
            value={reportFormat}
            onChange={(e) => setReportFormat(e.target.value as 'markdown' | 'json' | 'html')}
            className="text-[10px] font-mono px-2 py-1 rounded border border-slate-700 bg-slate-900 text-slate-300"
          >
            <option value="markdown">Markdown</option>
            <option value="json">JSON</option>
            <option value="html">HTML</option>
          </select>
        </div>
        {dispatchStatus && <p className="mt-2 text-[10px] text-slate-400">{dispatchStatus}</p>}
        {error && <p className="mt-2 text-[10px] text-rose-300">{error}</p>}
      </section>
    </div>
  );
}

function SectionLabel({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-slate-500">{icon}</span>
      <span className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">{label}</span>
    </div>
  );
}

function IdentityCell({
  label,
  value,
  valueNode,
  mono,
  valueClass,
}: {
  label: string;
  value?: string;
  valueNode?: React.ReactNode;
  mono?: boolean;
  valueClass?: string;
}) {
  return (
    <div className="bg-[#0d1520] border border-slate-700/50 rounded px-3 py-2">
      <div className="text-[9px] font-mono uppercase text-slate-600 mb-1">{label}</div>
      {valueNode ?? (
        <div className={`text-[11px] font-semibold ${mono ? 'font-mono' : ''} ${valueClass ?? 'text-slate-200'}`}>
          {value}
        </div>
      )}
    </div>
  );
}
