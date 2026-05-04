import { ChevronRight, Inbox } from 'lucide-react';
import type { Alert, Severity, AlertStatus } from '../types';

interface Props {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  filterCategory: string | null;
}

const BASELINE_LABELS = new Set(['benign', 'normal', 'normal traffic']);

function isBaselineAlert(alert: Alert): boolean {
  return BASELINE_LABELS.has((alert.attackType || '').trim().toLowerCase());
}

function severityStyle(s: Severity) {
  switch (s) {
    case 'CRITICAL': return 'bg-red-500/15 text-red-300 border-red-500/30';
    case 'HIGH':     return 'bg-orange-500/15 text-orange-300 border-orange-500/30';
    case 'MEDIUM':   return 'bg-amber-500/15 text-amber-300 border-amber-500/30';
    case 'LOW':      return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

function statusStyle(s: AlertStatus) {
  switch (s) {
    case 'ACTIVE':        return 'bg-red-500/10 text-red-400';
    case 'INVESTIGATING': return 'bg-cyan-500/10 text-cyan-400';
    case 'ESCALATED':     return 'bg-orange-500/10 text-orange-400';
    case 'RESOLVED':      return 'bg-green-500/10 text-green-400';
  }
}

function relTime(d: Date) {
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function severityDot(s: Severity) {
  switch (s) {
    case 'CRITICAL': return 'bg-red-400';
    case 'HIGH':     return 'bg-orange-400';
    case 'MEDIUM':   return 'bg-amber-400';
    case 'LOW':      return 'bg-slate-400';
  }
}

function isUnknownEmergency(alert: Alert): boolean {
  return Boolean(alert.unknownAttack) || /unknown|zero-day|unidentified/i.test(alert.attackType);
}

export default function AlertQueue({ alerts, selectedId, onSelect, filterCategory }: Props) {
  const threatAlerts = alerts.filter(a => !isBaselineAlert(a));
  const filtered = filterCategory
    ? threatAlerts.filter(a => a.attackType === filterCategory)
    : threatAlerts;

  return (
    <aside className="flex flex-col h-full bg-[#080d14] border-r border-slate-800 min-w-0 overflow-hidden">
      {/* Rail header */}
      <div className="px-4 pt-4 pb-3 border-b border-slate-800">
        <div className="flex items-center justify-between">
          <h2 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">Alert Queue</h2>
          <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded">
            {filtered.length} / {threatAlerts.length}
          </span>
        </div>
        <p className="text-[10px] text-slate-600 mt-1 leading-relaxed">
          Select an incident to inspect details.
        </p>
      </div>

      {/* Alert stream */}
      <div className="flex-1 min-h-0 overflow-y-auto overscroll-contain scrollbar-thin scroll-smooth">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 gap-3 px-4">
            <Inbox size={22} className="text-slate-700" />
            <p className="text-[11px] text-slate-600 text-center leading-relaxed">
              No threat alerts match the current filter.<br />Clear the threat filter to view all incidents.
            </p>
          </div>
        ) : (
          <div className="py-1">
            {filtered.map(alert => {
              const selected = alert.id === selectedId;
              const unknownEmergency = isUnknownEmergency(alert);
              return (
                <button
                  key={alert.id}
                  onClick={() => onSelect(alert.id)}
                  className={`w-full text-left px-4 py-3 border-b border-slate-800/70 transition-all group relative
                    ${unknownEmergency
                      ? 'bg-red-950/30 border-l-2 border-l-red-400 shadow-[inset_0_0_0_1px_rgba(248,113,113,0.22)]'
                      : selected
                        ? 'bg-cyan-500/8 border-l-2 border-l-cyan-500'
                        : 'hover:bg-slate-800/40 border-l-2 border-l-transparent'
                    }`}
                >
                  {/* Selected indicator glow */}
                  {selected && (
                    <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-cyan-400 shadow-[0_0_8px_theme(colors.cyan.400)]" />
                  )}

                  {/* Top row */}
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${severityDot(alert.severity)} ${alert.status === 'ACTIVE' ? 'animate-pulse' : ''}`} />
                      <span className="text-[11px] font-semibold text-slate-200 truncate">{alert.attackType}</span>
                    </div>
                    {unknownEmergency && (
                      <span className="text-[8px] font-mono font-bold text-white bg-red-500 border border-red-300/50 rounded px-1.5 py-0.5 animate-pulse">
                        TAKE ACTION
                      </span>
                    )}
                    {'occurrenceCount' in alert && (alert as Alert & { occurrenceCount?: number }).occurrenceCount ? (
                      <span className="text-[9px] font-mono text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 rounded px-1.5 py-0.5">
                        x{(alert as Alert & { occurrenceCount?: number }).occurrenceCount}
                      </span>
                    ) : null}
                    <ChevronRight size={12} className={`text-slate-700 shrink-0 transition-colors ${selected ? 'text-cyan-500' : 'group-hover:text-slate-500'}`} />
                  </div>

                  {/* Alert ID + time */}
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono text-slate-500">{alert.id}</span>
                    <span className="text-[10px] font-mono text-slate-600">{relTime(alert.timestamp)}</span>
                  </div>

                  {/* Source → Target */}
                  <div className="text-[10px] font-mono text-slate-500 mb-2 truncate">
                    <span className="text-slate-400">{alert.source}</span>
                    <span className="text-slate-700 mx-1">→</span>
                    <span className="text-slate-400">{alert.target}</span>
                  </div>

                  {/* Confidence + badges */}
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <div className="flex items-center gap-1">
                      <div className="w-14 h-1.5 rounded-full bg-slate-700 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            alert.confidence >= 90 ? 'bg-red-400' :
                            alert.confidence >= 75 ? 'bg-orange-400' :
                            alert.confidence >= 60 ? 'bg-amber-400' : 'bg-green-400'
                          }`}
                          style={{ width: `${alert.confidence}%` }}
                        />
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">{alert.confidence}%</span>
                    </div>

                    <span className={`text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded border uppercase ${severityStyle(alert.severity)}`}>
                      {unknownEmergency ? 'UNKNOWN CRITICAL' : alert.severity}
                    </span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase ${statusStyle(alert.status)}`}>
                      {alert.status}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </aside>
  );
}
