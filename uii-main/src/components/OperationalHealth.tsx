import { TrendingUp, TrendingDown, Minus, Activity, Zap } from 'lucide-react';
import type { SystemHealth, ThreatBreakdown, ThreatCategory } from '../types';

interface Props {
  health: SystemHealth;
  breakdown: ThreatBreakdown[];
  filterCategory: ThreatCategory | null;
  onFilterToggle: (cat: ThreatCategory) => void;
}

function TrendIcon({ trend }: { trend: 'up' | 'stable' | 'down' }) {
  if (trend === 'up') return <TrendingUp size={11} className="text-red-400" />;
  if (trend === 'down') return <TrendingDown size={11} className="text-green-400" />;
  return <Minus size={11} className="text-slate-500" />;
}

function StatusPill({ status, label }: { status: 'ONLINE' | 'FALLBACK' | 'OFFLINE' | 'READY' | 'PARTIAL' | 'DOWN' | 'SUCCESS' | 'FAILED' | 'SKIPPED'; label?: string }) {
  const configs: Record<string, { color: string; dot: string }> = {
    ONLINE:   { color: 'text-green-300 bg-green-500/10 border-green-500/25', dot: 'bg-green-400' },
    READY:    { color: 'text-green-300 bg-green-500/10 border-green-500/25', dot: 'bg-green-400' },
    SUCCESS:  { color: 'text-green-300 bg-green-500/10 border-green-500/25', dot: 'bg-green-400' },
    FALLBACK: { color: 'text-amber-300 bg-amber-500/10 border-amber-500/25', dot: 'bg-amber-400' },
    PARTIAL:  { color: 'text-amber-300 bg-amber-500/10 border-amber-500/25', dot: 'bg-amber-400' },
    SKIPPED:  { color: 'text-slate-400 bg-slate-500/10 border-slate-500/25', dot: 'bg-slate-500' },
    OFFLINE:  { color: 'text-red-300 bg-red-500/10 border-red-500/25', dot: 'bg-red-400' },
    DOWN:     { color: 'text-red-300 bg-red-500/10 border-red-500/25', dot: 'bg-red-400' },
    FAILED:   { color: 'text-red-300 bg-red-500/10 border-red-500/25', dot: 'bg-red-400' },
  };
  const cfg = configs[status] ?? configs.SKIPPED;
  return (
    <span className={`flex items-center gap-1 text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${cfg.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {label ?? status}
    </span>
  );
}

const maxCount = (breakdown: ThreatBreakdown[]) =>
  Math.max(...breakdown.map(b => b.count), 1);

export default function OperationalHealth({ health, breakdown, filterCategory, onFilterToggle }: Props) {
  const max = maxCount(breakdown);
  const benchmarkMissing = 'Benchmark metrics will appear once labeled training data is connected.';

  return (
    <aside className="flex flex-col h-full bg-[#080d14] border-l border-slate-800 overflow-y-auto scrollbar-thin">
      {/* Rail label */}
      <div className="px-4 pt-4 pb-3 border-b border-slate-800">
        <h2 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">Operational Health</h2>
      </div>

      {/* Model status */}
      <Module label="Detection Model" icon={<Cpu />}>
        <Row label="Model Status" right={<StatusPill status={health.modelStatus} />} />
        <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
          {health.modelDetail}
        </p>
        <MetricGrid items={[
          { label: 'Processed', value: `${health.processedTotal}`, note: 'events' },
          { label: 'Avg Confidence', value: `${health.avgConfidence}%`, note: 'live window' },
          { label: 'Recent Events', value: `${health.recentEventCount}`, note: 'posture window' },
          { label: 'Attack Share', value: `${health.attackShare}%`, note: 'recent ratio' },
        ]} />
        <p className="text-[10px] font-mono text-slate-600 leading-relaxed mt-1">
          {benchmarkMissing}
        </p>
      </Module>

      {/* Automation health */}
      <Module label="Automation & Integration" icon={<Zap />}>
        <Row label="Automation" right={<StatusPill status={health.automationStatus} />} />
        <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
          {health.automationDetail}
        </p>
        {health.lastError && (
          <p className="text-[10px] font-mono text-red-300/80 leading-relaxed break-all mt-2">
            Last error: {health.lastError}
          </p>
        )}
        <MetricGrid items={[
          { label: 'Retries', value: `${health.retryCount}`, note: 'latest run' },
          { label: 'MTTD', value: 'N/A', note: 'not yet wired' },
          { label: 'MTTR', value: 'N/A', note: 'not yet wired' },
          { label: 'FPR', value: 'N/A', note: 'needs labels' },
        ]} />
      </Module>

      {/* Threat breakdown */}
      <Module label="Traffic Taxonomy" icon={<Activity />} noBorder>
        <div className="space-y-2">
          {breakdown.map(item => {
            const isActive = filterCategory === item.category;
            const pct = (item.count / max) * 100;
            return (
              <button
                key={item.category}
                onClick={() => onFilterToggle(item.category)}
                className={`w-full text-left rounded px-2 py-2 transition-all border group ${
                  isActive
                    ? 'bg-cyan-500/8 border-cyan-500/30'
                    : 'bg-transparent border-transparent hover:bg-slate-800/40 hover:border-slate-700/50'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className={`text-[10px] font-mono truncate ${isActive ? 'text-cyan-300' : 'text-slate-300 group-hover:text-slate-200'}`}>
                    {item.category === 'Baseline' ? 'Baseline / Normal' : item.category}
                  </span>
                  <div className="flex items-center gap-1.5 shrink-0 ml-2">
                    <TrendIcon trend={item.trend} />
                    <span className={`text-[10px] font-mono font-semibold ${isActive ? 'text-cyan-400' : 'text-slate-400'}`}>
                      {item.count}
                    </span>
                  </div>
                </div>
                <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${isActive ? 'bg-cyan-400' : 'bg-slate-600 group-hover:bg-slate-500'}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </button>
            );
          })}
        </div>

        {breakdown.length === 0 && (
          <p className="text-[10px] text-slate-600 leading-relaxed py-2">
            No telemetry points received yet — waiting for the live stream.
          </p>
        )}

        {filterCategory && (
          <button
            onClick={() => onFilterToggle(filterCategory)}
            className="mt-3 w-full text-[10px] font-mono text-slate-500 hover:text-slate-300 py-1.5 rounded border border-slate-800 hover:border-slate-700 transition-all"
          >
            Clear Filter
          </button>
        )}
      </Module>
    </aside>
  );
}

function Cpu() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <path d="M15 2v2M9 2v2M2 9h2M2 15h2M22 9h-2M22 15h-2M15 22v-2M9 22v-2" />
    </svg>
  );
}

function Module({ label, icon, children, noBorder }: { label: string; icon: React.ReactNode; children: React.ReactNode; noBorder?: boolean }) {
  return (
    <div className={`px-4 py-4 ${!noBorder ? 'border-b border-slate-800' : ''}`}>
      <div className="flex items-center gap-2 mb-3">
        <span className="text-slate-500">{icon}</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{label}</span>
      </div>
      <div className="space-y-2">
        {children}
      </div>
    </div>
  );
}

function Row({ label, right }: { label: string; right: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-[10px] font-mono text-slate-600">{label}</span>
      {right}
    </div>
  );
}

function MetricGrid({ items }: { items: Array<{ label: string; value: string; note?: string }> }) {
  return (
    <div className="grid grid-cols-2 gap-2 mt-2">
      {items.map(item => (
        <div key={item.label} className="rounded border border-slate-800 bg-[#060a10] px-2.5 py-2">
          <div className="text-[9px] font-mono uppercase text-slate-600">{item.label}</div>
          <div className="mt-0.5 text-[12px] font-mono font-semibold text-slate-200">{item.value}</div>
          {item.note && <div className="text-[9px] font-mono text-slate-600 mt-0.5">{item.note}</div>}
        </div>
      ))}
    </div>
  );
}
