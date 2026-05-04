import { Shield, RefreshCw, Clock, AlertTriangle } from 'lucide-react';

interface Props {
  activeAlerts: number;
  lastUpdated: Date;
  autoRefresh: boolean;
  onToggleRefresh: () => void;
  dominantThreat: string;
  currentConfidence: number;
  simulationState: 'idle' | 'baseline' | 'attack-active';
}

function pad(n: number) {
  return String(n).padStart(2, '0');
}

function fmtTime(d: Date) {
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} UTC`;
}

export default function Header({ activeAlerts, lastUpdated, autoRefresh, onToggleRefresh, dominantThreat, currentConfidence, simulationState }: Props) {
  const stateLabel = simulationState === 'attack-active' ? 'ATTACK FLOW' : simulationState === 'baseline' ? 'BASELINE FLOW' : 'IDLE';
  return (
    <header className="relative border-b border-slate-800 bg-[#080d14]">
      {/* Subtle top accent line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500 to-transparent opacity-60" />

      <div className="flex items-center justify-between px-5 py-3 gap-4">
        {/* Identity */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 shrink-0">
            <Shield size={16} className="text-cyan-400" />
          </div>
          <div>
            <span className="text-sm font-semibold tracking-widest text-slate-100 uppercase">DeepShield</span>
            <div className="mt-1 flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/25 bg-cyan-500/8 text-cyan-300">
                Live confidence {currentConfidence.toFixed(0)}%
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${simulationState === 'attack-active' ? 'border-red-500/25 bg-red-500/8 text-red-300' : 'border-green-500/25 bg-green-500/8 text-green-300'}`}>
                {stateLabel}
              </span>
            </div>
          </div>
        </div>

        {/* Status strip */}
        <div className="hidden md:flex items-center gap-1">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-green-500/8 border border-green-500/20">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-60" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
            </span>
            <span className="text-[11px] font-mono text-green-400 tracking-wide">SYSTEM LIVE</span>
          </div>

          <div className="w-px h-6 bg-slate-700 mx-1" />

          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-500/8 border border-red-500/20">
            <AlertTriangle size={12} className="text-red-400" />
            <span className="text-[11px] font-mono text-slate-400">ACTIVE</span>
            <span className="text-[11px] font-mono text-red-300 font-semibold">{activeAlerts}</span>
          </div>

          <div className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded bg-orange-500/8 border border-orange-500/20">
            <span className="text-[10px] font-mono text-slate-500 uppercase">THREAT</span>
            <span className="text-[11px] font-mono text-orange-300 font-semibold">{dominantThreat}</span>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Last updated */}
          <div className="hidden sm:flex items-center gap-1.5 text-[10px] font-mono text-slate-500">
            <Clock size={10} />
            <span>{fmtTime(lastUpdated)}</span>
          </div>

          {/* Auto-refresh toggle */}
          <button
            onClick={onToggleRefresh}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] font-mono transition-all border ${
              autoRefresh
                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20'
                : 'bg-slate-800 border-slate-700 text-slate-500 hover:border-slate-600'
            }`}
          >
            <RefreshCw size={11} className={autoRefresh ? 'animate-spin-slow' : ''} />
            {autoRefresh ? 'AUTO-REFRESH ON' : 'AUTO-REFRESH OFF'}
          </button>
        </div>
      </div>
    </header>
  );
}
