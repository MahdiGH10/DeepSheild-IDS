import { Radio, Filter, Eye } from 'lucide-react';

interface Props {
  dominantThreat: string;
  activeAlerts: number;
  filterCategory: string | null;
  currentConfidence: number;
  simulationState: 'idle' | 'baseline' | 'attack-active';
}

export default function HeroBriefing({ dominantThreat, activeAlerts, filterCategory, currentConfidence, simulationState }: Props) {
  return (
    <div className="border-b border-slate-800 bg-[#090e16] px-5 py-2.5">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          <BriefingItem
            icon={<Radio size={11} className="text-cyan-400" />}
            label="Live Confidence"
            value={`${currentConfidence.toFixed(0)}%`}
            color={currentConfidence >= 70 ? 'red' : 'cyan'}
          />
          <BriefingItem
            icon={<Radio size={11} className="text-red-400" />}
            label="Dominant Threat"
            value={dominantThreat}
            color="red"
          />
          <BriefingItem
            icon={<Filter size={11} className="text-cyan-400" />}
            label="Queue Filter"
            value={filterCategory ?? 'All Categories'}
            color="cyan"
          />
          <BriefingItem
            icon={<Eye size={11} className="text-green-400" />}
            label="Monitor State"
            value={simulationState === 'attack-active' ? `${activeAlerts} active incident${activeAlerts !== 1 ? 's' : ''}` : simulationState === 'baseline' ? 'Baseline traffic only' : 'Waiting for telemetry'}
            color="green"
          />
        </div>
      </div>
    </div>
  );
}

function BriefingItem({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  color: 'red' | 'cyan' | 'green';
}) {
  const colors = {
    red: 'border-red-500/20 bg-red-500/5 text-red-300',
    cyan: 'border-cyan-500/20 bg-cyan-500/5 text-cyan-300',
    green: 'border-green-500/20 bg-green-500/5 text-green-300',
  };

  return (
    <div className={`flex items-center gap-2 px-2.5 py-1.5 rounded border ${colors[color]}`}>
      {icon}
      <span className="text-[10px] text-slate-500 font-mono uppercase">{label}:</span>
      <span className="text-[11px] font-mono font-medium">{value}</span>
    </div>
  );
}
