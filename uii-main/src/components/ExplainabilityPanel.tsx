import type { Feature } from '../types';

interface Props {
  features: Feature[];
  attackType: string;
}

const MAX_WEIGHT = 1.0;

export default function ExplainabilityPanel({ features, attackType }: Props) {
  const top = features[0];

  return (
    <div className="mt-4 border border-slate-700/50 rounded bg-[#0a111c]">
      <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">
          Model Explainability
        </span>
        <span className="text-[10px] font-mono text-slate-600">SHAP-derived feature weights</span>
      </div>

      {/* Narrative */}
      <div className="px-4 py-3 border-b border-slate-700/30 bg-cyan-500/3">
        <p className="text-[11px] text-slate-300 leading-relaxed">
          This alert was flagged primarily due to{' '}
          <span className="text-cyan-300 font-medium">{top?.name ?? 'anomaly patterns'}</span>
          {' '}(weight {((top?.weight ?? 0) * 100).toFixed(0)}%), consistent with known{' '}
          <span className="text-slate-200">{attackType}</span> behavioral signatures.
          The ensemble assigned high confidence based on the co-occurrence of {features.length} correlated indicators.
        </p>
      </div>

      {/* Feature bars */}
      <div className="px-4 py-3 space-y-2.5">
        {features.map((f, i) => (
          <div key={i}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono text-slate-300">{f.name}</span>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-slate-500">{f.value}</span>
                <span className="text-[10px] font-mono font-semibold text-cyan-400 w-9 text-right">
                  {(f.weight * 100).toFixed(0)}%
                </span>
              </div>
            </div>
            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${(f.weight / MAX_WEIGHT) * 100}%`,
                  background: f.weight > 0.85
                    ? 'linear-gradient(90deg, #ef4444, #f97316)'
                    : f.weight > 0.65
                    ? 'linear-gradient(90deg, #f97316, #eab308)'
                    : 'linear-gradient(90deg, #22d3ee, #0891b2)',
                }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="border-t border-slate-700/30 overflow-x-auto">
        <table className="w-full text-[10px] font-mono">
          <thead>
            <tr className="border-b border-slate-700/30">
              <th className="text-left px-4 py-2 text-slate-600 font-normal uppercase tracking-wider">#</th>
              <th className="text-left px-4 py-2 text-slate-600 font-normal uppercase tracking-wider">Feature</th>
              <th className="text-left px-4 py-2 text-slate-600 font-normal uppercase tracking-wider">Observed Value</th>
              <th className="text-right px-4 py-2 text-slate-600 font-normal uppercase tracking-wider">Weight</th>
            </tr>
          </thead>
          <tbody>
            {features.map((f, i) => (
              <tr key={i} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                <td className="px-4 py-2 text-slate-600">{i + 1}</td>
                <td className="px-4 py-2 text-slate-300">{f.name}</td>
                <td className="px-4 py-2 text-slate-400">{f.value}</td>
                <td className={`px-4 py-2 text-right font-semibold ${
                  f.weight > 0.85 ? 'text-red-400' : f.weight > 0.65 ? 'text-orange-400' : 'text-cyan-400'
                }`}>
                  {(f.weight * 100).toFixed(0)}%
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
