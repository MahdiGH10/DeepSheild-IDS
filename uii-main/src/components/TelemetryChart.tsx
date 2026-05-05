import { useEffect, useMemo, useState } from 'react';
import type { TelemetryPoint } from '../types';

interface Props {
  data: TelemetryPoint[];
}

const W = 1000;
const H = 340;
const PAD_L = 42;
const PAD_R = 14;
const PAD_T = 14;
const PAD_B = 34;
const CW = W - PAD_L - PAD_R;
const CH = H - PAD_T - PAD_B;
const DISPLAY_POINTS = 48;
const MAX_RENDER_POINTS = 96;
const CONFIDENCE_ALERT = 70;
const BASELINE_STEP_MS = 700;

type RangeKey = '1m' | '5m' | '1h' | 'live';

const RANGE_OPTIONS: Array<{ key: RangeKey; label: string; seconds: number }> = [
  { key: '1m', label: '1m', seconds: 60 },
  { key: '5m', label: '5m', seconds: 5 * 60 },
  { key: '1h', label: '1h', seconds: 60 * 60 },
  { key: 'live', label: 'Live', seconds: 120 },
];

type SlotPoint = {
  t: number;
  confidence: number;
  intensity: number;
  isAttack: boolean;
};

function clamp(n: number, min: number, max: number) {
  return Math.min(max, Math.max(min, n));
}

function yAt(value: number) {
  return PAD_T + CH - (clamp(value, 0, 100) / 100) * CH;
}

function xAt(index: number, total = DISPLAY_POINTS) {
  if (total <= 1) return PAD_L;
  return PAD_L + (index / (total - 1)) * CW;
}

function smoothPath(points: Array<{ x: number; y: number }>) {
  if (points.length < 2) return '';
  if (points.length === 2) return `M ${points[0].x} ${points[0].y} L ${points[1].x} ${points[1].y}`;

  let d = `M ${points[0].x} ${points[0].y}`;

  for (let i = 1; i < points.length - 1; i += 1) {
    const next = points[i + 1];
    const cpx2 = (points[i].x + next.x) / 2;
    const cpy2 = (points[i].y + next.y) / 2;
    d += ` Q ${points[i].x} ${points[i].y} ${cpx2} ${cpy2}`;
  }

  const last = points[points.length - 1];
  d += ` T ${last.x} ${last.y}`;
  return d;
}

function getTimeLabel(offsetSeconds: number) {
  const d = new Date(Date.now() - offsetSeconds * 1000);
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function samplePoints(points: SlotPoint[], maxPoints = MAX_RENDER_POINTS) {
  if (points.length <= maxPoints) return points;
  const sampled: SlotPoint[] = [];
  const step = (points.length - 1) / (maxPoints - 1);

  for (let i = 0; i < maxPoints; i += 1) {
    sampled.push(points[Math.round(i * step)]);
  }

  return sampled;
}

function baselinePoint(index: number, total = DISPLAY_POINTS, now = Date.now()): SlotPoint {
  const phase = now / BASELINE_STEP_MS;
  const wave = Math.sin((index + phase) / 4) * 5 + Math.cos((index + phase) / 7) * 3;
  const confidence = clamp(56 + wave, 42, 66);

  return {
    t: now - (total - index - 1) * BASELINE_STEP_MS,
    confidence,
    intensity: confidence / 100,
    isAttack: false,
  };
}

function baselineSeries(total = DISPLAY_POINTS, now = Date.now()): SlotPoint[] {
  return Array.from({ length: total }, (_, index) => baselinePoint(index, total, now));
}

function toSeries(input: TelemetryPoint[], now = Date.now()): SlotPoint[] {
  const slots = baselineSeries(DISPLAY_POINTS, now);
  const start = slots[0]?.t ?? now;
  const end = slots[slots.length - 1]?.t ?? now;
  const slotSpan = Math.max(end - start, BASELINE_STEP_MS);
  const slotStep = slotSpan / Math.max(slots.length - 1, 1);
  const livePoints = input
    .slice(-MAX_RENDER_POINTS)
    .map(point => ({
      t: point.t || now,
      confidence: clamp(point.confidence, 0, 100),
      intensity: clamp(point.intensity || point.confidence / 100, 0, 1),
      isAttack: point.isAttack,
    }))
    .filter(point => point.t >= start - slotStep && point.t <= end + slotStep);

  livePoints.forEach(point => {
    const nearestIndex = clamp(Math.round((point.t - start) / slotStep), 0, slots.length - 1);
    const indexes = point.isAttack
      ? [nearestIndex - 1, nearestIndex, nearestIndex + 1]
      : [nearestIndex];

    indexes.forEach(index => {
      if (index < 0 || index >= slots.length) return;
      const existing = slots[index];
      const confidence = point.isAttack
        ? Math.max(existing.confidence, point.confidence)
        : point.confidence;

      slots[index] = {
        t: existing.t,
        confidence,
        intensity: point.intensity,
        isAttack: existing.isAttack || point.isAttack,
      };
    });
  });

  return slots;
}

export default function TelemetryChart({ data }: Props) {
  const [clock, setClock] = useState(() => Date.now());
  const [series, setSeries] = useState<SlotPoint[]>(() => toSeries(data));
  const [selectedRange, setSelectedRange] = useState<RangeKey>('1m');

  useEffect(() => {
    let frame = 0;
    let lastUpdate = 0;

    const animate = (timestamp: number) => {
      if (timestamp - lastUpdate >= BASELINE_STEP_MS) {
        lastUpdate = timestamp;
        setClock(Date.now());
      }
      frame = requestAnimationFrame(animate);
    };

    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    setSeries(toSeries(data, clock));
  }, [clock, data]);

  const latest = series[series.length - 1];
  const selectedWindow = RANGE_OPTIONS.find(option => option.key === selectedRange) ?? RANGE_OPTIONS[0];
  const visibleSeries = useMemo(() => {
    const cutoff = clock - selectedWindow.seconds * 1000;
    const inWindow = series.filter(point => point.t >= cutoff);
    const source = inWindow.length ? inWindow : series.slice(-DISPLAY_POINTS);
    return samplePoints(source);
  }, [clock, selectedWindow.seconds, series]);

  const currentConf = Math.round(latest?.confidence ?? 0);

  const avgConf = useMemo(() => {
    const points = visibleSeries.slice(-14);
    if (!points.length) return 0;
    return Math.round(points.reduce((sum, point) => sum + point.confidence, 0) / points.length);
  }, [visibleSeries]);

  const peakConf = useMemo(() => {
    if (!visibleSeries.length) return 0;
    return Math.round(visibleSeries.reduce((peak, point) => Math.max(peak, point.confidence), 0));
  }, [visibleSeries]);

  const activeAttackCount = visibleSeries.filter(point => point.isAttack).length;
  const attackShare = Math.round((activeAttackCount / Math.max(visibleSeries.length, 1)) * 100);
  const signalState = activeAttackCount > 6 ? 'CRITICAL' : activeAttackCount > 3 ? 'ELEVATED' : 'BASELINE';
  const isAttackNow = Boolean(latest?.isAttack) || signalState !== 'BASELINE';

  const chartPoints = useMemo(
    () => visibleSeries.map((point, index) => ({
      x: xAt(index, visibleSeries.length),
      y: yAt(point.confidence),
      point,
      index,
    })),
    [visibleSeries]
  );

  const signalPaths = useMemo(() => {
    const bottom = PAD_T + CH;
    if (chartPoints.length < 2) return [];

    const segments: Array<{
      isAttack: boolean;
      points: Array<{ x: number; y: number }>;
    }> = [];
    let current = [
      { x: chartPoints[0].x, y: chartPoints[0].y },
      { x: chartPoints[1].x, y: chartPoints[1].y },
    ];
    let currentIsAttack = chartPoints[1].point.isAttack;

    for (let index = 2; index < chartPoints.length; index += 1) {
      const point = chartPoints[index];
      const previous = chartPoints[index - 1];
      const nextIsAttack = point.point.isAttack;

      if (nextIsAttack !== currentIsAttack) {
        segments.push({ isAttack: currentIsAttack, points: current });
        current = [
          { x: previous.x, y: previous.y },
          { x: point.x, y: point.y },
        ];
        currentIsAttack = nextIsAttack;
      } else {
        current.push({ x: point.x, y: point.y });
      }
    }

    segments.push({ isAttack: currentIsAttack, points: current });

    return segments.map(segment => {
      const line = smoothPath(segment.points);
      return {
        isAttack: segment.isAttack,
        line,
        surface: `${line} L ${segment.points[segment.points.length - 1].x} ${bottom} L ${segment.points[0].x} ${bottom} Z`,
      };
    });
  }, [chartPoints]);

  const xLabels = [
    { offset: selectedWindow.seconds, x: PAD_L },
    { offset: Math.round(selectedWindow.seconds * 0.75), x: PAD_L + CW * 0.25 },
    { offset: Math.round(selectedWindow.seconds * 0.5), x: PAD_L + CW * 0.5 },
    { offset: Math.round(selectedWindow.seconds * 0.25), x: PAD_L + CW * 0.75 },
    { offset: 0, x: PAD_L + CW },
  ];

  return (
    <div className="bg-[#080d14] border-b border-slate-800 px-5 py-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className={`w-1.5 h-1.5 rounded-full ${isAttackNow ? 'bg-red-400 animate-pulse' : 'bg-green-400'}`} />
          <span className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">
            Real-Time Telemetry
          </span>
          <span className="text-[10px] font-mono text-slate-600">- live confidence signal</span>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
          signalState === 'CRITICAL'
            ? 'text-red-300 bg-red-500/10 border-red-500/25'
            : signalState === 'ELEVATED'
              ? 'text-amber-300 bg-amber-500/10 border-amber-500/25'
              : 'text-green-300 bg-green-500/10 border-green-500/25'
        }`}>
          {signalState}
        </span>
      </div>

      <div className="grid grid-cols-5 gap-2 mb-3">
        <MetricCell label="Confidence (now)" value={`${currentConf}%`} alert={currentConf > CONFIDENCE_ALERT} />
        <MetricCell label="10s Avg" value={`${avgConf}%`} alert={avgConf > CONFIDENCE_ALERT} />
        <MetricCell label="Peak" value={`${peakConf}%`} alert={peakConf > CONFIDENCE_ALERT} />
        <MetricCell label="Signal State" value={signalState} alert={signalState !== 'BASELINE'} />
        <MetricCell label="Attack Share" value={`${attackShare}%`} alert={attackShare > 10} />
      </div>

      <div className="relative w-full overflow-hidden rounded bg-transparent border border-slate-800/70">
        <div className="px-4 pt-3 pb-2 flex items-start justify-between gap-3 border-b border-slate-800/50 bg-transparent">
          <div>
            <div className="text-[10px] font-semibold uppercase tracking-[0.32em] text-cyan-300">
              Network traffic - real-time telemetry
            </div>
            <div className="mt-1 text-[10px] font-mono text-slate-600">
              smooth live stream with selective attack signal
            </div>
          </div>
          <div className="flex gap-1.5">
            {RANGE_OPTIONS.map(option => (
              <button
                key={option.key}
                onClick={() => setSelectedRange(option.key)}
                className={`h-6 min-w-8 px-2 text-[9px] font-mono uppercase tracking-[0.18em] border transition-colors ${
                  selectedRange === option.key
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-400/10'
                    : 'border-slate-800 text-slate-500 hover:text-slate-300 hover:border-slate-700'
                }`}
                type="button"
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        <div className="px-4 pt-3 pb-2 bg-transparent">
          <div className="relative h-[340px] overflow-hidden bg-transparent">
            <svg
              className="absolute inset-0 h-full w-full"
              style={{ background: 'transparent' }}
              viewBox={`0 0 ${W} ${H}`}
              preserveAspectRatio="none"
              role="img"
              aria-label="Real-time telemetry area chart"
            >
              <defs>
                <linearGradient id="area-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00c8ff" stopOpacity="0.35" />
                  <stop offset="60%" stopColor="#00c8ff" stopOpacity="0.08" />
                  <stop offset="100%" stopColor="#00c8ff" stopOpacity="0" />
                </linearGradient>
                <linearGradient id="attack-surface-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff3366" stopOpacity="0.36" />
                  <stop offset="58%" stopColor="#ff3366" stopOpacity="0.13" />
                  <stop offset="100%" stopColor="#ff3366" stopOpacity="0" />
                </linearGradient>
              </defs>

              {[0, 25, 50, 75, 100].map(value => (
                <g key={value}>
                  <line
                    x1={PAD_L}
                    x2={W - PAD_R}
                    y1={yAt(value)}
                    y2={yAt(value)}
                    stroke="rgba(0,200,255,0.06)"
                    strokeWidth="1"
                  />
                  <text
                    x={PAD_L - 16}
                    y={yAt(value) + 3}
                    textAnchor="end"
                    fill="#4a7090"
                    fontSize="10"
                    fontFamily="'Share Tech Mono', monospace"
                  >
                    {value}
                  </text>
                </g>
              ))}

              {signalPaths.map((path, index) => (
                <path
                  key={`signal-surface-${index}`}
                  d={path.surface}
                  fill={path.isAttack ? 'url(#attack-surface-fill)' : 'url(#area-fill)'}
                />
              ))}
              {signalPaths.map((path, index) => (
                <path
                  key={`signal-line-${index}`}
                  d={path.line}
                  fill="none"
                  stroke={path.isAttack ? '#ff3366' : '#00c8ff'}
                  strokeWidth={path.isAttack ? '2' : '1.5'}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              ))}

              {xLabels.map(label => (
                <text
                  key={label.offset}
                  x={label.x}
                  y={H - 9}
                  textAnchor={label.offset === 60 ? 'start' : label.offset === 0 ? 'end' : 'middle'}
                  fill="#4a7090"
                  fontSize="10"
                  fontFamily="'Share Tech Mono', monospace"
                >
                  {getTimeLabel(label.offset)}
                </text>
              ))}
            </svg>
          </div>

          <div className="mt-2 flex items-center justify-between gap-3 text-[9px] font-mono text-slate-500">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-[2px] bg-cyan-400" />Baseline</div>
              <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-[2px] bg-[#ff3366]" />Attack</div>
            </div>
            <div className="text-slate-600">flows / s</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCell({ label, value, alert }: { label: string; value: string; alert?: boolean }) {
  return (
    <div className="bg-[#060a10] border border-slate-800/70 rounded px-3 py-2">
      <div className="text-[9px] font-mono uppercase text-slate-600 mb-0.5">{label}</div>
      <div className={`text-sm font-mono font-semibold ${alert ? 'text-red-300' : 'text-slate-200'}`}>
        {value}
      </div>
    </div>
  );
}
