import { useState, useEffect, useRef, useCallback } from 'react';
import type { Alert, TelemetryPoint } from '../types';
import { generateInitialTelemetry, MOCK_ALERTS } from '../data/mockData';

export function useLiveData(autoRefresh: boolean) {
  const [telemetry, setTelemetry] = useState<TelemetryPoint[]>(generateInitialTelemetry);
  const [alerts, setAlerts] = useState<Alert[]>(MOCK_ALERTS);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [eventCount, setEventCount] = useState(14820);
  const prevConfRef = useRef<number>(75);

  const tick = useCallback(() => {
    setLastUpdated(new Date());
    setEventCount(c => c + Math.floor(Math.random() * 6 + 2));

    setTelemetry(prev => {
      const last = prev[prev.length - 1];
      const isAttack = last?.isAttack
        ? Math.random() > 0.15
        : Math.random() > 0.85;
      const target = isAttack ? 72 + Math.random() * 22 : 18 + Math.random() * 28;
      const conf = prevConfRef.current * 0.65 + target * 0.35 + (Math.random() - 0.5) * 10;
      const clamped = Math.min(100, Math.max(0, conf));
      prevConfRef.current = clamped;

      const next: TelemetryPoint = {
        t: Date.now(),
        confidence: clamped,
        intensity: isAttack ? 0.55 + Math.random() * 0.45 : 0.08 + Math.random() * 0.28,
        isAttack,
      };
      return [...prev.slice(1), next];
    });

    // Occasionally mutate top alert status
    if (Math.random() > 0.85) {
      setAlerts(prev =>
        prev.map((a, i) =>
          i === 0 && a.status === 'ACTIVE'
            ? { ...a, timestamp: new Date() }
            : a
        )
      );
    }
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(tick, 2000);
    return () => clearInterval(id);
  }, [autoRefresh, tick]);

  return { telemetry, alerts, lastUpdated, eventCount };
}
