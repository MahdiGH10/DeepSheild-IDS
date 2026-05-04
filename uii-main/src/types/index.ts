export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AlertStatus = 'ACTIVE' | 'INVESTIGATING' | 'ESCALATED' | 'RESOLVED';
export type ThreatCategory = string;

export interface Feature {
  name: string;
  weight: number;
  value: string;
}

export interface AutomationRun {
  id: string;
  action: string;
  status: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  timestamp: Date;
  retries: number;
  note?: string;
}

export interface Alert {
  id: string;
  backendId?: number;
  attackType: ThreatCategory;
  source: string;
  target: string;
  confidence: number;
  severity: Severity;
  status: AlertStatus;
  timestamp: Date;
  protocol: string;
  port: number;
  indicators: string[];
  features: Feature[];
  automationRuns: AutomationRun[];
  riskSummary: string;
  unknownAttack?: boolean;
  emergencyLevel?: string | null;
}

export interface TelemetryPoint {
  t: number;
  confidence: number;
  intensity: number;
  isAttack: boolean;
}

export interface ThreatBreakdown {
  category: ThreatCategory;
  count: number;
  trend: 'up' | 'stable' | 'down';
}

export interface SystemHealth {
  modelStatus: 'ONLINE' | 'FALLBACK' | 'OFFLINE';
  automationStatus: 'READY' | 'PARTIAL' | 'DOWN';
  avgConfidence: number;
  processedTotal: number;
  retryCount: number;
  lastError?: string;
  lastRunStatus: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  integrationReady: boolean;
  uptime: string;
  modelDetail: string;
  automationDetail: string;
  recentEventCount: number;
  recentAttackLikeCount: number;
  attackShare: number;
}
