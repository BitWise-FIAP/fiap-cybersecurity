import type {
  PiiAction,
  PiiCategory,
  PiiSeverity,
  RiskLevel,
  RiskSummary,
  SecurityEvent,
} from './types';

const severityWeight: Record<PiiSeverity, number> = {
  low: 5,
  medium: 12,
  high: 25,
  critical: 40,
};

const actionResidualFactor: Record<PiiAction, number> = {
  blocked: 0.15,
  encrypted: 0.25,
  masked: 0.35,
  allowed: 1,
};

const riskLabels: Record<RiskLevel, string> = {
  baixo: 'Risco baixo',
  moderado: 'Risco moderado',
  alto: 'Risco alto',
  critico: 'Risco crítico',
};

const emptyBySeverity = (): Record<PiiSeverity, number> => ({
  low: 0,
  medium: 0,
  high: 0,
  critical: 0,
});

const emptyByCategory = (): Record<PiiCategory, number> => ({
  identificacao: 0,
  contato: 0,
  endereco: 0,
  credencial: 0,
  saude: 0,
  menor: 0,
  financeiro: 0,
  outro: 0,
});

export function createSecurityEvent(
  partial: Omit<SecurityEvent, 'id' | 'timestamp'> &
    Partial<Pick<SecurityEvent, 'id' | 'timestamp'>>,
): SecurityEvent {
  const { id, timestamp, ...rest } = partial;
  const random = Math.random().toString(36).slice(2, 10);
  return {
    id: id ?? `evt_${Date.now().toString(36)}_${random}`,
    timestamp: timestamp ?? new Date().toISOString(),
    ...rest,
  };
}

export function riskFromEvents(events: SecurityEvent[]): RiskSummary {
  const bySeverity = emptyBySeverity();
  const byCategory = emptyByCategory();
  let residualRaw = 0;
  let attemptedRaw = 0;
  let blocked = 0;
  let masked = 0;
  let encrypted = 0;
  let allowed = 0;

  for (const event of events) {
    const weight = severityWeight[event.severity];
    residualRaw += weight * actionResidualFactor[event.action];
    attemptedRaw += weight;
    bySeverity[event.severity] += 1;
    byCategory[event.category] += 1;

    if (event.action === 'blocked') blocked += 1;
    else if (event.action === 'masked') masked += 1;
    else if (event.action === 'encrypted') encrypted += 1;
    else allowed += 1;
  }

  const score = Math.min(100, Math.round(residualRaw));
  const attemptedScore = Math.min(100, Math.round(attemptedRaw));
  const level = riskLevelFromScore(score);

  return {
    score,
    attemptedScore,
    level,
    label: riskLabels[level],
    total: events.length,
    blocked,
    masked,
    encrypted,
    allowed,
    bySeverity,
    byCategory,
    generatedAt: new Date().toISOString(),
  };
}

export function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 75) return 'critico';
  if (score >= 50) return 'alto';
  if (score >= 20) return 'moderado';
  return 'baixo';
}

export function riskLabel(level: RiskLevel): string {
  return riskLabels[level];
}

export function severityWeightFor(severity: PiiSeverity): number {
  return severityWeight[severity];
}

export function residualFactorFor(action: PiiAction): number {
  return actionResidualFactor[action];
}
