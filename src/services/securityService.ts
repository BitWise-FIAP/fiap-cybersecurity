import {
  maskPiiDeep,
  sanitizeFreeText,
  scanPii,
} from '../security';
import type {
  PiiAction,
  PiiCategory,
  PiiSeverity,
  SecurityEvent,
  TaintSink,
  TaintSource,
} from '../security';

const API_URL =
  process.env.EXPO_PUBLIC_SECURITY_API_URL ?? 'http://localhost:3333';
const DEMO_TOKEN =
  process.env.EXPO_PUBLIC_SECURITY_TOKEN ?? 'trajetoria-demo';

export interface AppSecurityEvent {
  source?: TaintSource;
  sink?: TaintSink;
  action?: PiiAction;
  category?: PiiCategory;
  severity?: PiiSeverity;
  ruleIds?: string[];
  message?: string;
  maskedValue?: string;
  metadata?: Record<string, unknown>;
}

export async function reportSecurityEvent(
  event: AppSecurityEvent,
): Promise<boolean> {
  try {
    const payload: Omit<SecurityEvent, 'id' | 'timestamp'> = {
      source: event.source ?? 'form',
      sink: event.sink ?? 'log',
      action: event.action ?? 'blocked',
      category: event.category ?? 'outro',
      severity: event.severity ?? 'low',
      ruleIds: event.ruleIds ?? [],
      message:
        event.message ?? 'Evento de segurança registrado pelo aplicativo.',
      maskedValue: event.maskedValue,
      metadata: event.metadata,
    };

    const scan = scanPii(payload);
    const safePayload = scan.containsPii ? maskPiiDeep(payload) : payload;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    try {
      const response = await fetch(`${API_URL}/api/security/events`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-demo-token': DEMO_TOKEN,
        },
        body: JSON.stringify(safePayload),
        signal: controller.signal,
      });
      return response.ok;
    } finally {
      clearTimeout(timeout);
    }
  } catch {
    return false;
  }
}

export function scanLocal(value: unknown) {
  return scanPii(value);
}

export function sanitizeComment(value: string): string {
  return sanitizeFreeText(value);
}
