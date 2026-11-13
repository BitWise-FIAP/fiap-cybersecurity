import {
  createSecurityEvent,
  getHighestSeverity,
  maskPiiDeep,
  scanPii,
  severityWeightFor,
} from '../../src/security';
import type {
  PiiAction,
  PiiFinding,
  ProtectedPayload,
  SecurityEvent,
  TaintSink,
  TaintSource,
} from '../../src/security';
import { encryptPii } from './crypto';

export type ProtectPurpose = 'log' | 'ai' | 'response' | 'order' | 'feedback';

export interface ProtectOptions {
  purpose: ProtectPurpose;
  authenticated?: boolean;
  source?: TaintSource;
  sink?: TaintSink;
  context?: string;
  encryptionKey?: string;
  recordEvent?: (event: SecurityEvent) => void;
}

export interface ProtectedOrderPayload extends ProtectedPayload {
  encryptedPii?: string;
  maskedPii?: unknown;
}

function defaultSink(purpose: ProtectPurpose): TaintSink {
  if (purpose === 'log') return 'log';
  if (purpose === 'ai') return 'llm_prompt';
  if (purpose === 'response') return 'http_response';
  return 'database';
}

function protect(
  value: unknown,
  options: ProtectOptions,
): ProtectedOrderPayload {
  const scan = scanPii(value);
  if (!scan.containsPii) {
    return {
      sanitized: value,
      findings: [],
      events: [],
      blocked: false,
      action: 'allowed',
    };
  }

  const findings: PiiFinding[] = scan.findings;
  const highest = getHighestSeverity(findings) ?? findings[0].severity;
  const primary = [...findings].sort(
    (left, right) => severityWeightFor(right.severity) - severityWeightFor(left.severity),
  )[0];
  let action: PiiAction;
  let blocked = false;
  let sanitized: unknown;
  let encryptedPii: string | undefined;
  let maskedPii: unknown;

  if (options.purpose === 'log' || options.purpose === 'ai') {
    action = 'blocked';
    blocked = true;
    sanitized = maskPiiDeep(value);
  } else if (options.purpose === 'response') {
    if (options.authenticated) {
      action = 'masked';
      sanitized = maskPiiDeep(value);
    } else {
      action = 'blocked';
      blocked = true;
      sanitized = { error: 'Conteúdo protegido', code: 'PII_BLOCKED' };
    }
  } else if (options.purpose === 'order') {
    if (!options.encryptionKey) {
      throw new Error('Chave de criptografia ausente para proteger o pedido.');
    }
    action = 'encrypted';
    encryptedPii = encryptPii(JSON.stringify(value), options.encryptionKey);
    maskedPii = maskPiiDeep(value);
    sanitized = { encryptedPii, maskedPii };
  } else {
    action = 'masked';
    sanitized = maskPiiDeep(value);
  }

  const event = createSecurityEvent({
    source: options.source ?? 'api',
    sink: options.sink ?? defaultSink(options.purpose),
    action,
    category: primary.category,
    severity: highest,
    ruleIds: Array.from(new Set(findings.map((finding) => finding.ruleId))),
    message: `PII ${action} no fluxo de ${options.purpose}${options.context ? ` (${options.context})` : ''}.`,
    maskedValue: primary.maskedMatch,
    metadata: {
      purpose: options.purpose,
      authenticated: options.authenticated ?? false,
      context: options.context,
      categories: scan.categories,
      fields: scan.fields,
    },
  });

  if (options.recordEvent) options.recordEvent(event);

  return {
    sanitized,
    findings,
    events: [event],
    blocked,
    action,
    encryptedPii,
    maskedPii,
  };
}

export function protectPayload(
  value: unknown,
  options: ProtectOptions,
): ProtectedOrderPayload {
  return protect(value, options);
}

export function protectForLog(
  value: unknown,
  options: Omit<ProtectOptions, 'purpose'> = {},
): ProtectedOrderPayload {
  return protect(value, { ...options, purpose: 'log' });
}

export function protectForAi(
  value: unknown,
  options: Omit<ProtectOptions, 'purpose'> = {},
): ProtectedOrderPayload {
  return protect(value, { ...options, purpose: 'ai' });
}

export function protectForResponse(
  value: unknown,
  authenticated: boolean,
  options: Omit<ProtectOptions, 'purpose' | 'authenticated'> = {},
): ProtectedOrderPayload {
  return protect(value, { ...options, purpose: 'response', authenticated });
}

export function protectForOrder(
  value: unknown,
  encryptionKey: string,
  options: Omit<ProtectOptions, 'purpose' | 'encryptionKey'> = {},
): ProtectedOrderPayload {
  return protect(value, { ...options, purpose: 'order', encryptionKey });
}

export function protectForFeedback(
  value: unknown,
  options: Omit<ProtectOptions, 'purpose'> = {},
): ProtectedOrderPayload {
  return protect(value, { ...options, purpose: 'feedback' });
}
