import { maskPiiDeep, scanPii } from './pii';
import { createSecurityEvent } from './risk';
import type {
  PiiAction,
  PiiFinding,
  PiiScanResult,
  SecurityEvent,
  TaintSink,
  TaintSource,
} from './types';

export interface GuardOptions {
  authenticated?: boolean;
  context?: string;
  source?: TaintSource;
  recordEvent?: (event: SecurityEvent) => void;
}

export interface GuardResult {
  allowed: boolean;
  blocked: boolean;
  action: PiiAction;
  sanitized: unknown;
  findings: PiiFinding[];
  event?: SecurityEvent;
}

export class TaintTracker {
  private readonly defaultSource: TaintSource;
  private readonly defaultAuthenticated: boolean;
  private readonly recordEvent?: (event: SecurityEvent) => void;

  constructor(
    options: {
      source?: TaintSource;
      authenticated?: boolean;
      recordEvent?: (event: SecurityEvent) => void;
    } = {},
  ) {
    this.defaultSource = options.source ?? 'api';
    this.defaultAuthenticated = options.authenticated ?? false;
    this.recordEvent = options.recordEvent;
  }

  tag(value: unknown): PiiScanResult {
    return scanPii(value);
  }

  containsPii(value: unknown): boolean {
    return scanPii(value).containsPii;
  }

  guardSink(value: unknown, sink: TaintSink, options: GuardOptions = {}): GuardResult {
    const scan = this.tag(value);
    const authenticated = options.authenticated ?? this.defaultAuthenticated;

    if (!scan.containsPii) {
      return {
        allowed: true,
        blocked: false,
        action: 'allowed',
        sanitized: value,
        findings: [],
      };
    }

    const finding = scan.findings[0];
    let action: PiiAction;
    let blocked = false;
    let sanitized: unknown;

    if (sink === 'http_response') {
      if (authenticated) {
        action = 'masked';
        sanitized = maskPiiDeep(value);
      } else {
        action = 'blocked';
        blocked = true;
        sanitized = { error: 'Conteúdo protegido', code: 'PII_BLOCKED' };
      }
    } else if (sink === 'database') {
      action = 'encrypted';
      sanitized = '[ENCRYPTED]';
    } else {
      action = 'blocked';
      blocked = true;
      sanitized = maskPiiDeep(value);
    }

    const event = createSecurityEvent({
      source: options.source ?? this.defaultSource,
      sink,
      action,
      category: finding.category,
      severity: scan.highestSeverity ?? finding.severity,
      ruleIds: Array.from(new Set(scan.findings.map((item) => item.ruleId))),
      message: `PII ${action} antes de ${sink}${options.context ? ` (${options.context})` : ''}.`,
      maskedValue: finding.maskedMatch,
      metadata: {
        field: finding.field ?? finding.path,
        authenticated,
        context: options.context,
        categories: scan.categories,
      },
    });

    const record = options.recordEvent ?? this.recordEvent;
    if (record) record(event);

    return {
      allowed: false,
      blocked,
      action,
      sanitized,
      findings: scan.findings,
      event,
    };
  }
}

export function guardHttpResponse(
  value: unknown,
  authenticated: boolean,
  tracker?: TaintTracker,
): GuardResult {
  const engine = tracker ?? new TaintTracker({ authenticated });
  return engine.guardSink(value, 'http_response', { authenticated });
}

export function guardLlmPrompt(value: unknown, tracker?: TaintTracker): GuardResult {
  const engine = tracker ?? new TaintTracker({ source: 'llm' });
  return engine.guardSink(value, 'llm_prompt', { source: 'llm' });
}

export function guardDatabase(value: unknown, tracker?: TaintTracker): GuardResult {
  const engine = tracker ?? new TaintTracker({ source: 'database' });
  return engine.guardSink(value, 'database', { source: 'database' });
}

export function safeLog(
  value: unknown,
  context = 'security',
  tracker?: TaintTracker,
): GuardResult {
  const engine = tracker ?? new TaintTracker({ source: 'api' });
  const result = engine.guardSink(value, 'console', { context });
  console.log(`[${context}]`, result.sanitized);
  return result;
}
