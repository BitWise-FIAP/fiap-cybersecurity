import { existsSync, readFileSync } from 'node:fs';
import type { AppConfig } from '../config';
import type { Router } from '../http/router';
import { readJsonObject } from '../http/body';
import { sendJson, unauthorized } from '../http/responses';
import {
  createSecurityEvent,
  riskFromEvents,
  riskLevelFromScore,
  scanPii,
  severityWeightFor,
  residualFactorFor,
} from '../../src/security';
import type {
  PiiAction,
  PiiCategory,
  PiiSeverity,
  RiskLevel,
  SecurityEvent,
  TaintSink,
  TaintSource,
  TranslationResult,
} from '../../src/security';
import {
  protectForAi,
  protectForFeedback,
  protectForLog,
  protectForOrder,
  protectForResponse,
  protectPayload,
  type ProtectPurpose,
} from '../security/piiMiddleware';
import { translateSecurityEvent } from '../security/aiTranslator';
import type { SecurityEventStore } from '../security/eventStore';

const purposes: ProtectPurpose[] = ['log', 'ai', 'response', 'order', 'feedback'];
const sources: TaintSource[] = ['form', 'database', 'api', 'file', 'llm', 'demo'];
const sinks: TaintSink[] = [
  'console',
  'log',
  'http_response',
  'error_screen',
  'llm_prompt',
  'export',
  'database',
];
const actions: PiiAction[] = ['allowed', 'masked', 'encrypted', 'blocked'];
const categories: PiiCategory[] = [
  'identificacao',
  'contato',
  'endereco',
  'credencial',
  'saude',
  'menor',
  'financeiro',
  'outro',
];
const severities: PiiSeverity[] = ['low', 'medium', 'high', 'critical'];

export function registerSecurityRoutes(router: Router): void {
  router.add('GET', '/api/security/dashboard', async (_req, res, context) => {
    const payload = await buildDashboardPayload(context.eventStore, context.config);
    sendJson(res, 200, payload);
  });

  router.add('POST', '/api/security/demo', async (req, res, context) => {
    const body = await readJsonObject(req, res, context.config.maxBodyBytes);
    if (body === null) return;
    const scenario = body.scenario === 'leak' || body.scenario === 'safe' ? body.scenario : 'mixed';
    const created = createDemoEvents(context.eventStore, context.config, scenario);
    const payload = await buildDashboardPayload(context.eventStore, context.config);
    sendJson(res, 200, { ok: true, scenario, created: created.length, ...payload });
  });

  router.add('POST', '/api/security/scan', async (req, res, context) => {
    const body = await readJsonObject(req, res, context.config.maxBodyBytes);
    if (body === null) return;
    const purpose = purposes.includes(body.purpose as ProtectPurpose)
      ? (body.purpose as ProtectPurpose)
      : 'log';
    const target = body.payload ?? body;
    const authenticated = body.authenticated === true;
    const result = protectPayload(target, {
      purpose,
      authenticated,
      source: 'api',
      encryptionKey: context.config.encryptionKey,
      context: 'api.security.scan',
      recordEvent: (event) => context.eventStore.append(event),
    });
    const sanitized =
      purpose === 'order'
        ? { maskedPii: (result.sanitized as { maskedPii?: unknown }).maskedPii }
        : result.sanitized;
    sendJson(res, 200, {
      ok: true,
      purpose,
      containsPii: result.findings.length > 0,
      blocked: result.blocked,
      action: result.action,
      findings: result.findings,
      sanitized,
      risk: riskFromEvents(context.eventStore.read()),
    });
  });

  router.add('GET', '/api/security/events', (_req, res, context) => {
    if (!context.authenticated) {
      unauthorized(res);
      return;
    }
    sendJson(res, 200, {
      ok: true,
      events: context.eventStore.list(100),
      risk: context.eventStore.summary(),
    });
  });

  router.add('POST', '/api/security/events', async (req, res, context) => {
    if (!context.authenticated) {
      unauthorized(res);
      return;
    }
    const body = await readJsonObject(req, res, context.config.maxBodyBytes);
    if (body === null) return;

    const scan = scanPii(body);
    if (scan.containsPii) {
      const protectedResult = protectForLog(body, {
        source: 'api',
        context: 'api.security.events',
        recordEvent: (event) => context.eventStore.append(event),
      });
      sendJson(res, 200, {
        ok: true,
        sanitized: true,
        blocked: protectedResult.blocked,
        findings: protectedResult.findings,
      });
      return;
    }

    const event = normalizeIncomingEvent(body);
    context.eventStore.append(event);
    sendJson(res, 201, { ok: true, event });
  });

  router.add('POST', '/api/security/clear', (_req, res, context) => {
    if (!context.authenticated) {
      unauthorized(res);
      return;
    }
    context.eventStore.clear();
    sendJson(res, 200, { ok: true, cleared: true });
  });

  router.add('GET', '/api/security/report', (_req, res, context) => {
    if (!existsSync(context.config.reportPath)) {
      sendJson(res, 404, {
        ok: false,
        error: 'Relatório de taint analysis ainda não foi gerado.',
        hint: 'Execute npm run security:audit.',
      });
      return;
    }
    try {
      const report = JSON.parse(readFileSync(context.config.reportPath, 'utf8')) as unknown;
      sendJson(res, 200, { ok: true, report });
    } catch {
      sendJson(res, 500, {
        ok: false,
        error: 'Não foi possível ler o relatório de auditoria.',
      });
    }
  });
}

export function normalizeIncomingEvent(body: Record<string, unknown>): SecurityEvent {
  const source = sources.includes(body.source as TaintSource)
    ? (body.source as TaintSource)
    : 'api';
  const sink = sinks.includes(body.sink as TaintSink)
    ? (body.sink as TaintSink)
    : 'log';
  const action = actions.includes(body.action as PiiAction)
    ? (body.action as PiiAction)
    : 'blocked';
  const category = categories.includes(body.category as PiiCategory)
    ? (body.category as PiiCategory)
    : 'outro';
  const severity = severities.includes(body.severity as PiiSeverity)
    ? (body.severity as PiiSeverity)
    : 'low';
  const ruleIds = Array.isArray(body.ruleIds)
    ? body.ruleIds.filter((item): item is string => typeof item === 'string')
    : [];
  const message =
    typeof body.message === 'string' && body.message.trim()
      ? body.message.trim().slice(0, 240)
      : 'Evento de segurança registrado pelo aplicativo.';
  const maskedValue =
    typeof body.maskedValue === 'string' ? body.maskedValue.slice(0, 120) : undefined;
  const metadata =
    body.metadata && typeof body.metadata === 'object' && !Array.isArray(body.metadata)
      ? (body.metadata as Record<string, unknown>)
      : undefined;

  return createSecurityEvent({
    source,
    sink,
    action,
    category,
    severity,
    ruleIds,
    message,
    maskedValue,
    metadata,
  });
}

export function createDemoEvents(
  eventStore: SecurityEventStore,
  config: AppConfig,
  scenario: 'leak' | 'safe' | 'mixed',
): SecurityEvent[] {
  const events: SecurityEvent[] = [];

  if (scenario === 'leak' || scenario === 'mixed') {
    const leakPayload = {
      nome: 'Ana Beatriz Souza',
      cpf: '529.982.247-25',
      email: 'ana.souza@example.com',
      telefone: '(11) 98765-4321',
      cep: '01310-100',
      endereco_logradouro: 'Avenida Paulista',
      endereco_numero: '1000',
      endereco_bairro: 'Bela Vista',
      endereco_cidade: 'São Paulo',
      endereco_uf: 'SP',
      senha: 'senha-super-secreta',
      comentario:
        'Estou em tratamento para ansiedade e tomo medicamento controlado.',
      menor_de_idade: 1,
      responsavel: 'Maria Souza',
    };

    const logResult = protectForLog(leakPayload, {
      source: 'demo',
      context: 'demo.log',
    });
    events.push(...logResult.events);

    const publicResponse = protectForResponse(leakPayload, false, {
      source: 'demo',
      context: 'demo.http.public',
    });
    events.push(...publicResponse.events);

    const authResponse = protectForResponse(leakPayload, true, {
      source: 'demo',
      context: 'demo.http.auth',
    });
    events.push(...authResponse.events);

    const orderResult = protectForOrder(leakPayload, config.encryptionKey, {
      source: 'demo',
      context: 'demo.order',
    });
    events.push(...orderResult.events);

    const feedbackResult = protectForFeedback(
      {
        comentario: leakPayload.comentario,
        answers: { 1: true },
      },
      { source: 'demo', context: 'demo.feedback' },
    );
    events.push(...feedbackResult.events);

    const aiResult = protectForAi(leakPayload, {
      source: 'demo',
      context: 'demo.ai',
    });
    events.push(...aiResult.events);
  }

  if (scenario === 'safe' || scenario === 'mixed') {
    events.push(
      createSecurityEvent({
        source: 'demo',
        sink: 'http_response',
        action: 'allowed',
        category: 'outro',
        severity: 'low',
        ruleIds: [],
        message: 'Fluxo seguro: nenhum dado pessoal sensível encontrado.',
        metadata: { scenario: 'safe', context: 'demo.safe' },
      }),
    );
  }

  if (events.length) eventStore.appendMany(events);
  return events;
}

export async function buildDashboardPayload(
  eventStore: SecurityEventStore,
  config: AppConfig,
): Promise<Record<string, unknown>> {
  const allEvents = eventStore.read();
  const risk = riskFromEvents(allEvents);
  const events = allEvents.slice(-50).reverse();
  const target =
    events.find((event) => event.severity === 'high' || event.severity === 'critical') ??
    events[0];

  let translation: TranslationResult = {
    message:
      'Nenhum evento de risco registrado. O sistema está operando em estado seguro.',
    provider: 'fallback',
    model: 'local',
    cached: false,
  };

  if (target) {
    translation = await translateSecurityEvent(target, {
      openaiKey: config.openaiKey,
      geminiKey: config.geminiKey,
      openaiModel: config.openaiModel,
      geminiModel: config.geminiModel,
    });
  }

  const decoratedEvents = events.map((event) => ({
    ...event,
    translated: target && event.id === target.id ? translation.message : event.translated,
    riskLevel: eventRiskLevel(event),
  }));

  return {
    ok: true,
    app: config.appName,
    generatedAt: new Date().toISOString(),
    risk,
    translation,
    events: decoratedEvents,
    metrics: {
      total: risk.total,
      blocked: risk.blocked,
      masked: risk.masked,
      encrypted: risk.encrypted,
      allowed: risk.allowed,
      bySeverity: risk.bySeverity,
      byCategory: risk.byCategory,
    },
    privacy: {
      rawPiiExposed: false,
      note: 'Nenhuma PII bruta é retornada pelo dashboard. Valores são mascarados ou criptografados.',
      retention: 'Máximo de 500 eventos; dados fictícios para demonstração.',
    },
  };
}

function eventRiskLevel(event: SecurityEvent): RiskLevel {
  if (event.action === 'blocked') return 'baixo';
  if (event.action === 'allowed') {
    return event.severity === 'critical'
      ? 'critico'
      : event.severity === 'high'
        ? 'alto'
        : event.severity === 'medium'
          ? 'moderado'
          : 'baixo';
  }
  return riskLevelFromScore(
    Math.round(severityWeightFor(event.severity) * residualFactorFor(event.action)),
  );
}
