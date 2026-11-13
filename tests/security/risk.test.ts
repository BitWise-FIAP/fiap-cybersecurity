import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createSecurityEvent,
  riskFromEvents,
  riskLevelFromScore,
} from '../../src/security';

test('cria evento com id e timestamp', () => {
  const event = createSecurityEvent({
    source: 'api',
    sink: 'log',
    action: 'blocked',
    category: 'credencial',
    severity: 'critical',
    ruleIds: ['PII-PASSWORD'],
    message: 'Teste',
  });

  assert.match(event.id, /^evt_/);
  assert.ok(Date.parse(event.timestamp) > 0);
});

test('painel vazio fica em risco baixo', () => {
  const risk = riskFromEvents([]);
  assert.equal(risk.score, 0);
  assert.equal(risk.level, 'baixo');
  assert.equal(risk.total, 0);
});

test('evento crítico bloqueado tem risco residual baixo', () => {
  const risk = riskFromEvents([
    createSecurityEvent({
      source: 'api',
      sink: 'log',
      action: 'blocked',
      category: 'credencial',
      severity: 'critical',
      ruleIds: ['PII-PASSWORD'],
      message: 'Bloqueado',
    }),
  ]);

  assert.equal(risk.score, 6);
  assert.equal(risk.level, 'baixo');
  assert.equal(risk.attemptedScore, 40);
  assert.equal(risk.blocked, 1);
});

test('evento crítico permitido eleva o risco', () => {
  const risk = riskFromEvents([
    createSecurityEvent({
      source: 'api',
      sink: 'http_response',
      action: 'allowed',
      category: 'saude',
      severity: 'critical',
      ruleIds: ['PII-HEALTH'],
      message: 'Expôs dado',
    }),
  ]);

  assert.equal(risk.score, 40);
  assert.equal(risk.level, 'moderado');
  assert.equal(risk.allowed, 1);
});

test('muitos eventos permitidos saturam o score em 100', () => {
  const events = Array.from({ length: 5 }, () =>
    createSecurityEvent({
      source: 'api',
      sink: 'http_response',
      action: 'allowed',
      category: 'credencial',
      severity: 'critical',
      ruleIds: ['PII-PASSWORD'],
      message: 'Expôs credencial',
    }),
  );
  const risk = riskFromEvents(events);
  assert.equal(risk.score, 100);
  assert.equal(risk.level, 'critico');
});

test('limiares do farol', () => {
  assert.equal(riskLevelFromScore(0), 'baixo');
  assert.equal(riskLevelFromScore(19), 'baixo');
  assert.equal(riskLevelFromScore(20), 'moderado');
  assert.equal(riskLevelFromScore(49), 'moderado');
  assert.equal(riskLevelFromScore(50), 'alto');
  assert.equal(riskLevelFromScore(74), 'alto');
  assert.equal(riskLevelFromScore(75), 'critico');
  assert.equal(riskLevelFromScore(100), 'critico');
});
