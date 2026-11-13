import test from 'node:test';
import assert from 'node:assert/strict';
import { TaintTracker } from '../../src/security';
import type { SecurityEvent } from '../../src/security';

const VALID_CPF = '529.982.247-25';

test('bloqueia PII antes do console e registra evento', () => {
  const events: SecurityEvent[] = [];
  const tracker = new TaintTracker({
    source: 'form',
    recordEvent: (event) => events.push(event),
  });

  const result = tracker.guardSink({ cpf: VALID_CPF }, 'console', {
    context: 'test.console',
  });

  assert.equal(result.blocked, true);
  assert.equal(result.action, 'blocked');
  assert.equal(JSON.stringify(result.sanitized).includes(VALID_CPF), false);
  assert.equal(events.length, 1);
  assert.equal(events[0].sink, 'console');
  assert.equal(events[0].category, 'identificacao');
});

test('bloqueia resposta HTTP não autenticada', () => {
  const tracker = new TaintTracker();
  const result = tracker.guardSink(
    { nome: 'Ana Beatriz Souza', telefone: '(11) 98765-4321' },
    'http_response',
    { authenticated: false },
  );

  assert.equal(result.blocked, true);
  assert.equal(result.action, 'blocked');
  assert.deepEqual(result.sanitized, {
    error: 'Conteúdo protegido',
    code: 'PII_BLOCKED',
  });
});

test('mascara resposta HTTP autenticada', () => {
  const tracker = new TaintTracker();
  const result = tracker.guardSink(
    { cpf: VALID_CPF },
    'http_response',
    { authenticated: true },
  );

  assert.equal(result.blocked, false);
  assert.equal(result.action, 'masked');
  const sanitized = result.sanitized as Record<string, unknown>;
  assert.equal(sanitized.cpf, '[DOCUMENTO REMOVIDO]');
  assert.equal(JSON.stringify(sanitized).includes(VALID_CPF), false);
});

test('indica criptografia antes do banco', () => {
  const tracker = new TaintTracker();
  const result = tracker.guardSink(
    { contato: '(11) 98765-4321' },
    'database',
  );

  assert.equal(result.action, 'encrypted');
  assert.equal(result.sanitized, '[ENCRYPTED]');
});

test('permite fluxo sem PII', () => {
  const events: SecurityEvent[] = [];
  const tracker = new TaintTracker({ recordEvent: (event) => events.push(event) });
  const result = tracker.guardSink(
    { peca: 'Jaqueta jeans', tamanho: 'M' },
    'console',
  );

  assert.equal(result.allowed, true);
  assert.equal(result.blocked, false);
  assert.equal(result.action, 'allowed');
  assert.equal(events.length, 0);
});
