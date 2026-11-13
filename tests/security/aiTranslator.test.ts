import test from 'node:test';
import assert from 'node:assert/strict';
import {
  clearTranslationCache,
  translateSecurityEvent,
} from '../../backend/security/aiTranslator';
import { createSecurityEvent } from '../../src/security';

const event = createSecurityEvent({
  source: 'api',
  sink: 'log',
  action: 'blocked',
  category: 'credencial',
  severity: 'critical',
  ruleIds: ['PII-PASSWORD'],
  message: 'Credencial bloqueada antes do log.',
  maskedValue: '********',
});

test('usa fallback local quando não há chaves', async () => {
  clearTranslationCache();
  const result = await translateSecurityEvent(event);
  assert.equal(result.provider, 'fallback');
  assert.equal(result.model, 'local');
  assert.match(result.message, /senha|credencial/i);
});

test('usa OpenAI e faz cache da resposta', async () => {
  clearTranslationCache();
  let calls = 0;
  let requestBody = '';
  const fetchImpl: typeof fetch = async (_input, init) => {
    calls += 1;
    requestBody = String(init?.body ?? '');
    return new Response(
      JSON.stringify({
        choices: [{ message: { content: 'Mensagem traduzida pela OpenAI.' } }],
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  const first = await translateSecurityEvent(event, {
    openaiKey: 'test-key',
    fetchImpl,
  });
  assert.equal(first.provider, 'openai');
  assert.equal(first.message, 'Mensagem traduzida pela OpenAI.');
  assert.equal(calls, 1);
  assert.equal(requestBody.includes('529.982.247-25'), false);

  const second = await translateSecurityEvent(event, {
    openaiKey: 'test-key',
    fetchImpl,
  });
  assert.equal(second.cached, true);
  assert.equal(calls, 1);
});

test('cai para Gemini quando OpenAI falha', async () => {
  clearTranslationCache();
  let calls = 0;
  const fetchImpl: typeof fetch = async () => {
    calls += 1;
    if (calls === 1) throw new Error('openai offline');
    return new Response(
      JSON.stringify({
        candidates: [
          { content: { parts: [{ text: 'Mensagem traduzida pelo Gemini.' }] } },
        ],
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  const result = await translateSecurityEvent(event, {
    openaiKey: 'test-key',
    geminiKey: 'test-key',
    fetchImpl,
  });

  assert.equal(result.provider, 'gemini');
  assert.equal(result.message, 'Mensagem traduzida pelo Gemini.');
  assert.equal(calls, 2);
});

test('cai para fallback quando todos os provedores falham', async () => {
  clearTranslationCache();
  const fetchImpl: typeof fetch = async () => {
    throw new Error('rede indisponível');
  };

  const result = await translateSecurityEvent(event, {
    openaiKey: 'test-key',
    geminiKey: 'test-key',
    fetchImpl,
  });

  assert.equal(result.provider, 'fallback');
  assert.match(result.message, /senha|credencial/i);
});
