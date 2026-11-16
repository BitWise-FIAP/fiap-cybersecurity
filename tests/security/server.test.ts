import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createServer } from '../../backend/server';

const tempDir = mkdtempSync(join(tmpdir(), 'trajetoria-security-'));
const dataDir = join(tempDir, 'data');
const docsDir = join(tempDir, 'docs');
const demoToken = 'trajetoria-demo';

let server: Server;
let base = '';

before(async () => {
  const bundle = createServer({
    config: {
      port: 0,
      host: '127.0.0.1',
      dataDir,
      docsDir,
      reportPath: join(docsDir, 'evidencias', 'taint-report.json'),
      dashboardDir: resolve('backend/dashboard'),
      demoToken,
    },
  });
  server = bundle.server;
  await new Promise<void>((resolveListen) => {
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address() as AddressInfo;
  base = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolveClose) => {
    server.close(() => resolveClose());
  });
  rmSync(tempDir, { recursive: true, force: true });
});

test('health responde sem PII', async () => {
  const response = await fetch(`${base}/health`);
  assert.equal(response.status, 200);
  const data = (await response.json()) as { ok: boolean };
  assert.equal(data.ok, true);
});

test('simulação gera eventos sem vazar PII bruta', async () => {
  const response = await fetch(`${base}/api/security/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scenario: 'mixed' }),
  });
  assert.equal(response.status, 200);
  const data = (await response.json()) as {
    created: number;
    privacy: { rawPiiExposed: boolean };
    translation: { message: string };
  };
  assert.ok(data.created > 0);
  assert.equal(data.privacy.rawPiiExposed, false);
  assert.ok(data.translation.message.length > 0);

  const serialized = JSON.stringify(data);
  assert.equal(serialized.includes('529.982.247-25'), false);
  assert.equal(serialized.includes('Ana Beatriz Souza'), false);
  assert.equal(serialized.includes('ana.souza@example.com'), false);
  assert.equal(serialized.includes('senha-super-secreta'), false);
  assert.equal(serialized.includes('Estou em tratamento'), false);
});

test('dashboard público retorna apenas dados sanitizados', async () => {
  const response = await fetch(`${base}/api/security/dashboard`);
  assert.equal(response.status, 200);
  const data = (await response.json()) as {
    risk: { total: number };
    privacy: { rawPiiExposed: boolean };
    events: Array<{ maskedValue?: string }>;
  };
  assert.equal(data.privacy.rawPiiExposed, false);
  assert.ok(data.risk.total > 0);
  assert.ok(data.events.length > 0);
});

test('cada simulação substitui os eventos e o cenário crítico satura o risco', async () => {
  const leak = await fetch(`${base}/api/security/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scenario: 'leak' }),
  });
  assert.equal(leak.status, 200);
  const leakData = (await leak.json()) as { risk: { level: string } };
  assert.ok(leakData.risk.level === 'alto' || leakData.risk.level === 'critico');

  const safe = await fetch(`${base}/api/security/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scenario: 'safe' }),
  });
  assert.equal(safe.status, 200);
  const safeData = (await safe.json()) as {
    risk: { total: number; score: number; level: string };
  };
  assert.equal(safeData.risk.total, 1);
  assert.equal(safeData.risk.level, 'baixo');
  assert.ok(safeData.risk.score < 20);

  const critical = await fetch(`${base}/api/security/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scenario: 'critical' }),
  });
  assert.equal(critical.status, 200);
  const criticalData = (await critical.json()) as {
    risk: { score: number; level: string; allowed: number };
  };
  assert.equal(criticalData.risk.score, 100);
  assert.equal(criticalData.risk.level, 'critico');
  assert.equal(criticalData.risk.allowed, 3);
});

test('eventos exigem token de demonstração', async () => {
  const unauthorizedResponse = await fetch(`${base}/api/security/events`);
  assert.equal(unauthorizedResponse.status, 401);

  const response = await fetch(`${base}/api/security/events`, {
    headers: { 'x-demo-token': demoToken },
  });
  assert.equal(response.status, 200);
  const data = (await response.json()) as { events: unknown[] };
  assert.ok(Array.isArray(data.events));
});

test('scan bloqueia PII em logs', async () => {
  const response = await fetch(`${base}/api/security/scan`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      payload: { cpf: '529.982.247-25', senha: 'segredo' },
      purpose: 'log',
    }),
  });
  assert.equal(response.status, 200);
  const data = (await response.json()) as { blocked: boolean };
  assert.equal(data.blocked, true);
  const serialized = JSON.stringify(data);
  assert.equal(serialized.includes('529.982.247-25'), false);
  assert.equal(serialized.includes('segredo'), false);
});

test('pedido exige consentimento e nunca devolve PII bruta', async () => {
  const payload = {
    consent: true,
    items: ['1'],
    young: { nome: 'Ana Beatriz Souza', cpf: '529.982.247-25' },
    address: {
      cep: '01310-100',
      logradouro: 'Avenida Paulista',
      numero: '1000',
      complemento: '',
      bairro: 'Bela Vista',
      cidade: 'São Paulo',
      uf: 'SP',
      contato: '(11) 98765-4321',
    },
  };

  const withoutConsent = await fetch(`${base}/api/orders`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-demo-token': demoToken,
    },
    body: JSON.stringify({ ...payload, consent: false }),
  });
  assert.equal(withoutConsent.status, 403);

  const response = await fetch(`${base}/api/orders`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-demo-token': demoToken,
    },
    body: JSON.stringify(payload),
  });
  assert.equal(response.status, 201);
  const data = (await response.json()) as {
    order: { privacy: { encryptedAtRest: boolean; rawPiiReturned: boolean } };
  };
  assert.equal(data.order.privacy.encryptedAtRest, true);
  assert.equal(data.order.privacy.rawPiiReturned, false);

  const serialized = JSON.stringify(data);
  assert.equal(serialized.includes('529.982.247-25'), false);
  assert.equal(serialized.includes('(11) 98765-4321'), false);
  assert.equal(serialized.includes('Avenida Paulista'), false);
});

test('feedback remove dado de saúde do comentário', async () => {
  const response = await fetch(`${base}/api/feedback`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-demo-token': demoToken,
    },
    body: JSON.stringify({
      consent: true,
      orderId: 1,
      comment: 'Estou em tratamento para ansiedade e tomo medicamento.',
      answers: { 1: true },
    }),
  });
  assert.equal(response.status, 200);
  const data = (await response.json()) as {
    piiRemoved: boolean;
    comment: string;
  };
  assert.equal(data.piiRemoved, true);
  assert.equal(data.comment, '[DADO DE SAÚDE REMOVIDO]');
});
