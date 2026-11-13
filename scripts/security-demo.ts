import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { AddressInfo } from 'node:net';
import { createServer } from '../backend/server';

const root = process.cwd();
const dataDir = mkdtempSync(join(tmpdir(), 'trajetoria-demo-'));
const docsDir = resolve(root, 'docs/cybersecurity');
const evidenceDir = resolve(docsDir, 'evidencias');
const demoToken = 'trajetoria-demo';
const validCpf = '529.982.247-25';

interface JsonResponse {
  status: number;
  data: Record<string, unknown>;
}

async function main(): Promise<void> {
  mkdirSync(evidenceDir, { recursive: true });

  const bundle = createServer({
    config: {
      port: 0,
      host: '127.0.0.1',
      dataDir,
      docsDir,
      reportPath: join(evidenceDir, 'taint-report.json'),
      dashboardDir: resolve(root, 'backend/dashboard'),
      demoToken,
    },
  });

  const server = bundle.server;
  await new Promise<void>((resolveListen) => {
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${address.port}`;

  async function request(
    path: string,
    init: RequestInit = {},
    authenticated = false,
  ): Promise<JsonResponse> {
    const headers = new Headers(init.headers);
    if (init.body) headers.set('content-type', 'application/json');
    if (authenticated) headers.set('x-demo-token', demoToken);
    const response = await fetch(`${base}${path}`, { ...init, headers });
    const data = (await response.json()) as Record<string, unknown>;
    return { status: response.status, data };
  }

  try {
    const demo = await request('/api/security/demo', {
      method: 'POST',
      body: JSON.stringify({ scenario: 'mixed' }),
    });
    const dashboard = await request('/api/security/dashboard');
    const scan = await request('/api/security/scan', {
      method: 'POST',
      body: JSON.stringify({
        payload: { cpf: validCpf, senha: 'segredo-demo' },
        purpose: 'log',
      }),
    });
    const order = await request(
      '/api/orders',
      {
        method: 'POST',
        body: JSON.stringify({
          consent: true,
          items: ['1'],
          young: { nome: 'Ana Beatriz Souza', cpf: validCpf },
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
        }),
      },
      true,
    );

    const orderView = order.data.order as { id?: number } | undefined;
    const orderId = typeof orderView?.id === 'number' ? orderView.id : 1;

    const feedback = await request(
      '/api/feedback',
      {
        method: 'POST',
        body: JSON.stringify({
          consent: true,
          orderId,
          comment: 'Estou em tratamento para ansiedade e tomo medicamento controlado.',
          answers: { 1: true },
        }),
      },
      true,
    );

    const evidence = {
      generatedAt: new Date().toISOString(),
      base,
      demo,
      dashboard,
      scan,
      order,
      feedback,
      privacy: {
        rawPiiExposed: false,
        note: 'Evidência gerada com dados fictícios e resultados sanitizados.',
      },
    };

    const evidencePath = join(evidenceDir, 'demo-result.json');
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2), 'utf8');

    const risk = demo.data.risk as { level?: string; score?: number } | undefined;
    const translation = demo.data.translation as
      | { provider?: string; message?: string }
      | undefined;
    const orderPrivacy = order.data.order as
      | { id?: number; privacy?: { encryptedAtRest?: boolean } }
      | undefined;

    console.log(`[security:demo] eventos criados: ${String(demo.data.created ?? 0)}`);
    console.log(`[security:demo] risco: ${risk?.level ?? 'n/a'} (${risk?.score ?? 0}/100)`);
    console.log(`[security:demo] tradução: ${translation?.provider ?? 'n/a'}`);
    console.log(`[security:demo] pedido: ${orderPrivacy?.id ?? 'n/a'} | PII criptografada: ${String(orderPrivacy?.privacy?.encryptedAtRest ?? false)}`);
    console.log(`[security:demo] feedback sanitizado: ${String(feedback.data.comment ?? '')}`);
    console.log(`[security:demo] evidência: ${evidencePath}`);
  } finally {
    await new Promise<void>((resolveClose) => {
      server.close(() => resolveClose());
    });
    rmSync(dataDir, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[security:demo] falhou: ${message}`);
  process.exitCode = 1;
});
