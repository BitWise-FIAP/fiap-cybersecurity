import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  TaintTracker,
  createSecurityEvent,
  riskFromEvents,
  scanPii,
} from '../src/security';
import type { RiskLevel, SecurityEvent, TaintSink } from '../src/security';

const root = process.cwd();
const evidenceDir = resolve(root, 'docs/cybersecurity/evidencias');

const fixture = {
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
  comentario: 'Estou em tratamento para ansiedade e tomo medicamento controlado.',
  menor_de_idade: 1,
  responsavel: 'Maria Souza',
};

interface TraceEvidence {
  sink: TaintSink;
  authenticated: boolean;
  action: string;
  blocked: boolean;
  allowed: boolean;
  sanitizedPreview: string;
  findings: Array<{
    ruleId: string;
    category: string;
    severity: string;
    field?: string;
    maskedMatch: string;
  }>;
}

interface RiskScenario {
  scenario: string;
  description: string;
  score: number;
  level: RiskLevel;
  events: number;
}

function buildTrace(
  tracker: TaintTracker,
  sink: TaintSink,
  authenticated = false,
): TraceEvidence {
  const result = tracker.guardSink(fixture, sink, { authenticated });
  return {
    sink,
    authenticated,
    action: result.action,
    blocked: result.blocked,
    allowed: result.allowed,
    sanitizedPreview: JSON.stringify(result.sanitized).slice(0, 280),
    findings: result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      field: finding.field,
      maskedMatch: finding.maskedMatch,
    })),
  };
}

function scenarioEvents(
  scenario: 'safe' | 'blocked' | 'allowed' | 'critical',
): SecurityEvent[] {
  if (scenario === 'safe') return [];
  const base = {
    source: 'api' as const,
    sink: 'http_response' as const,
    category: 'credencial' as const,
    severity: 'critical' as const,
    ruleIds: ['PII-PASSWORD'],
    message: 'Cenário de evidência.',
  };
  if (scenario === 'blocked') {
    return [createSecurityEvent({ ...base, action: 'blocked', sink: 'log' })];
  }
  if (scenario === 'allowed') {
    return [createSecurityEvent({ ...base, action: 'allowed' })];
  }
  return [
    createSecurityEvent({ ...base, action: 'allowed' }),
    createSecurityEvent({ ...base, action: 'allowed' }),
    createSecurityEvent({ ...base, action: 'allowed' }),
  ];
}

function main(): void {
  mkdirSync(evidenceDir, { recursive: true });

  const scan = scanPii(fixture);
  const piiEvidence = {
    generatedAt: new Date().toISOString(),
    fixture: 'payload fictício com nome, CPF, e-mail, telefone, endereço, senha, saúde e menor de idade',
    containsPii: scan.containsPii,
    highestSeverity: scan.highestSeverity,
    categories: scan.categories,
    totalFindings: scan.findings.length,
    findings: scan.findings.map((finding) => ({
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      field: finding.field,
      path: finding.path,
      maskedMatch: finding.maskedMatch,
    })),
    redacted: scan.redacted,
    privacy: {
      rawPiiExposed: false,
      note: 'A fixture original não é gravada em disco; apenas a versão mascarada.',
    },
  };
  writeFileSync(join(evidenceDir, 'pii-scan.json'), JSON.stringify(piiEvidence, null, 2), 'utf8');

  const events: SecurityEvent[] = [];
  const tracker = new TaintTracker({
    source: 'form',
    recordEvent: (event) => events.push(event),
  });

  const traces: TraceEvidence[] = [
    buildTrace(tracker, 'console'),
    buildTrace(tracker, 'log'),
    buildTrace(tracker, 'http_response', false),
    buildTrace(tracker, 'http_response', true),
    buildTrace(tracker, 'llm_prompt'),
    buildTrace(tracker, 'database'),
    buildTrace(tracker, 'export'),
    buildTrace(tracker, 'error_screen'),
  ];

  const taintEvidence = {
    generatedAt: new Date().toISOString(),
    source: 'form',
    fixture: 'payload fictício (não persistido)',
    traces,
    events,
    risk: riskFromEvents(events),
    privacy: {
      rawPiiExposed: false,
      note: 'Todos os traces usam valores mascarados ou criptografados.',
    },
  };
  writeFileSync(
    join(evidenceDir, 'taint-traces.json'),
    JSON.stringify(taintEvidence, null, 2),
    'utf8',
  );

  const riskMatrix: RiskScenario[] = (
    [
      ['safe', 'Nenhum evento', 'safe'],
      ['blocked', 'PII crítica bloqueada antes do sink', 'blocked'],
      ['allowed', 'PII crítica permitida em resposta', 'allowed'],
      ['critical', 'Três exposições críticas permitidas', 'critical'],
    ] as const
  ).map(([scenario, description, key]) => {
    const scenarioRisk = riskFromEvents(scenarioEvents(key));
    return {
      scenario,
      description,
      score: scenarioRisk.score,
      level: scenarioRisk.level,
      events: scenarioRisk.total,
    };
  });

  const riskEvidence = {
    generatedAt: new Date().toISOString(),
    matrix: riskMatrix,
    thresholds: [
      { level: 'baixo', range: '0–19', color: 'verde' },
      { level: 'moderado', range: '20–49', color: 'amarelo' },
      { level: 'alto', range: '50–74', color: 'laranja' },
      { level: 'critico', range: '75–100', color: 'vermelho' },
    ],
  };
  writeFileSync(
    join(evidenceDir, 'risk-matrix.json'),
    JSON.stringify(riskEvidence, null, 2),
    'utf8',
  );

  const html = renderEvidenceHtml(piiEvidence, taintEvidence, riskEvidence);
  writeFileSync(join(evidenceDir, 'evidence.html'), html, 'utf8');

  console.log(`[security:evidence] findings de PII: ${piiEvidence.totalFindings}`);
  console.log(`[security:evidence] traces: ${traces.length}`);
  console.log(`[security:evidence] risco da simulação: ${taintEvidence.risk.level} (${taintEvidence.risk.score}/100)`);
  console.log(`[security:evidence] HTML: ${join(evidenceDir, 'evidence.html')}`);
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function badge(level: string): string {
  const normalized = level.toLowerCase();
  const tone =
    normalized === 'critico' || normalized === 'critical'
      ? 'red'
      : normalized === 'alto'
        ? 'orange'
        : normalized === 'moderado'
          ? 'yellow'
          : 'green';
  return `<span class="badge ${tone}">${escapeHtml(level)}</span>`;
}

function renderEvidenceHtml(
  pii: {
    totalFindings: number;
    containsPii: boolean;
    highestSeverity: string | null;
    categories: string[];
    findings: Array<Record<string, unknown>>;
    redacted: unknown;
  },
  taint: {
    traces: TraceEvidence[];
    risk: { score: number; level: string; total: number; blocked: number; allowed: number };
  },
  risk: { matrix: RiskScenario[] },
): string {
  const findingRows = pii.findings
    .map(
      (finding) => `<tr>
        <td><code>${escapeHtml(finding.ruleId)}</code></td>
        <td>${escapeHtml(finding.category)}</td>
        <td>${badge(String(finding.severity))}</td>
        <td>${escapeHtml(finding.field ?? finding.path ?? '—')}</td>
        <td><code>${escapeHtml(finding.maskedMatch)}</code></td>
      </tr>`,
    )
    .join('\n');

  const traceRows = taint.traces
    .map(
      (trace) => `<tr>
        <td><code>${escapeHtml(trace.sink)}</code></td>
        <td>${trace.authenticated ? 'sim' : 'não'}</td>
        <td>${escapeHtml(trace.action)}</td>
        <td>${trace.blocked ? 'bloqueado' : 'permitido'}</td>
        <td><code>${escapeHtml(trace.sanitizedPreview)}</code></td>
      </tr>`,
    )
    .join('\n');

  const riskRows = risk.matrix
    .map(
      (scenario) => `<tr>
        <td><strong>${escapeHtml(scenario.scenario)}</strong></td>
        <td>${escapeHtml(scenario.description)}</td>
        <td>${scenario.score}/100</td>
        <td>${badge(scenario.level)}</td>
      </tr>`,
    )
    .join('\n');

  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Evidências de Segurança — TRAJEtória</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: "Segoe UI", Arial, sans-serif; background: #f6f4fb; color: #251b3b; }
  header { background: linear-gradient(135deg, #4b2a86, #7b4fc9); color: #fff; padding: 36px 40px; }
  header h1 { margin: 0 0 8px; font-size: 30px; }
  header p { margin: 0; opacity: .9; }
  main { max-width: 1100px; margin: 0 auto; padding: 28px 24px 60px; }
  section { background: #fff; border-radius: 18px; padding: 22px 24px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(50, 30, 90, .08); }
  h2 { margin: 0 0 14px; font-size: 20px; color: #4b2a86; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card { background: #f1ecfb; border-radius: 14px; padding: 14px 16px; }
  .card span { display: block; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: #6d5a94; margin-bottom: 6px; }
  .card strong { font-size: 24px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid #ece7f7; vertical-align: top; }
  th { color: #5b4a80; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
  code { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; background: #f4f0fc; padding: 2px 5px; border-radius: 5px; word-break: break-word; }
  .badge { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; }
  .badge.green { background: #d9f7e5; color: #0b6b35; }
  .badge.yellow { background: #fff2c7; color: #7a5a00; }
  .badge.orange { background: #ffe0c2; color: #8a3d00; }
  .badge.red { background: #ffd6d6; color: #8f1111; }
  .note { background: #f1ecfb; border-left: 4px solid #7b4fc9; padding: 12px 14px; border-radius: 8px; font-size: 13px; }
  pre { background: #251b3b; color: #f6f4fb; padding: 16px; border-radius: 12px; overflow: auto; font-size: 12px; }
  footer { text-align: center; color: #6d5a94; font-size: 12px; padding: 20px; }
</style>
</head>
<body>
<header>
  <h1>Evidências de Segurança — TRAJEtória</h1>
  <p>FIAP Global Solution 2026.2 · Cybersecurity · dados fictícios e resultados sanitizados</p>
</header>
<main>
  <div class="cards">
    <div class="card"><span>Findings de PII</span><strong>${pii.totalFindings}</strong></div>
    <div class="card"><span>Severidade máxima</span><strong>${escapeHtml(pii.highestSeverity ?? '—')}</strong></div>
    <div class="card"><span>Categorias</span><strong>${pii.categories.length}</strong></div>
    <div class="card"><span>Sinks testados</span><strong>${taint.traces.length}</strong></div>
    <div class="card"><span>Risco da simulação</span><strong>${taint.risk.score}/100</strong></div>
  </div>

  <section>
    <h2>1. Catálogo de PII detectada</h2>
    <p class="note">A fixture original não é gravada em disco. A tabela abaixo mostra apenas os valores mascarados.</p>
    <table>
      <thead><tr><th>Regra</th><th>Categoria</th><th>Severidade</th><th>Campo</th><th>Valor mascarado</th></tr></thead>
      <tbody>${findingRows}</tbody>
    </table>
  </section>

  <section>
    <h2>2. Taint analysis: source → sink</h2>
    <table>
      <thead><tr><th>Sink</th><th>Autenticado</th><th>Ação</th><th>Resultado</th><th>Payload sanitizado</th></tr></thead>
      <tbody>${traceRows}</tbody>
    </table>
  </section>

  <section>
    <h2>3. Matriz de risco e farol</h2>
    <table>
      <thead><tr><th>Cenário</th><th>Descrição</th><th>Score</th><th>Farol</th></tr></thead>
      <tbody>${riskRows}</tbody>
    </table>
    <p class="note">Farol: verde (0–19), amarelo (20–49), laranja (50–74) e vermelho (75–100). O dashboard usa as mesmas faixas.</p>
  </section>

  <section>
    <h2>4. Payload redigido</h2>
    <pre>${escapeHtml(JSON.stringify(pii.redacted, null, 2))}</pre>
  </section>

  <section>
    <h2>5. Captura do dashboard</h2>
    <img src="dashboard.png" alt="Dashboard de segurança do TRAJEtória com farol de risco" style="width:100%;border-radius:14px;border:1px solid #e2d8f7;" />
    <p class="note">Captura gerada por npm run security:dashboard-shot com eventos fictícios. Nenhuma PII bruta é exibida.</p>
  </section>
</main>
<footer>TRAJEtória · evidências geradas automaticamente por <code>npm run security:evidence</code></footer>
</body>
</html>`;
}

main();
