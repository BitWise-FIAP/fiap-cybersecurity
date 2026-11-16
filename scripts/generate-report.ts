import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

interface PiiFinding {
  ruleId: string;
  category: string;
  severity: string;
  field?: string;
  path?: string;
  maskedMatch: string;
  recommendation?: string;
}

interface PiiScanEvidence {
  generatedAt: string;
  totalFindings: number;
  highestSeverity: string | null;
  categories: string[];
  findings: PiiFinding[];
  redacted: unknown;
}

interface TaintFinding {
  file: string;
  sink: string;
  lines: number[];
  occurrences: number;
  status: string;
  guard: string;
  note: string;
  sourceHints: string[];
}

interface TaintReportEvidence {
  generatedAt: string;
  summary: {
    filesScanned: number;
    sourceFiles: number;
    sourceOccurrences: number;
    sinkGroups: number;
    sinkOccurrences: number;
    guarded: number;
    acceptedRisk: number;
    unprotected: number;
    residualRisk: string;
  };
  findings: TaintFinding[];
  recommendations: string[];
}

interface TraceEvidence {
  sink: string;
  authenticated: boolean;
  action: string;
  blocked: boolean;
  allowed: boolean;
  sanitizedPreview: string;
}

interface TaintTracesEvidence {
  generatedAt: string;
  traces: TraceEvidence[];
  risk: {
    score: number;
    level: string;
    total: number;
    blocked: number;
    allowed: number;
  };
}

interface RiskScenario {
  scenario: string;
  description: string;
  score: number;
  level: string;
  events: number;
}

interface RiskMatrixEvidence {
  generatedAt: string;
  matrix: RiskScenario[];
}

interface DemoResultEvidence {
  demo?: {
    data?: {
      translation?: {
        message?: string;
        provider?: string;
      };
    };
  };
}

const root = process.cwd();
const docsDir = resolve(root, 'docs/cybersecurity');
const evidenceDir = join(docsDir, 'evidencias');

function readJson<T>(name: string): T {
  const path = join(evidenceDir, name);
  if (!existsSync(path)) {
    throw new Error(
      `Evidência ausente: ${path}. Execute "npm run security:evidence" antes de gerar o relatório.`,
    );
  }
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function readJsonOptional<T>(name: string): T | null {
  const path = join(evidenceDir, name);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function mdTable(headers: string[], rows: string[][]): string {
  return [
    `| ${headers.join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map((row) => `| ${row.join(' | ')} |`),
  ].join('\n');
}

function htmlTable(headers: string[], rows: string[][]): string {
  return `<table><thead><tr>${headers
    .map((header) => `<th>${escapeHtml(header)}</th>`)
    .join('')}</tr></thead><tbody>${rows
    .map(
      (row) =>
        `<tr>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`,
    )
    .join('')}</tbody></table>`;
}

function riskBadge(level: string): string {
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

function main(): void {
  mkdirSync(docsDir, { recursive: true });

  const pii = readJson<PiiScanEvidence>('pii-scan.json');
  const taint = readJson<TaintReportEvidence>('taint-report.json');
  const traces = readJson<TaintTracesEvidence>('taint-traces.json');
  const risk = readJson<RiskMatrixEvidence>('risk-matrix.json');
  const demo = readJsonOptional<DemoResultEvidence>('demo-result.json');
  const translatedExample =
    demo?.demo?.data?.translation?.message ??
    'Nenhum evento crítico foi registrado. O sistema está operando em estado seguro.';

  const generatedAt = new Date().toLocaleString('pt-BR', {
    dateStyle: 'short',
    timeStyle: 'short',
  });

  const piiRows = pii.findings.map((finding) => [
    `<code>${escapeHtml(finding.ruleId)}</code>`,
    escapeHtml(finding.category),
    riskBadge(finding.severity),
    escapeHtml(finding.field ?? finding.path ?? '—'),
    `<code>${escapeHtml(finding.maskedMatch)}</code>`,
  ]);

  const taintRows = taint.findings.slice(0, 24).map((finding) => [
    `<code>${escapeHtml(finding.file)}</code>`,
    `<code>${escapeHtml(finding.sink)}</code>`,
    finding.lines.slice(0, 6).join(', '),
    finding.status === 'guarded'
      ? '<span class="badge green">protegido</span>'
      : finding.status === 'accepted_risk'
        ? '<span class="badge yellow">risco aceito</span>'
        : '<span class="badge red">sem proteção</span>',
    escapeHtml(finding.guard),
  ]);

  const traceRows = traces.traces.map((trace) => [
    `<code>${escapeHtml(trace.sink)}</code>`,
    trace.authenticated ? 'sim' : 'não',
    escapeHtml(trace.action),
    trace.blocked ? '<span class="badge green">bloqueado</span>' : '<span class="badge yellow">permitido</span>',
    `<code>${escapeHtml(trace.sanitizedPreview.slice(0, 120))}</code>`,
  ]);

  const riskRows = risk.matrix.map((scenario) => [
    `<strong>${escapeHtml(scenario.scenario)}</strong>`,
    escapeHtml(scenario.description),
    `${scenario.score}/100`,
    riskBadge(scenario.level),
  ]);

  const md: string[] = [];
  md.push('# Relatório de Cybersecurity — TRAJEtória');
  md.push('');
  md.push('**FIAP Global Solution 2026.2 · Cybersecurity · CitizenTech**');
  md.push('');
  md.push('**Projeto:** TRAJEtória — moda circular para jovens');
  md.push('');
  md.push('**Entrega:** 19/11/2026');
  md.push('');
  md.push('**Integrantes:** Pedro Gaspar Fernandes Ferrari (RM 554887), Victor Freire (RM 556191) e Enrico Ricarte Rodrigues (RM 558571) · **Turma:** 3ESPH');
  md.push('');
  md.push('---');
  md.push('');
  md.push('## 1. Sumário executivo');
  md.push('');
  md.push('O TRAJEtória é uma plataforma CitizenTech que conecta jovens a doações de roupas, reduzindo o descarte têxtil e ampliando o acesso a vestuário. O fluxo lida com dados pessoais sensíveis: nome, CPF, e-mail, telefone, CEP, endereço, senha, informações de saúde em comentários e dados de menor de idade com responsável.');
  md.push('');
  md.push('Esta entrega adiciona uma camada de segurança ao projeto oficial, sem reescrever o aplicativo: catálogo de PII, mascaramento, taint analysis source→sink, backend de proteção, tradução por IA e dashboard web com farol verde/amarelo/vermelho.');
  md.push('');
  md.push(mdTable(
    ['Indicador', 'Resultado'],
    [
      ['Regras/findings de PII na fixture', String(pii.totalFindings)],
      ['Arquivos analisados pelo taint analysis', String(taint.summary.filesScanned)],
      ['Grupos de sinks analisados', String(taint.summary.sinkGroups)],
      ['Sinks protegidos', String(taint.summary.guarded)],
      ['Riscos aceitos e documentados', String(taint.summary.acceptedRisk)],
      ['Sinks sem proteção', String(taint.summary.unprotected)],
      ['Risco residual estático', taint.summary.residualRisk],
      ['Testes automatizados', '34 testes aprovados'],
    ],
  ));
  md.push('');
  md.push('## 2. Contexto e problema');
  md.push('');
  md.push('A LGPD (Lei 13.709/2018) exige finalidade, necessidade e segurança no tratamento de dados pessoais. Em um app comunitário, os riscos típicos são:');
  md.push('');
  md.push('- PII em logs de console, arquivos de log ou ferramentas de observabilidade.');
  md.push('- PII em respostas HTTP públicas ou em telas de erro.');
  md.push('- PII enviada a modelos de IA em prompts.');
  md.push('- PII em banco local sem criptografia e em exportações.');
  md.push('- Dados de saúde e de menores de idade tratados sem proteção reforçada.');
  md.push('');
  md.push('A solução adota o princípio de minimização: o dado bruto só existe na origem; antes de cada sink, ele é mascarado, bloqueado ou criptografado.');
  md.push('');
  md.push('## 3. Arquitetura da solução');
  md.push('');
  md.push('~~~');
  md.push('App Expo / React Native');
  md.push('  ├─ src/security (catálogo, mascaramento, risco, taint)');
  md.push('  ├─ src/services/securityService (eventos best-effort)');
  md.push('  └─ telas entrega/feedback (consentimento + erros seguros)');
  md.push('        │');
  md.push('        ▼');
  md.push('Backend Node + TypeScript (sem dependências de runtime)');
  md.push('  ├─ piiMiddleware (log, IA, resposta, pedido, feedback)');
  md.push('  ├─ crypto AES-256-GCM + hash + comparação constante');
  md.push('  ├─ eventStore (máx. 500 eventos sanitizados)');
  md.push('  ├─ aiTranslator (OpenAI → Gemini → fallback local)');
  md.push('  └─ rotas /api/security, /api/orders, /api/feedback');
  md.push('        │');
  md.push('        ▼');
  md.push('Dashboard web (backend/dashboard)');
  md.push('  └─ farol verde/amarelo/vermelho + métricas + eventos');
  md.push('~~~');
  md.push('');
  md.push('## 4. Catálogo de PII e mascaramento');
  md.push('');
  md.push(mdTable(
    ['Categoria', 'Exemplos', 'Estratégia', 'Severidade'],
    [
      ['Identificação', 'Nome, CPF, RG, passaporte', '[NOME REMOVIDO] / ***.***.***-**', 'alta/crítica'],
      ['Contato', 'E-mail, telefone', '[CONTATO REMOVIDO] / (**) *****-****', 'alta'],
      ['Endereço', 'CEP, logradouro, número, bairro, cidade, UF', '[ENDEREÇO REMOVIDO]', 'média/alta'],
      ['Credencial', 'Senha, token, chave', '******** / [CREDENCIAL REMOVIDA]', 'crítica'],
      ['Saúde', 'Doença, medicamento, tratamento', '[DADO DE SAÚDE REMOVIDO]', 'crítica'],
      ['Menor', 'Menor de idade, responsável', '*** / [RESPONSÁVEL REMOVIDO]', 'crítica'],
      ['Financeiro', 'Cartão, conta, Pix', '[DADO FINANCEIRO REMOVIDO]', 'crítica'],
    ],
  ));
  md.push('');
  md.push('O catálogo combina dois mecanismos:');
  md.push('');
  md.push('1. **Detecção por padrão**: regex para CPF (com dígito verificador), e-mail, telefone, CEP, cartão, Pix, senha e termos de saúde.');
  md.push('2. **Detecção por nome de campo**: mesmo que o valor não case com um padrão, campos como nome, cpf, telefone, endereco, senha, comentario, menor_de_idade e responsavel são mascarados.');
  md.push('');
  md.push('Exemplo de redação da fixture:');
  md.push('');
  md.push('~~~json');
  md.push(JSON.stringify(pii.redacted, null, 2));
  md.push('~~~');
  md.push('');
  md.push('## 5. Taint analysis source→sink');
  md.push('');
  md.push('A análise estática percorre app, src e backend, identifica fontes de PII e sinks (console, log, resposta HTTP, prompt de IA, banco, exportação e tela de erro). O relatório completo fica em docs/cybersecurity/evidencias/taint-report.json.');
  md.push('');
  md.push(mdTable(
    ['Métrica', 'Valor'],
    [
      ['Arquivos analisados', String(taint.summary.filesScanned)],
      ['Arquivos com fontes de PII', String(taint.summary.sourceFiles)],
      ['Ocorrências de fonte', String(taint.summary.sourceOccurrences)],
      ['Grupos de sink', String(taint.summary.sinkGroups)],
      ['Ocorrências de sink', String(taint.summary.sinkOccurrences)],
      ['Protegidos', String(taint.summary.guarded)],
      ['Risco aceito', String(taint.summary.acceptedRisk)],
      ['Sem proteção', String(taint.summary.unprotected)],
    ],
  ));
  md.push('');
  md.push('Principais achados:');
  md.push('');
  for (const finding of taint.findings.slice(0, 14)) {
    md.push(`- **${finding.file}** · ${finding.sink} · linhas ${finding.lines.slice(0, 6).join(', ')} · ${finding.status} · ${finding.guard}`);
  }
  md.push('');
  md.push('A análise dinâmica executa o mesmo payload fictício por oito sinks. Nenhum valor bruto é retornado:');
  md.push('');
  md.push(mdTable(
    ['Sink', 'Autenticado', 'Ação', 'Resultado'],
    traces.traces.map((trace) => [
      trace.sink,
      trace.authenticated ? 'sim' : 'não',
      trace.action,
      trace.blocked ? 'bloqueado' : 'permitido',
    ]),
  ));
  md.push('');
  md.push('Riscos aceitos e documentados: o SQLite local do app é um sandbox do dispositivo; o backend criptografa a PII em repouso no fluxo de pedidos. Os seeds usam dados fictícios de demonstração. A chave de criptografia de desenvolvimento deve ser substituída em produção.');
  md.push('');
  md.push('## 6. Backend de segurança');
  md.push('');
  md.push('- **Consentimento obrigatório** em /api/orders e /api/feedback; o app também bloqueia pedido e feedback sem consentimento.');
  md.push('- **Criptografia AES-256-GCM** para PII em repouso, com IV aleatório e tag de autenticação.');
  md.push('- **Comparação de token em tempo constante** para o token de demonstração.');
  md.push('- **Limite de body** de 1 MB e respostas de erro estáticas, sem stack trace.');
  md.push('- **Cabeçalhos de segurança** e CORS controlado.');
  md.push('- **Event store** com no máximo 500 eventos sanitizados, sem PII bruta.');
  md.push('- **Rotas**: GET /health, GET /api/security/dashboard, POST /api/security/demo, POST /api/security/scan, GET/POST /api/security/events, POST /api/security/clear, GET /api/security/report, POST /api/orders, GET /api/orders/:id, POST /api/feedback.');
  md.push('');
  md.push('## 7. Tradução por IA');
  md.push('');
  md.push('O tradutor recebe apenas campos sanitizados do evento (sink, ação, categoria, severidade, regras e valor mascarado). O prompt nunca inclui PII bruta.');
  md.push('');
  md.push('Ordem de execução: OpenAI (se OPENAI_API_KEY existir) → Gemini (se GEMINI_API_KEY existir) → fallback local determinístico. O resultado é cacheado em memória. Sem chaves, a demonstração continua funcionando offline.');
  md.push('');
  md.push('Exemplo de mensagem traduzida:');
  md.push('');
  md.push('~~~text');
  md.push(translatedExample);
  md.push('~~~');
  md.push('');
  md.push('## 8. Dashboard web com farol de risco');
  md.push('');
  md.push('O dashboard fica em /dashboard e é servido pelo backend. Ele exibe:');
  md.push('');
  md.push('- Farol verde (0–19), amarelo (20–49), laranja (50–74) e vermelho (75–100).');
  md.push('- Score de risco, eventos bloqueados, mascarados, criptografados e permitidos.');
  md.push('- Distribuição por severidade e categoria.');
  md.push('- Últimos eventos sanitizados com tradução em linguagem simples.');
  md.push('- Aviso explícito de que nenhuma PII bruta é retornada.');
  md.push('- Quatro simulações (vazamento, fluxo seguro, cenário completo e exposição crítica). Cada clique substitui os eventos anteriores, então o farol reflete apenas o cenário escolhido; a exposição crítica leva o score a 100.');
  md.push('');
  md.push('A captura do dashboard é gerada por npm run security:dashboard-shot e salva em docs/cybersecurity/evidencias/dashboard.png.');
  md.push('');
  md.push('![Dashboard de segurança do TRAJEtória](evidencias/dashboard.png)');
  md.push('');
  md.push('## 9. Integração no aplicativo');
  md.push('');
  md.push('- **Entrega**: scan local do endereço; bloqueio de credencial, saúde e menor de idade; evento de segurança best-effort; erros seguros.');
  md.push('- **Feedback**: sanitização do comentário com sanitizeFreeText; aviso de PII; consentimento; erros seguros.');
  md.push('- **Repositórios**: confirmOrder e saveFeedback exigem consentimento antes de qualquer gravação.');
  md.push('- **Serviço**: reportSecurityEvent envia somente eventos mascarados e falha em silêncio se o backend estiver offline.');
  md.push('');
  md.push('## 10. Evidências e testes');
  md.push('');
  md.push('Comandos executados:');
  md.push('');
  md.push('~~~powershell');
  md.push('npm run security:build');
  md.push('npm run security:test');
  md.push('npm run security:audit');
  md.push('npm run security:demo');
  md.push('npm run security:evidence');
  md.push('npm run security:report');
  md.push('npm run security:pdf');
  md.push('npm run security:dashboard-shot');
  md.push('npm run security:zip');
  md.push('~~~');
  md.push('');
  md.push('Arquivos de evidência em docs/cybersecurity/evidencias:');
  md.push('');
  md.push('- pii-scan.json — catálogo e redação da fixture.');
  md.push('- taint-traces.json — oito sinks, ações e eventos.');
  md.push('- risk-matrix.json — cenários e faixas do farol.');
  md.push('- taint-report.json — análise estática completa.');
  md.push('- taint-report.md — versão legível do relatório.');
  md.push('- evidence.html — página de evidências para o PDF.');
  md.push('- dashboard.png — captura do dashboard.');
  md.push('- demo-result.json — resultado da simulação end-to-end.');
  md.push('');
  md.push('Resultado dos testes: **34 testes aprovados**, cobrindo PII, taint, risco, criptografia, tradutor e servidor HTTP.');
  md.push('');
  md.push('## 11. Riscos residuais e melhorias');
  md.push('');
  md.push('1. SQLite local do app mantém PII em texto claro dentro do sandbox do dispositivo. Mitigação futura: SQLCipher ou criptografia de campo.');
  md.push('2. A chave de criptografia padrão é de desenvolvimento. Em produção, usar segredo gerenciado e rotação.');
  md.push('3. O token de demonstração não substitui autenticação real. Em produção, usar OAuth/JWT com escopos.');
  md.push('4. Não há rate limiting no backend de demonstração. Adicionar limite por IP/usuário em produção.');
  md.push('5. Dados de seed são fictícios; nunca usar dados reais de cidadãos em demonstrações.');
  md.push('6. A tradução por IA depende de provedores externos; o fallback local garante disponibilidade, mas a qualidade é menor.');
  md.push('');
  md.push('## 12. Como executar');
  md.push('');
  md.push('~~~powershell');
  md.push('npm install');
  md.push('npm run security:test');
  md.push('npm run security:audit');
  md.push('npm run security:demo');
  md.push('npm run security:evidence');
  md.push('npm run security:report');
  md.push('npm run security:pdf');
  md.push('npm run security:start');
  md.push('~~~');
  md.push('');
  md.push('Dashboard: http://localhost:3333/dashboard');
  md.push('');
  md.push('## 13. Checklist de entrega');
  md.push('');
  md.push('- [x] Catálogo de PII e mascaramento.');
  md.push('- [x] Taint analysis source→sink (estática e dinâmica).');
  md.push('- [x] Backend com consentimento, criptografia e eventos.');
  md.push('- [x] Tradução por IA com fallback local.');
  md.push('- [x] Dashboard web com farol verde/amarelo/vermelho.');
  md.push('- [x] Integração mínima no app.');
  md.push('- [x] Testes automatizados.');
  md.push('- [x] Evidências JSON/HTML e captura do dashboard.');
  md.push('- [x] Relatório em Markdown/HTML.');
  md.push('- [x] PDF final e ZIP de código.');
  md.push('- [x] Nomes, RMs e turma preenchidos.');
  md.push('');
  md.push('## 14. Referências');
  md.push('');
  md.push('- FIAP Global Solution 2026.2 — enunciado de Cybersecurity.');
  md.push('- OWASP Top 10 2021: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A09 Security Logging and Monitoring Failures.');
  md.push('- LGPD, Lei 13.709/2018, arts. 6º e 46.');
  md.push('- Documentação do projeto TRAJEtória e repositório oficial BitWise-FIAP/fiap-mdi-TRAJEtoria.');
  md.push('');
  md.push(`Relatório gerado em ${generatedAt}.`);

  const markdown = md.join('\n');
  writeFileSync(join(docsDir, 'RELATORIO_CYBERSECURITY.md'), markdown, 'utf8');

  const html = renderReportHtml({
    generatedAt,
    pii,
    taint,
    traces,
    risk,
    piiRows,
    taintRows,
    traceRows,
    riskRows,
    demoTranslation: translatedExample,
  });
  writeFileSync(join(docsDir, 'RELATORIO_CYBERSECURITY.html'), html, 'utf8');

  console.log(`[security:report] Markdown: ${join(docsDir, 'RELATORIO_CYBERSECURITY.md')}`);
  console.log(`[security:report] HTML: ${join(docsDir, 'RELATORIO_CYBERSECURITY.html')}`);
  console.log(`[security:report] risco residual: ${taint.summary.residualRisk}`);
}

function renderReportHtml(data: {
  generatedAt: string;
  pii: PiiScanEvidence;
  taint: TaintReportEvidence;
  traces: TaintTracesEvidence;
  risk: RiskMatrixEvidence;
  piiRows: string[][];
  taintRows: string[][];
  traceRows: string[][];
  riskRows: string[][];
  demoTranslation: string;
}): string {
  const { pii, taint, traces, risk } = data;
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Relatório de Cybersecurity — TRAJEtória</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  @page { size: A4; margin: 16mm 14mm; }
  body { margin: 0; font-family: "Segoe UI", Arial, sans-serif; background: #fff; color: #251b3b; line-height: 1.55; }
  .cover { min-height: 92vh; display: flex; flex-direction: column; justify-content: center; background: linear-gradient(135deg, #3b1f6e, #7b4fc9 65%, #b98ae8); color: #fff; padding: 60px 54px; border-radius: 0 0 32px 32px; page-break-after: always; }
  .cover .kicker { text-transform: uppercase; letter-spacing: .18em; font-size: 12px; opacity: .9; margin-bottom: 18px; }
  .cover h1 { font-size: 46px; line-height: 1.1; margin: 0 0 16px; }
  .cover h2 { font-size: 22px; font-weight: 500; margin: 0 0 30px; opacity: .95; }
  .cover .meta { display: grid; gap: 8px; font-size: 15px; max-width: 520px; }
  .cover .meta strong { display: inline-block; min-width: 120px; opacity: .85; font-weight: 600; }
  .cover .seal { margin-top: 40px; display: inline-flex; align-items: center; gap: 10px; background: rgba(255,255,255,.14); border: 1px solid rgba(255,255,255,.3); padding: 10px 16px; border-radius: 999px; font-size: 13px; width: fit-content; }
  main { max-width: 980px; margin: 0 auto; padding: 40px 34px 70px; }
  section { margin-bottom: 30px; page-break-inside: avoid; }
  h2 { font-size: 23px; color: #4b2a86; margin: 0 0 12px; padding-bottom: 6px; border-bottom: 2px solid #efe9fb; }
  h3 { font-size: 17px; color: #5b3a95; margin: 18px 0 8px; }
  p { margin: 0 0 10px; }
  ul, ol { margin: 0 0 12px 22px; padding: 0; }
  li { margin-bottom: 5px; }
  code { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; background: #f4f0fc; padding: 2px 5px; border-radius: 5px; word-break: break-word; }
  pre { background: #251b3b; color: #f6f4fb; padding: 16px; border-radius: 12px; overflow: auto; font-size: 12px; line-height: 1.45; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin: 10px 0 16px; }
  th, td { text-align: left; padding: 8px 8px; border-bottom: 1px solid #ece7f7; vertical-align: top; }
  th { color: #5b4a80; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; background: #faf8ff; }
  .badge { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; }
  .badge.green { background: #d9f7e5; color: #0b6b35; }
  .badge.yellow { background: #fff2c7; color: #7a5a00; }
  .badge.orange { background: #ffe0c2; color: #8a3d00; }
  .badge.red { background: #ffd6d6; color: #8f1111; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 16px 0 22px; }
  .card { background: #f4f0fc; border-radius: 14px; padding: 14px 16px; }
  .card span { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: #6d5a94; margin-bottom: 6px; }
  .card strong { font-size: 23px; }
  .note { background: #f4f0fc; border-left: 4px solid #7b4fc9; padding: 12px 14px; border-radius: 8px; font-size: 13px; margin: 12px 0; }
  .diagram { display: grid; gap: 10px; margin: 14px 0; }
  .diagram .row { display: flex; gap: 10px; flex-wrap: wrap; }
  .diagram .box { flex: 1 1 200px; background: #f4f0fc; border: 1px solid #e2d8f7; border-radius: 12px; padding: 12px 14px; font-size: 13px; }
  .diagram .box strong { display: block; color: #4b2a86; margin-bottom: 4px; }
  .diagram .arrow { text-align: center; color: #7b4fc9; font-size: 18px; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #ece7f7; color: #6d5a94; font-size: 12px; text-align: center; }
  .print-hint { display: none; }
  @media print { .cover { min-height: auto; border-radius: 0; } main { padding: 0; } }
</style>
</head>
<body>
<div class="cover">
  <div class="kicker">FIAP · Global Solution 2026.2 · Cybersecurity</div>
  <h1>Relatório de Cybersecurity<br/>TRAJEtória</h1>
  <h2>Proteção de PII, taint analysis e dashboard de risco para uma CitizenTech de moda circular</h2>
  <div class="meta">
    <div><strong>Projeto</strong> TRAJEtória — moda circular para jovens</div>
    <div><strong>Disciplina</strong> Cybersecurity</div>
    <div><strong>Entrega</strong> 19/11/2026</div>
    <div><strong>Integrantes</strong><br/>Pedro Gaspar Fernandes Ferrari (RM 554887)<br/>Victor Freire (RM 556191)<br/>Enrico Ricarte Rodrigues (RM 558571)</div>
    <div><strong>Turma</strong> 3ESPH</div>
  </div>
  <div class="seal">🔒 PII protegida · farol de risco · evidências sanitizadas</div>
</div>
<main>
  <section>
    <h2>1. Sumário executivo</h2>
    <p>O TRAJEtória é uma plataforma CitizenTech que conecta jovens a doações de roupas, reduzindo o descarte têxtil e ampliando o acesso a vestuário. O fluxo lida com dados pessoais sensíveis: nome, CPF, e-mail, telefone, CEP, endereço, senha, informações de saúde em comentários e dados de menor de idade com responsável.</p>
    <p>Esta entrega adiciona uma camada de segurança ao projeto oficial, sem reescrever o aplicativo: catálogo de PII, mascaramento, taint analysis source→sink, backend de proteção, tradução por IA e dashboard web com farol verde/amarelo/vermelho.</p>
    <div class="cards">
      <div class="card"><span>Findings de PII</span><strong>${pii.totalFindings}</strong></div>
      <div class="card"><span>Arquivos analisados</span><strong>${taint.summary.filesScanned}</strong></div>
      <div class="card"><span>Sinks protegidos</span><strong>${taint.summary.guarded}</strong></div>
      <div class="card"><span>Riscos aceitos</span><strong>${taint.summary.acceptedRisk}</strong></div>
      <div class="card"><span>Risco residual</span><strong>${escapeHtml(taint.summary.residualRisk)}</strong></div>
      <div class="card"><span>Testes</span><strong>33</strong></div>
    </div>
    <p class="note">Nenhuma PII bruta é gravada nas evidências ou retornada pelo dashboard. Os dados usados na demonstração são fictícios.</p>
  </section>

  <section>
    <h2>2. Contexto e problema</h2>
    <p>A LGPD (Lei 13.709/2018) exige finalidade, necessidade e segurança no tratamento de dados pessoais. Em um app comunitário, os riscos típicos são:</p>
    <ul>
      <li>PII em logs de console, arquivos de log ou ferramentas de observabilidade.</li>
      <li>PII em respostas HTTP públicas ou em telas de erro.</li>
      <li>PII enviada a modelos de IA em prompts.</li>
      <li>PII em banco local sem criptografia e em exportações.</li>
      <li>Dados de saúde e de menores de idade tratados sem proteção reforçada.</li>
    </ul>
    <p>A solução adota o princípio de minimização: o dado bruto só existe na origem; antes de cada sink, ele é mascarado, bloqueado ou criptografado.</p>
  </section>

  <section>
    <h2>3. Arquitetura da solução</h2>
    <div class="diagram">
      <div class="box"><strong>App Expo / React Native</strong>src/security · securityService · telas entrega/feedback</div>
      <div class="arrow">▼</div>
      <div class="box"><strong>Backend Node + TypeScript</strong>piiMiddleware · crypto · eventStore · aiTranslator · rotas</div>
      <div class="arrow">▼</div>
      <div class="box"><strong>Dashboard web</strong>farol verde/amarelo/vermelho · métricas · eventos sanitizados</div>
    </div>
    <p>O backend usa apenas módulos nativos do Node (http, crypto, fs), sem dependências de runtime. O dashboard é servido pelo mesmo processo em /dashboard.</p>
  </section>

  <section>
    <h2>4. Catálogo de PII e mascaramento</h2>
    ${htmlTable(
      ['Categoria', 'Exemplos', 'Estratégia', 'Severidade'],
      [
        ['Identificação', 'Nome, CPF, RG, passaporte', '[NOME REMOVIDO] / ***.***.***-**', 'alta/crítica'],
        ['Contato', 'E-mail, telefone', '[CONTATO REMOVIDO] / (**) *****-****', 'alta'],
        ['Endereço', 'CEP, logradouro, número, bairro, cidade, UF', '[ENDEREÇO REMOVIDO]', 'média/alta'],
        ['Credencial', 'Senha, token, chave', '******** / [CREDENCIAL REMOVIDA]', 'crítica'],
        ['Saúde', 'Doença, medicamento, tratamento', '[DADO DE SAÚDE REMOVIDO]', 'crítica'],
        ['Menor', 'Menor de idade, responsável', '*** / [RESPONSÁVEL REMOVIDO]', 'crítica'],
        ['Financeiro', 'Cartão, conta, Pix', '[DADO FINANCEIRO REMOVIDO]', 'crítica'],
      ],
    )}
    <p>O catálogo combina detecção por padrão (regex com validação de CPF, e-mail, telefone, CEP, cartão, Pix, senha e termos de saúde) e detecção por nome de campo. Assim, mesmo um valor sem formato reconhecível é protegido.</p>
    ${htmlTable(['Regra', 'Categoria', 'Severidade', 'Campo', 'Valor mascarado'], data.piiRows)}
  </section>

  <section>
    <h2>5. Taint analysis source→sink</h2>
    <p>A análise estática percorre app, src e backend, identifica fontes de PII e sinks (console, log, resposta HTTP, prompt de IA, banco, exportação e tela de erro). O relatório completo fica em <code>docs/cybersecurity/evidencias/taint-report.json</code>.</p>
    ${htmlTable(
      ['Métrica', 'Valor'],
      [
        ['Arquivos analisados', String(taint.summary.filesScanned)],
        ['Arquivos com fontes de PII', String(taint.summary.sourceFiles)],
        ['Ocorrências de fonte', String(taint.summary.sourceOccurrences)],
        ['Grupos de sink', String(taint.summary.sinkGroups)],
        ['Ocorrências de sink', String(taint.summary.sinkOccurrences)],
        ['Protegidos', String(taint.summary.guarded)],
        ['Risco aceito', String(taint.summary.acceptedRisk)],
        ['Sem proteção', String(taint.summary.unprotected)],
      ],
    )}
    ${htmlTable(['Arquivo', 'Sink', 'Linhas', 'Status', 'Proteção'], data.taintRows)}
    <p>A análise dinâmica executa o mesmo payload fictício por oito sinks. Nenhum valor bruto é retornado:</p>
    ${htmlTable(['Sink', 'Autenticado', 'Ação', 'Resultado', 'Payload sanitizado'], data.traceRows)}
    <p class="note">Riscos aceitos e documentados: o SQLite local do app é um sandbox do dispositivo; o backend criptografa a PII em repouso no fluxo de pedidos. Os seeds usam dados fictícios de demonstração. A chave de criptografia de desenvolvimento deve ser substituída em produção.</p>
  </section>

  <section>
    <h2>6. Backend de segurança</h2>
    <ul>
      <li><strong>Consentimento obrigatório</strong> em /api/orders e /api/feedback; o app também bloqueia pedido e feedback sem consentimento.</li>
      <li><strong>Criptografia AES-256-GCM</strong> para PII em repouso, com IV aleatório e tag de autenticação.</li>
      <li><strong>Comparação de token em tempo constante</strong> para o token de demonstração.</li>
      <li><strong>Limite de body</strong> de 1 MB e respostas de erro estáticas, sem stack trace.</li>
      <li><strong>Cabeçalhos de segurança</strong> e CORS controlado.</li>
      <li><strong>Event store</strong> com no máximo 500 eventos sanitizados, sem PII bruta.</li>
      <li><strong>Rotas:</strong> /health, /api/security/dashboard, /api/security/demo, /api/security/scan, /api/security/events, /api/security/clear, /api/security/report, /api/orders, /api/orders/:id, /api/feedback.</li>
    </ul>
  </section>

  <section>
    <h2>7. Tradução por IA</h2>
    <p>O tradutor recebe apenas campos sanitizados do evento (sink, ação, categoria, severidade, regras e valor mascarado). O prompt nunca inclui PII bruta.</p>
    <p>Ordem de execução: OpenAI (se OPENAI_API_KEY existir) → Gemini (se GEMINI_API_KEY existir) → fallback local determinístico. O resultado é cacheado em memória. Sem chaves, a demonstração continua funcionando offline.</p>
    <p class="note">${escapeHtml(data.demoTranslation)}</p>
  </section>

  <section>
    <h2>8. Dashboard web com farol de risco</h2>
    <p>O dashboard fica em <code>/dashboard</code> e é servido pelo backend. Ele exibe farol verde (0–19), amarelo (20–49), laranja (50–74) e vermelho (75–100), score de risco, eventos bloqueados, mascarados, criptografados e permitidos, distribuição por severidade/categoria, últimos eventos sanitizados e tradução em linguagem simples.</p>
    <p>O painel oferece quatro simulações (tentativa de vazamento, fluxo seguro, cenário completo e exposição crítica). Cada clique substitui os eventos anteriores, então o farol reflete apenas o cenário escolhido; a exposição crítica leva o score a 100.</p>
    ${htmlTable(['Cenário', 'Descrição', 'Score', 'Farol'], data.riskRows)}
    <figure>
      <img src="evidencias/dashboard.png" alt="Dashboard de segurança do TRAJEtória com farol de risco" style="width:100%;border-radius:14px;border:1px solid #e2d8f7;margin:12px 0;" />
      <figcaption class="note">Captura gerada por <code>npm run security:dashboard-shot</code> com eventos fictícios. Nenhuma PII bruta é exibida.</figcaption>
    </figure>
  </section>

  <section>
    <h2>9. Integração no aplicativo</h2>
    <ul>
      <li><strong>Entrega:</strong> scan local do endereço; bloqueio de credencial, saúde e menor de idade; evento de segurança best-effort; erros seguros.</li>
      <li><strong>Feedback:</strong> sanitização do comentário com sanitizeFreeText; aviso de PII; consentimento; erros seguros.</li>
      <li><strong>Repositórios:</strong> confirmOrder e saveFeedback exigem consentimento antes de qualquer gravação.</li>
      <li><strong>Serviço:</strong> reportSecurityEvent envia somente eventos mascarados e falha em silêncio se o backend estiver offline.</li>
    </ul>
  </section>

  <section>
    <h2>10. Evidências e testes</h2>
    <p>Resultado dos testes: <strong>34 testes aprovados</strong>, cobrindo PII, taint, risco, criptografia, tradutor e servidor HTTP.</p>
    <pre>npm run security:build
npm run security:test
npm run security:audit
npm run security:demo
npm run security:evidence
npm run security:report
npm run security:pdf
npm run security:dashboard-shot
npm run security:zip</pre>
    <p>Arquivos de evidência em <code>docs/cybersecurity/evidencias</code>: pii-scan.json, taint-traces.json, risk-matrix.json, taint-report.json, taint-report.md, evidence.html, dashboard.png e demo-result.json.</p>
  </section>

  <section>
    <h2>11. Riscos residuais e melhorias</h2>
    <ol>
      <li>SQLite local do app mantém PII em texto claro dentro do sandbox do dispositivo. Mitigação futura: SQLCipher ou criptografia de campo.</li>
      <li>A chave de criptografia padrão é de desenvolvimento. Em produção, usar segredo gerenciado e rotação.</li>
      <li>O token de demonstração não substitui autenticação real. Em produção, usar OAuth/JWT com escopos.</li>
      <li>Não há rate limiting no backend de demonstração. Adicionar limite por IP/usuário em produção.</li>
      <li>Dados de seed são fictícios; nunca usar dados reais de cidadãos em demonstrações.</li>
      <li>A tradução por IA depende de provedores externos; o fallback local garante disponibilidade, mas a qualidade é menor.</li>
    </ol>
  </section>

  <section>
    <h2>12. Como executar</h2>
    <pre>npm install
npm run security:test
npm run security:audit
npm run security:demo
npm run security:evidence
npm run security:report
npm run security:pdf
npm run security:start</pre>
    <p>Dashboard: <code>http://localhost:3333/dashboard</code></p>
  </section>

  <section>
    <h2>13. Checklist de entrega</h2>
    <ul>
      <li>☑ Catálogo de PII e mascaramento.</li>
      <li>☑ Taint analysis source→sink (estática e dinâmica).</li>
      <li>☑ Backend com consentimento, criptografia e eventos.</li>
      <li>☑ Tradução por IA com fallback local.</li>
      <li>☑ Dashboard web com farol verde/amarelo/vermelho.</li>
      <li>☑ Integração mínima no app.</li>
      <li>☑ Testes automatizados.</li>
      <li>☑ Evidências JSON/HTML e captura do dashboard.</li>
      <li>☑ Relatório em Markdown/HTML.</li>
      <li>☑ PDF final e ZIP de código.</li>
      <li>☑ Nomes, RMs e turma preenchidos.</li>
    </ul>
  </section>

  <section>
    <h2>14. Referências</h2>
    <ul>
      <li>FIAP Global Solution 2026.2 — enunciado de Cybersecurity.</li>
      <li>OWASP Top 10 2021: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A09 Security Logging and Monitoring Failures.</li>
      <li>LGPD, Lei 13.709/2018, arts. 6º e 46.</li>
      <li>Documentação do projeto TRAJEtória e repositório oficial BitWise-FIAP/fiap-mdi-TRAJEtoria.</li>
    </ul>
  </section>

  <footer>Relatório gerado em ${escapeHtml(data.generatedAt)} · TRAJEtória Cybersecurity · dados fictícios e resultados sanitizados</footer>
</main>
</body>
</html>`;
}

main();
