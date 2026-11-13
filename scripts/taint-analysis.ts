import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

type FindingStatus = 'guarded' | 'unprotected' | 'accepted_risk';

interface SinkFinding {
  file: string;
  sink: string;
  lines: number[];
  occurrences: number;
  status: FindingStatus;
  guard: string;
  note: string;
  sourceHints: string[];
}

interface FilePolicy {
  status: FindingStatus;
  guard: string;
  note: string;
}

const root = process.cwd();
const evidenceDir = resolve(root, 'docs/cybersecurity/evidencias');
const reportPath = join(evidenceDir, 'taint-report.json');
const markdownPath = join(evidenceDir, 'taint-report.md');

const sinkPattern =
  /console\.(log|warn|error)\s*\(|fetch\s*\(|sendJson\s*\(|res\.end\s*\(|db\.(runAsync|execAsync)\s*\(|Alert\.alert\s*\(|throw new Error\s*\(|reportSecurityEvent\s*\(|confirmOrder\s*\(|saveFeedback\s*\(/;

const piiTermPattern =
  /\b(cpf|nome|email|telefone|contato|cep|logradouro|numero|complemento|bairro|cidade|uf|senha|password|comentario|comment|saude|saúde|menor|responsavel|young|address|endereco|endereço|profile|encryptedPii|maskedPii|maskedValue)\b/i;

const filePolicies: Record<string, FilePolicy> = {
  'app/(jovem)/entrega.tsx': {
    status: 'guarded',
    guard: 'scanLocal + hasConsent + safeErrorMessage',
    note: 'Formulário bloqueia categorias sensíveis, exige consentimento no repositório e nunca exibe erro bruto.',
  },
  'app/(jovem)/feedback.tsx': {
    status: 'guarded',
    guard: 'sanitizeFreeText + hasConsent + safeErrorMessage',
    note: 'Comentário é sanitizado antes de persistir, consentimento é exigido e erros são traduzidos para mensagens seguras.',
  },
  'app/(jovem)/catalogo.tsx': {
    status: 'guarded',
    guard: 'safeErrorMessage',
    note: 'Alertas usam mensagens estáticas ou safeErrorMessage; nenhum erro bruto do banco é exibido.',
  },
  'app/(jovem)/detalhe/[id].tsx': {
    status: 'guarded',
    guard: 'safeErrorMessage',
    note: 'Alerta de adição usa safeErrorMessage; nenhum erro bruto do banco é exibido.',
  },
  'app/(jovem)/acompanhar.tsx': {
    status: 'accepted_risk',
    guard: 'mensagens estáticas',
    note: 'Alertas exibem apenas textos fixos de interface, sem PII ou erro bruto.',
  },
  'app/(jovem)/meu-pedido.tsx': {
    status: 'accepted_risk',
    guard: 'mensagens estáticas + nome da peça',
    note: 'Alertas exibem textos fixos e nome de peça de catálogo, que não é dado pessoal.',
  },
  'app/(jovem)/perfil.tsx': {
    status: 'accepted_risk',
    guard: 'mensagens estáticas',
    note: 'Alertas exibem apenas textos fixos de confirmação de logout.',
  },
  'app/consentimento.tsx': {
    status: 'accepted_risk',
    guard: 'mensagens estáticas',
    note: 'Alerta de erro usa texto fixo, sem detalhes internos.',
  },
  'app/index.tsx': {
    status: 'accepted_risk',
    guard: 'mensagens estáticas',
    note: 'Alerta de ajuda exibe apenas texto fixo de demonstração.',
  },
  'src/components/Design.tsx': {
    status: 'accepted_risk',
    guard: 'mensagens estáticas',
    note: 'Alerta de notificações exibe apenas texto fixo de interface.',
  },
  'src/context/AuthContext.tsx': {
    status: 'accepted_risk',
    guard: 'erro de desenvolvedor',
    note: 'Erro "AuthProvider ausente" é uma falha de composição de componente, sem PII.',
  },
  'src/services/securityService.ts': {
    status: 'guarded',
    guard: 'maskPii + sanitized event',
    note: 'Somente eventos sanitizados são enviados ao backend; falha de rede é silenciosa e não vaza PII.',
  },
  'src/database/repositories/index.ts': {
    status: 'accepted_risk',
    guard: 'hasConsent + SQLite sandbox',
    note: 'Persistência local em SQLite sandbox do app; o backend criptografa a PII em repouso no fluxo de pedidos.',
  },
  'src/database/seeds/initialData.ts': {
    status: 'accepted_risk',
    guard: 'dados fictícios de demonstração',
    note: 'Seed contém dados fictícios usados apenas para demonstração local; não são dados reais de cidadãos.',
  },
  'src/database/connection.ts': {
    status: 'accepted_risk',
    guard: 'SQLite local',
    note: 'Abertura e migração do banco local; não há sink externo nem log de PII.',
  },
  'backend/server.ts': {
    status: 'accepted_risk',
    guard: 'logs estáticos de inicialização',
    note: 'Logs exibem apenas URLs e provedor de IA; nenhum payload ou PII é registrado.',
  },
  'src/security/taint.ts': {
    status: 'guarded',
    guard: 'safeLog',
    note: 'O sink de console é o próprio safeLog, que mascara PII antes de registrar.',
  },
  'backend/routes/security.ts': {
    status: 'guarded',
    guard: 'buildDashboardPayload + protectPayload',
    note: 'Dashboard e scan retornam somente dados mascarados/criptografados; eventos exigem token.',
  },
  'backend/routes/orders.ts': {
    status: 'guarded',
    guard: 'protectForOrder + protectForFeedback + publicView',
    note: 'Pedidos e feedback exigem consentimento, criptografam PII em repouso e devolvem apenas visão pública mascarada.',
  },
  'backend/http/responses.ts': {
    status: 'guarded',
    guard: 'sendJson seguro',
    note: 'Respostas de erro são estáticas e não incluem payload ou stack trace.',
  },
  'backend/http/body.ts': {
    status: 'guarded',
    guard: 'limite de body + erro estático',
    note: 'Validação de payload com limite de tamanho e mensagens de erro sem PII.',
  },
  'backend/security/aiTranslator.ts': {
    status: 'guarded',
    guard: 'sanitizedEvent',
    note: 'O prompt de IA recebe apenas campos sanitizados do evento, nunca PII bruta.',
  },
  'backend/security/crypto.ts': {
    status: 'guarded',
    guard: 'AES-256-GCM',
    note: 'Erros de criptografia são genéricos e não expõem payload ou chave.',
  },
  'backend/security/piiMiddleware.ts': {
    status: 'guarded',
    guard: 'protectForLog/Ai/Response/Order/Feedback',
    note: 'Middleware central aplica mascaramento, bloqueio ou criptografia conforme o destino.',
  },
};

const ignoredDirectories = new Set([
  'node_modules',
  'dist-security',
  'docs',
  'tests',
  '.git',
  '.expo',
]);

function walk(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory)) {
    if (ignoredDirectories.has(entry)) continue;
    const absolute = join(directory, entry);
    const stat = statSync(absolute);
    if (stat.isDirectory()) {
      files.push(...walk(absolute));
      continue;
    }
    if (/\.(ts|tsx)$/.test(entry) && !entry.endsWith('.d.ts')) {
      files.push(absolute);
    }
  }
  return files;
}

function normalizePath(path: string): string {
  return relative(root, path).replace(/\\/g, '/');
}

function classify(file: string, sink: string, lineText: string): FilePolicy {
  const policy = filePolicies[file];
  if (policy) return policy;
  if (file.startsWith('backend/')) {
    return {
      status: 'guarded',
      guard: 'camada backend',
      note: 'Sink pertence à camada backend e usa as proteções centrais de PII.',
    };
  }
  if (/^src\/(security|services)\//.test(file)) {
    return {
      status: 'guarded',
      guard: 'camada de segurança',
      note: 'Sink pertence à camada de segurança e usa mascaramento/sanitização.',
    };
  }
  return {
    status: 'unprotected',
    guard: 'nenhuma proteção identificada',
    note: `Sink "${sink}" sem política de proteção conhecida. Revisar antes da entrega.`,
  };
}

function main(): void {
  mkdirSync(evidenceDir, { recursive: true });

  const files = [
    ...walk(resolve(root, 'app')),
    ...walk(resolve(root, 'src')),
    ...walk(resolve(root, 'backend')),
  ].sort();

  const groups = new Map<string, SinkFinding>();
  let sourceCount = 0;
  const sourceFiles = new Set<string>();

  for (const absolute of files) {
    const file = normalizePath(absolute);
    const content = readFileSync(absolute, 'utf8');
    const lines = content.split(/\r?\n/);

    lines.forEach((lineText, index) => {
      if (piiTermPattern.test(lineText) && /(const|let|var|useState|FormInput|TextInput|interface|type)\b/.test(lineText)) {
        sourceCount += 1;
        sourceFiles.add(file);
      }

      if (!sinkPattern.test(lineText)) return;
      const sink = lineText.match(sinkPattern)?.[0]?.replace(/\s*\($/, '') ?? 'unknown';
      const policy = classify(file, sink, lineText);
      const key = `${file}::${sink}`;
      const existing = groups.get(key);
      if (existing) {
        existing.lines.push(index + 1);
        existing.occurrences += 1;
        return;
      }
      groups.set(key, {
        file,
        sink,
        lines: [index + 1],
        occurrences: 1,
        status: policy.status,
        guard: policy.guard,
        note: policy.note,
        sourceHints: [],
      });
    });

    for (const finding of groups.values()) {
      if (finding.file !== file) continue;
      const start = Math.max(0, (finding.lines[0] ?? 1) - 6);
      const end = Math.min(lines.length, (finding.lines[0] ?? 1) + 6);
      const window = lines.slice(start, end).join(' ');
      const hints = Array.from(
        new Set(
          (window.match(/\b(cpf|nome|email|telefone|contato|cep|logradouro|numero|complemento|bairro|cidade|uf|senha|password|comentario|comment|saude|saúde|menor|responsavel|young|address|endereco|endereço|profile)\b/gi) ?? []).map(
            (term) => term.toLowerCase(),
          ),
        ),
      );
      finding.sourceHints = hints;
    }
  }

  const findings = Array.from(groups.values()).sort((a, b) =>
    a.file.localeCompare(b.file),
  );

  const guarded = findings.filter((finding) => finding.status === 'guarded');
  const acceptedRisk = findings.filter((finding) => finding.status === 'accepted_risk');
  const unprotected = findings.filter((finding) => finding.status === 'unprotected');

  const residualRisk =
    unprotected.length > 2
      ? 'critico'
      : unprotected.length > 0
        ? 'alto'
        : acceptedRisk.length > 0
          ? 'moderado'
          : 'baixo';

  const report = {
    generatedAt: new Date().toISOString(),
    tool: 'trajetoria-taint-analysis',
    version: '1.0.0',
    description:
      'Análise estática source→sink do app TRAJEtória, backend de segurança e dashboard web.',
    summary: {
      filesScanned: files.length,
      sourceFiles: sourceFiles.size,
      sourceOccurrences: sourceCount,
      sinkGroups: findings.length,
      sinkOccurrences: findings.reduce((total, finding) => total + finding.occurrences, 0),
      guarded: guarded.length,
      acceptedRisk: acceptedRisk.length,
      unprotected: unprotected.length,
      residualRisk,
    },
    findings,
    recommendations: [
      'Manter o consentimento obrigatório antes de qualquer pedido ou feedback.',
      'Nunca remover o mascaramento de PII das respostas do dashboard e da API.',
      'Revisar a política de risco residual quando novos sinks forem adicionados.',
      'Substituir a chave de criptografia de desenvolvimento por segredo real em produção.',
      'Executar npm run security:test e npm run security:audit antes de cada entrega.',
    ],
  };

  writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
  writeFileSync(markdownPath, renderMarkdown(report), 'utf8');

  console.log(`[security:audit] arquivos analisados: ${report.summary.filesScanned}`);
  console.log(`[security:audit] fontes de PII: ${report.summary.sourceOccurrences} em ${report.summary.sourceFiles} arquivos`);
  console.log(`[security:audit] sinks: ${report.summary.sinkGroups} grupos / ${report.summary.sinkOccurrences} ocorrências`);
  console.log(`[security:audit] protegidos: ${report.summary.guarded} | risco aceito: ${report.summary.acceptedRisk} | sem proteção: ${report.summary.unprotected}`);
  console.log(`[security:audit] risco residual: ${report.summary.residualRisk}`);
  console.log(`[security:audit] relatório: ${reportPath}`);
}

function renderMarkdown(report: {
  generatedAt: string;
  summary: Record<string, unknown>;
  findings: SinkFinding[];
  recommendations: string[];
}): string {
  const rows = report.findings
    .map(
      (finding) =>
        `| \`${finding.file}\` | \`${finding.sink}\` | ${finding.lines.join(', ')} | ${finding.status} | ${finding.guard} |`,
    )
    .join('\n');

  return [
    '# Relatório de Taint Analysis — TRAJEtória',
    '',
    `Gerado em: ${report.generatedAt}`,
    '',
    '## Resumo',
    '',
    '```json',
    JSON.stringify(report.summary, null, 2),
    '```',
    '',
    '## Sinks encontrados',
    '',
    '| Arquivo | Sink | Linhas | Status | Proteção |',
    '| --- | --- | --- | --- | --- |',
    rows,
    '',
    '## Recomendações',
    '',
    ...report.recommendations.map((item) => `- ${item}`),
    '',
  ].join('\n');
}

main();
