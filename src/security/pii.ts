import type {
  PiiAction,
  PiiCategory,
  PiiFinding,
  PiiScanResult,
  PiiSeverity,
} from './types';

type MaskKind =
  | 'pattern'
  | 'full'
  | 'credential'
  | 'health'
  | 'minor'
  | 'address'
  | 'name'
  | 'contact'
  | 'document';

interface PiiFieldDefinition {
  key: string;
  label: string;
  category: PiiCategory;
  severity: PiiSeverity;
  action: PiiAction;
  mask: MaskKind;
}

interface PiiRule {
  id: string;
  name: string;
  category: PiiCategory;
  severity: PiiSeverity;
  action: PiiAction;
  pattern: RegExp;
  mask: string;
  message: string;
  wholeString?: boolean;
  validate?: (value: string) => boolean;
}

const severityRank: Record<PiiSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const field = (
  key: string,
  label: string,
  category: PiiCategory,
  severity: PiiSeverity,
  action: PiiAction,
  mask: MaskKind,
): PiiFieldDefinition => ({ key, label, category, severity, action, mask });

export const PII_FIELD_CATALOG: Record<string, PiiFieldDefinition> = {
  nome: field('nome', 'Nome', 'identificacao', 'medium', 'masked', 'name'),
  nome_mae: field('nome_mae', 'Nome da mãe', 'identificacao', 'high', 'masked', 'name'),
  identificacao: field('identificacao', 'Identificação de acesso', 'identificacao', 'high', 'masked', 'full'),
  data_nascimento: field('data_nascimento', 'Data de nascimento', 'identificacao', 'high', 'masked', 'full'),
  cpf: field('cpf', 'CPF', 'identificacao', 'high', 'masked', 'document'),
  rg: field('rg', 'RG', 'identificacao', 'medium', 'masked', 'document'),
  email: field('email', 'E-mail', 'contato', 'medium', 'masked', 'contact'),
  telefone: field('telefone', 'Telefone', 'contato', 'medium', 'masked', 'contact'),
  contato: field('contato', 'Contato', 'contato', 'medium', 'masked', 'contact'),
  contato_entrega: field('contato_entrega', 'Contato de entrega', 'contato', 'medium', 'masked', 'contact'),
  cep: field('cep', 'CEP', 'endereco', 'low', 'masked', 'address'),
  endereco: field('endereco', 'Endereço', 'endereco', 'medium', 'masked', 'address'),
  logradouro: field('logradouro', 'Logradouro', 'endereco', 'medium', 'masked', 'address'),
  numero: field('numero', 'Número', 'endereco', 'low', 'masked', 'address'),
  complemento: field('complemento', 'Complemento', 'endereco', 'low', 'masked', 'address'),
  bairro: field('bairro', 'Bairro', 'endereco', 'low', 'masked', 'address'),
  cidade: field('cidade', 'Cidade', 'endereco', 'low', 'masked', 'address'),
  uf: field('uf', 'UF', 'endereco', 'low', 'masked', 'address'),
  senha: field('senha', 'Senha', 'credencial', 'critical', 'blocked', 'credential'),
  senha_hash: field('senha_hash', 'Hash de senha', 'credencial', 'critical', 'encrypted', 'credential'),
  password: field('password', 'Senha', 'credencial', 'critical', 'blocked', 'credential'),
  comentario: field('comentario', 'Comentário livre', 'outro', 'low', 'masked', 'pattern'),
  observacao: field('observacao', 'Observação', 'outro', 'low', 'masked', 'pattern'),
  descricao: field('descricao', 'Descrição', 'outro', 'low', 'masked', 'pattern'),
  mensagem: field('mensagem', 'Mensagem', 'outro', 'low', 'masked', 'pattern'),
  laudo: field('laudo', 'Laudo', 'saude', 'high', 'blocked', 'health'),
  diagnostico: field('diagnostico', 'Diagnóstico', 'saude', 'high', 'blocked', 'health'),
  medicamento: field('medicamento', 'Medicamento', 'saude', 'high', 'blocked', 'health'),
  saude: field('saude', 'Dado de saúde', 'saude', 'high', 'blocked', 'health'),
  menor_de_idade: field('menor_de_idade', 'Indicador de menor de idade', 'menor', 'high', 'blocked', 'minor'),
  responsavel: field('responsavel', 'Responsável legal', 'menor', 'high', 'masked', 'full'),
  guardiao: field('guardiao', 'Guardião legal', 'menor', 'high', 'masked', 'full'),
  genero: field('genero', 'Gênero', 'outro', 'low', 'masked', 'full'),
  tamanho_referencia: field('tamanho_referencia', 'Tamanho de referência', 'outro', 'low', 'masked', 'full'),
  tamanhos_json: field('tamanhos_json', 'Tamanhos', 'outro', 'low', 'masked', 'full'),
};

export const PII_RULES: PiiRule[] = [
  {
    id: 'PII-HEALTH',
    name: 'Dado de saúde',
    category: 'saude',
    severity: 'high',
    action: 'blocked',
    pattern:
      /\b(?:laudo|diagn[oó]stico|doen[cç]a|medicamento|receita|CID|sa[uú]de|alergia|defici[eê]ncia|transtorno|terapia|press[aã]o|diabetes|HIV|ansiedade|depress[aã]o)\b/gi,
    mask: '[DADO DE SAÚDE REMOVIDO]',
    message: 'Possível dado de saúde detectado no texto.',
    wholeString: true,
  },
  {
    id: 'PII-MINOR',
    name: 'Dado de menor de idade',
    category: 'menor',
    severity: 'high',
    action: 'blocked',
    pattern:
      /\b(?:menor de idade|respons[aá]vel|guardi[aã]o|autoriza[cç][aã]o do respons[aá]vel)\b/gi,
    mask: '[DADO DE MENOR REMOVIDO]',
    message: 'Referência a menor de idade ou responsável legal detectada.',
    wholeString: true,
  },
  {
    id: 'PII-PASSWORD',
    name: 'Credencial em texto claro',
    category: 'credencial',
    severity: 'critical',
    action: 'blocked',
    pattern: /(?:senha|password|passwd|pwd)\s*[:=]\s*[^\s,;]+/gi,
    mask: '********',
    message: 'Credencial em texto claro detectada.',
  },
  {
    id: 'PII-CPF',
    name: 'CPF',
    category: 'identificacao',
    severity: 'high',
    action: 'masked',
    pattern: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g,
    mask: '***.***.***-**',
    message: 'CPF detectado.',
    validate: isValidCpf,
  },
  {
    id: 'PII-RG',
    name: 'RG',
    category: 'identificacao',
    severity: 'medium',
    action: 'masked',
    pattern: /\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b/g,
    mask: '**.***.***-*',
    message: 'Possível RG detectado.',
  },
  {
    id: 'PII-EMAIL',
    name: 'E-mail',
    category: 'contato',
    severity: 'medium',
    action: 'masked',
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    mask: '***@***.***',
    message: 'E-mail detectado.',
  },
  {
    id: 'PII-CEP',
    name: 'CEP',
    category: 'endereco',
    severity: 'low',
    action: 'masked',
    pattern: /\b\d{5}-?\d{3}\b/g,
    mask: '*****-***',
    message: 'CEP detectado.',
  },
  {
    id: 'PII-PHONE',
    name: 'Telefone',
    category: 'contato',
    severity: 'medium',
    action: 'masked',
    pattern: /\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?9?\d{4}[-\s]?\d{4}\b/g,
    mask: '(**) *****-****',
    message: 'Telefone detectado.',
  },
  {
    id: 'PII-ADDRESS',
    name: 'Endereço',
    category: 'endereco',
    severity: 'medium',
    action: 'masked',
    pattern: /\b(?:endere[cç]o|rua|avenida|av\.|logradouro|bairro|complemento)\b\s*:?\s*[^\n,;]{3,}/gi,
    mask: '[ENDEREÇO REMOVIDO]',
    message: 'Possível endereço detectado.',
  },
  {
    id: 'PII-NAME',
    name: 'Nome',
    category: 'identificacao',
    severity: 'medium',
    action: 'masked',
    pattern: /\b(?:nome|nome completo)\b\s*:?\s*[A-ZÀ-Ý][A-Za-zÀ-ÿ]+(?:\s+[A-ZÀ-Ý][A-Za-zÀ-ÿ]+)+/gi,
    mask: '[NOME REMOVIDO]',
    message: 'Possível nome completo detectado.',
  },
];

export function isValidCpf(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 11 || /^(\d)\1{10}$/.test(digits)) return false;
  const first = calculateCpfDigit(digits, 9);
  const second = calculateCpfDigit(digits, 10);
  return digits[9] === String(first) && digits[10] === String(second);
}

function calculateCpfDigit(digits: string, length: number): number {
  let sum = 0;
  for (let index = 0; index < length; index += 1) {
    sum += Number(digits[index]) * (length + 1 - index);
  }
  const remainder = sum % 11;
  return remainder < 2 ? 0 : 11 - remainder;
}

function getFieldDefinition(key: string): PiiFieldDefinition | undefined {
  const direct = PII_FIELD_CATALOG[key];
  if (direct) return direct;
  if (key.startsWith('endereco_')) {
    return {
      ...PII_FIELD_CATALOG.endereco,
      key,
      label: `Endereço (${key.replace('endereco_', '')})`,
    };
  }
  return undefined;
}

function maskForKind(kind: MaskKind, value: unknown): string {
  if (kind === 'credential') return '********';
  if (kind === 'health') return '[DADO DE SAÚDE REMOVIDO]';
  if (kind === 'minor') return '***';
  if (kind === 'address') return '[ENDEREÇO REMOVIDO]';
  if (kind === 'name') return '[NOME REMOVIDO]';
  if (kind === 'contact') return '[CONTATO REMOVIDO]';
  if (kind === 'document') return '[DOCUMENTO REMOVIDO]';
  if (kind === 'full') return '***';
  if (typeof value === 'string') return maskPiiInString(value);
  return '***';
}

function ruleMatches(rule: PiiRule, text: string): RegExpMatchArray[] {
  const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`;
  const regex = new RegExp(rule.pattern.source, flags);
  return Array.from(text.matchAll(regex));
}

function isCovered(start: number, end: number, covered: Array<[number, number]>): boolean {
  return covered.some(([coveredStart, coveredEnd]) => start < coveredEnd && end > coveredStart);
}

function findingFromMatch(
  rule: PiiRule,
  match: RegExpMatchArray,
  fieldPath?: string,
): PiiFinding {
  const start = match.index ?? 0;
  const end = start + match[0].length;
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    category: rule.category,
    severity: rule.severity,
    action: rule.action,
    field: fieldPath,
    path: fieldPath,
    start,
    end,
    maskedMatch: rule.mask,
    message: rule.message,
    metadata: rule.validate ? { validated: true } : undefined,
  };
}

export function scanString(text: string, fieldPath?: string): PiiFinding[] {
  if (!text) return [];
  const findings: PiiFinding[] = [];

  for (const rule of PII_RULES) {
    if (!rule.wholeString) continue;
    const matches = ruleMatches(rule, text);
    if (matches.length > 0) {
      findings.push(findingFromMatch(rule, matches[0], fieldPath));
      return findings;
    }
  }

  const covered: Array<[number, number]> = [];
  for (const rule of PII_RULES) {
    if (rule.wholeString) continue;
    const matches = ruleMatches(rule, text);
    for (const match of matches) {
      if (rule.validate && !rule.validate(match[0])) continue;
      const start = match.index ?? 0;
      const end = start + match[0].length;
      if (isCovered(start, end, covered)) continue;
      covered.push([start, end]);
      findings.push(findingFromMatch(rule, match, fieldPath));
    }
  }

  return findings.sort((a, b) => (a.start ?? 0) - (b.start ?? 0));
}

export function maskPiiInString(text: string): string {
  if (!text) return text;
  for (const rule of PII_RULES) {
    if (!rule.wholeString) continue;
    if (ruleMatches(rule, text).length > 0) return rule.mask;
  }

  let result = text;
  for (const rule of PII_RULES) {
    if (rule.wholeString) continue;
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`;
    const regex = new RegExp(rule.pattern.source, flags);
    result = result.replace(regex, (match) => {
      if (rule.validate && !rule.validate(match)) return match;
      return rule.mask;
    });
  }
  return result;
}

export function maskPiiDeep(value: unknown, fieldPath?: string): unknown {
  if (typeof value === 'string') return maskPiiInString(value);
  if (Array.isArray(value)) {
    return value.map((item, index) => maskPiiDeep(item, fieldPath ? `${fieldPath}[${index}]` : `[${index}]`));
  }
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      const definition = getFieldDefinition(key);
      const path = fieldPath ? `${fieldPath}.${key}` : key;
      if (definition) {
        output[key] = maskForKind(definition.mask, item);
      } else {
        output[key] = maskPiiDeep(item, path);
      }
    }
    return output;
  }
  return value;
}

export function scanPii(value: unknown, fieldPath?: string): PiiScanResult {
  const findings: PiiFinding[] = [];

  const visit = (current: unknown, path?: string): void => {
    if (typeof current === 'string') {
      findings.push(...scanString(current, path));
      return;
    }
    if (Array.isArray(current)) {
      current.forEach((item, index) => visit(item, path ? `${path}[${index}]` : `[${index}]`));
      return;
    }
    if (current && typeof current === 'object') {
      for (const [key, item] of Object.entries(current as Record<string, unknown>)) {
        const childPath = path ? `${path}.${key}` : key;
        const definition = getFieldDefinition(key);
        if (definition) {
          const masked =
            definition.mask === 'pattern'
              ? '[TEXTO LIVRE]'
              : maskForKind(definition.mask, item);
          findings.push({
            ruleId: `FIELD-${definition.key}`,
            ruleName: definition.label,
            category: definition.category,
            severity: definition.severity,
            action: definition.action,
            field: childPath,
            path: childPath,
            maskedMatch: masked,
            message: `${definition.label} mapeado como PII (${definition.category}).`,
            metadata: { fieldMapping: true },
          });
        }
        visit(item, childPath);
      }
    }
  };

  visit(value, fieldPath);

  const deduped = dedupeFindings(findings);
  const categories = Array.from(new Set(deduped.map((finding) => finding.category)));
  const highestSeverity = deduped.reduce<PiiSeverity | null>((highest, finding) => {
    if (!highest) return finding.severity;
    return severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest;
  }, null);

  return {
    containsPii: deduped.length > 0,
    findings: deduped,
    categories,
    highestSeverity,
    fields: Array.from(new Set(deduped.map((finding) => finding.field ?? finding.path ?? 'unknown'))),
    redacted: maskPiiDeep(value, fieldPath),
  };
}

function dedupeFindings(findings: PiiFinding[]): PiiFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.ruleId}|${finding.path ?? ''}|${finding.start ?? ''}|${finding.end ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function sanitizeFreeText(value: string, maxLength = 300): string {
  const withoutControl = value.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
  return maskPiiInString(withoutControl).slice(0, maxLength);
}

export function getHighestSeverity(findings: PiiFinding[]): PiiSeverity | null {
  return findings.reduce<PiiSeverity | null>((highest, finding) => {
    if (!highest) return finding.severity;
    return severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest;
  }, null);
}

export function containsSensitiveCategory(findings: PiiFinding[]): boolean {
  return findings.some((finding) =>
    ['credencial', 'saude', 'menor'].includes(finding.category),
  );
}

export function safeErrorMessage(error: unknown, fallback = 'Não foi possível concluir a operação. Tente novamente.'): string {
  const message = error instanceof Error ? error.message : String(error ?? '');
  if (/consentimento|termo/i.test(message)) {
    return 'É necessário aceitar o termo de consentimento antes de continuar.';
  }
  if (/preencha|obrigat/i.test(message)) {
    return 'Preencha todos os campos obrigatórios antes de continuar.';
  }
  if (/indispon[ií]vel|reservada/i.test(message)) {
    return 'Uma das peças não está mais disponível. Volte ao pedido e revise a seleção.';
  }
  if (/selecione|pe[cç]a|peca/i.test(message)) {
    return 'Revise as peças selecionadas antes de enviar.';
  }
  if (/entregue|feedback/i.test(message)) {
    return 'O feedback só está disponível para pedidos entregues.';
  }
  if (/avaliou|j[aá] enviou|j[aá] avaliado/i.test(message)) {
    return 'Este pedido já foi avaliado. Obrigado!';
  }
  if (/rede|network|fetch|timeout|conex[aã]o/i.test(message)) {
    return 'Não foi possível conectar ao serviço de segurança. Tente novamente.';
  }
  return fallback;
}

export function minimizePii(value: unknown, purpose: 'log' | 'dashboard' | 'ai' | 'response'): unknown {
  if (purpose === 'response') return maskPiiDeep(value);
  return maskPiiDeep(value);
}
