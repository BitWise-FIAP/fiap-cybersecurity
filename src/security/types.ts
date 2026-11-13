export type PiiCategory =
  | 'identificacao'
  | 'contato'
  | 'endereco'
  | 'credencial'
  | 'saude'
  | 'menor'
  | 'financeiro'
  | 'outro';

export type PiiSeverity = 'low' | 'medium' | 'high' | 'critical';
export type PiiAction = 'allowed' | 'masked' | 'encrypted' | 'blocked';
export type TaintSource = 'form' | 'database' | 'api' | 'file' | 'llm' | 'demo';
export type TaintSink =
  | 'console'
  | 'log'
  | 'http_response'
  | 'error_screen'
  | 'llm_prompt'
  | 'export'
  | 'database';
export type RiskLevel = 'baixo' | 'moderado' | 'alto' | 'critico';

export interface PiiFinding {
  ruleId: string;
  ruleName: string;
  category: PiiCategory;
  severity: PiiSeverity;
  action: PiiAction;
  field?: string;
  path?: string;
  start?: number;
  end?: number;
  maskedMatch: string;
  message: string;
  metadata?: Record<string, unknown>;
}

export interface PiiScanResult {
  containsPii: boolean;
  findings: PiiFinding[];
  categories: PiiCategory[];
  highestSeverity: PiiSeverity | null;
  fields: string[];
  redacted: unknown;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  source: TaintSource;
  sink: TaintSink;
  action: PiiAction;
  category: PiiCategory;
  severity: PiiSeverity;
  ruleIds: string[];
  message: string;
  maskedValue?: string;
  metadata?: Record<string, unknown>;
  translated?: string;
  translationProvider?: string;
  riskLevel?: RiskLevel;
  riskScore?: number;
}

export interface RiskSummary {
  score: number;
  attemptedScore: number;
  level: RiskLevel;
  label: string;
  total: number;
  blocked: number;
  masked: number;
  encrypted: number;
  allowed: number;
  bySeverity: Record<PiiSeverity, number>;
  byCategory: Record<PiiCategory, number>;
  generatedAt: string;
}

export interface TranslationResult {
  message: string;
  provider: 'openai' | 'gemini' | 'fallback';
  model: string;
  cached: boolean;
}

export interface ProtectedPayload {
  sanitized: unknown;
  findings: PiiFinding[];
  events: SecurityEvent[];
  blocked: boolean;
  action: PiiAction;
}
