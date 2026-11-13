import type { SecurityEvent, TranslationResult } from '../../src/security';

export interface TranslatorOptions {
  openaiKey?: string;
  geminiKey?: string;
  openaiModel?: string;
  geminiModel?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

const cache = new Map<string, TranslationResult>();

function cacheKey(event: SecurityEvent): string {
  return [
    event.category,
    event.severity,
    event.action,
    event.sink,
    event.source,
    event.ruleIds.join(','),
  ].join('|');
}

function sanitizedEvent(event: SecurityEvent): Record<string, unknown> {
  return {
    category: event.category,
    severity: event.severity,
    action: event.action,
    sink: event.sink,
    source: event.source,
    ruleIds: event.ruleIds,
    message: event.message,
  };
}

function buildPrompt(event: SecurityEvent): string {
  return [
    'Você é o tradutor de segurança do TRAJEtória, um projeto social de doação de roupas.',
    'Explique para uma pessoa não técnica, em português do Brasil, em no máximo 2 frases, o que o evento abaixo significa e qual é o risco.',
    'Não invente dados. Não cite dados pessoais. Não use jargão sem explicar.',
    `Evento sanitizado: ${JSON.stringify(sanitizedEvent(event))}`,
    'Responda apenas com a explicação.',
  ].join('\n');
}

export async function translateSecurityEvent(
  event: SecurityEvent,
  options: TranslatorOptions = {},
): Promise<TranslationResult> {
  const key = cacheKey(event);
  const cached = cache.get(key);
  if (cached) return { ...cached, cached: true };

  const timeoutMs = options.timeoutMs ?? 8000;
  const fetchImpl = options.fetchImpl ?? fetch;

  if (options.openaiKey) {
    try {
      const result = await callOpenAI(event, {
        ...options,
        fetchImpl,
        timeoutMs,
      });
      cache.set(key, result);
      return result;
    } catch {
      // fallback para Gemini ou tradutor local
    }
  }

  if (options.geminiKey) {
    try {
      const result = await callGemini(event, {
        ...options,
        fetchImpl,
        timeoutMs,
      });
      cache.set(key, result);
      return result;
    } catch {
      // fallback para o tradutor local
    }
  }

  const fallback: TranslationResult = {
    message: fallbackMessage(event),
    provider: 'fallback',
    model: 'local',
    cached: false,
  };
  cache.set(key, fallback);
  return fallback;
}

async function callOpenAI(
  event: SecurityEvent,
  options: TranslatorOptions & { fetchImpl: typeof fetch; timeoutMs: number },
): Promise<TranslationResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    const response = await options.fetchImpl('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${options.openaiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: options.openaiModel ?? 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content:
              'Você traduz eventos de segurança para linguagem simples, sem expor dados pessoais.',
          },
          { role: 'user', content: buildPrompt(event) },
        ],
        temperature: 0.2,
        max_tokens: 120,
      }),
      signal: controller.signal,
    });

    if (!response.ok) throw new Error(`OpenAI HTTP ${response.status}`);
    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const message = data.choices?.[0]?.message?.content?.trim();
    if (!message) throw new Error('OpenAI sem conteúdo.');
    return {
      message,
      provider: 'openai',
      model: options.openaiModel ?? 'gpt-4o-mini',
      cached: false,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function callGemini(
  event: SecurityEvent,
  options: TranslatorOptions & { fetchImpl: typeof fetch; timeoutMs: number },
): Promise<TranslationResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  const model = options.geminiModel ?? 'gemini-1.5-flash';
  try {
    const response = await options.fetchImpl(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${options.geminiKey}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: buildPrompt(event) }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 120 },
        }),
        signal: controller.signal,
      },
    );

    if (!response.ok) throw new Error(`Gemini HTTP ${response.status}`);
    const data = (await response.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    const message = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    if (!message) throw new Error('Gemini sem conteúdo.');
    return { message, provider: 'gemini', model, cached: false };
  } finally {
    clearTimeout(timeout);
  }
}

export function fallbackMessage(event: SecurityEvent): string {
  if (event.action === 'allowed') {
    return 'Nenhum dado sensível foi exposto. O fluxo autenticado permaneceu protegido e o risco é baixo.';
  }

  if (event.category === 'credencial') {
    return event.action === 'blocked'
      ? 'Uma tentativa de expor uma senha foi bloqueada antes de chegar aos logs. Nenhuma credencial saiu do sistema.'
      : 'Uma credencial foi identificada e tratada automaticamente. O acesso permanece protegido.';
  }
  if (event.category === 'saude') {
    return 'Um dado de saúde foi identificado e removido automaticamente. O conteúdo não foi gravado nem enviado para a IA.';
  }
  if (event.category === 'menor') {
    return 'Uma informação de menor de idade foi bloqueada. O sistema exige consentimento do responsável e não expõe esse dado.';
  }
  if (event.category === 'identificacao') {
    return 'Um documento de identificação foi mascarado antes de aparecer no painel. O valor completo permanece protegido.';
  }
  if (event.category === 'contato') {
    return 'Um dado de contato foi mascarado. A equipe vê apenas a versão protegida, sem acesso ao valor completo.';
  }
  if (event.category === 'endereco') {
    return 'O endereço foi criptografado antes de ser armazenado. Apenas a versão mascarada é exibida no painel.';
  }
  return 'Um dado pessoal foi identificado e tratado automaticamente pelo módulo de segurança. O risco residual é baixo.';
}

export function clearTranslationCache(): void {
  cache.clear();
}
