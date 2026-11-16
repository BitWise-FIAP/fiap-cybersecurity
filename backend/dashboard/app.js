const categoryLabels = {
  identificacao: 'Identificação',
  contato: 'Contato',
  endereco: 'Endereço',
  credencial: 'Credencial',
  saude: 'Saúde',
  menor: 'Menor de idade',
  financeiro: 'Financeiro',
  outro: 'Outro',
};

const severityLabels = {
  low: 'Baixa',
  medium: 'Média',
  high: 'Alta',
  critical: 'Crítica',
};

const actionLabels = {
  allowed: 'Permitido',
  masked: 'Mascarado',
  encrypted: 'Criptografado',
  blocked: 'Bloqueado',
};

const providerLabels = {
  openai: 'OpenAI',
  gemini: 'Gemini',
  fallback: 'Fallback local',
};

const elements = {
  status: document.getElementById('status'),
  refresh: document.getElementById('refresh'),
  riskLabel: document.getElementById('risk-label'),
  riskLight: document.getElementById('risk-light'),
  riskScore: document.getElementById('risk-score'),
  riskScoreLabel: document.getElementById('risk-score-label'),
  riskAttempted: document.getElementById('risk-attempted'),
  riskCounts: document.getElementById('risk-counts'),
  aiProvider: document.getElementById('ai-provider'),
  aiMessage: document.getElementById('ai-message'),
  aiMeta: document.getElementById('ai-meta'),
  metricTotal: document.getElementById('metric-total'),
  metricBlocked: document.getElementById('metric-blocked'),
  metricMasked: document.getElementById('metric-masked'),
  metricEncrypted: document.getElementById('metric-encrypted'),
  metricAllowed: document.getElementById('metric-allowed'),
  categories: document.getElementById('categories'),
  eventsBody: document.getElementById('events-body'),
  generatedAt: document.getElementById('generated-at'),
  demoLeak: document.getElementById('demo-leak'),
  demoSafe: document.getElementById('demo-safe'),
  demoMixed: document.getElementById('demo-mixed'),
  demoCritical: document.getElementById('demo-critical'),
};

let busy = false;

function setStatus(message, kind) {
  elements.status.textContent = message;
  elements.status.className = 'status';
  if (kind) elements.status.classList.add(kind);
}

function setBusy(value) {
  busy = value;
  for (const button of [
    elements.refresh,
    elements.demoLeak,
    elements.demoSafe,
    elements.demoMixed,
    elements.demoCritical,
  ]) {
    button.disabled = value;
  }
}

async function fetchJson(url, options) {
  const response = await fetch(url, {
    cache: 'no-store',
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Falha HTTP ${response.status}`);
  }
  return data;
}

async function refresh() {
  if (busy) return;
  try {
    setBusy(true);
    setStatus('Consultando o módulo de segurança...');
    const data = await fetchJson('/api/security/dashboard');
    render(data);
    setStatus('Painel atualizado. Nenhuma PII bruta foi retornada.', 'success');
  } catch (error) {
    setStatus(`Não foi possível carregar o painel: ${error.message}`, 'error');
  } finally {
    setBusy(false);
  }
}

async function runDemo(scenario) {
  if (busy) return;
  try {
    setBusy(true);
    setStatus('Executando simulação segura com dados fictícios...');
    const data = await fetchJson('/api/security/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scenario, reset: true }),
    });
    render(data);
    const label =
      scenario === 'leak'
        ? 'tentativa de vazamento'
        : scenario === 'safe'
          ? 'fluxo seguro'
          : scenario === 'critical'
            ? 'exposição crítica'
            : 'cenário completo';
    setStatus(
      `Simulação concluída: ${label}. ${data.created} evento(s) tratado(s) sem expor PII bruta. Painel substituído.`,
      'success',
    );
  } catch (error) {
    setStatus(`Falha na simulação: ${error.message}`, 'error');
  } finally {
    setBusy(false);
  }
}

function render(data) {
  const risk = data.risk || {};
  const level = risk.level || 'baixo';
  elements.riskLabel.textContent = risk.label || 'Risco baixo';
  elements.riskLight.className = `traffic risk-${level}`;
  elements.riskScore.className = `score risk-${level}`;
  elements.riskScore.textContent = String(risk.score ?? 0);
  elements.riskScoreLabel.textContent = `${risk.score ?? 0}/100`;
  elements.riskAttempted.textContent = `${risk.attemptedScore ?? 0}/100`;
  elements.riskCounts.textContent = `${risk.total ?? 0} eventos · ${risk.blocked ?? 0} bloqueados · ${risk.masked ?? 0} mascarados · ${risk.encrypted ?? 0} criptografados`;

  const translation = data.translation || {};
  elements.aiProvider.textContent =
    providerLabels[translation.provider] || 'Fallback local';
  elements.aiMessage.textContent =
    translation.message || 'Nenhum evento analisado ainda.';
  elements.aiMeta.textContent = `Modelo: ${translation.model || 'local'}${translation.cached ? ' · resposta em cache' : ''}`;

  elements.metricTotal.textContent = String(data.metrics?.total ?? 0);
  elements.metricBlocked.textContent = String(data.metrics?.blocked ?? 0);
  elements.metricMasked.textContent = String(data.metrics?.masked ?? 0);
  elements.metricEncrypted.textContent = String(data.metrics?.encrypted ?? 0);
  elements.metricAllowed.textContent = String(data.metrics?.allowed ?? 0);

  renderCategories(risk.byCategory || {});
  renderEvents(Array.isArray(data.events) ? data.events : []);

  elements.generatedAt.textContent = data.generatedAt
    ? `Gerado em ${formatDate(data.generatedAt)}`
    : '—';
}

function renderCategories(byCategory) {
  elements.categories.replaceChildren();
  const entries = Object.entries(byCategory)
    .filter(([, count]) => Number(count) > 0)
    .sort((left, right) => Number(right[1]) - Number(left[1]));

  if (!entries.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'Nenhuma categoria de PII registrada ainda.';
    elements.categories.append(empty);
    return;
  }

  const max = Math.max(...entries.map(([, count]) => Number(count)));
  for (const [category, count] of entries) {
    const row = document.createElement('div');
    row.className = 'category-row';

    const label = document.createElement('span');
    label.textContent = categoryLabels[category] || category;

    const track = document.createElement('div');
    track.className = 'category-track';
    const fill = document.createElement('div');
    fill.className = 'category-fill';
    fill.style.width = `${Math.max(8, (Number(count) / max) * 100)}%`;
    track.append(fill);

    const value = document.createElement('strong');
    value.textContent = String(count);

    row.append(label, track, value);
    elements.categories.append(row);
  }
}

function renderEvents(events) {
  elements.eventsBody.replaceChildren();
  if (!events.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 8;
    cell.className = 'empty';
    cell.textContent = 'Nenhum evento registrado.';
    row.append(cell);
    elements.eventsBody.append(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement('tr');
    row.append(
      cell(formatDate(event.timestamp)),
      cell(event.source || '—'),
      cell(categoryLabels[event.category] || event.category || '—'),
      pillCell(severityLabels[event.severity] || event.severity, event.severity),
      pillCell(actionLabels[event.action] || event.action, event.action),
      cell(event.sink || '—'),
      monoCell(event.maskedValue || '—'),
      pillCell(event.riskLevel || '—', event.riskLevel),
    );
    elements.eventsBody.append(row);
  }
}

function cell(text) {
  const element = document.createElement('td');
  element.textContent = text;
  return element;
}

function monoCell(text) {
  const element = document.createElement('td');
  const span = document.createElement('span');
  span.className = 'mono';
  span.textContent = text;
  element.append(span);
  return element;
}

function pillCell(text, kind) {
  const element = document.createElement('td');
  const pill = document.createElement('span');
  pill.className = `pill ${kind || ''}`.trim();
  pill.textContent = text || '—';
  element.append(pill);
  return element;
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('pt-BR');
}

elements.refresh.addEventListener('click', refresh);
elements.demoLeak.addEventListener('click', () => runDemo('leak'));
elements.demoSafe.addEventListener('click', () => runDemo('safe'));
elements.demoMixed.addEventListener('click', () => runDemo('mixed'));
elements.demoCritical.addEventListener('click', () => runDemo('critical'));

refresh();
setInterval(() => {
  if (document.visibilityState === 'visible' && !busy) refresh();
}, 30000);
