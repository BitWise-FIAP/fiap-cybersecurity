# Evidências — Cybersecurity TRAJEtória

FIAP Global Solution 2026.2 · Cybersecurity · CitizenTech TRAJEtória.

Todos os dados usados nas evidências são fictícios. Nenhuma PII bruta é gravada nos arquivos abaixo.

## 1. Documentos principais

| Arquivo | Conteúdo |
| --- | --- |
| `RELATORIO_CYBERSECURITY.pdf` | Relatório final em PDF, pronto para entrega. |
| `RELATORIO_CYBERSECURITY.html` | Versão web do relatório, usada para gerar o PDF. |
| `RELATORIO_CYBERSECURITY.md` | Fonte em Markdown do relatório. |
| `EVIDENCIAS.pdf` | Página de evidências em PDF. |
| `evidencias/evidence.html` | Página de evidências com tabelas e farol de risco. |

## 2. Evidências técnicas

| Arquivo | O que comprova |
| --- | --- |
| `evidencias/pii-scan.json` | Catálogo de PII, severidade, categoria e valores mascarados da fixture. |
| `evidencias/taint-traces.json` | Oito sinks testados com ações blocked/masked/encrypted e eventos gerados. |
| `evidencias/risk-matrix.json` | Cenários de risco e faixas do farol verde/amarelo/laranja/vermelho. |
| `evidencias/taint-report.json` | Análise estática source→sink do app, backend e dashboard. |
| `evidencias/taint-report.md` | Versão legível do relatório de taint analysis. |
| `evidencias/demo-result.json` | Simulação end-to-end: dashboard, scan, pedido e feedback. |
| `evidencias/dashboard.png` | Captura real do dashboard web com eventos de demonstração. |

## 3. Testes automatizados

Comando:

```powershell
npm run security:test
```

Resultado esperado: **33 testes aprovados**, cobrindo:

- `pii.test.ts`: catálogo, CPF, mascaramento, saúde, erros seguros.
- `taint.test.ts`: console, log, resposta HTTP, banco e fluxo sem PII.
- `risk.test.ts`: score, farol e cenários.
- `crypto.test.ts`: AES-256-GCM, hash, máscara e comparação constante.
- `aiTranslator.test.ts`: OpenAI, Gemini, fallback e cache.
- `server.test.ts`: health, demo, dashboard, token, scan, pedido e feedback.

## 4. Como reproduzir

```powershell
npm install
npm run security:test
npm run security:audit
npm run security:demo
npm run security:evidence
npm run security:report
npm run security:pdf
npm run security:dashboard-shot
npm run security:zip
```

## 5. Privacidade das evidências

- A fixture original não é persistida: apenas a versão mascarada aparece nos JSONs.
- O dashboard retorna `privacy.rawPiiExposed: false`.
- O backend usa AES-256-GCM para PII em repouso no fluxo de pedidos.
- O token de demonstração é comparado em tempo constante.
- Nenhum segredo real é incluído no ZIP; `.env` é excluído e `.env.example` é mantido.
