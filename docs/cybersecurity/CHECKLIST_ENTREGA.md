# Checklist de entrega — Cybersecurity TRAJEtória

FIAP Global Solution 2026.2 · entrega até 19/11/2026 23h55.

## Identificação

- [ ] Preencher nome completo e RM de cada integrante no relatório.
- [ ] Confirmar o link do vídeo (YouTube não listado ou arquivo).
- [ ] Confirmar o nome final do ZIP.

## Código

- [x] Catálogo de PII em `src/security/pii.ts`.
- [x] Taint analysis em `src/security/taint.ts`.
- [x] Cálculo de risco e farol em `src/security/risk.ts`.
- [x] Backend Node/TypeScript em `backend/`.
- [x] Middleware de PII em `backend/security/piiMiddleware.ts`.
- [x] Criptografia AES-256-GCM em `backend/security/crypto.ts`.
- [x] Tradutor OpenAI/Gemini/fallback em `backend/security/aiTranslator.ts`.
- [x] Dashboard web em `backend/dashboard/`.
- [x] Integração mínima no app: `entrega.tsx`, `feedback.tsx`, repositórios e `securityService.ts`.
- [x] Consentimento obrigatório em `confirmOrder` e `saveFeedback`.
- [x] Erros seguros em telas de catálogo, detalhe, entrega e feedback.

## Testes e validação

- [x] `npm run security:build` sem erros.
- [x] `npm run security:test` com 33 testes aprovados.
- [x] `npm run security:audit` com 0 sinks sem proteção.
- [x] `npm run security:demo` com pedido criptografado e feedback sanitizado.
- [x] `npm run security:evidence` gerando JSONs e HTML.
- [x] `npm run security:report` gerando Markdown e HTML.
- [x] `npm run security:pdf` gerando `RELATORIO_CYBERSECURITY.pdf` e `EVIDENCIAS.pdf`.
- [x] `npm run security:dashboard-shot` gerando `dashboard.png`.

## Documentos

- [x] `docs/cybersecurity/RELATORIO_CYBERSECURITY.pdf`.
- [x] `docs/cybersecurity/EVIDENCIAS.pdf`.
- [x] `docs/cybersecurity/RELATORIO_CYBERSECURITY.md`.
- [x] `docs/cybersecurity/EVIDENCIAS.md`.
- [x] `docs/cybersecurity/ROTEIRO_VIDEO.md`.
- [x] `docs/cybersecurity/CHECKLIST_ENTREGA.md`.
- [x] `docs/cybersecurity/evidencias/` com JSONs, HTML e PNG.

## Pacote

- [x] `TRAJEtoria-Cybersecurity.zip` gerado.
- [x] ZIP inclui app, src, backend, scripts, tests, docs/cybersecurity e configs.
- [x] ZIP exclui `node_modules`, `dist-security`, `.git`, `.expo`, `backend/data` e `.env`.
- [x] ZIP inclui `.env.example` sem segredos.

## Privacidade e segurança

- [x] Nenhuma PII real usada em demonstrações.
- [x] Nenhuma PII bruta nos JSONs, HTMLs, PDFs ou dashboard.
- [x] Nenhuma chave real no código ou no ZIP.
- [x] Aviso de risco residual no relatório.
- [x] Recomendações de produção documentadas.

## Antes de enviar

- [ ] Abrir o PDF e conferir capa, sumário, tabelas e quebras de página.
- [ ] Abrir `dashboard.png` e confirmar que o farol e os eventos aparecem.
- [ ] Assistir ao vídeo e conferir áudio e dados fictícios.
- [ ] Conferir se o ZIP abre e contém a pasta `docs/cybersecurity`.
- [ ] Enviar PDF, ZIP e link do vídeo no prazo.
