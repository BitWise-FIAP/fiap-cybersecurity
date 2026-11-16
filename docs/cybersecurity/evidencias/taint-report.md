# Relatório de Taint Analysis — TRAJEtória

Gerado em: 2026-11-16T13:54:24.999Z

## Resumo

```json
{
  "filesScanned": 41,
  "sourceFiles": 15,
  "sourceOccurrences": 48,
  "sinkGroups": 37,
  "sinkOccurrences": 103,
  "guarded": 20,
  "acceptedRisk": 17,
  "unprotected": 0,
  "residualRisk": "moderado"
}
```

## Sinks encontrados

| Arquivo | Sink | Linhas | Status | Proteção |
| --- | --- | --- | --- | --- |
| `app/(jovem)/acompanhar.tsx` | `Alert.alert` | 12, 21 | accepted_risk | mensagens estáticas |
| `app/(jovem)/catalogo.tsx` | `Alert.alert` | 21 | guarded | safeErrorMessage |
| `app/(jovem)/detalhe/[id].tsx` | `Alert.alert` | 15 | guarded | safeErrorMessage |
| `app/(jovem)/entrega.tsx` | `reportSecurityEvent` | 24, 31 | guarded | scanLocal + hasConsent + safeErrorMessage |
| `app/(jovem)/entrega.tsx` | `Alert.alert` | 25, 33, 35 | guarded | scanLocal + hasConsent + safeErrorMessage |
| `app/(jovem)/entrega.tsx` | `confirmOrder` | 30 | guarded | scanLocal + hasConsent + safeErrorMessage |
| `app/(jovem)/feedback.tsx` | `Alert.alert` | 16, 30, 32 | guarded | sanitizeFreeText + hasConsent + safeErrorMessage |
| `app/(jovem)/feedback.tsx` | `reportSecurityEvent` | 22, 29 | guarded | sanitizeFreeText + hasConsent + safeErrorMessage |
| `app/(jovem)/feedback.tsx` | `saveFeedback` | 28 | guarded | sanitizeFreeText + hasConsent + safeErrorMessage |
| `app/(jovem)/meu-pedido.tsx` | `Alert.alert` | 12, 14 | accepted_risk | mensagens estáticas + nome da peça |
| `app/(jovem)/perfil.tsx` | `Alert.alert` | 15 | accepted_risk | mensagens estáticas |
| `app/consentimento.tsx` | `Alert.alert` | 19 | accepted_risk | mensagens estáticas |
| `app/index.tsx` | `Alert.alert` | 24 | accepted_risk | mensagens estáticas |
| `backend/http/body.ts` | `sendJson` | 12, 22 | guarded | limite de body + erro estático |
| `backend/http/responses.ts` | `sendJson` | 35, 76, 92, 96, 100 | guarded | sendJson seguro |
| `backend/http/responses.ts` | `res.end` | 49, 60, 71, 88 | guarded | sendJson seguro |
| `backend/routes/orders.ts` | `sendJson` | 18, 32, 61, 75, 83, 89, 104, 113, 141 | guarded | protectForOrder + protectForFeedback + publicView |
| `backend/routes/security.ts` | `sendJson` | 63, 79, 108, 125, 147, 158, 167, 172, 181, 183 | guarded | buildDashboardPayload + protectPayload |
| `backend/security/aiTranslator.ts` | `throw new Error` | 125, 130, 163, 168 | guarded | sanitizedEvent |
| `backend/security/crypto.ts` | `throw new Error` | 32 | guarded | AES-256-GCM |
| `backend/security/piiMiddleware.ts` | `throw new Error` | 83 | guarded | protectForLog/Ai/Response/Order/Feedback |
| `backend/server.ts` | `res.end` | 43, 67, 113 | accepted_risk | logs estáticos de inicialização |
| `backend/server.ts` | `sendJson` | 56, 84, 116 | accepted_risk | logs estáticos de inicialização |
| `backend/server.ts` | `console.log` | 129, 132, 135 | accepted_risk | logs estáticos de inicialização |
| `src/components/Design.tsx` | `Alert.alert` | 30 | accepted_risk | mensagens estáticas |
| `src/context/AuthContext.tsx` | `throw new Error` | 20 | accepted_risk | erro de desenvolvedor |
| `src/database/connection.ts` | `db.execAsync` | 9, 16, 17 | accepted_risk | SQLite local |
| `src/database/connection.ts` | `throw new Error` | 13 | accepted_risk | SQLite local |
| `src/database/repositories/index.ts` | `throw new Error` | 12, 41, 43, 45, 65, 68, 71, 73, 79, 89, 92, 93, 95 | accepted_risk | hasConsent + SQLite sandbox |
| `src/database/repositories/index.ts` | `db.runAsync` | 27, 46, 50, 75, 78, 80, 82, 83, 84, 96, 97 | accepted_risk | hasConsent + SQLite sandbox |
| `src/database/repositories/index.ts` | `confirmOrder` | 64 | accepted_risk | hasConsent + SQLite sandbox |
| `src/database/repositories/index.ts` | `saveFeedback` | 88 | accepted_risk | hasConsent + SQLite sandbox |
| `src/database/seeds/initialData.ts` | `db.runAsync` | 31 | accepted_risk | dados fictícios de demonstração |
| `src/security/taint.ts` | `console.log` | 147 | guarded | safeLog |
| `src/services/catalogService.ts` | `throw new Error` | 9 | guarded | camada de segurança |
| `src/services/securityService.ts` | `reportSecurityEvent` | 32 | guarded | maskPii + sanitized event |
| `src/services/securityService.ts` | `fetch` | 55 | guarded | maskPii + sanitized event |

## Recomendações

- Manter o consentimento obrigatório antes de qualquer pedido ou feedback.
- Nunca remover o mascaramento de PII das respostas do dashboard e da API.
- Revisar a política de risco residual quando novos sinks forem adicionados.
- Substituir a chave de criptografia de desenvolvimento por segredo real em produção.
- Executar npm run security:test e npm run security:audit antes de cada entrega.
