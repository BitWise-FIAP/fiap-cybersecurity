# TRAJEtória - CitizenTech | Cybersecurity

> **Global Solution 2026.2 — Cybersecurity**  
> Esta é a versão de Cybersecurity do TRAJEtória. O app Expo/React Native é a base do protótipo; a entrega de Mobile Development & IoT é mantida em repositório separado. O foco aqui é o mapeamento de PII, a taint analysis, a tradução de risco por IA e o dashboard.

## Ficha da CitizenTech

| Item | Descrição |
| --- | --- |
| Nome da solução | TRAJEtória |
| Localização | São Caetano do Sul / Região do ABC — SP |
| Cidadão beneficiado | Jovens em situação de vulnerabilidade social, de 16 a 24 anos, indicados por ONGs parceiras, que precisam de roupas sociais adequadas para entrevistas de emprego, processos seletivos e primeiros dias de trabalho. |
| Problema | Jovens em vulnerabilidade não têm roupas sociais adequadas para entrevistas e oportunidades de trabalho, enquanto doações de roupas chegam às ONGs de forma desorganizada, sem rastreio, sem curadoria de tamanho e sem garantia de que cheguem a quem realmente precisa. |
| Como a solução resolve | A TRAJEtória conecta ONGs, operação logística e jovens em um único fluxo: as ONGs cadastram e validam os jovens; a operação organiza o acervo de peças (categoria, tamanho, estado de conservação e foto); o jovem solicita um pedido de até 5 peças; a operação aprova, separa, despacha e entrega; e o jovem devolve feedback informando quais peças realmente serviram, realimentando o acervo. Nesta entrega, o recorte de Cybersecurity protege os dados pessoais que circulam nesse fluxo. |
| Partes envolvidas | ONGs parceiras (cadastro e validação dos jovens), operação da TRAJEtória (gestão do acervo e logística de entrega), jovens beneficiados (solicitação e feedback) e administração da plataforma. |
| Repositório | https://github.com/BitWise-FIAP/fiap-cybersecurity |
| Indicador de impacto | Percentual de peças entregues que "serviram" segundo o feedback dos jovens (peças reprovadas voltam ao acervo), número de jovens atendidos por mês e, no recorte de Cybersecurity, percentual de eventos com PII bloqueados, mascarados ou criptografados sem exposição bruta. |
| ODS relacionados | ODS 10 — Redução das Desigualdades (acesso a vestuário adequado para ingresso no mercado de trabalho); ODS 8 — Trabalho Decente e Crescimento Econômico (apoio à empregabilidade de jovens); ODS 12 — Consumo e Produção Responsáveis (reuso de roupas por meio da doação organizada). |
| Tecnologias | Expo/React Native + TypeScript, Expo Router, SQLite, Node.js/TypeScript, AES-256-GCM, taint analysis estática, dashboard web e integração opcional com LLM (OpenAI/Gemini) com fallback local. |
| Jornada apresentada | Acesso → consentimento → catálogo → detalhes → seleção → endereço → envio → acompanhamento → feedback. |
| Diferencial | Peças selecionadas gratuitamente, conforme tamanhos cadastrados, com reserva e histórico de entrega. |
| Equipe e RMs | Pedro Gaspar Fernandes Ferrari (RM 554887), Victor Freire (RM 556191) e Enrico Ricarte Rodrigues (RM 558571). |
| Turma | 3ESPH. |
| Data | novembro de 2026. |
| Base de dados | Dados e imagens de demonstração; não há dados pessoais reais. |

## Sobre esta entrega

A entrega de Cybersecurity cobre os três pontos da disciplina:

1. **Mapeamento de PII** — catálogo e regras de parsing para CPF, RG, saúde, senha, contato, endereço e dados de menor de idade, com mascaramento ou criptografia antes de logs, banco e respostas HTTP.
2. **Taint analysis** — rastreamento source→sink para impedir que PII chegue a logs, telas de erro ou respostas públicas.
3. **Tradução via IA e dashboard** — tradução de eventos técnicos em mensagens compreensíveis e painel com farol de risco e indicador de **Risco Cidadão**.

**Entregáveis:** PDF com a documentação e prints do código/evidências de PII, taint analysis, IA e dashboard; ZIP ou link do GitHub com o código; vídeo do dashboard mostrando a atividade e o print de tela do painel gerando o indicador de Risco Cidadão. O PDF e o código são enviados separadamente no Teams, por um integrante, até **19/11/2026 às 23h55**.

Para Cybersecurity, **não é exigido print das telas do app**. Os prints obrigatórios são os do código e das evidências no PDF, além do print do dashboard.

## Como executar

Requisitos: Node.js 22.13 ou superior.

```powershell
npm install
npm run check
npm run security:test
npm run security:audit
npm run security:demo
npm run security:start
```

Dashboard: `http://localhost:3333/dashboard`.

Para regenerar as evidências e o pacote:

```powershell
npm run security:evidence
npm run security:report
npm run security:pdf
npm run security:dashboard-shot
npm run security:zip
```

## Dashboard

O dashboard tem quatro simulações:

- **Fluxo seguro** — farol verde, score 5.
- **Tentativa de vazamento** — farol laranja, score 51.
- **Cenário completo** — farol laranja, score 56.
- **Exposição crítica** — farol vermelho, score 100.

Cada clique substitui os eventos anteriores, então o farol reflete apenas o cenário escolhido. Os dados são fictícios e nenhuma PII bruta é retornada pelo painel.

## Módulo de Cybersecurity

- Catálogo de PII e mascaramento em `src/security/`.
- Middleware de parsing e proteção de PII no backend.
- Criptografia AES-256-GCM para PII do pedido.
- Taint analysis source→sink com relatório de sinks protegidos e riscos aceitos.
- Tradução de eventos técnicos por LLM com fallback local.
- Dashboard web com farol, eventos e indicador de Risco Cidadão.
- 34 testes automatizados cobrindo PII, taint, risco, criptografia, IA e servidor.

## Evidências e documentação

- `docs/cybersecurity/RELATORIO_CYBERSECURITY.pdf` — relatório final.
- `docs/cybersecurity/EVIDENCIAS.pdf` — evidências do protótipo.
- `docs/cybersecurity/RELATORIO_CYBERSECURITY.md` — fonte do relatório.
- `docs/cybersecurity/EVIDENCIAS.md` — fonte das evidências.
- `docs/cybersecurity/evidencias/dashboard.png` — print do dashboard.
- `docs/cybersecurity/evidencias/taint-report.md` — relatório de taint analysis.

## Estrutura relevante

```text
src/security/          catálogo de PII, mascaramento, risco e taint analysis
backend/               servidor Node/TypeScript, middlewares, criptografia, tradutor e dashboard
tests/security/        34 testes automatizados
scripts/               evidências, relatório, PDF, captura e ZIP
docs/cybersecurity/    relatório, evidências e PDFs
app/                   protótipo mobile (origem dos fluxos de PII)
database/              schema SQLite do protótipo
```

## Protótipo mobile (opcional)

O app Expo/React Native é a base do protótipo e serve para demonstrar a origem dos dados. A entrega completa de Mobile Development & IoT é mantida em repositório separado.

```powershell
npx expo start
```

Login fictício: `lucas.demo` / `trajetoria123`.

## Validação

- `npm run check` — TypeScript sem erros.
- `npm run security:test` — 34 testes aprovados.
- `npm run security:audit` — taint analysis com 0 sinks sem proteção.
- `npm run security:demo` — simulação end-to-end com PII criptografada e feedback sanitizado.
- `npm run security:all` — pipeline completa de build, testes, evidências, relatório, PDF, captura e ZIP.

## Referências

- LGPD — Lei nº 13.709/2018.
- OWASP Top 10.
- Node.js e TypeScript.
- Expo e React Native.

**Uso de dados reais:** não inclua chaves de API, senhas de produção ou dados pessoais reais. Se integrar serviços futuramente, configure `.env` e mantenha-o no `.gitignore`.
