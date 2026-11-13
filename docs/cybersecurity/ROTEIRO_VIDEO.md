# Roteiro do vídeo — Cybersecurity TRAJEtória

Duração sugerida: 6 a 8 minutos. Grave a tela do app, do terminal e do dashboard.

## Antes de gravar

```powershell
npm install
npm run security:test
npm run security:audit
npm run security:demo
npm run security:evidence
npm run security:report
npm run security:pdf
npm run security:dashboard-shot
npm run security:start
```

Abra `http://localhost:3333/dashboard` em uma aba e deixe o terminal visível.

## Cena 1 — Abertura (30 s)

**Fala:** “Este é o TRAJEtória, uma CitizenTech de moda circular que conecta jovens a doações de roupas. Nesta entrega de Cybersecurity, mostramos como o projeto protege dados pessoais em todo o fluxo: app, backend, IA e dashboard.”

**Tela:** tela inicial do app e logo do projeto.

## Cena 2 — Problema e PII (45 s)

**Fala:** “O app lida com nome, CPF, e-mail, telefone, CEP, endereço, senha, comentários de saúde e dados de menor de idade. Sem proteção, esses dados podem vazar em logs, respostas HTTP, prompts de IA, banco local ou telas de erro.”

**Tela:** `docs/cybersecurity/RELATORIO_CYBERSECURITY.pdf`, seção 2.

## Cena 3 — Arquitetura (45 s)

**Fala:** “A solução tem três camadas: o app usa o módulo de segurança para escanear e mascarar; o backend Node aplica consentimento, criptografia e eventos; e o dashboard web mostra o farol de risco.”

**Tela:** diagrama da seção 3 do relatório.

## Cena 4 — App: entrega e feedback (60 s)

**Fala:** “Na tela de entrega, se o jovem digitar uma senha, um dado de saúde ou informação de menor de idade, o app bloqueia o envio e registra um evento. Os erros são traduzidos para mensagens seguras, sem SQL ou stack trace.”

**Tela:** app em `Entrega`, tentar enviar um endereço com “senha” ou “ansiedade”. Mostrar o alerta.

**Fala:** “No feedback, o comentário passa por sanitização. Dados de saúde são substituídos por ‘DADO DE SAÚDE REMOVIDO’ e o usuário vê um aviso de PII.”

**Tela:** app em `Feedback`, digitar um comentário com CPF ou termo de saúde e mostrar o aviso.

## Cena 5 — Backend e consentimento (60 s)

**Fala:** “O backend exige consentimento em pedidos e feedback. A PII do pedido é criptografada com AES-256-GCM e a resposta devolve apenas a visão pública mascarada. O token de demonstração é comparado em tempo constante.”

**Tela:** terminal.

```powershell
npm run security:demo
```

Mostrar a saída: eventos criados, risco, tradução, pedido com PII criptografada e feedback sanitizado.

## Cena 6 — Dashboard com farol (60 s)

**Fala:** “O dashboard mostra o farol verde, amarelo, laranja e vermelho. Aqui vemos o score de risco, eventos bloqueados, mascarados, criptografados e permitidos, além da tradução em linguagem simples.”

**Tela:** dashboard. Clicar em “Simular vazamento”, “Fluxo seguro” e “Cenário completo”. Mostrar a mudança do farol e a mensagem de privacidade.

## Cena 7 — Taint analysis e testes (60 s)

**Fala:** “A análise estática percorre app, src e backend e encontra fontes e sinks. O relatório mostra sinks protegidos, riscos aceitos e nenhum sink sem proteção. Os 33 testes automatizados cobrem PII, taint, risco, criptografia, IA e servidor.”

**Tela:** terminal.

```powershell
npm run security:audit
npm run security:test
```

Mostrar o resumo: 41 arquivos, 37 grupos de sinks, 0 sem proteção, 33 testes aprovados.

## Cena 8 — Encerramento (30 s)

**Fala:** “Com isso, o TRAJEtória protege PII na origem, no trânsito e no destino, com evidências reproduzíveis e um dashboard que torna o risco visível para toda a equipe. Obrigado!”

**Tela:** dashboard e PDF final.

## Checklist de gravação

- [ ] Áudio limpo e sem dados reais.
- [ ] Usar apenas dados fictícios.
- [ ] Mostrar o dashboard com eventos.
- [ ] Mostrar o PDF final.
- [ ] Mostrar a saída dos testes.
- [ ] Não exibir `.env` nem chaves reais.
- [ ] Duração entre 6 e 8 minutos.
