$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$zipPath = Join-Path $root "TRAJEtoria-Cybersecurity.zip"
$staging = Join-Path $env:TEMP ("trajetoria-cyber-" + [Guid]::NewGuid().ToString("N"))

New-Item -ItemType Directory -Path $staging | Out-Null

function Copy-IfExists([string]$relative) {
  $source = Join-Path $root $relative
  if (Test-Path -LiteralPath $source) {
    $destination = Join-Path $staging $relative
    $parent = Split-Path -Parent $destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
      New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
  }
}

Write-Host "[security:zip] preparando pacote..."

foreach ($directory in @("app", "assets", "database", "src", "backend", "scripts", "tests")) {
  Copy-IfExists $directory
}

Copy-IfExists "docs\cybersecurity"

foreach ($internalDoc in @(
  "docs\cybersecurity\CHECKLIST_ENTREGA.md",
  "docs\cybersecurity\ROTEIRO_VIDEO.md"
)) {
  $stagedDoc = Join-Path $staging $internalDoc
  if (Test-Path -LiteralPath $stagedDoc) {
    Remove-Item -LiteralPath $stagedDoc -Force
  }
}

foreach ($file in @(
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "tsconfig.security.json",
  ".env.example",
  ".gitignore",
  "README.md",
  "CORRECAO_DEPENDENCIAS.md",
  "MANIFESTO_ENTREGA.json",
  "app.json",
  "babel.config.js",
  "metro.config.js",
  "eas.json"
)) {
  Copy-IfExists $file
}

$runtimeData = Join-Path $staging "backend\data"
if (Test-Path -LiteralPath $runtimeData) {
  Remove-Item -LiteralPath $runtimeData -Recurse -Force
}

$secretEnv = Join-Path $staging ".env"
if (Test-Path -LiteralPath $secretEnv) {
  Remove-Item -LiteralPath $secretEnv -Force
}

$readme = @"
# TRAJEtória — Pacote de Cybersecurity

FIAP Global Solution 2026.2 · Cybersecurity · CitizenTech TRAJEtória.

## Conteúdo

- app/ — aplicativo Expo/React Native (integração mínima de segurança).
- assets/ e database/ — dados fictícios de demonstração e schema SQLite.
- src/security/ — catálogo de PII, mascaramento, risco e taint analysis.
- backend/ — servidor Node/TypeScript, middlewares de PII, criptografia, tradutor e dashboard.
- tests/security/ — 34 testes automatizados.
- scripts/ — geração de evidências, relatório, PDF, captura e ZIP.
- docs/cybersecurity/ — relatório, evidências e PDFs.

## Como executar

~~~powershell
npm install
npm run security:test
npm run security:audit
npm run security:demo
npm run security:evidence
npm run security:report
npm run security:pdf
npm run security:dashboard-shot
npm run security:start
~~~

Dashboard: http://localhost:3333/dashboard

O dashboard oferece quatro simulações: fluxo seguro (verde), tentativa de vazamento (laranja), cenário completo (laranja) e exposição crítica (vermelho, score 100). Cada simulação substitui os eventos anteriores.

## Privacidade

Os dados usados nas demonstrações são fictícios. Nenhuma PII bruta é gravada nas evidências ou retornada pelo dashboard.
"@

Set-Content -LiteralPath (Join-Path $staging "LEIA-ME.md") -Value $readme -Encoding UTF8

if (Test-Path -LiteralPath $zipPath) {
  Remove-Item -LiteralPath $zipPath -Force
}

Write-Host "[security:zip] compactando..."
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zipPath -CompressionLevel Optimal

Remove-Item -LiteralPath $staging -Recurse -Force

$size = (Get-Item -LiteralPath $zipPath).Length
Write-Host "[security:zip] ok: $zipPath ($([math]::Round($size / 1MB, 2)) MB)"
