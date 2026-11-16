$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$evidence = Join-Path $root "docs\cybersecurity\evidencias"
$output = Join-Path $evidence "dashboard.png"
$serverEntry = Join-Path $root "dist-security\backend\server.js"

$browsers = @(
  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
  "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
  "C:\Program Files\Google\Chrome\Application\chrome.exe",
  "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
)

$browser = $browsers | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $browser) {
  throw "Edge ou Chrome nao encontrado. Instale um navegador Chromium para capturar o dashboard."
}

New-Item -ItemType Directory -Path $evidence -Force | Out-Null

Write-Host "[security:dashboard-shot] compilando backend..."
Push-Location $root
try {
  & npm run security:build
  if ($LASTEXITCODE -ne 0) { throw "Falha no build do backend." }
} finally {
  Pop-Location
}

$port = Get-Random -Minimum 3400 -Maximum 3999
$tempData = Join-Path $env:TEMP ("trajetoria-dashboard-data-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempData -Force | Out-Null
$env:PORT = "$port"
$env:HOST = "127.0.0.1"
$env:SECURITY_DATA_DIR = $tempData

Write-Host "[security:dashboard-shot] iniciando backend na porta $port..."
$server = Start-Process -FilePath "node" -ArgumentList $serverEntry -WorkingDirectory $root -PassThru -WindowStyle Hidden

try {
  $base = "http://127.0.0.1:$port"
  $ready = $false
  for ($attempt = 0; $attempt -lt 40; $attempt++) {
    try {
      $health = Invoke-WebRequest -Uri "$base/health" -UseBasicParsing -TimeoutSec 1
      if ($health.StatusCode -eq 200) {
        $ready = $true
        break
      }
    } catch {
      Start-Sleep -Milliseconds 250
    }
  }
  if (-not $ready) {
    throw "Backend nao respondeu em $base/health."
  }

  Write-Host "[security:dashboard-shot] populando eventos de demonstracao..."
  Invoke-RestMethod -Uri "$base/api/security/demo" -Method Post -ContentType "application/json" -Body '{"scenario":"mixed"}' | Out-Null

  $tempProfile = Join-Path $env:TEMP ("trajetoria-shot-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $tempProfile | Out-Null

  $arguments = @(
    "--headless",
    "--disable-gpu",
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1440,1280",
    "--virtual-time-budget=9000",
    "--user-data-dir=$tempProfile",
    "--screenshot=$output",
    "$base/dashboard"
  )

  Write-Host "[security:dashboard-shot] capturando $output..."
  & $browser @arguments | Out-Null
  $exitCode = $LASTEXITCODE

  Remove-Item -LiteralPath $tempProfile -Recurse -Force -ErrorAction SilentlyContinue

  if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $output)) {
    throw "Falha ao capturar o dashboard (exit $exitCode)."
  }

  $size = (Get-Item -LiteralPath $output).Length
  Write-Host "[security:dashboard-shot] ok: $output ($([math]::Round($size / 1KB, 1)) KB)"
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  }
  Remove-Item Env:PORT -ErrorAction SilentlyContinue
  Remove-Item Env:HOST -ErrorAction SilentlyContinue
  Remove-Item Env:SECURITY_DATA_DIR -ErrorAction SilentlyContinue
  if ($tempData -and (Test-Path -LiteralPath $tempData)) {
    Remove-Item -LiteralPath $tempData -Recurse -Force -ErrorAction SilentlyContinue
  }
}
