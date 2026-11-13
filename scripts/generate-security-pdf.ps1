$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$docs = Join-Path $root "docs\cybersecurity"
$evidence = Join-Path $docs "evidencias"

$reportHtml = Join-Path $docs "RELATORIO_CYBERSECURITY.html"
$reportPdf = Join-Path $docs "RELATORIO_CYBERSECURITY.pdf"
$evidenceHtml = Join-Path $evidence "evidence.html"
$evidencePdf = Join-Path $docs "EVIDENCIAS.pdf"

$browsers = @(
  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
  "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
  "C:\Program Files\Google\Chrome\Application\chrome.exe",
  "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
)

$browser = $browsers | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $browser) {
  throw "Edge ou Chrome nao encontrado. Instale um navegador Chromium para gerar o PDF."
}

if (-not (Test-Path -LiteralPath $reportHtml)) {
  throw "HTML do relatorio nao encontrado: $reportHtml. Execute npm run security:report."
}
if (-not (Test-Path -LiteralPath $evidenceHtml)) {
  throw "HTML de evidencias nao encontrado: $evidenceHtml. Execute npm run security:evidence."
}

function ConvertTo-FileUrl([string]$path) {
  $full = (Resolve-Path -LiteralPath $path).Path.Replace("\", "/")
  return "file:///$full"
}

function Export-Pdf([string]$htmlPath, [string]$pdfPath) {
  $url = ConvertTo-FileUrl $htmlPath
  $tempProfile = Join-Path $env:TEMP ("trajetoria-pdf-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $tempProfile | Out-Null

  $arguments = @(
    "--headless",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-pdf-header-footer",
    "--virtual-time-budget=6000",
    "--user-data-dir=$tempProfile",
    "--print-to-pdf=$pdfPath",
    $url
  )

  Write-Host "[security:pdf] gerando $pdfPath"
  & $browser @arguments | Out-Null
  $exitCode = $LASTEXITCODE

  Remove-Item -LiteralPath $tempProfile -Recurse -Force -ErrorAction SilentlyContinue

  if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $pdfPath)) {
    throw "Falha ao gerar PDF: $pdfPath (exit $exitCode)"
  }

  $size = (Get-Item -LiteralPath $pdfPath).Length
  Write-Host "[security:pdf] ok: $pdfPath ($([math]::Round($size / 1KB, 1)) KB)"
}

Export-Pdf $reportHtml $reportPdf
Export-Pdf $evidenceHtml $evidencePdf

Write-Host "[security:pdf] concluido."
