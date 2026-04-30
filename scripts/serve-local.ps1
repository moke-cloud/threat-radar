# Local dev server for ThreatRadar.
#
# Stages a _site/ directory mirroring the GitHub Pages layout (web/ files at
# root + data/ copied in), then serves it on http://localhost:8765.
#
# Run from anywhere:
#   pwsh threat-radar/scripts/serve-local.ps1
# or
#   cd threat-radar && pwsh scripts/serve-local.ps1
#
# Requires Python 3 (only for the http.server). Use Ctrl+C to stop.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$site = Join-Path $root "_site"
if (Test-Path $site) { Remove-Item -Recurse -Force $site }
New-Item -ItemType Directory -Path $site | Out-Null

Copy-Item -Path (Join-Path $root "web/*") -Destination $site -Recurse

$siteData = Join-Path $site "data"
New-Item -ItemType Directory -Path $siteData | Out-Null
$dataDir = Join-Path $root "data"
foreach ($name in @("index.json", "critical.json", "stats.json")) {
    $src = Join-Path $dataDir $name
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $siteData $name)
    } else {
        Write-Warning "$name not found in data/. Run the collector first."
    }
}

Write-Host "Serving $site at http://localhost:8765" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray
Push-Location $site
try {
    python -m http.server 8765
} finally {
    Pop-Location
}
