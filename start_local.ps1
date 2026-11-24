$ErrorActionPreference = "Stop"

$env:HTTP_PORT = "8080"
$env:HTTPS_PORT = "8443"
$env:DASHBOARD_PORT = "1082"
$env:DATA_DIR = ".\data_local"

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " ATHENA SHIELD (LOCAL MODE)" -ForegroundColor Cyan
Write-Host " Dashboard : http://127.0.0.1:1082/login" -ForegroundColor Green
Write-Host " Login     : admin / GuardianWAF@2026" -ForegroundColor Yellow
Write-Host " Proxy     : HTTP :8080 / HTTPS :8443" -ForegroundColor Gray
Write-Host "=========================================================" -ForegroundColor Cyan

if (Test-Path "C:\Users\muiss\.gemini\antigravity\scratch\tools\go\bin\go.exe") {
    $env:GOROOT = "C:\Users\muiss\.gemini\antigravity\scratch\tools\go"
    $env:GOPATH = "C:\Users\muiss\.gemini\antigravity\scratch\tools\gopath"
    $env:GOCACHE = "C:\Users\muiss\.gemini\antigravity\scratch\tools\gocache"
    $env:CGO_ENABLED = "0"
    & "$env:GOROOT\bin\go.exe" build -trimpath -ldflags="-s -w" -o .\athena-shield.exe ./cmd/athena
}

.\athena-shield.exe
