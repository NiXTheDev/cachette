#!/usr/bin/env pwsh
# Local pre-push gates, in dependency order: formatting, lints, then tests.
# A later gate never runs if an earlier one fails, so a clippy error is not
# buried under a long test run.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

function Invoke-Gate {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Step
    )
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Step
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# Keep test scratch on the repo's drive. Windows tests use %TEMP%, which is on
# C: here: the per-run cachette-* directories cause system-drive I/O contention
# and accumulate forever. A dedicated, cleared-each-run directory fixes both.
$testTemp = Join-Path (Split-Path -Parent $PSScriptRoot) 'temp\test-tmp'
New-Item -ItemType Directory -Force -Path $testTemp | Out-Null
Get-ChildItem -LiteralPath $testTemp -Force -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
$env:TEMP = $testTemp
$env:TMP = $testTemp
$env:TMPDIR = $testTemp

if (Get-Command fnm -ErrorAction SilentlyContinue) {
    # `fnm env` puts the default Node on PATH. Only pin a project version when
    # the repo actually declares one; `fnm use` without a dotfile errors.
    fnm env --use-on-cd | Out-String | Invoke-Expression
    if ((Test-Path .node-version) -or (Test-Path .nvmrc)) {
        fnm use | Out-Null
    }
}

Invoke-Gate 'cargo fmt --check' {
    cargo fmt --check
}
Invoke-Gate 'cargo clippy --workspace --all-targets -- -D warnings' {
    cargo clippy --workspace --all-targets -- -D warnings
}
Invoke-Gate 'cargo test --workspace -j 2' {
    cargo test --workspace -j 2
}

Write-Host 'All gates passed.' -ForegroundColor Green
