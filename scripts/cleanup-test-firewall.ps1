#!/usr/bin/env pwsh
# Prune Windows Firewall rules left behind by Cargo's hashed test executables.
#
# Every `cargo test` rebuild gives each test harness a new <name>-<hash>.exe.
# Windows treats each path as a distinct program, so a few development sessions
# leave dozens of inbound "cachette-<hash>" rules. Production rules whose
# Program lives outside this checkout's target/ tree are left alone.
#
# Dry-run by default; pass -Apply to actually remove rules (needs elevation).
param([switch] $Apply)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$targetRoot = Join-Path $repo 'target'
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like 'cachette*' })

if (-not $rules) {
    Write-Host 'No cachette firewall rules found.'
    return
}

$stale = @()
foreach ($rule in $rules) {
    $program = @($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Program })
    if (-not $program -or -not ($program | Where-Object {
        $_ -and $_.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)
    })) {
        continue
    }
    $stale += [pscustomobject]@{ Rule = $rule; Program = $program -join '; ' }
}

if (-not $stale) {
    Write-Host 'No test-only cachette firewall rules found.'
    return
}

Write-Host ("{0} test-only rule(s) under {1}:" -f $stale.Count, $targetRoot)
$stale | ForEach-Object { Write-Host ("  {0} -> {1}" -f $_.Rule.DisplayName, $_.Program) }

if (-not $Apply) {
    Write-Host 'Dry run. Re-run with -Apply to remove them.'
    return
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Removing firewall rules needs an elevated PowerShell.'
}
foreach ($entry in $stale) {
    Remove-NetFirewallRule -InputObject $entry.Rule
}
Write-Host ("Removed {0} rule(s)." -f $stale.Count)
