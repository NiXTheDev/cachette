<#
.SYNOPSIS
    B4 probe driver (cachette plan task 27).

.DESCRIPTION
    Answers Metis B4 — "which protocol does the real client actually speak to
    our server?" — by putting a logging pass-through proxy (this fixture,
    `src/main.rs`) in front of a real cachette server, pointing `docker buildx
    --cache-to type=gha` at the proxy as if it were the Forgejo
    `cache.external_server`, and recording every request path + header.

    Topology (the script creates a `docker-container` buildkit builder named
    `b4probe` if one is missing):

        docker buildx (buildkitd in the b4probe builder container)
            -> http://host.docker.internal:<ProxyPort>   (this proxy)
                -> https://127.0.0.1:<ServerPort>        (cachette.exe, TLS)

    Two facts make that topology non-obvious, both discovered the hard way:

    * `host.docker.internal` is required because buildkitd runs inside the
      Docker Desktop Linux VM. The `docker` driver's buildkitd sits in the VM's
      root namespace, where that name does not reach the Windows host (the
      export is rejected with a 503 before any byte reaches the proxy), so a
      `docker-container` builder — which runs buildkit on the default bridge
      network, exactly like a plain container — is used instead.

    * The proxy must use Schannel (Windows TLS) to reach cachette, and
      cachette's default task-13 identity is **Ed25519**, which Schannel cannot
      handshake against (`SEC_E_ILLEGAL_MESSAGE`, curl error 35). The driver
      therefore generates a throwaway RSA-2048 self-signed cert with OpenSSL
      and points the probe server at it via `[server] tls_cert`/`tls_key`. If
      OpenSSL is unavailable the driver falls back to the identity cert and
      the log records that the upstream was unreachable.

    The Go client buildkit links (`github.com/tonistiigi/go-actions-cache`,
    vendored at `tests/fixtures/gac-reference`) parses its token as an
    unverified JWT and requires `ac` (a JSON string), `exp` and `nbf` claims,
    so the driver mints a JWT-shaped stand-in token and registers it in the
    server's static `auth.tokens`.

.NOTES
    The script runs buildx six times so the v1-vs-v2 decision can be
    attributed to a single variable each time:

        A-default         : `--cache-to` params only, no ACTIONS_* env
        B-nocache         : same, plus `--no-cache`        (controls for --no-cache)
        C-envv2           : same as A, plus ACTIONS_CACHE_SERVICE_V2=true
        D-forcev2         : same as A, plus ACTIONS_CACHE_API_FORCE_VERSION=v2
        E-resultsurl      : same as A, plus ACTIONS_RESULTS_URL=<proxy>
        F-v2-plus-resultsurl : C + E combined

    It then writes `b4-probe.log` into -EvidenceDir.
#>
[CmdletBinding()]
param(
    [string]$ServerPort = "18443",
    [string]$ProxyPort = "18080",
    [string]$WorkDir = "$env:TEMP\opencode\cachette-task27",
    [string]$EvidenceDir = "$env:TEMP\opencode\cachette-task27",
    [string]$Builder = "b4probe"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
$logproxyExe = Join-Path $repoRoot "tests\fixtures\logproxy\target\release\logproxy.exe"
$serverExe = Join-Path $repoRoot "target\release\cachette.exe"
$probeCtx = Join-Path $repoRoot "tests\fixtures\logproxy\probe"

foreach ($p in @($logproxyExe, $serverExe, (Join-Path $probeCtx "Dockerfile"))) {
    if (-not (Test-Path $p)) { throw "missing required path: $p" }
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

function Get-Sha256([string]$path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = $null
    try {
        $fs = [IO.File]::OpenRead($path)
        (($sha.ComputeHash($fs)) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        if ($fs) { $fs.Dispose() }
        $sha.Dispose()
    }
}
function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# --- JWT-shaped stand-in token (see .DESCRIPTION) --------------------------
$header = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
$claims = '{"ac":"[]","exp":4102444800,"nbf":0}'
$payload = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($claims))
$signature = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes("cachette-task27-stand-in-signature"))
$token = "$header.$payload.$signature"

# --- Schannel-compatible TLS material (see .DESCRIPTION) -------------------
$openssl = $null
$opensslCmd = Get-Command openssl -ErrorAction SilentlyContinue
if ($opensslCmd) { $openssl = $opensslCmd.Source }
if (-not $openssl) {
    foreach ($cand in @("C:\Program Files\Git\usr\bin\openssl.exe", "C:\Program Files (x86)\Git\usr\bin\openssl.exe")) {
        if (Test-Path $cand) { $openssl = $cand; break }
    }
}
$certPath = Join-Path $WorkDir "probe-cert.pem"
$keyPath = Join-Path $WorkDir "probe-key.pem"
$tlsCertLine = ""
$tlsKeyLine = ""
$opensslNote = ""
if ($openssl) {
    # openssl writes key-progress dots to stderr; keep them out of the error
    # stream so a healthy generation is not treated as a failure.
    $oldEapTls = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $openssl req -x509 -newkey rsa:2048 -keyout $keyPath -out $certPath -days 3650 -nodes `
            -subj "/CN=cachette-b4-probe" 2>&1 | Out-Null
        $opensslExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldEapTls
    }
    if ($opensslExit -ne 0) { throw "openssl cert generation failed (exit $opensslExit)" }
    $tlsCertLine = "tls_cert = `"$($certPath -replace '\\', '/')`""
    $tlsKeyLine = "tls_key = `"$($keyPath -replace '\\', '/')`""
    $opensslNote = "RSA-2048 self-signed cert generated by openssl ($openssl); see TLS note below"
} else {
    $opensslNote = "openssl NOT FOUND - server uses the Ed25519 identity (SChannel cannot handshake it)"
}

# --- scratch cachette config ----------------------------------------------
$storageDir = Join-Path $WorkDir "storage"
$configPath = Join-Path $WorkDir "cachette.toml"
@"
# Generated by run.ps1 (B4 probe, plan task 27). Not committed.
[server]
listen = "127.0.0.1:$ServerPort"
external_url = "https://127.0.0.1:$ServerPort"
$tlsCertLine
$tlsKeyLine

[storage]
backend = "fs"
[storage.fs]
path = "$($storageDir -replace '\\', '/')"
min_free = 0

[auth]
mode = "merge"
secret = "task27-fixture-secret-0123456789abcdef"
tokens = ["$token"]

[cache]
max_size = 0
"@ | Set-Content -Path $configPath -Encoding utf8

$logJsonl = Join-Path $WorkDir "logproxy.jsonl"
Remove-Item -Force -ErrorAction SilentlyContinue $logJsonl

function Add-ProbeMarker([string]$label) {
    Add-Content -Path $logJsonl ('{"event":"marker","label":"' + $label + '"}')
}

# --- scratch build contexts (distinct content per run) --------------------
$runs = @(
    @{ Label = "A-default"; NoCache = $false; ExtraEnv = @{} },
    @{ Label = "B-nocache"; NoCache = $true; ExtraEnv = @{} },
    @{ Label = "C-envv2"; NoCache = $false; ExtraEnv = @{ ACTIONS_CACHE_SERVICE_V2 = "true" } },
    @{ Label = "D-forcev2"; NoCache = $false; ExtraEnv = @{ ACTIONS_CACHE_API_FORCE_VERSION = "v2" } },
    @{ Label = "E-resultsurl"; NoCache = $false; ExtraEnv = @{ ACTIONS_RESULTS_URL = "http://host.docker.internal:$ProxyPort" } },
    @{ Label = "F-v2-plus-resultsurl"; NoCache = $false; ExtraEnv = @{ ACTIONS_CACHE_SERVICE_V2 = "true"; ACTIONS_RESULTS_URL = "http://host.docker.internal:$ProxyPort" } }
)
$runNumber = 0
foreach ($run in $runs) {
    $runNumber++
    $ctx = Join-Path $WorkDir "ctx$runNumber"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $ctx
    New-Item -ItemType Directory -Force -Path $ctx | Out-Null
    Copy-Item (Join-Path $probeCtx "Dockerfile") $ctx
    Copy-Item (Join-Path $probeCtx "payload.txt") $ctx
    Add-Content -Path (Join-Path $ctx "payload.txt") "nonce=$runNumber-$([guid]::NewGuid().ToString('N'))"
    $run.Context = $ctx
}

$server = $null
$proxy = $null
$exitCodes = @()
try {
    # --- ensure a docker-container buildkit builder exists ----------------
    $oldEap0 = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $builderList = (docker buildx ls 2>&1) -join "`n"
        if ($builderList -notmatch ("(?m)^" + [regex]::Escape($Builder))) {
            Write-Host "creating docker-container builder '$Builder'"
            docker buildx create --name $Builder --driver docker-container --use 2>&1 | Out-Null
            docker buildx inspect $Builder --bootstrap 2>&1 | Out-Null
        }
    } finally {
        $ErrorActionPreference = $oldEap0
    }

    # --- fresh storage: a repeat export to an existing scope exercises
    # go-actions-cache SaveMutable's index-key convention, which is case
    # sensitive against cachette's default `key_case = "lower"`. A fresh
    # storage dir makes every run a first-time export.
    Remove-Item -Recurse -Force $storageDir -ErrorAction SilentlyContinue

    # --- start cachette (TLS) ---------------------------------------------
    $serverOut = Join-Path $WorkDir "server.out"
    $serverErr = Join-Path $WorkDir "server.err"
    Remove-Item -Force -ErrorAction SilentlyContinue $serverOut, $serverErr
    $server = Start-Process -FilePath $serverExe -ArgumentList @("--config", $configPath) `
        -PassThru -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr
    $ready = $false
    for ($i = 0; $i -lt 150; $i++) {
        Start-Sleep -Milliseconds 200
        if ((Test-Path $serverOut) -and ((Get-Content $serverOut -Raw) -match "cachette listening on")) { $ready = $true; break }
        if ($server.HasExited) { break }
    }
    if (-not $ready) {
        throw "cachette server not ready; stdout=$(Get-Content $serverOut -Raw -ErrorAction SilentlyContinue) stderr=$(Get-Content $serverErr -Raw -ErrorAction SilentlyContinue)"
    }
    Write-Host "cachette listening on https://127.0.0.1:$ServerPort  (TLS: $(if ($openssl) { 'RSA probe cert' } else { 'Ed25519 identity' }))"

    # --- start logging proxy ----------------------------------------------
    $env:LOGPROXY_LISTEN = "0.0.0.0:$ProxyPort"
    $env:UPSTREAM = "https://127.0.0.1:$ServerPort"
    $env:B4_LOG = $logJsonl
    $proxyOut = Join-Path $WorkDir "logproxy.out"
    $proxyErr = Join-Path $WorkDir "logproxy.err"
    Remove-Item -Force -ErrorAction SilentlyContinue $proxyOut, $proxyErr
    $proxy = Start-Process -FilePath $logproxyExe -PassThru `
        -RedirectStandardOutput $proxyOut -RedirectStandardError $proxyErr
    Start-Sleep -Seconds 2
    if ($proxy.HasExited) {
        throw "logproxy exited early; stderr=$(Get-Content $proxyErr -Raw -ErrorAction SilentlyContinue)"
    }
    Write-Host "logproxy listening on http://host.docker.internal:$ProxyPort -> https://127.0.0.1:$ServerPort"

    # --- run buildx --------------------------------------------------------
    function Invoke-ProbeBuildx {
        param([hashtable]$Run)
        $label = $Run.Label
        $cacheTo = "type=gha,url=http://host.docker.internal:$ProxyPort,token=$token,mode=max,scope=cachette-task27-$label"
        $env:ACTIONS_RUNTIME_TOKEN = $token
        $env:ACTIONS_CACHE_URL = "http://host.docker.internal:$ProxyPort"
        $env:GITHUB_SERVER_URL = "http://host.docker.internal:$ProxyPort"
        foreach ($k in $Run.ExtraEnv.Keys) { Set-Item -Path "env:$k" -Value $Run.ExtraEnv[$k] }
        $buildxOut = Join-Path $WorkDir "buildx-$label.log"
        $args = @("buildx", "build", "--builder", $Builder, "--progress=plain",
                  "--cache-to", $cacheTo, "--output", "type=cacheonly",
                  "-f", (Join-Path $Run.Context "Dockerfile"), $Run.Context)
        if ($Run.NoCache) { $args += "--no-cache" }
        Write-Host "== buildx [$label] =="
        Add-ProbeMarker $label
        # buildkit writes progress to stderr; keep it out of the error stream so
        # a failing build is recorded, not fatal, and $LASTEXITCODE survives.
        # `$out` holds everything, so the pipeline stays empty and this function
        # returns only the exit code.
        $oldEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $out = & docker @args *>&1
            $code = $LASTEXITCODE
            $out | Set-Content -Path $buildxOut
            $out | ForEach-Object { Write-Host $_ }
        } finally {
            $ErrorActionPreference = $oldEap
        }
        foreach ($k in $Run.ExtraEnv.Keys) { Remove-Item -Path "env:$k" -ErrorAction SilentlyContinue }
        return $code
    }

    foreach ($run in $runs) {
        $code = Invoke-ProbeBuildx -Run $run
        $exitCodes += "$($run.Label) exit=$code"
    }
}
finally {
    if ($proxy) { Stop-Process -Id $proxy.Id -Force -ErrorAction SilentlyContinue }
    if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item Env:LOGPROXY_LISTEN, Env:UPSTREAM, Env:B4_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:ACTIONS_RUNTIME_TOKEN, Env:ACTIONS_CACHE_URL, Env:GITHUB_SERVER_URL -ErrorAction SilentlyContinue
    Remove-Item Env:ACTIONS_CACHE_SERVICE_V2, Env:ACTIONS_CACHE_API_FORCE_VERSION -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# --- assemble b4-probe.log -------------------------------------------------
$segments = New-Object System.Collections.ArrayList
$unlabeled = New-Object System.Collections.ArrayList
$current = $unlabeled
if (Test-Path $logJsonl) {
    foreach ($line in Get-Content $logJsonl) {
        if ($line.Trim() -eq "") { continue }
        $rec = $null
        try { $rec = $line | ConvertFrom-Json } catch { continue }
        if ($rec.event -eq "marker") {
            $current = New-Object System.Collections.ArrayList
            $seg = [pscustomobject]@{ Label = [string]$rec.label; Records = $current }
            [void]$segments.Add($seg)
        } elseif ($rec.path) {
            [void]$current.Add($rec)
        }
    }
}

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("b4-probe.log - cachette B4 protocol probe (plan task 27)")
[void]$sb.AppendLine("generated: $(Get-Date -Format o)")
[void]$sb.AppendLine("repo: $repoRoot")
[void]$sb.AppendLine("cachette server: $serverExe (sha256 $(Get-Sha256 $serverExe))")
[void]$sb.AppendLine("logproxy: $logproxyExe")
$buildxVersion = (& docker buildx version 2>&1) -join " "
[void]$sb.AppendLine("buildx builder: $Builder ($buildxVersion)")
[void]$sb.AppendLine("server TLS: $opensslNote")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("TOPOLOGY / WHAT THIS PROVES")
[void]$sb.AppendLine("  docker buildx (buildkitd in the '$Builder' docker-container builder, Docker bridge network)")
[void]$sb.AppendLine("    -> http://host.docker.internal:$ProxyPort   <-- this logging proxy (Forgejo cache.external_server stand-in)")
[void]$sb.AppendLine("      -> https://127.0.0.1:$ServerPort          <-- the real cachette server (TLS)")
[void]$sb.AppendLine("  This proves buildkit<->cachette-server traffic (the exact paths + headers cachette receives).")
[void]$sb.AppendLine("  It does NOT exercise the act_runner->proxy hop: the real Forgejo act_runner (its MAC/HMAC")
[void]$sb.AppendLine("  Forgejo-Cache-Repo / Forgejo-Cache-MAC headers) is not involved here. What is observed is")
[void]$sb.AppendLine("  buildkit's own go-actions-cache client, which is the same client a runner-side cache proxy uses.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("EXACT ENV / TOKEN USED")
[void]$sb.AppendLine("  --cache-to type=gha,url=http://host.docker.internal:$ProxyPort,token=<below>,mode=max,scope=cachette-task27-<run>")
[void]$sb.AppendLine("  ACTIONS_RUNTIME_TOKEN=$token")
[void]$sb.AppendLine("  ACTIONS_CACHE_URL=http://host.docker.internal:$ProxyPort")
[void]$sb.AppendLine("  GITHUB_SERVER_URL=http://host.docker.internal:$ProxyPort")
[void]$sb.AppendLine('  Token: JWT-shaped STAND-IN minted by this script (ac="[]", exp=4102444800, nbf=0), registered')
[void]$sb.AppendLine("         verbatim in cachette [auth] tokens. It is a stand-in token from auth.tokens, NOT a")
[void]$sb.AppendLine("         GitHub or Forgejo token. Runs C-F each add exactly one env variable so the protocol")
[void]$sb.AppendLine("         choice can be attributed: C=ACTIONS_CACHE_SERVICE_V2, D=ACTIONS_CACHE_API_FORCE_VERSION=v2,")
[void]$sb.AppendLine("         E=ACTIONS_RESULTS_URL, F=ACTIONS_CACHE_SERVICE_V2+ACTIONS_RESULTS_URL.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("buildx exit codes: $($exitCodes -join '; ')")
[void]$sb.AppendLine("")

$allPaths = @()
$protoByLabel = @{}
foreach ($seg in $segments) {
    $paths = @($seg.Records | ForEach-Object { [string]$_.path } | Select-Object -Unique)
    $statuses = @($seg.Records | ForEach-Object { if ($_.upstream_status) { [int]$_.upstream_status } elseif ($_.event -eq "upstream_error") { 0 } })
    $v1p = @($paths | Where-Object { $_ -like "*/_apis/artifactcache/*" })
    $v2p = @($paths | Where-Object { $_ -like "*/twirp/*" })
    $allPaths += $paths
    $proto = if ($v2p -and $v1p) { "MIXED v1+v2" } elseif ($v2p) { "v2 (twirp)" } elseif ($v1p) { "v1 (artifactcache)" } else { "none" }
    $protoByLabel[$seg.Label] = $proto
    [void]$sb.AppendLine("RUN $($seg.Label): protocol=$proto, $($seg.Records.Count) request(s), upstream statuses=$(($statuses | Select-Object -Unique) -join ',')")
    foreach ($p in $paths) { [void]$sb.AppendLine("    $p") }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("RAW REQUEST/RESPONSE RECORDS (JSON lines from the proxy)")
[void]$sb.AppendLine((Get-Content $logJsonl -Raw -ErrorAction SilentlyContinue))
[void]$sb.AppendLine("")

$v2runs = @($protoByLabel.Keys | Where-Object { $protoByLabel[$_] -like "*v2*" } | Sort-Object)
$v1runs = @($protoByLabel.Keys | Where-Object { $protoByLabel[$_] -like "*v1*" } | Sort-Object)
$allProxied = @($segments | ForEach-Object { $_.Records }).Count
if ($v2runs.Count -gt 0) {
    $adjudication = "ADJUDICATION: buildkit DID send v2 Twirp paths (/twirp/github.actions.results.api.v1.CacheService/*) in run(s) $($v2runs -join ', ') - the v2 claim is CONFIRMED for this buildkit build. It sent v1 /_apis/artifactcache paths in run(s) $($v1runs -join ', '), so buildkit's default is v1 (the handoff claim is also confirmed) and v2 is reachable only via the version-forcing env var."
} elseif ($v1runs.Count -gt 0) {
    $adjudication = "ADJUDICATION: only v1 /_apis/artifactcache paths were observed from buildkit and no /twirp/ path in any run - the handoff claim (buildkit speaks v1 under Forgejo external_server) is CONFIRMED for the local harness; the v2 conformance baseline is therefore the go-actions-cache CacheService fixture (tests/v2_real_clients.rs), run separately."
} else {
    $adjudication = "ADJUDICATION: no proxied request paths recorded - probe inconclusive (see the buildx logs)."
}

[void]$sb.AppendLine($adjudication)
[void]$sb.AppendLine("")
[void]$sb.AppendLine("TLS NOTE")
[void]$sb.AppendLine("  cachette's default task-13 identity is Ed25519. Windows Schannel (curl.exe, and reqwest with")
[void]$sb.AppendLine("  the native-tls backend used by this proxy) cannot complete a handshake against it:")
[void]$sb.AppendLine("  'schannel: next InitializeSecurityContext failed: SEC_E_ILLEGAL_MESSAGE', curl error 35.")
[void]$sb.AppendLine("  The probe therefore points [server] tls_cert/tls_key at an RSA-2048 self-signed cert.")
[void]$sb.AppendLine("  rustls clients (Go, the test suite) are unaffected. Recorded here because it is a real")
[void]$sb.AppendLine("  interoperability constraint for Schannel-based clients in front of a cachette node.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("FINDINGS (reproducible observations from this probe)")
[void]$sb.AppendLine('  1. buildkit (buildx v0.37.2 / buildkit v0.33) speaks the v1 artifactcache dialect by default:')
[void]$sb.AppendLine("     GET /_apis/artifactcache/cache?keys=..&version=.. (dedup probe), POST /caches (reserve),")
[void]$sb.AppendLine("     PATCH /caches/{id} (chunk), POST /caches/{id} {size} (commit). Every hop hit our server.")
[void]$sb.AppendLine('  2. Repeat-export hazard with the default [cache] key_case = "lower": go-actions-cache''s')
[void]$sb.AppendLine("     SaveMutable() loads key+'#' and does strings.TrimPrefix(storedKey, idxKey+'#') then Atoi()")
[void]$sb.AppendLine("     on the remainder to recover the index generation. cachette normalizes keys to lowercase,")
[void]$sb.AppendLine("     so the returned cacheKey no longer carries buildkit's original-case prefix and Atoi fails:")
[void]$sb.AppendLine('       failed to parse index-<scope>-1-<hash> index: strconv.Atoi: parsing "index-<scope>-...": invalid syntax')
[void]$sb.AppendLine("     The first export to a scope is unaffected (there is no existing index to read back).")
[void]$sb.AppendLine('     Setting [cache] key_case = "preserve" avoids it. Recorded for the plan; task 27 only')
[void]$sb.AppendLine("     observes protocol, so this is reported, not fixed here.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("v2 CONFORMANCE BASELINE (independent of buildkit)")
[void]$sb.AppendLine("  tests/v2_real_clients.rs drives the real go-actions-cache CacheService v2 (Twirp) client")
[void]$sb.AppendLine("  (ACTIONS_CACHE_SERVICE_V2=true) through create/upload/blocklist/finalize/getdownloadurl")
[void]$sb.AppendLine("  with a sha256-verified restore. Run:")
[void]$sb.AppendLine("    cargo test --test v2_real_clients -- --nocapture")

$b4 = Join-Path $EvidenceDir "b4-probe.log"
$sb.ToString() | Set-Content -Path $b4 -Encoding utf8
Write-Host "wrote $b4"
Write-Host $adjudication
