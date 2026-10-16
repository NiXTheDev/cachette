# Forgejo act_runner

When Forgejo's `act_runner` is configured with an external cache server
(`cache.external_server`), its cache proxy speaks the **legacy artifactcache v1
REST** protocol with **HMAC** authentication. cachette implements exactly that,
so a Forgejo runner can use cachette as its shared cache with no client-side
changes.

## Runner configuration

In the runner's config file, point the cache at cachette and give it the same
secret cachette expects (the `cache` section):

```yaml
cache:
  enabled: true
  external_server: "https://cache.example.com"
  secret: "change-me-to-16-plus-chars"
```

Notes:

- `external_server` is cachette's base URL. The runner appends the
  `/_apis/artifactcache/` paths below to it.
- `secret` must match cachette's `[auth] secret`. It is the HMAC key, not a
  bearer token.

## cachette configuration

```toml
[server]
listen = "0.0.0.0:8080"
# The URL the runner can reach it on, so archive URLs are absolute:
external_url = "https://cache.example.com"

[storage.fs]
path = "/var/lib/cachette"

[auth]
# "hmac" restricts v1 to Forgejo HMAC headers; "merge" also accepts bearer
# tokens (handy for a buildx client hitting the same node).
mode = "hmac"
# Must equal the runner's cache.secret:
secret = "change-me-to-16-plus-chars"
# Reject HMAC signatures older than this many seconds (0 disables the check):
hmac_max_age_seconds = 600
```

If cachette is behind a reverse proxy that terminates TLS, the runner reaches it
at the proxy's `https://` URL and `external_url` must be that public URL. See
[tls.md](tls.md).

## How the HMAC is checked

The runner signs every v1 request with these headers:

| Header | Meaning |
|---|---|
| `Forgejo-Cache-Repo` | Repository path, e.g. `owner/repo`. |
| `Forgejo-Cache-RunNumber` | Workflow run number. |
| `Forgejo-Cache-Timestamp` | Unix seconds when the MAC was minted. |
| `Forgejo-Cache-MAC` | Hex HMAC-SHA256 over the payload below. |
| `Forgejo-Cache-WriteIsolationKey` | Optional; treated as empty when absent. |

The signed payload is:

```text
<repo>><run>><timestamp>><writeIsolationKey>
```

Verification fails closed: any missing header, an unparseable timestamp, bad
hex, or a MAC mismatch is rejected. A timestamp more than 5 seconds in the
future is rejected, and a signature older than `auth.hmac_max_age_seconds` is
rejected (unless that is `0`).

## Endpoints the runner uses

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/_apis/artifactcache/cache?keys=<k>&version=<v>` | Look up a cache entry; returns a signed, absolute `archiveLocation` on a hit. |
| `POST` | `/_apis/artifactcache/caches` | Reserve a cache id for a key/version. |
| `PATCH` | `/_apis/artifactcache/caches/{cacheId}` | Upload one chunk (supports resume). |
| `POST` | `/_apis/artifactcache/caches/{cacheId}` | Commit the upload. |
| `GET` | `/_apis/artifactcache/artifacts/{cacheId}` | Download the artifact via the signed URL. |
| `POST` | `/_apis/artifactcache/caches/clean` | Remove caches by key. |

The download is fetched without an `Authorization` header: the signed
`archiveLocation` alone authorizes it. In single-node `hmac` mode a bare GET is
also accepted, while `bearer`/`merge` mode (and any cluster) requires the signed
URL.

## Troubleshooting

- **`401 authentication required`** - the runner's `cache.secret` does not match
  `auth.secret`, the HMAC headers are missing, or the timestamp is stale
  (raise `hmac_max_age_seconds` if your clocks drift).
- **`403 invalid or expired url`** - the runner followed an `archiveLocation`
  whose TTL (`v1.signed_url_ttl_seconds`) elapsed, or the URL was altered.
- **`404` on a cache save/restore** - the runner is not reaching cachette's
  `/_apis/artifactcache/*` paths; confirm `external_server` has no trailing
  path segment.
- **TLS failures** - the built-in certificate is self-signed. Terminate TLS at a
  reverse proxy with a CA-trusted certificate, or configure `tls_cert`/
  `tls_key`. Do not point runners at plain TCP; cachette is TLS-only.
- **Windows `curl.exe`** - Schannel cannot complete the handshake against the
  built-in listener; use `openssl s_client` or a Node client for manual checks.

## GitHub Actions, Gitea, and GHES (bearer)

Forgejo's runner uses HMAC. GitHub Actions runners, GHES, and Gitea runners
authenticate with a Bearer token (`ACTIONS_RUNTIME_TOKEN`) instead. For those,
set `auth.mode = "bearer"` (or `merge`) and register the token; see
[clients.md](clients.md).
</content>
</invoke>
