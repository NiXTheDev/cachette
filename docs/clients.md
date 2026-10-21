# Clients and protocols

cachette serves both cache protocols on the same HTTP port:

- **v1 artifactcache** (`/_apis/artifactcache/*`) - the legacy REST API used by
  the `@actions/cache` toolkit and `go-actions-cache`. See
  [forgejo.md](forgejo.md) for the Forgejo runner's HMAC flow.
- **v2 Twirp `CacheService`** (`/twirp/github.actions.results.api.v1.CacheService/*`)
  plus the Azure block-blob upload emulation (`/v2/upload/{entryId}`) and signed
  ranged downloads (`/v2/artifacts/{entryId}`).

## v2 endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry` | Reserve a key/version; returns `signed_upload_url`, `signed_download_url`, and `cache_id`. |
| `POST` | `/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload` | Publish a completed upload. |
| `POST` | `/twirp/github.actions.results.api.v1.CacheService/SupersedeCacheEntry` | Delete the entry for a key so a re-create is not a duplicate. |
| `POST` | `/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL` | Resolve a key (with restore keys) to a signed download URL. |
| `POST` | `/twirp/github.actions.results.api.v1.CacheService/FindMissingOrStaleCacheEntries` | Report which key/versions are missing. |
| `PUT` | `/v2/upload/{entryId}` | Block-blob upload (`comp=block`, `comp=blocklist`, or a whole-blob PUT). |
| `GET` | `/v2/artifacts/{entryId}` | Signed, ranged artifact download. |

Twirp requests and responses use `snake_case` JSON field names (the proto field
names). `application/json` is the content type. Errors use the Twirp envelope
`{"code":"...","msg":"..."}`.

## `@actions/cache` (toolkit)

The Actions toolkit speaks **v1**. Give it the cache base URL and a token:

- `ACTIONS_CACHE_URL` - cachette's base URL. The toolkit appends
  `_apis/artifactcache/`.
- `ACTIONS_RUNTIME_TOKEN` - a token cachette accepts (see "Tokens" below).

The toolkit requires an **absolute** `archiveLocation`, so set
`server.external_url` to the URL the runner can reach. Use `auth.mode = "bearer"`
or `"merge"`, since the toolkit authenticates with a bearer token rather than
Forgejo HMAC headers.

On a server that is not `github.com` (GHES or a Forgejo/Gitea instance), the
toolkit uses this v1 path.

## `docker buildx --cache-to type=gha`

`docker buildx`'s `type=gha` exporter uses `go-actions-cache`, which can speak
**either** protocol. It selects the protocol from the environment:

| Selection | Environment |
|---|---|
| v1 (default) | `ACTIONS_CACHE_URL` + `ACTIONS_RUNTIME_TOKEN` |
| v2 `CacheService` | `ACTIONS_RESULTS_URL` + `ACTIONS_RUNTIME_TOKEN`, with `ACTIONS_CACHE_SERVICE_V2=true` or `ACTIONS_CACHE_API_FORCE_VERSION=v2` |

`ACTIONS_CACHE_API_FORCE_VERSION` accepts exactly `v1` or `v2` (any other value
is an error), and it takes precedence over `ACTIONS_CACHE_SERVICE_V2`. cachette
accepts both protocols, so the choice is the client's and needs no server
change. To see which one a build uses, watch the request paths in the server log
while a build runs.

### What the B4 probe found

cachette's B4 probe (`docker buildx` v0.37.2 / buildkit v0.33 in a
`docker-container` builder, pointed at a logging pass-through proxy in front of
a real node) watched every request and settled the "which dialect does buildx
use?" question:

- All four runs - default, `--no-cache`, `ACTIONS_CACHE_SERVICE_V2=true`, and
  `ACTIONS_CACHE_API_FORCE_VERSION=v2` - stayed on **v1**
  (`/_apis/artifactcache/*`: `GET /cache`, `POST /caches`, `PATCH /caches/{id}`,
  `POST /caches/{id}`). Zero `/twirp/` requests appeared.
- The v2-selection criteria in the table above were not satisfied in that probe:
  it exported `ACTIONS_CACHE_URL`/`GITHUB_SERVER_URL` but never
  `ACTIONS_RESULTS_URL`, and `go-actions-cache` gates its v2 branch on the
  latter. So the probe proves buildx's **default** is v1; it does not prove
  buildx *cannot* speak v2.
- Conclusion: treat v1 as the default path for `type=gha`, and use the
  go-actions-cache `CacheService` fixture (see `tests/v2_real_clients.rs`) as the
  v2 conformance baseline.

One repeat-export caveat was found at the same time, and it is why the default
`cache.key_case` is `preserve`: with `cache.key_case = "lower"`, buildkit's
**second** export to the same scope fails, because `go-actions-cache` reads the
stored index key back and `Atoi`s the generation suffix after `TrimPrefix`.
cachette lowercased the key, so the prefix no longer matched. GitHub cache keys
are case-sensitive, so `preserve` is both the GitHub-parity behaviour and the
safe default; set `cache.key_case = "lower"` only for Forgejo-style folding.

buildx requires a token: pass `token=` in the `--cache-to`/`--cache-from`
spec, or set `ACTIONS_RUNTIME_TOKEN`. Example against the v1 path:

```bash
docker buildx build \
  --cache-to   "type=gha,url=${ACTIONS_CACHE_URL},token=${ACTIONS_RUNTIME_TOKEN},mode=max" \
  --cache-from "type=gha,url=${ACTIONS_CACHE_URL},token=${ACTIONS_RUNTIME_TOKEN}" \
  -t example:latest .
```

## Tokens

cachette accepts a bearer token two ways:

- a **static** token: any string listed in `[auth] tokens`; or
- a **dynamic** token: registered at runtime with
  `POST /_internal/register?token=<token>` and removed with
  `POST /_internal/revoke?token=<token>`.

One important client detail: `go-actions-cache` (and therefore buildx) parses
`ACTIONS_RUNTIME_TOKEN` locally as a JWT **before** sending any request, and
requires the claims `ac` (a string containing a JSON array of scopes), `exp`,
and `nbf`. The token can still be any string cachette accepts, but it must be
JWT-shaped for that client. The simplest recipe is to mint one and list it in
`[auth] tokens`:

```bash
# Mint an HS256 JWT that go-actions-cache accepts. `ac` is a string holding a
# JSON array of scopes; "[]" means no restriction.
secret='change-me-to-16-plus-chars'
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)
payload=$(printf '%s' "{\"ac\":\"[]\",\"exp\":$((now + 3600)),\"nbf\":$((now - 60))}" | b64url)
signature=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$secret" -binary | b64url)
printf '%s\n' "$header.$payload.$signature"
```

Put the printed token in `[auth] tokens` and export it as
`ACTIONS_RUNTIME_TOKEN`. Signing it with `auth.secret` additionally makes it a
valid cachette JWT (accepted by the Twirp API in `bearer`/`merge` mode), but
listing it as a static token is what makes it work for the **v1** routes too.

```toml
[auth]
mode = "merge"
secret = "change-me-to-16-plus-chars"
tokens = ["<the JWT printed above>"]
```

## Capability URLs

Both protocols hand the client a signed URL (`?id&exp&mac`) for the actual
upload or download bytes rather than authorizing those routes with a bearer
token. The URL is short-lived; see the capability-URL note in the README and
[tls.md](tls.md) for the TTL knobs and revocation.
</content>
</invoke>
