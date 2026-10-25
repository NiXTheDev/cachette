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

### In this repository's own CI

The runners use forgejo-runner's native external cache server support:
`cache.enabled = true`, `cache.external_server = https://acc.nixthedev.ru/`,
and a stabilized `cache.secret` (128-hex shared secret). Job containers get a
one-time `ACTIONS_CACHE_URL`/`ACTIONS_RUNTIME_TOKEN` pair for the runner's
cache proxy, and the proxy authenticates its forwarded requests to cachette
with forgejo artifactcache HMAC (the `Forgejo-Cache-*` headers, keyed to the
shared secret; see also [forgejo.md](forgejo.md)). The only server-side
follow-through this needs:

- `[auth] secret` must equal the runner's `cache.secret` (it is the HMAC key,
  not a listed [token](#tokens));
- `[auth] mode` must be `hmac` or `merge` (not `bearer`-only);
- `[server] external_url` must be the runner-reachable `https://` URL the
  toolkit requires for absolute `archiveLocation`s.

No workflow needs `ACTIONS_*` env overrides and no forge repository secret
is involved. Everything that caches in the workflows speaks toolkit v1
through that proxy, using each action's own restore-at-start/store-at-end
semantics:

- `Swatinem/rust-cache` in every rust job (cargo registry + target state);
- an explicit `actions/cache@v4` step in every rust job for the rustup
  toolchains dir, keyed on `dtolnay/rust-toolchain`'s `cachekey` output
  (the cold toolchain download is the biggest cost on these runners;
  release.yml keys per `matrix.target` instead);
- the test job's `setup-node`/`setup-go` built-in caches (npm tarballs for
  the `@actions/cache` fixture; go build + module state for the vendored
  go fixtures) - no explicit steps needed;
- two explicit `actions/cache@v6` steps for the pinned docker-compose /
  docker CLI binaries, with install steps that version-guard the cache hit.

For reusable downstream examples of caching steps against cachette, see
[forgejo.md](forgejo.md), "Using cache in workflow steps".

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

Why a long-lived static bearer instead of on-demand/OIDC minting:

- Forgejo Actions does not hand jobs OIDC `id_token`s (GitHub-only), and
  `go-actions-cache` insists on its local JWT shape with the `ac` claim -
  a generic id-token would be refused by the exporter client itself.
- The step-cache path is already "on demand": the runner's cache proxy
  mints per-request Forgejo HMAC headers, so no bearer is stored for it.
- A per-run mint through `POST /_internal/register` still needs an admin
  credential inside the job, which only relocates the same secret.

So one static JWT is listed twice (forge secret + `[auth] tokens`); its
TTL is set years out because the client enforces `exp` locally.

One important client detail: `go-actions-cache` (and therefore buildx) parses
`ACTIONS_RUNTIME_TOKEN` locally as a JWT **before** sending any request, and
requires the claims `ac` (a string containing a JSON array of scopes), `exp`,
and `nbf`. The token can still be any string cachette accepts, but it must be
JWT-shaped for that client. A missing, malformed, or expired token ends the
whole build at exporter configure time (`token contains an invalid number of
segments`, `cache token expired at ...`); `ignore-error` only covers export
failures during the build, never this parse. The simplest recipe is the
repo's own mint, which reads `[auth].secret` from the config file for the
HS256 key (so the printed string is ALSO a valid cachette Twirp JWT in
`bearer`/`merge` mode):

```bash
cachette token mint buildx-jwt             # exp defaults to 10y
cachette token mint buildx-jwt --exp 90s   # suffixes s/m/h/d/w/y
cachette token mint buildx-jwt --exp 3600  # bare integers count as seconds (1h)
```

List the printed string verbatim in `[auth] tokens` and export it as the
forge secret/export `ACTIONS_RUNTIME_TOKEN`.

Without a cachette binary at hand, the same token minted by hand (`ac` is a
string holding a JSON array of scopes; "[]" means no restriction; `exp` is
client-enforced, so for a CI-lifetime bearer sit it years out - the +10y
value below - instead of a short ttl):

```bash
secret='change-me-to-16-plus-chars'
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)
payload=$(printf '%s' "{\"ac\":\"[]\",\"exp\":$((now + 315360000)),\"nbf\":$((now - 60))}" | b64url)
signature=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$secret" -binary | b64url)
printf '%s\n' "$header.$payload.$signature"
```

Signing by hand with `auth.secret` additionally makes it a valid cachette JWT
(accepted by the Twirp API in `bearer`/`merge` mode); listing it as a static
token is what makes it work for the **v1** routes too.

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
