# v1.3 design: per-forge auth and tenant-yielding HMAC (Plane C+)

Status: **proposal** (2026-11-22). Nothing here is implemented or committed. Companion to `docs/multi-storage.md`; both are v1.3 candidates. Base: v1.2.

## Why

The HMAC plane currently resolves every authenticated request to `Namespace::legacy()` (`src/auth/mod.rs:160`). That is why v1.2's boot guard refuses `merge`/`hmac` once OIDC or the runtime plane is enabled: Plane C cannot express a tenant, and letting it through would silently dump every HMAC request into one shared namespace.

But the HMAC payload already carries a **signed repository**:

```text
<repo>><run>><timestamp>><writeIsolationKey>     # HMAC-SHA256 with the forge's cache.secret
```

`Forgejo-Cache-Repo` is therefore integrity-protected: it comes from the Forgejo server's task payload and is signed by the forgejo-runner cache proxy with the runner's `cache.secret` (`act/cacheproxy/handler.go:50-58`), so an untrusted job cannot change it. That is enough to yield a tenant. Making the HMAC plane tenant-yielding:

- gives per-repo namespaces to the runner-proxy cache path (`actions/cache`, rust-cache, toolchain caches — `docs/clients.md`, `docs/forgejo.md`);
- removes the reason for the "tenant-yielding plane ⇒ bearer only" guard, so `auth.mode = "merge"` stays valid alongside OIDC/runtime;
- lets two credentials for the same forge — the proxy's HMAC and buildx's Bearer token — resolve into one identity and one storage tree.

## Verified headers (forgejo-runner `main`)

Confirmed from the runner source (`act/cacheproxy/handler.go:147-155` and `act/artifactcache/mac.go:41-50`), sent on every request the cache proxy forwards to the external cache server:

| Header | Meaning |
|---|---|
| `Forgejo-Cache-Repo` | `preset.Repository`, full `owner/repo` |
| `Forgejo-Cache-RunNumber` | actually `preset.RunID` (despite the name) |
| `Forgejo-Cache-RunId` | random 16-char proxy run key |
| `Forgejo-Cache-Timestamp` | Unix seconds, minted once when the run registers |
| `Forgejo-Cache-MAC` | HMAC-SHA256 hex over the four-field payload |
| `Forgejo-Cache-Host` | the cache proxy's own external URL |
| `Forgejo-Cache-WriteIsolationKey` | present only when non-empty |

Two of these (`RunId`, `Host`) are missing from `docs/forgejo.md`; that table should be corrected separately. The per-run timestamp matters for the HMAC plane: `auth.hmac_max_age_seconds` is measured against run start, not request time, so a non-zero value rejects jobs that outlive it.

## Config shape: one block per forge

All credential planes for a forge live in one block, keyed by the forge label. The label is the single identity used by `[storage.namespaces]` and `[storage.routes]`, regardless of which plane authenticated the request.

```toml
[auth]
mode = "merge"

# global OIDC knobs stay on the parent
oidc_jwks_refresh_seconds = 1800
oidc_jwks_max_keys = 32
oidc_jwks_ca_pem = "/etc/ssl/certs/ca-certificates.crt"

[auth.hangar]
# runner-proxy path: HMAC over the signed four-field payload
hmac_secret = "<runner cache.secret>"      # also the HS256 key of a minted buildx JWT

# direct Bearer path: forge-issued runtime token
runtime_secret = "/etc/cachette/forgejo-token.secret"   # FILE PATH, base64url-decoded to 32 bytes
runtime_tenant_claim = "oidc_extra.repository"          # default

# direct Bearer path: OIDC id_token
oidc_issuer = "https://hangar.nixthedev.ru/api/actions"
oidc_audiences = ["cachette"]
oidc_jwks_url = "https://hangar.nixthedev.ru/api/actions/.well-known/keys"
oidc_tenant_claim = "repository"                        # default
oidc_require = { "repository" = "NiXTheDev/cachette" }  # optional narrowing
oidc_leeway_seconds = 30

[auth.another-forge]
hmac_secret = "<its runner cache.secret>"
```

- The block key is the **forge label**; it replaces the separate `[auth.hmac]` map, `[auth.runtime."<forge>"]` block and `[auth.oidc."<issuer>"]` block.
- `oidc_issuer` is required whenever any `oidc_*` key is present: the block key is a human label, not the issuer, so `iss` must still be matched exactly.
- Each block needs at least one plane configured.
- Multiple self-hosted instances get one block each. Public forges (Codeberg, GitHub) don't carry our secret; they use OIDC with an explicit buildx URL/token.

### Migration from v1.2

This is step 2 of the full migration order in `docs/multi-storage.md` §5 — config first, then state, then optional data/namespace rewrites.

- `[auth.oidc."<issuer>"]` → `[auth."<label>"]` with `oidc_issuer = "<issuer>"`. The label is chosen by the admin; the generated example uses the issuer's host as a suggestion.
- The v1.2 global `[auth.oidc]` knobs (`jwks_refresh_seconds`, `jwks_max_keys`, `jwks_ca_pem`) → `oidc_*` on `[auth]`.
- `[auth.runtime."<forge>"]` → the same forge block, with `secret` renamed `runtime_secret` (still a file path).
- A bare `[auth].secret` remains accepted with **v1.1 semantics**: one anonymous forge, `Namespace::legacy()`. Its meaning does not change on upgrade. Per-forge namespacing activates only when a forge block exists.

## Two credential paths, one forge

**Runner-proxy path (`actions/cache`, rust-cache, etc.).** The proxy signs `Forgejo-Cache-*` headers with `hmac_secret` and forwards them to cachette. `Forgejo-Cache-Repo` supplies the tenant → `hangar|owner/repo`.

**Direct buildx path.** `go-actions-cache` needs a token; it takes either `token=` or the injected `ACTIONS_RUNTIME_TOKEN`. With the runtime plane enabled, the explicit `token=` can be dropped entirely:

```yaml
cache-from: type=gha,url=<url>
cache-to: type=gha,url=<url>,mode=max,ignore-error=true
```

Forgejo injects `ACTIONS_RUNTIME_TOKEN` into every job (`runner.go:310`). It is an HS256 JWT signed by the forge's general token signing secret — the `[oauth2] JWT_SECRET` that is base64url-encoded in `app.ini` and decoded into the `runtime_secret` file — so it verifies against that forge's block and yields tenant `oidc_extra.repository`. Same path as the HMAC request: `hangar|owner/repo`.

`scope=` on the buildx flags remains a **key prefix inside that namespace**, not another identity level.

A minted long-lived `buildx-jwt` still works: it is signed with the same secret as `hmac_secret`, so it verifies and identifies the forge, but it carries no tenant claim — it resolves to **just the forge**. That is the forge-scoped case in `docs/multi-storage.md`'s payload layout (`<root>/hangar/{blobs,parts,tmp}/`). The trade must be explicit: that cache is shared by everyone holding the JWT, with no per-repo isolation.

`go-actions-cache` parses its token locally before sending anything and requires `ac`/`exp`/`nbf`; Forgejo's runtime token has all three, but one real buildx export should confirm compatibility before removing `token=`.

## Verification changes

- `hmac::verify` currently returns `bool`; make it return `Option<HmacIdentity { forge, tenant }>`.
- Try each forge block's `hmac_secret` in turn with the existing constant-time MAC comparison; first match wins.
- Require a non-empty `Forgejo-Cache-Repo`; a missing/empty value is a structural rejection (401), never a default tenant.
- Duplicate secrets across forge blocks are a **boot error** — otherwise the identity would depend on iteration order.
- Runtime-token and OIDC verification become per-forge: try the matching block's `runtime_secret` / `oidc_*` fields, same claim checks as v1.2.
- Timestamp freshness, hex parsing and the rest of the fail-closed checks are unchanged.

## Namespace resolution

Every plane yields `(forge, tenant?)`; the tenant may be absent for a static minted JWT. The identity goes through the existing choke point (`state::resolve_namespace`, called from `auth/mod.rs:177` and `twirp.rs:107`):

1. exact `"<forge>|<tenant>"` → mapped namespace, if `[storage.namespaces]` has that key;
2. forge-only `"<forge>"` → mapped namespace (optional explicit admin mapping);
3. otherwise → the derived identity itself, `"<forge>|<tenant>"` or `"<forge>"`.

The payload layout in `docs/multi-storage.md` then gives `<root>/<forge>/<owner>/<repo>/{blobs,parts,tmp}` for case 3 with a tenant, and `<root>/<forge>/{blobs,parts,tmp}` for a forge-only identity. No implicit fallback between the two — a forge-scoped cache is only created when an admin chooses a forge-only namespace.

## Validation changes

Replace the unconditional guard in `validate_tenancy` (`src/config/validate.rs:218`):

- no tenant-yielding plane enabled → any mode (v1.1 behavior);
- any forge block with `hmac_secret` → HMAC yields tenants, so any mode;
- OIDC or runtime enabled, no forge block → `hmac`/`merge` remain a boot error (existing `HmacInMultiTenant`), only `bearer` is valid.

New boot errors: a forge block with no plane, `oidc_*` keys without `oidc_issuer`, empty label or secret, duplicate secrets across blocks. Missing signed repo is a request-time 401.

## Trust note

The repo claim is signed with a secret held by the runner proxy and the admin, so a job cannot forge it. Whoever holds that secret can assert **any** repo on that forge — the same class of trust as Plane B's token-signing secret, but narrower: one purpose (cache) and one forge, not the forge's whole token surface. The runtime secret is broader (it can mint any runtime token on the forge) and belongs inside the same trust boundary as the forge's database. Both belong in the docs next to the existing Plane B warning.

## Rollout and tests

- v1.2 configs keep the same behavior and the same on-disk namespace `""`.
- Adding forge blocks does **not** migrate existing `""` rows; that stays an explicit offline operation.
- Tests: matching secret selects its forge; wrong secret falls through to the next; duplicate secrets fail boot; missing/empty repo header yields 401; repo names with path metacharacters stay one namespace key; exact namespace mapping still applies; a minted JWT with no tenant resolves to the forge; the runtime token yields `oidc_extra.repository`; OIDC config migrates to a forge block with `oidc_issuer`; scalar `[auth].secret` keeps the legacy namespace; OIDC + forge block + `merge` boots; OIDC + scalar secret + `merge` is still refused.
