# Per-forge authentication

cachette groups every credential plane for a forge into one configuration
block. A request authenticated by the forge's runner proxy, by a runtime token
or by an OIDC identity resolves to the same forge, and usually the same tenant,
so all three paths can share one cache namespace and one storage instance.

A v1.2 configuration keeps working unchanged: a bare `[auth] secret` still
means one anonymous forge and the legacy namespace. Per-forge namespacing starts
as soon as a forge block exists.

## Configuration

Blocks are keyed by the forge label and live under `[auth.forge]`:

```toml
[auth]
mode = "merge"

# global OIDC knobs stay on the parent
oidc_jwks_refresh_seconds = 1800
oidc_jwks_max_keys = 32
oidc_jwks_ca_pem = "/etc/ssl/certs/ca-certificates.crt"

[auth.forge.hangar]
# runner-proxy path: HMAC over the signed header payload
hmac_secret = "the runner cache.secret"

# runtime-token path: file holding the forge's base64url token secret
runtime_secret = "/etc/cachette/forgejo-token.secret"
runtime_tenant_claim = "oidc_extra.repository"

# OIDC path: exact iss plus its keys and claim rules
oidc_issuer = "https://hangar.nixthedev.ru/api/actions"
oidc_audiences = ["cachette"]
oidc_jwks_url = "https://hangar.nixthedev.ru/api/actions/.well-known/keys"
oidc_tenant_claim = "repository"
oidc_require = { "repository" = "NiXTheDev/cachette" }
oidc_leeway_seconds = 30

[auth.forge.another-forge]
hmac_secret = "its runner cache.secret"
```

Rules:

- The block key is the forge identity used by `[storage.namespaces]` and
  `[storage.routes]`, whichever plane authenticated the request. Keep it
  stable: renaming a block changes the derived namespace.
- `oidc_issuer` is required if any `oidc_*` key is present. The label is a
  human name, not the issuer, so `iss` is still matched byte-exactly.
- Each block needs at least one plane. Public forges that cannot share our
  secret use OIDC with an explicit token; self-hosted forges can use any of
  the three.
- `oidc_audiences`, `oidc_jwks_url`, `oidc_tenant_claim`, `oidc_require` and
  `oidc_leeway_seconds` are optional. The tenant claim defaults to
  `repository`; `oidc_require` narrows which identities are accepted.

`doctor --migrate-config` maps v1.2 tables into this shape without removing
the old ones: `[auth.oidc."<issuer>"]` becomes `[auth.forge.<label>]` with
`oidc_issuer` set (the issuer host is offered as the label), the global OIDC
knobs move to `oidc_*` on `[auth]`, and `[auth.runtime."<forge>"]` becomes
`runtime_secret` in that forge's block. The old tables stay authoritative for
one release and print a boot-time deprecation warning pointing at the new
blocks. `cachette --print-config` masks all secrets.

## How each plane identifies a request

**Runner proxy (HMAC).** Forgejo's cache proxy signs four header fields with
the runner's `cache.secret` and forwards them on every cache request:

| Header | Meaning |
| --- | --- |
| `Forgejo-Cache-Repo` | full `owner/repo`, the signed tenant |
| `Forgejo-Cache-RunNumber` | the run id (the header name is historical) |
| `Forgejo-Cache-RunId` | random proxy run key |
| `Forgejo-Cache-Timestamp` | Unix seconds from run registration |
| `Forgejo-Cache-MAC` | HMAC-SHA256 over the four fields |
| `Forgejo-Cache-Host` | the proxy's external URL |
| `Forgejo-Cache-WriteIsolationKey` | present only when non-empty |

cachette tries each forge block's `hmac_secret` in turn with a constant-time
comparison; the first match identifies the forge. The signed repo becomes the
tenant, `<forge>|<owner/repo>`. An absent or empty repo is a 401, never a
default tenant. Duplicate secrets across blocks are rejected at boot because
identity must not depend on block order. `auth.hmac_max_age_seconds` is checked
against the run's start timestamp, so a long job with a short max age is
rejected — set it to `0` to disable that freshness check.

**Runtime token (Bearer).** Forgejo injects `ACTIONS_RUNTIME_TOKEN` into every
job. It is an HS256 JWT signed by the forge's token secret, which
`runtime_secret` names as a *file path*. Verification yields
`oidc_extra.repository` as the tenant, so a buildx client can authenticate
without an explicit `token=` on its cache flags:

```yaml
cache-from: type=gha,url=<url>
cache-to: type=gha,url=<url>,mode=max,ignore-error=true
```

`scope=` on those flags remains a key prefix *inside* the tenant namespace, not
another identity level. A statically minted `buildx-jwt` signed with
`hmac_secret` verifies too, but carries no tenant claim; it resolves to just
the forge. That cache is shared by everyone holding the JWT, so opt into it
deliberately.

**OIDC (Bearer).** Each block matches one exact `iss` and verifies the JWT's
audience, signature, optional claim pins and clock skew. `oidc_tenant_claim`
supplies the tenant half of the namespace. Missing audiences, a plaintext
issuer or JWKS URL, and a missing CA bundle are boot errors rather than silent
fallbacks.

When a request carries both HMAC headers and a Bearer token, **HMAC wins** and
decides the tenant; the Bearer token is not consulted for that request. This
matches merge mode's historical ordering.

## Namespace resolution

Every plane yields `(forge, tenant?)`, where the tenant may be absent for a
statically minted JWT. The identity passes through the existing resolution
choke point:

1. exact `"<forge>|<tenant>"` → the namespace mapped in `[storage.namespaces]`;
2. forge-only `"<forge>"` → a mapped namespace, if the admin configured one;
3. otherwise the identity itself, `"<forge>|<tenant>"` or `"<forge>"`.

There is no implicit fallback between a tenant namespace and a forge namespace:
a forge-scoped cache exists only when an admin maps or mints one. `[storage.routes]`
then decides which storage instance that namespace uses.

## Boot rules

- With no tenant-yielding plane enabled, any `auth.mode` is accepted (v1.1
  behavior).
- A forge block with `hmac_secret` yields tenants, so `merge` and `hmac` are
  valid alongside OIDC and runtime tokens.
- OIDC or runtime enabled without any forge HMAC block still refuses `hmac`
  and `merge`: a static secret cannot express a tenant, so those modes would
  funnel every request into one shared namespace.
- A forge block with no plane, `oidc_*` keys without `oidc_issuer`, or an empty
  label is a boot error. A request with a missing signed repo is a 401.

## Trust boundary

The repo claim is signed with a secret held by the runner proxy and the admin,
so a job cannot forge it. Whoever holds that secret can assert **any** repo on
that forge — the same class of trust as the runtime token's signing secret,
but narrower: one purpose (cache) and one forge, not the forge's whole token
surface. The runtime secret is broader (it can mint any runtime token on the
forge) and belongs inside the same trust boundary as the forge's database.
Treat both as forge-wide credentials and rotate them with the forge.

## See also

- [Multiple storage backends](multi-storage.md) — instances, routes and quotas.
- [Multi-tenant shared cache](shared-cache.md) — identities and namespaces.
- [OIDC](oidc.md) — issuer and JWKS verification details.
