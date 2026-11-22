# Design: OIDC bearer authentication (v1.1 workstream A)

Status: **implemented** in v1.1.0 (2026-11-15). Amended 2026-11-15 for v1.2 - see "v1.2 amendments" at the end of this document. The v1.2 shape is the contract for v1.2; the text above stays as the record of what shipped.

## Why

`docs/clients.md` records what v1.0 ships and why: Forgejo Actions does not hand jobs OIDC `id_token`s, and `go-actions-cache` refuses anything but our minted HS256 JWT shape (`ac`/`exp`/`nbf`). Those facts are unchanged. What OIDC closes is the remaining leg of the Clients story: **direct API consumers** of cachette
- the actions/checkout-style REST calls, a `cachette` CLI, scripts, any POST/GET against `/_apis/artifactcache` - currently authenticate with a **long-lived static bearer** listed in two places (forge secret + `[auth] tokens`). A bearer with a years-long TTL is exactly the class of secret CI is bad at keeping.

With OIDC verification those consumers can instead present a **short-lived JWT issued by the forge's IdP** (Keycloak, authentik, Forgejo's own OAuth2 layer, a future Forgejo Actions `id_token` implementation): no stored secret, per-run expiry, server-checked scope. Static tokens and the dynamic `TokenStore` keep working unchanged; OIDC is an additional acceptance path on the same `Authorization: Bearer` header.

## The verification chain today

`src/auth/mod.rs::require_auth` resolves mode (`hmac` / `bearer` / `merge`) and bears the request through:

- `auth::hmac::verify` - Forgejo `Forgejo-Cache-*` headers, staleness window from `[auth] hmac_max_age_seconds`;
- `auth::bearer::verify` - static `[auth] tokens` (constant-time compare), the sqlite `TokenStore` (`/_internal/register` / `revoke`), or a self-minted HS256 JWT verified by signature against `[auth].secret` (the `cachette token mint buildx-jwt` shape; the server holds the key it was signed with, so no `[auth] tokens` listing is required).

`auth::jwt.rs` mints/validates our **self-issued HS256** shape. That primitive is unrelated to OIDC and stays as is: it serves the v1 bearer gate (verified by signature, no static listing), the v2 Twirp gate, and `ops::mint` for `ACTIONS_RUNTIME_TOKEN`, all of which must keep speaking the go-actions-cache shape.

## Design

An `oidc` arm inside `bearer::verify`. A bearer token that fails the static/TokenStore/self-minted-JWT checks is then attempted **as a JOSE JWT**:

1. Split and decode header + claims (base64url, no padding - same routine the HS256 module already has).
2. **Algorithm pin.** `alg` must be `RS256`. `none`, `HS256`, `HS384`, or any other value is rejected *before any key material is consulted* - this closes the classic algorithm-confusion family where an attacker re-signs a token with a symmetric key derived from the public one.
3. Resolve the verification key from the JWKS cache by `(issuer, kid)`. Claims-side constraints are checked *after* signature verification, in this order: `iss` ∈ configured issuers, `aud` ∈ configured audiences, `exp` > now, `nbf` ≤ now (both with a configurable skew leeway).
4. Signature over the two JWT segments is verified with the resolved RSA public key. On success the request is authorized.

Failures at any step **fall through** to the final 401 (the token is simply not authorized) - never to anonymous. Log a single warn line with the failure stage; include no token material.

### Claims and scoping

Tokens are accepted only if they carry the required claims from config. The config surface is `require` = a claim -> value map matched as **exact string equality** (no pattern matching; anything richer is a footgun):

```toml
[auth.oidc]
enabled = false
# every token must have been issued by one of these and state one audience:
issuers = ["https://auth.example.org/realms/ci"]
audiences = ["cachette"]
# optional per-deploy pin: e.g. repo allowlist for IdPs that expose it
# (GitHub-style claim names are used verbatim when present):
require = { repository = "NiXTheDev/cachette" }
# skew tolerated on exp/nbf checks:
leeway_seconds = 30
```

`require` is optional. Issuers/audiences are mandatory when `enabled`. Claim values are matched as exact strings against existing claim values - a JWT with array-valued claims must contain the value, and is otherwise rejected.

cachette performs **no per-run state**: verification is stateless (JWKS + checks), so there is nothing to register or revoke, and no new accounting/loss surfaces.

### JWKS handling

- Keys fetched from `{issuer}/.well-known/jwks.json` **or** an explicit URL per issuer (`jwks_urls` map; some IdPs deviate and both formas are cheap).
- Cache is `(issuer, kid) -> key`, refreshed on TWO triggers: a periodic TTL (`jwks_refresh_seconds`, default 1800), and **lifted on a unknown kid hit** (lazy refresh, singleflighted - one fetch in flight, other requests await or fail with the current knowledge cerated).
- Signature verification uses `aws_lc_rs::signature::RsaPublicKeyComponents` with RSA PKCS#1 SHA-256 (2048-8192-bit params). `aws-lc-rs` is the crypto provider rustls *already resolves in this tree* (default since rustls 0.23, see `cluster/tls_client.rs`), so this design promotes it to an explicit direct dependency. Zero new compilation units, but it is a direct dep addition - flagged for approval per the no-new-crates rule. (The original draft named `ring`: same API surface - aws-lc-rs is the maintained fork ring merged into - but wrong driver; corrected during implementation.)
- `ES256`/`PS256` stays out of scope; single-alg keeps the pin meaningful.

### Fetching

Outbound HTTPS GET with the **hand-rolled HTTP/1.1 + `Connection: close`** pattern already proven in `cluster/heartbeat.rs` (no HTTP client crate is added). Trust roots come from an explicit `jwks_ca_pem` PEM bundle in config; self-hosted IdPs commonly have their own CA and public IdPs carry bundle downloads, so this avoids pulling in a web-roots crate. A JWKS fetch failure (DNS, TLS, 5xx) leaves the cache untouched and fails **closed** for tokens needing a new key; previously-cached keys verify normally until their entries expire.

> A note on where this fits with Forgejo today: While Forgejo Actions cannot
> presently issue `id_token`s and go-actions-cache beware only its local JWT
> shape, this path is deliberately generic: it accepts any conformant RS256
> token from a configured issuer, so it lights up without code change the day
> the forge (or the IdP in from of it) issues run-scoped tokens.

## Config surface

```toml
[auth.oidc]           # every field default-off
enabled = false
issuers = []          # required when enabled
audiences = []        # required when enabled
jwks_urls = {}        # issuer -> explicit JWKS URL (optional)
require = {}          # claim -> exact value (optional)
leeway_seconds = 30
jwks_refresh_seconds = 1800
jwks_max_keys = 32
jwks_ca_pem = ""      # path to PEM bundle; required when enabled
```

`config::validate` gains the wiring rules (enabled implies issuers, audiences, `jwks_ca_pem`). `deny_unknown_fields` protects the surface.

## What does NOT change

- Go-actions-cache compatibility: `ACTIONS_RUNTIME_TOKEN` stays our minted HS256 shape (`ac` claim + short TTL); `ops::mint` is untouched.
- Static tokens, the `TokenStore`, `/_internal/*`, Forgejo HMAC, signed URLs - all unchanged; OIDC is an **additional** bearer acceptance path.
- v1 download path: signed URLs remain the authorization there (no bearer is presented by the stock clients).

## Test plan

- **Vectors:** pre-generated RSA keypair + tokens minted in tests (JWKS JSON served locally); negative vectors for: alg=none, HS256-signed with the public key file contents, expired exp, future nbf, wrong aud, unknown iss, unknown kid (with exhausted refresh), tampered payload.
- **Chain:** static token still wins; TokenStore token still wins; disabled `[auth.oidc]` leaves behavior byte-identical to v1.0.
- **JWKS:** endpoint rotation (new kid appears -> lazy refresh succeeds); endpoint down while a cached key still verifies; singleflight under concurrent misses; leeway boundary tests.
- **Config:** validate errors for enabled without required fields; `--print-config` roundtrip.

## Rollout

Default **off**; toggling `enabled` on a live node requires only a restart. No wire or client changes of any kind.

An enabled `[auth.oidc]` is a **tenant-yielding plane** in the multi-tenant shared cache (`docs/shared-cache.md`): every accepted token must carry the issuer block's `tenant_claim`, and the token's tenant selects the storage namespace. That makes the deployment multi-tenant by definition, so the HMAC plane cannot be enabled alongside it - HMAC's repo/run fields are client-asserted and cannot express a tenant. `auth.mode = "hmac"` or `"merge"` with `[auth.oidc] enabled = true` is therefore a boot-time error; use `auth.mode = "bearer"`. Cluster mode is allowed alongside it: the peer wire carries the namespace and refuses a peer of a different protocol version (`docs/shared-cache.md` §8).

## v1.2 amendments (2026-11-15)

### Per-issuer configuration blocks

The v1.1 table made `audiences` and `require` **global**: one deployment could trust many issuers, but every issuer shared one audience list and one set of claim pins. That does not survive the first second IdP - Forgejo's Actions integration audience (`u:1:<uuid>`) has nothing to do with a Keycloak client id, and a repository pin has nothing to do with a group pin. `jwks_urls` was already per-issuer, so the shape was half-way there.

The v1.2 shape makes the issuer the block:

```toml
[auth.oidc]
enabled = true
jwks_refresh_seconds = 1800
jwks_max_keys = 32
jwks_ca_pem = "/etc/ssl/certs/ca-certificates.crt"   # default trust roots

[auth.oidc."https://hangar.nixthedev.ru/api/actions"]
audiences = ["u:1:7aa18c62-d578-484f-8d6e-2b62a540c95a"]
jwks_url = "https://hangar.nixthedev.ru/api/actions/.well-known/keys"
# the claim whose VALUE is the tenant (workstream F); default "repository"
tenant_claim = "repository"
require = { "repository" = "NiXTheDev/cachette" }    # optional narrowing
leeway_seconds = 30
ca_pem = "/etc/ssl/certs/private-root.pem"           # overrides the default roots

[auth.oidc."https://keycloak.example.org/realms/ci"]
audiences = ["cachette"]
jwks_url = "https://keycloak.example.org/realms/ci/protocol/openid-connect/certs"
require = { "groups" = "ci" }
```

TOML allows the parent table plus any number of quoted sub-tables, so one `[auth.oidc]` parent carries the global knobs while each issuer is its own block.

- **Per issuer:** `audiences` (required), `jwks_url` (defaults to `{issuer}/.well-known/jwks.json`), `tenant_claim` (default `repository`), `require`, `leeway_seconds`, and `ca_pem` (overrides the global roots for a private-CA issuer).
- **Global:** `enabled`, `jwks_refresh_seconds`, `jwks_max_keys`, `jwks_ca_pem` (the default trust roots).

Implementation note: serde's `flatten` cannot be combined with `deny_unknown_fields`, so the issuer map is a `#[serde(flatten)] BTreeMap<String, OidcIssuerConfig>` on a parent struct that drops `deny_unknown_fields`; each issuer block keeps `deny_unknown_fields`, so an unknown key *inside* a block is still rejected, and the parent's own key set is validated explicitly against the known global keys.

Compatibility: the v1.1 flat shape is **rejected** in v1.2 with a precise error naming the new form. The feature shipped in v1.1.0 with no deployed configuration behind it, and a half-global shape is worse than a clean break - a silent "works with one issuer" fallback would hide exactly the misconfiguration this change removes.

### `nbf` is optional (RFC 7519 section 4.1.5)

The v1.1 verifier treated a **missing** `nbf` as `Malformed` (`src/auth/oidc.rs`: `claim_secs(claims.get("nbf"))?` maps `None` to an error). RFC 7519 makes `nbf` optional, and real issuers omit it: Forgejo's OAuth2-app `id_token` sets `ExpiresAt`, `IssuedAt` and `Audience` but no `NotBefore` (`routers/web/auth/oauth.go`), and Auth0- and Google-style tokens likewise. Every such token was rejected as malformed.

The v1.2 rule: an absent `nbf` means no lower bound; a **present** `nbf` that is not an integer stays a structural failure. (Forgejo's *Actions* ID token does set `nbf` - `routers/api/actions/id_token.go` - so it was never affected; the OAuth2-app family was.)

### Per-issuer tenants (workstream F)

The OIDC plane is one of the credential planes of the multi-tenant shared cache (`docs/shared-cache.md`): the issuer block is the **forge**, and the **tenant** is the VALUE of the block's `tenant_claim` (default `repository`), so the namespace is `"<issuer>|<tenant>"`. The tenant cannot be a fixed pin: one issuer serves every repository on that forge, so a constant would collapse all of them into one namespace. `require` pins narrow which tokens are accepted (and may pin the same claim to a single repo), but they do not define the tenant; a token without the tenant claim is a structural rejection, never the default namespace. That is why the per-issuer shape is load-bearing rather than cosmetic - one deployment can trust many forges at once, each with its own audiences, pins, roots and tenant claim.
