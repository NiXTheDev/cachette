# Design: multi-tenant shared cache (v1.2 workstream F)

Status: **proposed** 2026-11-15 - awaiting approve/veto. Implementation follows
this document; this doc is the contract.

## Why

A site admin wants cachette to be **the** cache of their forge: every runner
- the instance's own global runners, and runners sitting in some user's own
datacenter - caching into one deployment the admin runs and pays for.

GitHub's model is the reference, and it is worth stating it correctly because
the intuition is often backwards: GitHub's cache is a **hosted service**
(`cache.actions.githubusercontent.com`), not something that lives on the
runner. A self-hosted runner in a user's datacenter caches into the same
repository-scoped cache GitHub's own runners use - slower link, same cache.
So "one cache for every runner, wherever it runs" is the *normal* model, and
a per-runner-local cache is the exotic one.

And the cache does not have to belong to one forge. The same deployment can
serve a Forgejo instance, a Gitea instance, a GitLab, a plain CI that speaks
the Actions cache dialects - one storage pool, one eviction policy, one
admin. What separates those tenants from each other is exactly the thing
cachette does not have today: a tenant identity the server can *trust*.

What cachette ships today cannot be shared safely:

- **one shared secret, no tenant identity.** The Forgejo HMAC plane keys on
  `[auth] secret`, which the runner's `cache.secret` must equal. The MAC
  payload carries `<repo>><run>><timestamp><writeIsolationKey>` - all of it
  *client-asserted*. Anyone holding the shared secret can mint a valid MAC
  naming any repo. For a single tenant that is fine; for a shared cache it
  means "tenant identity" is not a thing the server can know.
- **one global accounting pool.** `accounting(used_bytes)` is a single row
  compared against `max_size` / `min_free`; eviction is a global LRU. One
  tenant can evict another tenant's cache, and nothing bounds a tenant's
  share of the disk.
- **no isolation.** The v1 key scope is folded into the client's key hash by
  the client. The server never sees the scope string, so it cannot partition
  on it - and must not trust it if it did.

So the work is not "let more people in". It is: **give the server a tenant
identity it can trust, make the storage honor it, and make the accounting
fair** - across as many forges as the admin wants to serve.

## The three facts this design rests on

1. **Tenant identity comes from the credential, never from the request.**
   Every request-scoped string a client controls (key name, version, scope,
   the HMAC payload's repo/run) is attacker-controlled input. Identity must
   be *derived* from a credential the server verifies.
2. **A shared cache must survive a greedy tenant, and a hostile one.**
   Isolation of reads and writes, a per-tenant disk budget, and eviction
   that cannot starve a tenant that is behaving.
3. **The HMAC plane cannot express a tenant.** Therefore a multi-tenant
   deployment must refuse HMAC requests, and must have at least one
   per-job credential plane that yields a tenant.

## What exists today (the surfaces this touches)

- **auth** (`src/auth/mod.rs::require_auth`): modes `hmac` / `bearer` /
  `merge`. Bearer arms: static `[auth] tokens`, the sqlite `TokenStore`, and
  cachette's own minted HS256 JWT. v1.1 added the OIDC arm (RS256 + JWKS +
  issuer/audience/claim pins). v1.2 reshapes the OIDC config into per-issuer
  blocks - see `docs/oidc.md`.
- **storage** (`src/storage/fs.rs`): one flat `entries` table (`key`,
  `version`, `artifact_key`, `digest`, `layout`), a single-row `accounting`
  table (`used_bytes`), `chunks` + `entry_chunks` for CDC, and `meta` for the
  schema version. `SCHEMA_VERSION = 2`, with verified, ordered migrations.
- **eviction** (`src/storage/eviction.rs`): policies `lru` / `none`, a global
  `max_size` and `min_free` floor, a reservation TTL reaper, and (v1.1) the
  CDC garbage sweeper.
- **the trait** (`src/storage/mod.rs::StorageBackend`): key-bearing methods
  take a key and a `Version`; `Entry` / `EntryStat` are the row shapes.

## Design

### 1. Namespaces are the row identity

A row is identified by **(namespace, key, version)**.

The namespace comes from the credential via an **admin-side mapping**:

- default: the namespace is derived from the credential's tenant (and its
  forge), so every tenant is isolated by construction;
- the admin may map several tenants onto one namespace, which makes their
  rows deliberately shared - the "shared cache across a team" case, decided
  by the admin and never by the client.

Two tenants in different namespaces never observe each other's rows, even
with an identical key and version. Two tenants in the same namespace share
rows on purpose. The client-chosen scope stays part of the key hash exactly
as today; it can only make two clients collide if the admin put them in one
namespace.

### 2. The namespace is also the accounting unit

Storage rows, byte accounting, quotas, and eviction are all per namespace.
This keeps the model consistent - there is exactly one unit of storage - and
makes the shared-namespace case honest: tenants that share a namespace share
a disk budget, which is what "sharing a cache" means. Per-*tenant* budgets
inside a shared namespace are deliberately **not** offered in v1.2: with
shared rows, per-tenant bytes are not well-defined (a namespace row may be
referenced by several tenants).

So the admin's levers are: *which tenants share a namespace*, and *what each
namespace may cost*.

### 3. Credential planes - three shapes, all per-source

Each plane yields a **forge** (who vouches) and a **tenant** (who within
that forge). The mapping from credential to (forge, tenant) is
admin-configured per source.

**Plane A - OIDC (v1.1, reshaped in v1.2).** An RS256 token from a
configured IdP, verified against that IdP's JWKS. Per-issuer blocks (see
`docs/oidc.md`) carry the audiences, the tenant claim, the claim pins and
the trust roots, so one deployment can trust many IdPs at once - a Forgejo
instance's Actions issuer, a Gitea instance's issuer, GitHub's OIDC issuer,
a corporate Keycloak. The **tenant** is the VALUE of the issuer block's
`tenant_claim` (default `repository`): one issuer serves many repositories
on that forge, so a constant pin cannot be the tenant - it would collapse
them all into one namespace. `require` pins only narrow which tokens are
accepted; a token without the tenant claim is a structural rejection, never
a default. Revocable, per-job, no secret in the runner.

**Plane B - NEW: forge runtime tokens (HS256).** The forge hands every job
an `ACTIONS_RUNTIME_TOKEN`; the v1 toolkit presents it, and it is the
credential the v1 plane *actually* has today. Shape
(`services/actions/auth.go::CreateAuthorizationToken`): HS256 over the
forge's general token signing secret, claims `exp`, `nbf`, `iat`, `scp`
(`repo:owner/name write:actions`), `ac`, `oidc_sub`, and `oidc_extra` - a
JSON blob carrying the job's identity (`repository`, `repository_owner`,
`event_name`, `actor`, `sha`, `run_id`, `run_number`, `workflow`, `ref`,
`head_ref`, ...). The tenant is `oidc_extra.repository`, falling back to
`oidc_extra.repository_owner`.

Per-forge configuration (the claim layout differs per forge, so the tenant
claim path is configurable):

```toml
[auth.runtime."https://hangar.nixthedev.ru"]
enabled = true
# the forge's general token signing secret - the same one that signed the
# runtime tokens the runners already hold
secret = "/etc/cachette/forgejo-token-secret"
# where the tenant lives inside the token
tenant_claim = "oidc_extra.repository"
# optional narrowing
scopes = ["repo:NiXTheDev/*"]
# optional per-tenant claim pins (same semantics as [auth.oidc."<issuer>"].require)
require = { "event_name" = "push" }
leeway_seconds = 30
```

Trust note, stated plainly: this secret can mint **any** runtime token, so a
cachette holding it sits inside that forge's trust boundary - exactly like
the forge's database. That is an acceptable trade for "the cache serves every
runner on the instance", but it must be a deliberate decision, and Plane A
remains the better shape where it applies.

**Plane C - HMAC (existing).** Single-tenant by definition: the repo and run
in the MAC payload are client-asserted and therefore cannot be an identity.
In a multi-tenant deployment Plane C is **refused** (boot-time error), not
silently degraded.

### 4. Storage: tenancy in the schema

- `entries` gains `namespace TEXT NOT NULL DEFAULT ''`, and the key index
  becomes `(namespace, key, version)`.
- `accounting` becomes per-namespace: `(namespace, used_bytes, entries,
  last_touch)`.
- `chunks` and `entry_chunks` gain the same namespace column, so CDC
  accounting and the GC sweeper are namespace-scoped by construction.
- Migration: `SCHEMA_VERSION` 2 -> 3, one ordered migration adding the
  columns and backfilling `''`, verified at boot exactly like the v1.1
  migrations (a lying version row still refuses to open).
- Legacy rows carry namespace `''`. In single-tenant mode they stay
  reachable as today. In multi-tenant mode they are reachable only through
  an explicit namespace mapping - the admin can map a namespace to `''` if
  they want the pre-existing cache to stay shared.
- Signed capability URLs carry the namespace inside the MAC:
  `archiveLocation` and the v2 upload/download URLs append the resolved
  namespace to the existing payload (`"{path}|{id}|{exp}|{ns}"`) and send
  `ns` percent-encoded in the query. The MAC covers the raw form. A URL
  minted for one namespace therefore cannot be replayed against another -
  stripping or swapping `ns` is a MAC mismatch, exactly like tampering with
  `id` - and URLs minted before namespaces (no `ns`) validate to `''`, so a
  rolling upgrade keeps serving them.

### 5. Quotas and eviction fairness

Every namespace has a limit. The storage section governs the **default**,
and an operator overrides it per namespace - exactly, or with a wildcard
over the tenant part so a whole owner never has to be enumerated:

```toml
[storage.quotas]
default = "20GiB"
# exact namespace (the default namespace form is "<forge>|<tenant>")
"https://hangar.nixthedev.ru|NiXTheDev/cachette" = "50GiB"
# tenant-side wildcard: EACH repo of that owner gets this limit - on any
# forge. It is a per-repo limit, NOT a shared budget across the owner's
# repos: ten repos under that pattern may hold ten times the limit.
"NiXTheDev/*" = "5GiB"
# forge-scoped wildcard: every repo of that owner on one forge
"https://github.com|octo-org/*" = "5GiB"
```

Matching, most specific first:

1. the exact namespace string;
2. the longest matching pattern - `*` matches any run of characters, and a
   pattern without a `|` matches the **tenant part** of any forge's
   namespace (so `NiXTheDev/*` covers that owner everywhere);
3. `default`.

Every rule sets the limit of the namespaces it matches, one limit each: a
wildcard is a shorthand for "the same limit for each of these namespaces",
not a pool they share. The only way two namespaces share a budget is to
put them in ONE namespace - an explicit, admin-side decision.

Rules match the **resolved** namespace, after `[storage.namespaces]`
mapping: a tenant mapped to `nixthedev` is budgeted by a rule naming
`nixthedev` (or a pattern matching that name), not by the default-form
`"<forge>|<tenant>"` string it no longer uses.

The rules are overrides only: the default governs every namespace no rule
matches, and a namespace with its own rule is budgeted by that rule alone.
Sizes use the repo's existing bytesize syntax (the same form
`[storage] min_free` parses).

A namespace several tenants share is budgeted as ONE (it is one storage
unit), so a wildcard rule never silently splits a shared budget: shared
namespaces are named explicitly and budgeted by their own exact rule.

Eviction order, when the global floor (`min_free`) or a namespace quota is
pressured:

1. namespaces over their quota are evicted first, LRU within the namespace;
2. then the global LRU across namespaces, as today.

The admin's `max_size` / `min_free` floor is absolute: no namespace, however
greedy, can push the disk below it, and the reservation TTL reaper and the
CDC sweeper only ever touch their own namespace's rows.

### 6. Observability

- `cachette cache list --namespace <ns>`, `cachette cache prune --namespace
  <ns>`, and a `--namespaces` section in `cachette doctor` (entries, bytes,
  quota, usage per namespace).
- Metrics: per-namespace bytes/entries. Cardinality is bounded by
  construction - namespaces are admin-defined, not client-defined - so this
  is safe to expose as labeled metrics (unlike per-tenant labels keyed by
  request-supplied ids).

### 7. Many forges, one cache

The composite identity is **(forge, tenant)**, where the forge is the source
that vouched for the credential:

| plane | forge | tenant | typical source |
|---|---|---|---|
| A (OIDC) | the issuer string | the value of the issuer block's `tenant_claim` (default `repository`) | Forgejo Actions ID token, GitHub OIDC, Keycloak |
| B (runtime) | the configured forge id | `oidc_extra.repository` | Forgejo / Gitea runners |
| C (HMAC) | - | - | single-tenant only |

The namespace defaults to `"<forge>|<tenant>"` - isolated per tenant per
forge - and the admin overrides it explicitly to share:

```toml
[storage.namespaces]
# "<forge>|<tenant>" -> namespace
"https://hangar.nixthedev.ru|NiXTheDev/cachette" = "nixthedev"
"https://github.com|octo-org/api" = "acme-shared"
```

A tenant of forge A can therefore never land in a namespace of forge B
unless the admin says so.

The mapping is applied where the credential is verified, after the plane
yields `"<forge>|<tenant>"` and before anything touches storage; the
RESOLVED namespace is the one the request's storage view, quota rules,
and signed-URL MAC see. It is boot-time wiring: a change needs a restart.

**What "serve GitHub's runners" can and cannot mean** - worth being precise,
because the two halves differ:

- **Yes, for the layer cache.** buildx's `type=gha` exporter takes an
  explicit URL and token, so a GitHub Actions workflow can point its Docker
  layer cache at cachette: `cache-from: type=gha,url=https://cache.example,
  token=$TOKEN` - the same shape cachette already dogfoods. The token can be
  a GitHub **OIDC id_token** (`permissions: id-token: write`, fetched with
  `core.getIDToken()`), which GitHub publishes a JWKS for
  (`token.actions.githubusercontent.com/.well-known/jwks`) - so Plane A
  verifies it, and `require` can pin the repository. This is the supported
  path for GitHub-hosted workflows.
- **No, for GitHub's own Actions cache service traffic.** The v1/v2 cache
  calls a GitHub runner makes are addressed to the URLs GitHub injects
  (`ACTIONS_CACHE_URL`, `ACTIONS_RESULTS_URL`) and authenticated with
  GitHub's `ACTIONS_RUNTIME_TOKEN`, whose signing key GitHub does not
  publish. A third-party cache service cannot verify those tokens, and the
  runner does not take the URL from the workflow. So a GitHub workflow's
  *actions/cache* steps stay on GitHub; its *buildx layer cache* can be
  pointed at cachette.

### 8. The cluster wire

Namespaces travel with the key: the peer protocol's key-bearing requests
grow a namespace field, and the protocol version is bumped so a mixed
cluster fails loudly instead of silently sharing one tenant's rows with
another's. Peers relay and store the same namespaced rows; the namespace is
part of the row identity everywhere, so a peer never has to know which
namespace a request belongs to beyond carrying it.

### 9. Failure modes

- A `[storage.namespaces]` key that is not `"<forge>|<tenant>"` (a missing
  or empty half): refuse at boot. Namespaces themselves need no
  declaration - a name exists once a tenant mapped to it stores rows - so
  a mistyped *tenant* cannot be detected at boot; it simply keeps its own
  default namespace, which `cachette doctor --namespaces` makes visible.
- A credential that yields no tenant (an OIDC token without the pinned
  claim, a runtime token without `oidc_extra.repository`): rejected as a
  structural failure. In multi-tenant mode there is **no anonymous
  fallback** - an unauthenticated request is a miss/error, never "the
  default tenant".
- HMAC enabled together with multi-tenant mode: boot error.
- A cluster with peers of different protocol versions: refuse to join (the
  existing version negotiation).

## What does NOT change

- **Single-tenant deployments are untouched.** No config change, no client
  change, no wire change; the namespace column defaults to `''` and the
  accounting row keeps its shape.
- The v1 and v2 wire protocols on the client-facing side, key hashing,
  signed-URL authorization, the CDC layout, and the OIDC gates
  (RS256-only, kid routing, fail-closed).
- The HMAC plane's semantics (it stays exactly as documented in
  `docs/forgejo.md`).

## Test plan

- **Isolation:** two namespaces, same key + version -> two distinct rows; a
  cross-namespace read is a miss; a cross-namespace delete is a no-op; a
  cross-namespace finalize cannot publish.
- **Shared namespace:** two tenants mapped to one namespace see each other's
  entries; the quota is namespace-wide, not per tenant.
- **Cross-forge:** a tenant of forge A cannot read or evict a tenant of
  forge B even with identical key and version; the default namespace derives
  from both.
- **Runtime-token plane:** valid signature accepted; wrong signature, expired,
  future `nbf`, missing `oidc_extra`, `oidc_extra` without `repository`, and
  a `scp` outside the allow-list all rejected; a token whose tenant differs
  from the pinned `require` rejected.
- **HMAC in multi-tenant mode:** boot refusal with a precise error.
- **OIDC without a tenant:** rejection (not a silent default tenant).
- **Fairness:** an over-quota namespace is evicted before an under-quota one;
  the global `min_free` floor holds under a greedy writer.
- **CDC:** the sweeper never touches another namespace's chunks; refs
  counting is namespace-scoped; a staged conversion is not swept.
- **Cluster:** a mixed-version cluster refuses to form; a namespace survives a
  relay hop unchanged.
- **Migration:** version 2 -> 3 adds the columns and backfills; a newer
  index refuses to boot; a lying version row is caught; a reboot is a no-op.

## Rollout

Default **off**: no `[auth.runtime]`, no `[storage.quotas]`, no namespace
mappings -> byte-identical v1.1 behavior. Enabling tenancy means configuring
a credential plane that yields a tenant (Plane A and/or B) and, optionally,
namespace mappings; that wiring is boot-time, so it needs a restart - no
client-visible protocol change beyond the namespace that rides along inside
the authenticated request.

An enabled OIDC block is tenant-yielding by construction (its
`tenant_claim` must be present on every accepted token), so enabling tenancy
also means the HMAC plane must be off: Plane C cannot express a tenant, and
the boot guard refuses it rather than silently degrading every HMAC request
to one shared namespace.
