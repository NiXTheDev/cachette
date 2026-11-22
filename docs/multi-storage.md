# v1.3 design: multiple storage backends

Status: **proposal** (2026-11-21). Nothing here is committed until the design is approved. Base: the v1.2 tip (`feat/cachette-v1.2`).

Tagline candidates (undecided):

- "Storage Galore, place the cache anywhere the hell you want"
- "Storage-a-nanza, place the cache anywhere the hell you want"
- suggestion: "Fine, I'll put it anywhere." (echoes the v1 merge-commit voice)

Settled: v1.3 includes **all** storage options — multiple local `fs` roots, network mounts (SMB/NFS) and S3-compatible object storage. The legacy `[storage.fs]` form is accepted as the `default` instance; routes match the resolved namespace; quotas are a separate repeatable plane, not part of the storage block.

## Why

v1.2 made the namespace the unit of identity and quota, but there is still exactly one storage backend and one SQLite index per process. That blocks three ordinary needs:

- two local directories on different drives, each with its own free-space floor and quota budget;
- object storage in more than one region/provider (S3-compatible buckets), chosen by tenant or namespace;
- a single config that expresses a default floor once and overrides it per backend instead of repeating it in every backend block.

The goal is one cachette process serving many storages, with routing derived from the same credential/namespace resolution v1.2 already uses.

## Config shape (user's direction)

Tuwunel-style, but reusing the section cachette already has: `[server]` is the one flat block of knobs almost every deployment touches. It absorbs the old `[cache]` and `[log]` keys (their names don't collide). `[v1]` and `[v2]` merge into `[auth]` (also distinct keys). `[cluster]` stays. Everything else is a top-level section that defines only what it needs. TOML headers are absolute from the root, so `[storage]` is not a child of `[server]`.

```toml
[server]
# The important knobs, flat.
data_path = "/etc/cachette"             # dir -> /etc/cachette/cachette.db; or name a
                                        # .db file directly (see §6). Defaults to the
                                        # config file's directory if unset.
listen = "0.0.0.0:8080"
min_free = 0.2                          # default floor for all instances
max_size = "32GiB"                      # bytesize accepted (1024-based)
eviction = "lru"
key_case = "preserve"
reservation_ttl_seconds = 3600
level = "info"                          # was [log] level
format = "text"                         # was [log] format

[auth]
mode = "bearer"
# v1.signed_url_ttl_seconds, v2.jwt_secret, v2.jwt_ttl_seconds land here too
# (distinct key names), alongside mode/secret/tokens/oidc/runtime.

# Repeatable storage instances; `type` picks fs / s3 / network mount.
# `[[storage.instances]]` (not `[[storage]]`): `[storage]` stays a table so
# `[storage.fs]`, `[storage.cdc]` and `[storage.routes]` remain valid TOML.
[[storage.instances]]
name = "default"
type = "fs"
path = "/cache"                         # payloads only; no DB here

[[storage.instances]]
name = "scratch"
type = "fs"
path = "/mnt/fast/cachette"
min_free = "10%"                        # overrides the server min_free

[[storage.instances]]
name = "us-east"
type = "s3"
bucket = "cachette-us-east"
region = "us-east-1"
endpoint = "https://s3.example.com"
# credentials from the environment / instance profile, never in the TOML

# Namespace -> storage instance. Default instance is `default`.
[storage.routes]
"acme|*" = "us-east"
"*" = "default"

# Quotas are a SEPARATE plane, not part of storage. Repeatable:
[[quota]]
scope = "instance"        # cap the whole named storage instance
target = "scratch"
limit = "200GiB"

[[quota]]
scope = "namespace"       # cap a tenant / repo namespace
target = "acme/*"
limit = "5GiB"

# [cluster] stays; [cdc] and the storage sections stay top-level.
```

Migration rule: a legacy v1.2 config is still accepted and maps to the new shape with the `default` instance:

- `[server]` stays; `[cache] *` and `[log] *` move into `[server]` (no key collisions); `[v1] *` and `[v2] *` move into `[auth]`.
- `[storage.fs] path` was **both** the cache root and the control-plane directory. Migration keeps it as the `default` instance root and sets `server.data_path` to the same value, so an existing install's DB, identity and tokens do not move; a warning explains the split. Fresh configs instead default `server.data_path` to the config file's directory (e.g. `/etc/cachette`) and use `/cache` as the payload example.
- `[storage.fs] min_free` -> `server.min_free`; `[storage.quotas]` rules -> `[[quota]] scope="namespace"`.

A file that mixes bare **root-level keys** with `[server]` is refused with a precise error; other top-level sections are expected and fine. Environment overrides use the section path: `CACHETTE__SERVER__DATA_PATH`, `CACHETTE__SERVER__MAX_SIZE`, `CACHETTE__STORAGE__...`, etc.

Rules:

- `server.min_free` is the **default** free-space floor; an instance's own `min_free` overrides it. Storage says where bytes live, how much may be used in total and when cleanup starts.
- `[[storage.instances]]` is a repeatable array of instances; `type = "fs"` or `"s3"` etc. Mixed types can coexist in one file.
- Every instance needs a stable `name`; the first/legacy instance is `default`.
- `[storage.namespaces]` keeps its v1.2 meaning (identity -> namespace name). `[storage.routes]` maps the **resolved namespace** to a storage instance; `"*"` is the catch-all.
- Quotas are decoupled from storage: a repeatable `[[quota]]` table says how much a **tenant** may occupy, either an entire instance (`scope = "instance"`) or a namespace/repo/user (`scope = "namespace"`). `limit` accepts the usual byte denominations (`GB`, `TB`, …), 1024-based, converted to bytes. `server.max_size` gains the same bytesize form.
- The legacy `[storage.fs] path` form is accepted: it seeds both the `default` instance's cache path and `server.data_path`, with a warning that it used to serve both roles. No data is moved automatically; a precise boot error is emitted only if both the legacy and array forms are present.

## Design

### 1. Instance registry

- `AppState` keeps `HashMap<String, Arc<dyn StorageBackend>>` plus a `default_instance` name instead of one `Option<Arc<dyn StorageBackend>>`.
- `storage_scoped(namespace)` becomes `storage_scoped(namespace) -> Option<Arc<dyn StorageBackend>>` by looking up `resolve_storage(namespace)` first, then scoping the resulting instance. Existing handlers keep their current call shape.
- `resolve_storage(namespace)` applies `[storage.routes]`: exact namespace first, then a glob (**longest matching pattern wins**, independent of declaration order), then `"*"`. Unmatched namespaces go to `default`.
- Instances own **only** payload directories. There is no per-instance SQLite file and no per-root lock: all index/accounting rows live in the single `cachette.db`, keyed by instance, and one process-wide lock sits in `server.data_path`. Namespaces inside one instance stay isolated as in v1.2.

### 2. Quotas are a separate plane

- Storage owns capacity: `total` (from `server.max_size` or the disk total), the `min_free` floor, and when cleanup runs. `server.max_size` accepts bytesize strings (`"32GiB"`, `"2TB"`) as well as raw integers.
- Quotas (`[[quota]]`) own limits, not placement. `scope = "instance"` caps the named storage instance as a whole; `scope = "namespace"` caps a resolved namespace (repo/user) wherever it lands. Rules are repeatable and most-specific wins, with the same glob semantics as v1.2.
- Accounting stays per (instance, namespace) through the existing trait methods; eviction consults both the storage floor and the applicable quota.

### 3. Cluster wire

- **One server, one DB:** each cachette process owns its own DB under its own `server.data_path`. Peers never share a DB file or a database connection — cluster state is still exchanged over the peer wire, as in v1.2. `instance` identifies a storage root *within* one server, not a peer.
- Peer requests carry a `storage` field naming the target instance, alongside the namespace; heartbeats advertise per-instance capacity, not one number.
- Placement becomes `(peer, instance)` rather than just `peer`; the owner writes to the named instance it is told to (no re-mapping), matching the v1.2 rule for namespaces.
- Peer protocol version bumps from 2 to 3; a v2 peer gets the same 426 treatment as v1.2 gives v1 peers. No degraded compat mode and no opt-in flag — a mixed cluster drains rather than risking cross-tenant writes.
- Quota rules and usage are **piggybacked on the existing heartbeat** first; a separate gossip protocol is the planned follow-up once the wire format and the consensus math have settled. This keeps v1.3 to one new peer field set rather than a new transport.
- **Quotas are semi-binding with a cluster fallback.** Each peer advertises its configured quota rules (per instance and per namespace) in gossip. A missing rule is an **abstention**, not a vote for "no quota". For a given `(scope, target)` a server resolves the limit in this order:
  1. its own configured rule, if any — always wins;
  2. otherwise the cluster consensus value — the value with the most votes (**plurality**, no weighting by capacity); ties mean no consensus;
  3. otherwise no quota.

  Voting is **per `(scope, target)`**: every server gets one vote for each namespace or instance, independently — not one vote for the whole cluster or one vote shared across all rules. A server that configures `team-a` but not `team-b` votes only on `team-a` and abstains on `team-b`. A single configured server among abstainers therefore sets the cluster value for that target. When two admins configure different values, plurality picks the most popular one, even without a majority. A mismatch never breaks placement: every server can resolve *some* answer, and a server with no rule simply inherits the cluster's.
- **The limit covers cluster-wide usage, not per-instance usage.** Each peer advertises its usage per `(instance, namespace)`; every server sums the reports into a global total. Admission compares the resolved limit against that total plus the requested bytes, so adding instances does not multiply the budget. Each peer's usage report includes its active reservations. Gossip is eventually consistent, so a small overshoot window is accepted and documented — no leader election or quota-token service in v1.3.
- **Stale peer reports:** if a peer's usage report is older than its freshness window, that peer's contribution is **ignored** in the global total rather than treated as zero or blocking admissions. A warning is logged so the gap is visible.
- **Partition behavior:** with no usable consensus view, a server falls back to its own configured rules only; if it has none, no quota applies. Availability wins over strictness, matching the existing cluster posture.

### 4. Backends

- **fs (phase 1):** the existing `FsStorage` with a configurable root; two instances are just two roots. No code change beyond the registry.
- **networked fs (phase 1):** an `fs` instance whose `path` is an SMB/NFS mount; no dedicated backend needed, document the mount/failure semantics.
- **S3-compatible (phase 2):** a new `StorageBackend` implementation. **One bucket with a per-instance key prefix** (instance name becomes the prefix) — simpler IAM and lifecycle rules than a bucket per instance. Blobs and CDC chunks live under that prefix; index rows live in the central control DB keyed by instance, so manifests, accounting and range reads keep their atomicity without any DB in the bucket. Credentials come from the environment (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_ENDPOINT_URL` etc.) with config-file keys as a fallback for simple deployments; env always wins and config secrets are masked in `--print-config`. Multipart/range operations and crash windows need their own design pass before implementation.

#### Payload layout (fs and networked fs)

New instances lay payloads out as a readable hierarchy derived from the resolved identity:

```text
<root>/<forge>/<owner>/<repo>/{blobs,parts,tmp}/   # tenant-scoped identity
<root>/<forge>/{blobs,parts,tmp}/                  # forge-only identity
```

`forge` is the label (or an encoded issuer URL); `owner/repo` is the tenant. Both cases are real: a minted buildx JWT has no tenant claim and resolves to just the forge, while the runner proxy's signed repo and the runtime token's `oidc_extra.repository` resolve to a tenant. The legacy namespace `""` uses `<root>/__legacy__/{blobs,parts,tmp}/`.

Deduplicated CDC `chunks/` live at **instance or forge level**, not per tenant: a chunk can be shared across namespaces, so placing it in one tenant's tree would break dedup. Consequently `du` on a tenant directory reports **exclusive** bytes only; quota and eviction must keep using the SQLite accounting, with `du` as an ops cross-check. S3 mirrors the prefix structure but has no `du`.

The legacy `default` instance keeps its existing hashed layout until an explicit offline `cachette state migrate` converts it — no automatic rewrite of v1.2 data on upgrade.

### 5. Operations and reload

- `cachette doctor` and `--print-config` list every instance, its floor and its route rules; secrets remain masked.
- Offline commands (`gc`, `verify`, `cache`) take `--storage <name>`, defaulting to `default`, and acquire that instance's data-dir lock.
- SIGHUP reload: **`[storage.routes]` and `[[quota]]` are reloadable** (atomic swap of the routing table and parsed quota rules); the instance set and `[auth.<forge>]` blocks stay boot-only, like v1.2's namespace mappings. `min_free` is already reloadable.

#### Migration commands (`cachette doctor`)

- `doctor --migrate <file>` — **full migration**. Takes a full backup, writes the new config in place, then moves data according to it: blobs/parts/tmp into the new `storage.fs.path`, the SQLite DB with its WAL/SHM sidecars, identity and token store into `server.data_path`. Optional `--let-me-edit` pauses after the backup and config write but **before any file moves**, so the operator can edit the generated config; the rest of the migration uses the edited file. Nothing is deleted until the verification pass succeeds.
- `doctor --migrate-config <file>` — **config only**, no data movement. The generated config is written to `<file>.bak` and the original is left untouched; use this to inspect or hand-edit the proposed result.
- `doctor --migrate-config --write <file>` — writes the new config **in place**, backing up the old one verbatim as `<file>.bak`.

All three start from the **generated example** (the complete commented schema) as their template: keys present in the source are activated/populated in place, and repeatable sections are emitted as `[[...]]` instances from the source groups, in schema order under their parent section rather than appended ad hoc. An existing `<file>.bak` is never overwritten — the command refuses.
- Warnings are explicit for each moved key: `[storage.fs] path` -> `[[storage.instances]] name="default" type="fs" path=...` **and** `server.data_path` set to the same old path (so state does not move), `[storage.fs] min_free` -> `server.min_free`, `[cache] *` and `[log] *` -> `[server]`, `[v1]/[v2] *` -> `[auth]`, `[storage.quotas] *` -> `[[quota]]`. Auth migrations (see `docs/hmac-tenancy.md`): `[auth.oidc."<issuer>"]` -> `[auth."<label>"]` with `oidc_issuer`, the global `[auth.oidc]` knobs -> `oidc_*` on `[auth]`, and `[auth.runtime."<forge>"]` -> the same forge block with `secret` renamed `runtime_secret`. Unsupported OIDC flat remnants are called out by name (v1.2 already rejects them).
- **Nothing is silently dropped.** Any key or section that migration cannot map is appended at the end of the generated file, verbatim, inside its original section header and commented out, with a note giving the original line/position and the new key that superseded it (or "no replacement"). This keeps removed configuration readable and recoverable without making the new config boot-fail on unknown keys.
- The generated file ends with a short `# migrated by cachette <version>` + timestamp header and a summary of warnings; `doctor` exits nonzero when any key was unmapped so automation notices.
- Env-only escape hatch: `CACHETTE_AUTO_MIGRATE_CONFIG=1`. It is deliberately **not** a config key (the old config could not express it). When a legacy config is detected, cachette writes the generated file to `<file>.migrated`, never overwrites the original, logs a loud warning that automatic migration is dangerous, can change security-relevant settings and may prevent cachette from starting, then exits nonzero so an operator must review and replace the file before the next boot. Without the env var, an unmigrated legacy config gets a precise boot error pointing at `doctor`. Setting the var on an already-current config is a harmless warning, not a migration.

#### Warning tiers for `doctor --migrate`

Both migration commands report before they act: the full plan and every tier's warnings are printed first, with `--let-me-edit` pausing before data moves. `doctor --migrate` is DANGER throughout (it writes config and moves files); `doctor --migrate-config` is NOTICE/CAUTION only, and `--write` still backs up the original. Every report ends with a machine-readable summary (counts per tier) plus the exit code.

Reports are layered so a routine config rewrite cannot quietly turn into a data operation. For the data-moving steps, DANGER confirmations are required below; `--migrate` groups them into one confirmed operation with one backup, while the individual `state migrate` commands keep their own gates.

1. **NOTICE** — mechanical moves with no semantic change (`[cache]`/`[log]` → `[server]`, `[v1]`/`[v2]` → `[auth]`, key renames). Listed, no gate.
2. **CAUTION** — changes that alter authentication, identity or placement: auth blocks gaining `oidc_issuer`, `hmac_secret`/`runtime_secret` file paths, the `data_path` split, `[[quota]]` and `[storage.routes]` changes, `key_case`, and `server.data_path` being equal to or nested with any `storage.*.path`. `--write` refuses these unless `--ack-caution` is passed; the warning spells out what each change means for the running server.
3. **DANGER** — anything that overwrites or relocates existing files: writing over a config (even with `.bak`), `state migrate --from/--to`, `--layout`, and namespace re-tag. Requires an explicit typed confirmation naming the action (`--confirm migrate-state`, `--confirm migrate-layout`, `--confirm retag-namespaces`), plus a verified backup. For the individual `state migrate` commands, omitting `--confirm` prints the plan and exits; `doctor --migrate` groups the steps into one confirmed operation.

   Backups are produced by the tool, not left to the operator:

   - `doctor --migrate-config --write` copies the **old config verbatim** to `<file>.bak` before writing anything. `doctor --migrate` does the same as part of its full backup, so either path leaves a rollback point. An existing `.bak` is never overwritten; the command refuses instead.
   - Every DANGER data command first writes a compressed snapshot of the source state dir to `<state dir>.<UTC-timestamp>.tar.zst` (`.tar.gz` when zstd is unavailable), verifies the archive by reading it back, and aborts before touching data if the snapshot fails. `--print-config` and the command report show the archive path so restore is one command: offline `cachette state restore <archive> --to <state dir>`, which verifies the archive and refuses a non-empty target unless `--force`.
4. **IRREVERSIBLE** — deleting source data. Never part of `--migrate`. It is a separate `cachette state migrate --delete-source <backup>`, only after a successful migration and a verification pass, with its own typed confirmation. Nothing in v1.3 deletes source data by default.

- Unknown/unmapped keys are always an error-level item and make `doctor` exit nonzero, regardless of tier — "nothing silently dropped" still holds.
- The env-only escape hatch (`CACHETTE_AUTO_MIGRATE_CONFIG=1`) is classified **IRREVERSIBLE-adjacent**: it writes `<file>.migrated`, never overwrites the original, logs the loud danger warning, and exits nonzero so an operator must review and replace the file by hand.
- `--print-config` on the generated file is the final verification step and is recommended before restarting the server at every tier.

#### Migration order (all layers)

Nothing below happens automatically at boot. A legacy v1.2 config still boots as `default` with its old paths, layout and namespace, so config migration is optional for a plain upgrade; it is required before using new storage, per-forge auth or quota features.

1. **Back up.** Stop the server. `doctor --migrate <file>` takes the full backup: old config verbatim to `<file>.bak`, plus a `<state dir>.<timestamp>.tar.zst` snapshot of the state dir (DB, identity, tokens, lock) that is verified before proceeding. A payload-root snapshot is optional (`--snapshot-payloads`) — layout migration is additive until verification, so old blobs are not deleted early.
2. **Config, then files.** Either run `doctor --migrate <file>` for the whole sequence, use `--let-me-edit` to pause after the config write and before any file moves, or do it in stages: `doctor --migrate-config --write <file>` for config only (old config → `<file>.bak`), then the `state migrate` commands for each data step. Review warnings and confirm `--print-config` before starting the server. Auth blocks, `[server]` flat keys, `[[storage.instances]]`, `[[quota]]` and routes all land in the config.
3. **State** — if `server.data_path` differs from the old location, run `cachette state migrate --from <old> --to <new>` **offline**. This copies the SQLite DB, identity and token store, verifies the identity fingerprint is unchanged, and never deletes the source. The DB itself is migrated in place to schema v4 (one `instance` column; all existing rows assigned to `default`) by the normal boot migration, not by this copy.
4. **Data layout (optional)** — v1.2 blobs stay in the hashed layout under `default` until an explicit offline `cachette state migrate --layout` rewrites them into `<root>/<forge>/<tenant>/{blobs,parts,tmp}`. Chunks are relocated to instance/forge level in the same pass, preserving refs.
5. **Namespace re-tag (optional)** — existing rows in `""` are **not** auto-assigned to a forge/tenant. An explicit offline operation re-tags them when the admin knows which identity owned the old single-tenant cache; otherwise they remain accessible as `__legacy__`. Both forms are supported: repeatable `--retag 'old=new'` pairs for small migrations, and a dedicated TOML mapping file for bulk rewrites.
6. **Cluster** — drain peers one at a time and restart them with the new config. Protocol v2 peers get 426 against a v3 node and are excluded from placement, so a mixed cluster degrades rather than sharing wrong rows.
7. **Workflows** — outside config: once the runtime plane is verified with a real buildx export, `token=` and the long-lived `CACHETTE_BUILDX_JWT` secret can be removed from the workflow.

Rollback at any earlier step is a stop + restore of the two backups; steps 4 and 5 are additive and can be deferred indefinitely. Step 3 never deletes the source, so reverting to the old config and old paths is safe until the operator chooses otherwise.

### 6. State directory (non-cache files)

Today the SQLite index, the dynamic-token store, the Ed25519 identity and the data-dir lock all live inside `[storage.fs] path`, next to blobs and scratch. That does not survive several cache roots or a remote (S3) instance: those files are control-plane state, not cache payloads.

New layout:

```text
<state dir>/
  cachette.db          # or the .db filename given by data_path;
                       # tokens + per-instance indexes, with WAL/SHM sidecars
  identity/            # node key + certificate (cluster.cert_path still overrides)
  .cachette.lock       # process-wide lock (supersedes per-cache-root locks)
  doctor/              # optional diagnostic exports
```

`server.data_path` accepts **either a directory or a SQLite file path**:

- if the **last path component ends in `.db`**, the path is the DB file and is used verbatim — `/path/to/elsewhere/data.db`, or even `/path/to/somewhere/else/.db` (an empty stem is fine);
- otherwise it is a directory and the DB is `<dir>/cachette.db` (`/path/to/somewhere` → `/path/to/somewhere/cachette.db`).

The suffix is checked only on the final component, so a parent directory named `*.db` does not turn a nested path into a file. The default config directory has no suffix and therefore resolves to a directory.

Non-DB state (`identity/`, `.cachette.lock`, `doctor/`) lives in the **DB file's parent directory** in all cases, so naming a file path does not scatter state. `--print-config` and `doctor` report both the resolved DB path and the state directory.

- `server.data_path` defaults to the **directory containing the config file**: `/etc/cachette` on Linux, `/config` in Docker, `%APPDATA%\cachette` on Windows. Pointing `--config` at a mounted directory therefore keeps config and state together; an explicit value always wins. It holds the one control DB, identity, token store and process-wide lock regardless of how many storage instances exist or where their roots are — no DB, index or lock file is ever created alongside a payload root. The operator owns this directory: it must be writable by the service user and now holds state as well as configuration. For a legacy single-fs config, migration sets it to the old `[storage.fs] path`, so existing state does not move.
- Cache roots hold **only** cache payloads and disposable scratch: `blobs/`, `parts/`, `chunks/`, `tmp/` for `fs`; bucket prefixes for S3. Sweeps may delete anything there, so nothing mission-critical is stored in an instance.
- `server.data_path` equal to, or nested with, any `storage.*.path` is a **warning**, not a boot error: state and payloads in one tree make `du` misleading and let a sweep reach state. Fresh configs should keep them separate (`/etc/cachette` vs `/cache`); a migrated v1.2 config is the expected exception, since its old `[storage.fs] path` seeds both.
- The control DB gains an `instance` column (schema v4): key derivation becomes `hash(instance || namespace || key)`, accounting is keyed by `(instance, namespace)`, and the single schema stamp lives in `meta`. The migration assigns every v1.2 row to instance `default`.
- Moving an existing state directory is an explicit offline operation (`cachette state migrate --from <old> --to <new>`), never an automatic copy at boot. `cachette doctor` reports the active state path and whether it sits on the same filesystem as any cache root.

**Settled:** one local SQLite control DB at `server.data_path` — a directory resolves to `<dir>/cachette.db`, a file path is used verbatim — with an `instance` column. The alternative — one index file per instance — would duplicate identity/token handling for a smaller migration. External RDBMS backends (PG/MySQL) are **out of scope**: the index layer is built on `rusqlite`, and a portable backend would require a rewrite plus a second migration path without solving a v1.3 requirement. One server = one DB: each cachette process owns its file and never shares it with a peer. Cluster peers exchange state over the wire, not through a common DB.

### 7. Generated example config

v1.3 stops hand-maintaining `cachette.example.toml`. A **declarative Rust spec table plus one renderer** emits every knob with its default and comment, so new keys cannot be forgotten; the checked-in file becomes generated output. A `cachette config example` command exposes the same renderer. It also backs `doctor --migrate`: migration starts from the generated example, populates what it can, emits repeatable instances in schema order, and keeps unmapped residue at the end. The hand-maintained complete example landed first as a separate config-only fix on `release` (#16).

## Rollout

- Single-instance v1.2 configs resolve to instance `default` with the same path, the same index and the same `min_free`; migration sets `server.data_path` to the old `[storage.fs] path`, so behaviour and on-disk locations are unchanged. Fresh configs default state to the config dir and payloads to `/cache`.
- Adding a second instance never touches the first one's data; the namespace is still part of the row identity inside each instance.
- Mixed-version clusters fail loudly via the protocol version gate, never by silently writing to the wrong storage.

## Phases

1. Config shape, validation, instance registry, legacy compatibility, `fs` multi-instance + routes.
2. Per-instance quota/accounting/eviction/reaper and CLI `--storage`.
3. Cluster wire v3 with instance-aware placement and capacity.
4. S3-compatible backend and networked-fs guidance — both land in v1.3.

## Test plan

- Config: default floor vs override, duplicate names, both legacy and array forms, unknown route target, missing credentials, print-config masking.
- Migration: a v1.2 config migrates to the new shape with named warnings (including all auth moves); an unmapped key is appended commented-out under its original section at the end of the file, and `doctor` exits nonzero; plain `--migrate-config` writes only `<file>.bak` and leaves the original untouched, while `--write` replaces it and backs up the old one. Warning tiers are enforced: CAUTION needs `--ack-caution`, DANGER needs the matching typed `--confirm`, and no path deletes source data without `--delete-source`. `--write` creates `<file>.bak` and refuses to overwrite an existing one; data commands create and verify a `.tar.zst`/`.tar.gz` snapshot and abort if it fails; `state restore` refuses a non-empty target without `--force`. State migration copies DB/identity/tokens without deleting the source and preserves the identity fingerprint. Schema v4 assigns every v1.2 row to `default`. Layout migration preserves chunk refs; the legacy hashed layout stays readable until it runs. Namespace re-tag moves only explicitly named rows; `""` rows stay in `__legacy__` by default.
- Isolation: same namespace/key on two instances yields two rows; a route change sends a namespace to a different instance without touching the old one.
- Quotas: an instance-scope cap and a namespace-scope cap can coexist; a quota on instance A does not constrain the same namespace on B; bytesize limits (`"32GiB"`, `"2TB"`) parse 1024-based for both quotas and `server.max_size`; eviction respects each instance's floor and its quotas.
- Cluster: instance on the wire survives a relay hop; a v2 peer gets 426; placement considers per-instance capacity. Quota resolution: a local rule wins over the consensus; absent local rule takes the plurality value; voting is one vote per server **per namespace/instance**, abstentions are ignored, ties mean no consensus, and one configured server among abstainers sets the cluster value for that target. Usage aggregation sums reports from all peers so two servers cannot each spend the full budget; active reservations count toward the global total; a partitioned server falls back to local-only rules (or none).
- CLI: `gc`/`verify`/`cache` on a named instance refuse when another process holds that instance's lock; the default instance stays unaffected.

## Open decisions

- Legacy shape: accepted as `default` (settled), with a precise error only when bare sections are mixed with `[server]`.
- Route key: resolved namespace (settled).
- Quota section name: `[[quota]]` as written in the example; the instance/namespace scope split is settled.
- Cluster quota policy: settled — semi-binding; local rule wins, otherwise a cluster-wide plurality vote (abstentions ignored) supplies the value; the limit applies to aggregate usage across all peers; bounded overshoot and local fallback on partition are accepted (see §3).
- Control-plane storage: settled — one local SQLite DB with an `instance` column, no external RDBMS in v1.3 (see §6).
- Scope: per-forge auth / HMAC tenancy (`docs/hmac-tenancy.md`) is **in v1.3**; its forge-level namespace fallback stays deferred.
- Auth precedence: HMAC wins when both HMAC headers and a Bearer token are present; legacy OIDC/runtime tables stay authoritative with a deprecation warning.
- Route glob ties: longest matching pattern wins; quota gossip piggybacks on heartbeat first, with a separate gossip protocol as a follow-up; stale peer usage is ignored.
- S3: one bucket with per-instance prefixes; credentials from env with config-file fallback (env wins). Reload: routes + quotas on SIGHUP; instances and forge blocks boot-only.
- Tagline: decide later, at the release cut.
