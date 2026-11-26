# Multiple storage backends

cachette can serve several storage instances at once. Each instance is an
independent place to keep cache payloads — another local directory, an SMB/NFS
mount, or an S3-compatible bucket — with its own free-space floor. Namespace
routing decides which instance a cache entry lands in; quotas cap what a
tenant or an instance may occupy, independently of placement.

A single-instance configuration keeps working unchanged: `[storage.fs] path`
becomes the `default` instance, and no other section is required.

## Configuration

The main knobs are flat on `[server]`. It absorbs the old `[cache]` and `[log]`
keys, while `[v1]` and `[v2]` keys live on `[auth]`. The names do not collide.
`[cluster]` stays as it is, and `[storage]` remains a table so that
`[storage.fs]`, `[storage.cdc]` and `[storage.routes]` are valid TOML.

```toml
[server]
data_path = "/etc/cachette"             # dir -> /etc/cachette/cachette.db, or a
                                        # .db file path used verbatim; defaults to
                                        # the config file's directory
listen = "0.0.0.0:8080"
max_size = "32GiB"                      # bytesize accepted (1024-based)
eviction = "lru"
key_case = "preserve"
reservation_ttl_seconds = 3600
level = "info"
format = "text"

[auth]
mode = "bearer"
# signed_url_ttl_seconds, jwt_secret, jwt_ttl_seconds, and the per-forge
# [auth.forge.<label>] blocks live here too

[storage.fs]
path = "/var/lib/cachette"              # legacy root; also the default state dir
min_free = 0.2                          # default floor for every instance

# Repeatable instances. `type` picks the backend.
[[storage.instances]]
name = "default"
type = "fs"
path = "/cache"                         # payloads only; no database here

[[storage.instances]]
name = "scratch"
type = "fs"
path = "/mnt/fast/cachette"
min_free = "10%"                        # overrides server.min_free

[[storage.instances]]
name = "us-east"
type = "s3"
bucket = "cachette-us-east"
region = "us-east-1"
endpoint = "https://s3.example.com"

# Resolved namespace -> instance. Unmatched namespaces go to `default`.
[storage.routes]
"acme|*" = "us-east"
"*" = "default"

# Limits are a separate plane from storage.
[[quota]]
scope = "instance"                      # cap a whole instance
target = "scratch"
limit = "200GiB"

[[quota]]
scope = "namespace"                     # cap a tenant / repo namespace
target = "acme/*"
limit = "5GiB"
```

Rules:

- `[storage.fs].min_free` is the default free-space floor. An instance's
  `min_free` overrides it for that instance's **eviction sweep**;
  reserve-time admission still uses the server-wide floor, and heartbeat
  capacity advertising reports the default instance. `server.max_size`
  accepts bytesize strings as well as raw integers.
- Every instance has a stable `name`; the legacy instance is `default`.
- `[storage.namespaces]` keeps its meaning from the multi-tenant model:
  identity → namespace name. `[storage.routes]` then maps the **resolved
  namespace** to an instance.
- `[[quota]]` is repeatable. `scope = "instance"` caps a named instance as a
  whole; `scope = "namespace"` caps a resolved namespace wherever it lands.
  `limit` uses 1024-based byte denominations.
- `[storage.fs] path` is still accepted. It seeds the `default` instance and
  the legacy state location; a boot error is emitted only if both the legacy
  form and `[[storage.instances]]` are present.
- A file mixing bare root-level keys with `[server]` is rejected with a
  precise error. Environment overrides follow the section path, for example
  `CACHETTE__SERVER__DATA_PATH`, `CACHETTE__SERVER__MAX_SIZE`, and
  `CACHETTE__STORAGE__...`.

## How routing works

The credential gate resolves a request to a namespace, and the storage layer
maps that namespace to an instance:

1. `[storage.namespaces]` can remap an identity into a shared namespace.
2. `[storage.routes]` matches the resolved namespace: exact match first, then
   a glob (the **longest matching pattern wins**, regardless of declaration
   order), then `"*"`.
3. An unmatched namespace goes to `default`.

`AppState` holds a map of named backends. `storage_scoped(namespace)` looks up
the instance and returns a backend view scoped to that namespace, so handlers
keep their existing call shape and tenants stay isolated even when two of them
use the same key.

Changing routes does not require a restart: SIGHUP swaps the routing table
atomically. The instance set and the per-forge auth blocks are boot-only.

## Backends

Every instance publishes the same `StorageBackend` interface to the routes:
index rows, reservations, parts and CDC chunks stay in the local control
database and on the instance's local root. Only the bytes of `whole` entries
go through a payload store, chosen by `type`:

| `type` | Payload home | CDC | Credentials |
| --- | --- | --- | --- |
| `fs` | `<path>/blobs/{id}.blob` | yes | none |
| `fs` with `mount_url` | the same path, mounted by the OS (SMB, NFS, mounted WebDAV) | yes | the OS mount's |
| `s3` | one bucket, keys under `prefix/{id}` | no | `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, config fallback |
| `webdav` | `url/prefix/{id}` over PUT/GET/DELETE | no | optional `username` + `password_file` |
| `copyparty` | `url/prefix/{id}` via up2k | no | optional `username` + `password_file` (the `PW` header) |
| `azure` | one container, blobs under `prefix/{id}` | no | `AZURE_STORAGE_ACCOUNT`/`AZURE_STORAGE_KEY`, config fallback |
| `ftp` | `ftp://host/base/prefix/{id}`, passive mode | no | optional `username` + `password_file` |
| `sftp` | `sftp://host/base/prefix/{id}` via the system `sftp` client | no | SSH key or agent (`private_key_file`) |

**fs** needs nothing beyond a writable root. Mounted network filesystems are
ordinary `fs` instances: `mount_url` records what is mounted at `path` so
`doctor` can report it, but cachette only sees a local directory. Mounting and
failure semantics stay with the operating system.

**S3** uses one bucket for all entries in the instance, with per-instance key
prefixes. The index, manifests and accounting stay local; there is no database
in the bucket. `endpoint` selects path-style addressing for S3-compatible
servers (MinIO, Ceph); without it, AWS virtual-host addressing is used with
`region`. SigV4 is signed in-process. Environment credentials win over
`access_key`/`secret_key` in the config, and `AWS_SESSION_TOKEN` is forwarded.

**WebDAV** talks HTTP directly to a collection (PUT/GET with byte ranges and
DELETE). WebDAV that is mounted by the OS is an `fs` instance instead; both
forms are supported because WebDAV is used both ways.

**copyparty** speaks its native up2k protocol. The client hashes the payload
in up2k chunks (SHA-512 truncated to 33 bytes, base64url), asks the server
which chunks it is missing, and sends only those with `X-Up2k-Hash` and
`X-Up2k-Wark` headers. A handshake with an empty missing list means the file
is already there — including when copyparty hardlink-deduplicated it — so no
bytes are transferred. up2k is chunked on the wire but stores whole files on
the server, so cachette keeps its own local CDC manifests while treating the
copyparty copy as one blob. Set `wsalt` to the server's `--wsalt` when file
IDs matter.

**Azure Blob** signs requests in-process with Shared Key (HMAC-SHA256 over the
canonical request). One container holds the instance's blobs under a key
prefix. Environment credentials win over `account`/`access_key` in the config;
a custom `endpoint` selects an emulator such as Azurite with path-style
addressing.

**FTP** is a plain passive-mode client (`USER`/`PASS`/`TYPE I`/`PASV`/`STOR`/
`RETR`/`DELE`). Ranged reads use `REST <offset>`; servers without `REST` are
reported rather than silently downloading the wrong bytes. FTPS is not
implemented — mount an FTPS endpoint through rclone and use an `fs` instance.

**SFTP** uses the system `sftp` client in batch mode with `BatchMode=yes`, so
only key/agent authentication is supported (`private_key_file` is passed as
`-i`). Each operation is one short-lived process, and a ranged read downloads
the object to a temporary file before slicing it. For high-traffic caches,
mount the remote filesystem (sshfs/rclone) and use an `fs` instance instead.

All remote stores require `ca_pem` for `https` endpoints (and Azure's default
public endpoint is https): the same explicit-trust posture as OIDC's
`jwks_ca_pem`. Config secrets are masked in `--print-config`.

### Capabilities and the adapter seam

`StorageBackend::capabilities()` reports what an instance can do: `chunked`
(CDC manifests), `ranged` (byte-range reads) and `atomic_commit` (publish in
one store-level step). `[storage.cdc] enabled` is still a **global** flag:
validation refuses to boot if any configured instance lacks `chunked`, so a
single remote instance disables CDC for the mixed fleet. A per-instance CDC
flag is a follow-up. Adding a backend means providing a payload store and its
capability set; the index, quota and route layers do not change.

Remote stores keep a read-through cache under `<root>/blobs/{id}.blob`:
publishing uploads the local blob after the index commit (a failed upload
compensates by dropping the row), then removes the cache file. A ranged read
downloads only the requested bytes into a sparse cache file, so a partial read
never pulls a whole artifact. Boot reconciliation keeps rows whose cache file
is absent, because the authoritative copy is remote.

## Payload layout

Every instance's local root has the same layout:

```text
<root>/blobs/{id}.blob    finalized whole payload (or a remote read-through cache)
<root>/parts/{id}.part    staged payload awaiting finalize
<root>/chunks/{id}.chunk  deduplicated CDC chunk payloads
<root>/tmp/               scratch for atomic temp-file + rename writes
```

`id` is derived from the instance, namespace and key, so the same key in two
namespaces or two instances never shares a row. CDC chunks are shared across
namespaces inside one instance: a chunk may be referenced by several entries,
so quotas and eviction use the SQLite accounting rather than `du`, which only
reports exclusive bytes for a directory. A remote instance has no meaningful
`du` for its authoritative bytes.

Nothing is rewritten on upgrade. The tenant-scoped directory layout and the
`cachette state migrate --layout` conversion are planned as a follow-up; the
hashed layout above is what v1.3 actually stores.

## State directory

The SQLite control database, dynamic-token store, Ed25519 identity and
process-wide lock live outside the payload roots, under `server.data_path`:

```text
<state dir>/
  cachette.db          # or the .db filename given by data_path;
                       # tokens + per-instance indexes, WAL/SHM sidecars
  identity/            # node key + certificate (cluster.cert_path overrides)
  .cachette.lock       # process-wide lock
  doctor/              # optional diagnostic exports
```

`server.data_path` accepts either a directory or a database file path:

- if the final path component ends in `.db`, it is the database file, used
  verbatim — `/var/lib/cachette/data.db`, or even `.../.db` with an empty
  stem;
- otherwise it is a directory and the database is `<dir>/cachette.db`.

Only the last component is checked, so a parent directory named `*.db` does
not turn a nested path into a file. When unset, the path defaults to the
config file's directory (`/etc/cachette` on Linux, `/config` in Docker,
`%APPDATA%\cachette` on Windows). Non-database state is stored in the
database file's parent directory in all cases.

A legacy single-filesystem config keeps its state at the old `[storage.fs]
path`; migration sets `server.data_path` to that path explicitly so nothing
moves on upgrade. A `data_path` that equals or contains a storage root logs a
warning — state and payloads in one tree make `du` misleading and let a sweep
reach state. The legacy case is the expected exception.

One server owns one control database; peers never share a file or connection.
Named instances are isolated inside it by derivation: their entry ids hash the
instance together with the namespace and key, and their accounting/chunk rows
use an instance-prefixed namespace key. The legacy `default` instance keeps the
v1.1/v1.2 derivation verbatim, so pre-v1.3 rows stay reachable without a
rewrite. Moving an existing state directory is an offline operation, never an
automatic copy at boot.

## Quotas

Storage owns capacity — the disk total or `server.max_size`, the `min_free`
floor, and when cleanup runs. Quotas own limits: `[[quota]]` caps a whole
instance or a resolved namespace, with exact or wildcard targets; the most
specific rule wins. An over-quota namespace is evicted first (worst excess
first, LRU within it), before the global free-space floor reclaims anything.
`eviction = "none"` leaves quotas advisory.

In a cluster, quota resolution is semi-binding. Each peer advertises its
configured rules and its usage in the heartbeat. For each `(scope, target)`:

1. a server's own configured rule always wins;
2. otherwise the value with the most votes becomes the fallback — one vote
   per server per target, with **abstention** meaning "no rule configured".
   At least **two agreeing peers** are required; a lone vote or a tie means
   no consensus, so one bad peer cannot impose a quota;
3. otherwise no quota applies.

A single configured server among abstainers sets the cluster value for that
target. In this release the heartbeat still publishes one aggregate usage row
for the default instance; peer usage is stored by `(instance, namespace)` but
is **not** summed into admission control, and key-bearing v3 requests do not
carry an instance name. Treat cluster quotas as rule consensus only, not as
an enforced shared budget. Adding instances can therefore multiply capacity,
and eventual gossip convergence allows a small overshoot. A server that loses
its consensus view falls back to its own rules (or none).

Quota rules and usage piggyback on the existing heartbeat. A dedicated gossip
protocol is planned as a follow-up. Peer protocol version 3 carries the
instance name on key-bearing requests; a v2 peer receives `426 Upgrade
Required` and is excluded from placement, so a mixed cluster drains instead
of risking cross-tenant writes.

## Operations and reload

`cachette doctor` and `--print-config` list every instance, its floor and its
route rules, with secrets masked. Offline commands (`gc`, `verify`, `cache`)
take `--storage <name>`, default to `default`, and acquire that instance's
lock. SIGHUP reloads routes and quotas; instances and forge auth blocks need a
restart.

`cachette config example` prints the generated example config. It comes from
a declarative schema with one renderer, so every knob and default is present
and new fields cannot be forgotten.

### Upgrading from v1.2

A legacy config still boots with one `default` instance, the old payload
path, the old state path and the legacy namespace. Migration is optional for
a plain upgrade and required before using new storage, per-forge auth or
quota features. All migration work is offline and explicit.

`doctor --migrate <file>` performs the full sequence: back up the config and
state, write the new config in place, then move payloads and state according
to it. `--let-me-edit` pauses after the config write and before any file
moves so the generated config can be edited first. `doctor --migrate-config
<file>` writes the proposed config to `<file>.bak` and leaves the original
untouched; adding `--write` replaces the original and backs it up.

Migration starts from the generated example and populates the values found in
the old config. Keys it cannot map are appended at the end, commented out,
with their original position and a note about what replaced them. Nothing is
silently dropped. Old config is copied verbatim to `<file>.bak` before any
write, and an existing `.bak` is never overwritten. Data-moving commands
write a verified `<state dir>.<timestamp>.snapshot` directory copy with a
BLAKE3 manifest before touching files; `cachette state restore <snapshot>
--to <state dir>` verifies and restores it. Deleting source data is a separate
explicit command, never part of migration.

Actions are grouped into warning tiers:

1. **NOTICE** — mechanical key moves, listed without a gate.
2. **CAUTION** — changes to auth, identity or placement; `--write` requires
   `--ack-caution`.
3. **DANGER** — overwrites or file moves; requires a typed `--confirm
   migrate-state`, `--confirm migrate-layout` or `--confirm retag-namespaces`
   and a verified backup.
4. **IRREVERSIBLE** — source deletion, only via a separate command after a
   successful migration and verification.

Every report prints the full plan first and ends with a machine-readable
summary and exit code. Setting `CACHETTE_AUTO_MIGRATE_CONFIG=1` makes cachette
write a reviewed `<file>.migrated` copy, log a loud danger warning, and exit
nonzero; it never overwrites the original. `--print-config` on the result is
the final check before restarting.

Migration order: back up; generate the config (optionally edit it); move the
state directory if `data_path` changed; optionally convert the payload layout;
optionally re-tag legacy namespaces; drain and restart cluster peers one at a
time; then remove the long-lived buildx token from workflows once the runtime
plane is verified. Namespace re-tag accepts repeatable `--retag 'old=new'`
pairs or a TOML mapping file for bulk rewrites. Rollback at any earlier step
is a stop plus restore of the two backups; layout and re-tag steps are
additive and can be deferred.

## See also

- [Configuration reference](configuration.md) — every key and default.
- [Multi-tenant shared cache](shared-cache.md) — identities, namespaces and
  credential planes.
- [Per-forge authentication](hmac-tenancy.md) — HMAC, runtime tokens and OIDC
  in one block per forge.
- [Clustering](cluster.md) — discovery, pinning and placement.
