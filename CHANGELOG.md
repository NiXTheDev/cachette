# Changelog

All notable changes to cachette are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning with the major digit reserved for truly breaking silently-incompatible changes. Design contracts live in `docs/`. Dates are the release commits' dates (Hangar publish timestamps can differ by a day).

## [1.3.0] - 2026-11-23

*Stick it to the ceiling for all I care! It's storage-a-nanza baby!*

v1.3 turns one cache into a storage plane. Several named instances sit behind one control database, namespaces route to them, and the backends advertise what they can do instead of pretending every store is a local disk.

### Added

- **Multiple storage instances.** `[[storage.instances]]` declares named `fs` roots, network mounts or remote stores. `[storage.routes]` maps resolved namespaces by exact match, longest glob, `"*"` and then `default`; routes and `[[quota]]` rules reload on SIGHUP while the instance set is boot-only. One server owns one SQLite control database at `server.data_path`.
- **Storage backends with capabilities.** `fs` (including OS-mounted SMB/NFS/WebDAV) supports CDC and ranged reads. Native S3, Azure Blob, direct WebDAV, FTP, SFTP and copyparty up2k backends store whole blobs with a sparse local read-through cache; `StorageBackend::capabilities()` drives validation, so CDC is refused for stores that cannot hold chunk manifests. S3 and Azure sign requests in-process with credentials from the usual AWS/Azure environment variables. copyparty hashes with up2k's SHA-512 chunk scheme and uploads only the chunks the server is missing, benefiting from its hardlink dedup. FTP uses passive mode with `REST` for ranges; SFTP drives the system `sftp` client with key/agent auth (no new SSH dependency).
- **Per-forge authentication.** `[auth.forge.<label>]` carries HMAC, runtime-token and OIDC settings together. A signed runner-repo header yields that forge and repository as the tenant, so `auth.mode = "merge"` is valid next to the OIDC and runtime planes; HMAC wins when both HMAC headers and a Bearer token are present. Legacy tables keep working with a boot-time deprecation warning.
- **Offline migration tooling.** `doctor --migrate` and `doctor --migrate-config [--write]` plan or write a v1.3 config and move state with verified BLAKE3-manifest snapshots. `state migrate/restore/retag/delete-source` are separate explicit commands with NOTICE/CAUTION/DANGER/IRREVERSIBLE tiers and typed confirmations.
- **Cluster protocol 3.** Quota rules and per-namespace usage ride on heartbeats; local rules win, otherwise a plurality vote per target supplies the fallback, abstentions are ignored and stale reports are discarded. v2 peers get `426 Upgrade Required`.
- **Generated configuration example.** `cachette config example` and the checked-in example come from one declarative schema and renderer, so every knob and default is present. Secrets are masked in `--print-config`.

### Changed

- **State moved under `server.data_path`.** A `.db` final component is the database file verbatim; otherwise the database is `<dir>/cachette.db`. The control database, token store, identity and lock no longer live in a payload root.
- **Release metadata.** Release bodies are generated from this changelog and a shared template at publish time; CI uses current buildx/actions pins and cross-builds the arm64 Windows legs on amd64 hosts.

### Upgrading

A legacy config still boots with one `default` instance, the old payload path, the old state path and the legacy namespace. Use `cachette doctor --migrate-config` to review the generated v1.3 config, then `doctor --migrate` for the state move; both are offline and explicitly confirmed. Payload-layout conversion stays a follow-up: the hashed `blobs/parts/chunks` layout is unchanged in v1.3. See `docs/multi-storage.md` for instances, routes and backends, and `docs/hmac-tenancy.md` for per-forge credentials.

## [1.2.0] - 2026-11-21

*One cache, many forges: credentials choose namespaces, quotas bound them, and peers without protocol v2 get 426.*

v1.2 makes the namespace the unit of identity. One cachette, one cluster, many forges - and the tenant comes from the CREDENTIAL, never from the request. The v1 key scope is client-controlled, and the HMAC payload's `<repo>><run>` is client-asserted, so neither can carry an identity the server can trust. Now they do not have to.

### Added

- **Namespaced storage.** Schema v3 adds a `namespace` to each row; the same key in two namespaces is two isolated entries with two payloads, and the legacy namespace keeps the v1.1 id derivation verbatim so existing rows and blob files stay reachable. A verified migration backfills pre-v1.2 rows; a newer index is refused at boot.
- **Per-request namespace resolution.** Credentials resolve to a namespace in the auth gate and every client-facing handler addresses storage through a `scoped()` view. Admin mappings in `[storage.namespaces]` can fold identities into a shared namespace. Capability URLs MAC-bind the resolved namespace (a stripped or swapped `ns` is a mismatch; pre-namespace URLs stay valid).
- **Per-namespace quotas.** `[storage.quotas]` sets a `default` plus exact or tenant-side wildcard rules, most-specific wins. An over-quota namespace is evicted first (worst excess first, LRU within it), before the global `min_free` floor reclaims anything; `eviction = "none"` leaves quotas advisory. v1 `cacheSize` reports the tenant's quota window narrowed by the global budget, and a periodic sweep enforces quotas continuously.
- **Forge runtime tokens (Plane B).** `[auth.runtime."<forge>"]` verifies HS256 tokens signed by a forge's general token secret (read from a file at boot, empty/unreadable is fatal), with a configurable tenant claim, scope allow-list and claim pins. Runtime tokens are tried before OIDC, so an HS256 token never reaches the RS256 verifier.
- **Namespace-aware cluster wire.** Every key-bearing peer request carries the resolved namespace and `x-cachette-peer-protocol: 2`. A missing or different version is refused with `426 Upgrade Required` (hello and heartbeat included), so a mixed cluster drains to "no healthy peer" instead of merging tenants' rows. Multi-tenant + cluster is now supported.
- **CDC completion (B-3).** The zero-ref purge consults the referring entry's layout and namespaces (a complete `chunked` manifest is a referrer even if `refs` drifted; referrers from any namespace count). Crash bounds for whole-to-chunked conversion converge under boot + sweep with `used_bytes` on the at-rest invariant.

### Changed

- **OIDC is per issuer.** `[auth.oidc."<issuer>"]` carries its own audiences, tenant claim, claim pins, trust roots and clock skew; the v1.1 flat table is rejected with a precise error naming the new form. `nbf` is optional as RFC 7519 requires; a present but non-numeric `nbf` is still a structural failure.
- **Boot guard.** A tenant-yielding plane (OIDC or runtime) requires `auth.mode = "bearer"`; HMAC stays single-tenant and is refused in a multi-tenant boot. Cluster mode is allowed with the namespace-bearing wire.
- **Build and CI.** Rust 1.100 and Zig 0.17.1; every external `uses:` still resolves to hangar mirrors. The rustup mirror ladder now probes the pinned channel manifest instead of `stable`, so a mirror that lacks 1.100 cannot win the race and 404 the toolchain install.

### Upgrading

with no tenant-yielding plane configured, every credential still resolves to the legacy namespace and single-tenant deployments are byte-identical. Existing OIDC configs must move to the per-issuer block shape (the boot error names the new form), and a tenant-yielding plane requires `auth.mode = "bearer"` - HMAC stays single-tenant and is refused in a multi-tenant boot rather than degraded. See `docs/shared-cache.md` for the tenancy model and migration notes.

## [1.1.0] - 2026-11-15

### Added

- **OIDC bearer auth.** RS256-only verification against your IdP's JWKS, kid routing, a cache that survives rotation via prefetch + lazy singleflight, and fail-closed gates. Enabled through the flat `[auth.oidc]` table (`issuers`, `audiences`, `jwks_urls`, `require`).
- **Self-minted HS256 bearer JWTs** verified by signature in the v1 gate, in addition to static and dynamically registered tokens (`cachette token mint`).
- **Content-defined chunking (CDC).** The `gear-fastcdc-v1` splitter, `[storage.cdc]` chunk storage alongside the whole-blob layout, refs-counted accounting, a GC sweeper, a paced whole-to-chunked backfill walker, and a layout-aware read path — all opt-in.
- **Versioned schema migrations.** The index records a schema version, applies verified migrations at boot, and refuses an index newer than the binary.
- **Eight-target release matrix** with pinned cross toolchains and a registry-published multi-arch image; all external actions mirrored.

## [1.0.0] - 2026-10-25

Initial release (`cc76396`).

### Added

- One static binary serving the legacy v1 `artifactcache` REST API and the v2 Twirp `CacheService` API (plus the Azure block-blob upload emulation) on a runner-facing port, with a dedicated mTLS peer port for clustering.
- Filesystem storage with a SQLite index, chunked resumable v1 uploads, reservation TTL reaping, and capacity-based eviction (`lru`, `oldest`, `none`, with fraction/percent/bytesize `min_free`).
- Signed capability URLs (`?id&exp&mac`) for downloads and v2 block uploads.
- HMAC and static/dynamic bearer authentication, admin token register/revoke, and hot config reload on `SIGHUP`.
- Peer-to-peer clustering: static seeds, mDNS discovery, fingerprint pinning with TOFU, capacity-aware placement, heartbeats, graceful drain, and owner-side relayed uploads.
- Self-signed Ed25519 node identity that survives restarts and storage wipes, plus `cachette doctor`, `gc`, `verify`, `cache`, and `identity` CLI commands.
- TLS recipes and a Docker image; CI dogfoods a live cachette for its `docker buildx` layer cache.

[1.3.0]: https://hangar.nixthedev.ru/NiXTheDev/cachette/pulls/18 [1.2.0]: https://hangar.nixthedev.ru/NiXTheDev/cachette/pulls/13 [1.1.0]: https://hangar.nixthedev.ru/NiXTheDev/cachette/releases/tag/v1.1.0 [1.0.0]: https://hangar.nixthedev.ru/NiXTheDev/cachette/releases/tag/v1.0.0
