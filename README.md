# cachette

A small, self-contained GitHub Actions **cache server**: one static binary that
serves both the legacy `artifactcache` v1 REST API (what Forgejo `act_runner`
speaks) and the v2 Twirp `CacheService` API (what the GitHub Actions toolkit
and `docker buildx --cache-to type=gha` speak) over a single, always-TLS port.

- Blobs live on the local filesystem under a directory you choose; metadata and
  usage accounting live in a SQLite file beside them.
- One listener serves every route. TLS is never optional.
- Auth is a shared secret: Forgejo HMAC headers, bearer tokens, or both.
- Optional peer-to-peer clustering discovers nodes, tracks capacity, and places
  a cache write on the least-loaded healthy owner.

## Features

- **Dual protocol on one port.** v1 `/_apis/artifactcache/*` and v2
  `/twirp/github.actions.results.api.v1.CacheService/*` (plus the v2 Azure
  block-blob upload emulation) are served by the same binary.
- **Chunked, resumable uploads.** v1 `PATCH` chunks are staged and committed;
  abandoned reservations are reaped on a timer.
- **Capacity model with eviction.** `lru`, `oldest`, or `none`, driven by a
  `min_free` free-space floor that accepts a fraction, a percent, or a byte
  size.
- **Signed capability URLs.** Downloads are authorized by a short-lived
  `?id&exp&mac` HMAC token; there is no anonymous read path.
- **Cluster placement.** Seed peers by address and pin their certificate
  fingerprints; the entry node streams a v1 upload to the least-loaded healthy
  owner over pinned mTLS (the blob bytes never touch the entry node).
- **Self-signed node identity.** First boot mints an Ed25519 keypair and
  certificate; the fingerprint is stable across restarts and storage wipes.

## Quickstart

1. Build (or download) the `cachette` binary. The only runtime requirement is
   the binary itself; the filesystem storage backend and SQLite index are built
   in.

2. Write a config file. At minimum, set a storage path and an auth secret of at
   least 16 characters:

   ```toml
   [server]
   listen = "0.0.0.0:8080"
   # Set this to your public URL when a proxy terminates TLS for you, so the
   # archive/capability URLs handed to clients are absolute and correct:
   external_url = "https://cache.example.com"

   [storage.fs]
   path = "/var/lib/cachette"

   [auth]
   mode = "merge"
   secret = "change-me-to-16-plus-chars"
   ```

3. Start it:

   ```bash
   ./cachette --config /etc/cachette/cachette.toml
   ```

   On the first boot the server mints a node identity under the storage path
   (or `cluster.cert_path`), then prints a readiness line:

   ```text
   cachette listening on http://0.0.0.0:8080
   ```

4. Check liveness. The main listener is plain HTTP unless a
   `[server] tls_cert`/`tls_key` pair is configured:

   ```bash
   curl http://127.0.0.1:8080/health
   # {"version":"0.1.0","node_id":"<64-hex fingerprint>"}
   ```

   `GET /metrics` on the same listener returns the Prometheus text-format
   counters (`requests_total{route,code}`, `bytes_in`, `bytes_out`,
   `evictions_total`, `reservations_active`, `storage_used_bytes`):

   ```bash
   curl http://127.0.0.1:8080/metrics
   ```

   If TLS is enabled on the listener, probe it with `curl -k https://...`
   (supply a CA-trusted certificate through `server.tls_cert`/`server.tls_key`
   for real clients); see [docs/tls.md](docs/tls.md).

5. Point your runner at it. See [docs/forgejo.md](docs/forgejo.md) for Forgejo
   `act_runner`, [docs/clients.md](docs/clients.md) for the GitHub toolkit and
   `docker buildx --cache-to type=gha`, and [compose.yaml](compose.yaml) for a
   container sample.

## Configuration

Configuration is a single TOML file. Every key is denied if unknown: a typo or a
key from a newer release is a hard startup error, not a silent default.

### Default config locations

When `--config` is not passed, cachette looks for `cachette.toml` in a
platform-specific directory. An explicit `--config <path>` always overrides the
default (and a missing explicit path is an error rather than a silent
fallback).

| Platform | Directory | File |
|---|---|---|
| Linux / BSD / macOS | `/etc/cachette` | `/etc/cachette/cachette.toml` |
| Windows | `%APPDATA%\cachette` | `%APPDATA%\cachette\cachette.toml` |
| Docker image | `/config` | `/config/cachette.toml` |

If no default file is present, cachette starts on the built-in defaults (and
still refuses to serve until `auth.secret` is set). A ready-to-edit file with
every key and its default is [cachette.example.toml](cachette.example.toml).

### Configuration reference

Compact view; [docs/configuration.md](docs/configuration.md) has the full
reference, valid-value notes, and examples.

| Section | Key | Value | Default |
|---|---|---|---|
| `server` | `listen` | `host:port` (IPv6 as `[::1]:8080`) | `0.0.0.0:8080` |
| `server` | `external_url` | absolute URL advertised to clients | derived from `listen` as `http://<host>:<port>` (wildcard host becomes loopback) |
| `server` | `tls_cert` | PEM certificate path (with `tls_key`) | unset (listener is plain HTTP) |
| `server` | `tls_key` | PEM private-key path (with `tls_cert`) | unset |
| `storage` | `backend` | `fs` | `fs` |
| `storage.fs` | `path` | blob root directory | `/var/lib/cachette` |
| `storage.fs` | `min_free` | fraction (`0.2`), percent (`"20%"`), or bytesize (`"2GiB"`/`"2GB"`, 1024-based) | `0.2` |
| `cache` | `max_size` | bytes, `0` = unlimited | `0` |
| `cache` | `eviction` | `lru`, `oldest`, `none` | `lru` |
| `cache` | `key_case` | `lower`, `preserve` | `preserve` |
| `cache` | `reservation_ttl_seconds` | seconds, must be `> 0` | `3600` |
| `auth` | `mode` | `hmac`, `bearer`, `merge` | `merge` |
| `auth` | `secret` | 16+ characters, required to serve | unset |
| `auth` | `tokens` | list of static bearer tokens | `[]` |
| `auth` | `hmac_max_age_seconds` | seconds, `0` = disabled | `600` |
| `v1` | `signed_url_ttl_seconds` | seconds (governs v1 and v2 capability URLs) | `900` |
| `v2` | `jwt_secret` | HS256 secret (falls back to `auth.secret`) | unset |
| `v2` | `jwt_ttl_seconds` | seconds (governs the Twirp JWT) | `300` |
| `cluster` | `enabled` | boolean | `false` |
| `cluster` | `node_id` | string label | unset (uses the identity fingerprint) |
| `cluster` | `listen` | `host:port` dedicated mTLS peer listener | `0.0.0.0:8081` |
| `cluster` | `advertise_addr` | `host:port` peers dial | `cluster.listen` |
| `cluster` | `mdns` | boolean | `true` |
| `cluster` | `seeds` | list of `host[:port]` | `[]` |
| `cluster` | `seed_fingerprints` | map of `node_id` to hex fingerprint | `{}` |
| `cluster` | `tiebreak` | `random`, `roundrobin`, `progressive` | `random` |
| `cluster` | `cert_path` | identity directory | `<storage.fs.path>/identity` |
| `cluster` | `heartbeat_interval_seconds` | seconds | `5` |
| `cluster` | `peer_timeout_seconds` | seconds | `15` |
| `log` | `level` | `trace`, `debug`, `info`, `warn`, `error` | `info` |
| `log` | `format` | `text`, `json` | `text` |

### Environment overrides

Every key can be set or overridden by an environment variable; environment
values win over the file. The convention is `CACHETTE__SECTION__KEY`
(double underscore between segments), and names are case-insensitive:

```bash
export CACHETTE__SERVER__LISTEN="0.0.0.0:8080"
export CACHETTE__AUTH__MODE="merge"
export CACHETTE__AUTH__SECRET="change-me-to-16-plus-chars"
./cachette --print-config
```

- **Scalars** are written as text (`CACHETTE__CACHE__MAX_SIZE="1024"`).
  Booleans are `true`/`false`; unsigned integers must parse as an unsigned
  integer.
- **Lists** are comma-separated, with surrounding spaces trimmed and empty
  items dropped:
  `CACHETTE__AUTH__TOKENS="token-one, token-two"` and
  `CACHETTE__CLUSTER__SEEDS="cache-a:8080,cache-b:8080"`.
- **Maps** are a JSON object of string values:
  `CACHETTE__CLUSTER__SEED_FINGERPRINTS='{"cache-a":"AA11","cache-b":"BB22"}'`.
- **Bare keys** without a section prefix-match a unique field name, e.g.
  `CACHETTE__LISTEN` and `CACHETTE__ENABLED`.
- A `CACHETTE__*` variable that maps to no known key is a hard error that names
  the offending variable; non-`CACHETTE` variables are ignored.

### Live reload

`cachette serve` re-reads the config file on `SIGHUP` (Unix) without dropping
connections. Reloadable: `[auth]` (`mode`, `secret`, `tokens`,
`hmac_max_age_seconds`), the per-request `[cache]`/`[storage.fs]` admission
numbers (`max_size`, `min_free`, `reservation_ttl_seconds`, `key_case`,
`signed_url_ttl_seconds`, `max_chunk_bytes`), and `[log] level`. Boot-only
(listener, storage backend and data directory, cluster wiring, `[v2]` JWT
secret) — restart to change. A malformed file is rejected and the previous
config stays in effect. See
[docs/configuration.md](docs/configuration.md#live-reload).

## CLI usage

```text
cachette [OPTIONS] [COMMAND]

Commands:
  identity            Print the node fingerprint and identity certificate path
  identity rotate     Renew the certificate for the same key (fingerprint unchanged)
  verify              Recompute every published entry's digest and report mismatches
  cache list          List finalized cache entries (--json for machine output)
  cache prune         Delete entries not accessed within --older-than <dur>
  gc                  Run the reservation reaper + orphan-blob sweep once, then exit
  doctor              Check config, storage, SQLite, identity, seeds, and disk
  token mint          Print a Forgejo artifactcache HMAC token for the secret
  cluster status      Print the live cluster member table from a running server

Options:
  --config <path>   Path to a TOML config file (overrides the platform default)
  --print-config    Print the resolved configuration (secrets masked) and exit
  -h, --help        Print help
  -V, --version     Print version
```

- `cachette --print-config` resolves the file plus environment, then prints the
  effective configuration as JSON with every secret field masked as `***`. It
  succeeds even when `auth.secret` is unset.
- `cachette identity` prints the node fingerprint and the identity certificate
  path, minting the identity on first run. Use it to collect
  `cluster.seed_fingerprints` values.
- `cachette identity rotate` re-issues the identity certificate for the *same*
  key with a refreshed validity window, then prints the (unchanged) fingerprint
  and cert path. Because a pin is the key's SPKI fingerprint — not the
  certificate, whose validity window peers ignore — every existing
  `cluster.seed_fingerprints` entry stays valid: no re-seed, no cluster
  coordination. It exits non-zero when the identity is missing; it never mints
  a new key, which would change the fingerprint.
- `cachette verify` re-hashes every published blob against the digest recorded at
  publish time (plan task 50) and exits non-zero, naming each corrupt / missing /
  size-mismatched entry.
- `cachette cache list [--json]` and `cachette cache prune --older-than 7d`
  inspect and selectively evict entries through the same storage path the server
  uses. `--dry-run` reports without deleting.
- `cachette gc` runs one TTL-reaper + orphan-blob sweep (the same pass the server
  runs periodically) and exits.
- `cachette doctor` is a read-only health check: config, writable data dir,
  SQLite `PRAGMA integrity_check`, identity fingerprint, seed reachability, and
  disk headroom. It exits non-zero when any check fails.
- `cachette token mint --scope read|write [--repo owner/repo] [--run N]` prints
  the `Forgejo-Cache-*` header values for the configured `auth.secret`, so an
  operator never hand-rolls the HMAC.
- `cachette cluster status [--watch]` reads the live member table from a running
  server over a loopback admin endpoint. It is the only subcommand that needs a
  live server.
- `verify`, `cache`, and `gc` take an exclusive lock on the data directory and
  refuse with a clear message while a server (or another ops command) holds it.
  `doctor` and `token mint` never touch the data directory and do not lock.
- `cachette --version` prints `cachette 0.1.0`.
- A configuration error exits with status `2`.

## Authentication

Requests never fall through to anonymous access: a missing or invalid
credential is `401 {"error":"authentication required"}`.

### Auth modes

| `auth.mode` | v1 `/_apis/artifactcache/*` | v2 Twirp `CacheService` | Capability URLs (`/v2/upload`, `/v2/artifacts`) |
|---|---|---|---|
| `hmac` | `Forgejo-Cache-*` HMAC headers only | static/dynamic bearer tokens; self-minted JWT rejected | signed `?id&exp&mac` |
| `bearer` | `Authorization: Bearer <token>` | static/dynamic bearer token, or a self-minted HS256 JWT | signed `?id&exp&mac` |
| `merge` | HMAC headers **or** bearer token | static/dynamic bearer token, or a self-minted HS256 JWT | signed `?id&exp&mac` |

Notes:

- A **static** token is any string in `[auth] tokens`; a **dynamic** token is
  registered at runtime through `POST /_internal/register?token=<token>` and
  revoked with `POST /_internal/revoke?token=<token>`. Those admin routes accept
  `Authorization: Bearer <auth.secret>`, or are loopback-only while cluster mode
  is disabled.
- The v2 capability URLs (`/v2/upload/{id}`, `/v2/artifacts/{id}`) are
  authorized **only** by their signed URL, never by a bearer token.
- Artifact **downloads** on v1 are likewise authorized by the signed
  `archiveLocation`; both real clients fetch it with no `Authorization` header.

### Capability URL security

A signed URL carries `?id=<id>&exp=<unix>&mac=<hex>`, where
`mac = HMAC-SHA256(auth.secret, "{path}|{id}|{exp}")`. The resource path is
bound into the MAC, so any change to the path, id, or expiry fails with
`403 {"error":"invalid or expired url"}`.

- Two TTL knobs govern validity: `v1.signed_url_ttl_seconds` (default `900`)
  covers both the v1 `archiveLocation` and the v2 capability URLs;
  `v2.jwt_ttl_seconds` (default `300`) covers the Twirp JWT.
- Expiry is checked when the request starts; a transfer already in progress
  runs to completion.
- To revoke outstanding URLs and JWTs, rotate `auth.secret` (and `v2.jwt_secret`
  if you set one separately). Static bearer tokens in `[auth] tokens` are
  unaffected unless you also change the list.

Keep the TTL short and rotate the secret if a URL leaks.

## TLS in one minute

The main listener is plaintext HTTP unless a `[server] tls_cert`/`tls_key`
pair is configured: no implicit TLS to fight with, and a reverse proxy that
terminates the public TLS can forward to plain HTTP. When the pair is set, the
listener serves that certificate and clients need it CA-trusted (or a trust
override). Peers have their own dedicated listener — `[cluster] listen`
(default `0.0.0.0:8081`, bound only when `[cluster] enabled`), which always
terminates TLS with the self-signed node identity certificate; peer trust is a
fingerprint pin, not a CA chain. Recipes for nginx, Traefik, `ssh -L/-R`,
WireGuard, and proxy-level rate limiting are in
[docs/tls.md](docs/tls.md).

## Cluster

Set `[cluster] enabled = true`, list peers in `seeds`, and pin their
fingerprints in `seed_fingerprints`. Nodes discover each other, heartbeat their
capacity, and place each v1 cache write on the least-loaded healthy owner, which
streams the blob straight to that owner over pinned mTLS. Peers connect on the
dedicated `[cluster] listen` port (default `0.0.0.0:8081`), which always serves
the self-signed identity certificate — it is never the runner-facing port.
`cluster.mdns` advertises on the local link by default (disable it on a VPS with
no usable multicast interface). See [docs/cluster.md](docs/cluster.md).

## Documentation

- [docs/configuration.md](docs/configuration.md) - full configuration
  reference, environment overrides, validation, and logging.
- [docs/forgejo.md](docs/forgejo.md) - wiring a Forgejo `act_runner` cache
  proxy (v1 + HMAC).
- [docs/clients.md](docs/clients.md) - the GitHub Actions toolkit, `docker
  buildx --cache-to type=gha`, and GitHub/Gitea bearer auth.
- [docs/cluster.md](docs/cluster.md) - enable clustering, seeds, mDNS, pinning
  and trust-on-first-use, and placement.
- [docs/tls.md](docs/tls.md) - TLS edge recipes (nginx, Traefik, SSH tunnel,
  WireGuard) and rate limiting at the proxy.
- [docs/encrypted-storage.md](docs/encrypted-storage.md) - encrypting the
  storage volume with LUKS, ZFS, or BitLocker.

### CI & releases

Three Forgejo workflows (`.forgejo/workflows/`) take a commit from lint to
published artifact. `push-checks.yml` (every branch push) and `pr-checks.yml`
(pull requests to `release`) run the same gates: rustfmt/clippy, the workspace
tests including the v1 + v2 real-client round-trips (`node`/`npm`/`go` must be
present or the job fails), the example-config/compose lint, and the multi-node
cluster suites - followed by the docker job: a registry-published multi-arch
image (`linux/amd64` + `linux/arm64`, tags `0.1.0`/`0.1`/`0` + `latest` +
`release` read from `Cargo.toml`) on pushes to the `release` branch, and a
validation-only amd64 build everywhere else (no `:dev` tag waterfalls). Both
legs share a buildkit layer cache served by cachette itself (docker buildx
`type=gha` against the `acc.nixthedev.ru` cache; an unset
`CACHETTE_BUILDX_JWT` only means cache misses, never failures). `release.yml`
runs on `v*` tags and on pushes to the `release` branch: it cross-compiles the
four targets (linux/windows x amd64/arm64), writes `SHA256SUMS`, and attaches
the binaries + checksums to a release tagged `v<version>` - the pushed tag on a
tag build, or `Cargo.toml`'s package version on a `release`-branch build.
Merging a `feat/*` pull request into `release` therefore fires both pipelines
at once: the image publish and the release cut.

## Not in this release

These are intentionally out of scope for this version; cachette does not
advertise or require them:

- Chunk-level (content-addressed) deduplication between cache entries.
- Server-side (on-the-fly) compression of blob contents.
- Application-level encryption of blobs (transport is TLS, not the Noise
  protocol). Encrypt the storage volume instead (see
  [docs/encrypted-storage.md](docs/encrypted-storage.md)).
- Storage backends other than the local filesystem (no S3 or WebDAV).
- Replication of cache entries between nodes: each entry lives on the single
  node that owns it.

## License

See the repository for license information.
</content>
</invoke>
