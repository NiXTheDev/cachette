# Configuration

cachette is configured by a single TOML file plus optional environment
overrides. This page is the full reference; the README has a compact table.

## Load order

1. `--config <path>` if given. An explicit path that does not exist is a hard
   error (no silent fallback).
2. Otherwise the platform default file, if it exists:
   `/etc/cachette/cachette.toml` (*nix), `%APPDATA%\cachette\cachette.toml`
   (Windows), or `/config/cachette.toml` (Docker image).
3. If neither exists, the built-in defaults are used.
4. `CACHETTE__*` environment variables are applied last and win over the file.

Unknown keys, unknown `CACHETTE__*` variables, wrong types, and values outside
their allowed set are all hard errors that name the offending key or variable.
This is deliberate: a typo fails the boot instead of silently keeping a default.

## Reference

Closed sets (enums) are validated at parse time; structural rules (below) at
`load` time.

### `[server]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `listen` | string | `"0.0.0.0:8080"` | `host:port`; IPv6 literals bracketed, e.g. `[::1]:8080`. |
| `external_url` | string | derived | Absolute base URL advertised to clients. When unset it is derived from `listen` as `http://<host>:<port>`, with a wildcard host mapped to loopback (`0.0.0.0` -> `127.0.0.1`, `::` -> `[::1]`). Set it explicitly to your public `https://...` when a reverse proxy terminates TLS, so the v1 `archiveLocation` and v2 capability URLs are absolute and correct. |
| `tls_cert` | path | unset | PEM certificate. Must be set together with `tls_key`. |
| `tls_key` | path | unset | PEM private key. Must be set together with `tls_cert`. |

When `tls_cert`/`tls_key` are unset, the server uses the node identity
certificate minted on first boot (see [cluster.md](cluster.md)).

### `[storage]` and `[storage.fs]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `storage.backend` | `fs` | `fs` | The filesystem backend is the only one in this release. |
| `storage.fs.path` | path | `"/var/lib/cachette"` | Blob root. The SQLite index and the default identity directory live here. |
| `storage.fs.min_free` | fraction / percent / bytesize | `0.2` | Free-space floor before eviction triggers. |

`min_free` accepts three forms:

- a fraction between `0` and `1` (exclusive) as a bare number: `min_free = 0.2`
- a percent string: `min_free = "20%"`
- a bytesize string, **1024-based** (so `GB` == `GiB`): `min_free = "2GiB"` or
  `min_free = "2GB"`

A bare word such as `min_free = "abc"` and an out-of-range fraction are
rejected. Set an explicit `path` on Windows; the default is a Unix-style path.

### `[cache]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `max_size` | integer | `0` | Maximum cache size in bytes; `0` means unlimited (the disk total is used for capacity). |
| `eviction` | `lru` / `oldest` / `none` | `lru` | `lru` and `oldest` reclaim space down to the free-space floor; `none` refuses a new reservation when below the floor instead. |
| `key_case` | `lower` / `preserve` | `lower` | Key normalization before exact and prefix matching. |
| `reservation_ttl_seconds` | integer | `3600` | Reservation lifetime; must be greater than `0`. Expired reservations and their partial chunk files are reaped. |

### `[auth]`, `[v1]`, `[v2]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `auth.mode` | `hmac` / `bearer` / `merge` | `merge` | See the auth modes table in the README. |
| `auth.secret` | string | unset | Shared secret for HMAC and (by fallback) the Twirp JWT. **Required to serve**, minimum 16 characters. Only `--print-config` tolerates an unset secret. |
| `auth.tokens` | list of strings | `[]` | Static bearer tokens. |
| `auth.hmac_max_age_seconds` | integer | `600` | Maximum age of an HMAC signature; `0` disables the staleness check. A timestamp more than 5 seconds in the future is always rejected. |
| `v1.signed_url_ttl_seconds` | integer | `900` | TTL for v1 `archiveLocation` tokens **and** v2 capability URLs. |
| `v2.jwt_secret` | string | falls back to `auth.secret` | HS256 secret used to validate the Twirp JWT. |
| `v2.jwt_ttl_seconds` | integer | `300` | TTL for the self-minted Twirp JWT. |

### `[cluster]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | boolean | `false` | Off means a standalone node. |
| `node_id` | string | unset | Human label for the node; falls back to the identity fingerprint. |
| `advertise_addr` | `host:port` | `server.listen` | Address peers dial for this node. |
| `mdns` | boolean | `true` | Advertise and browse `_cachette._tcp.local.` on the local link. |
| `seeds` | list of `host[:port]` | `[]` | Peers to contact directly. A missing port defaults to the `server.listen` port. |
| `seed_fingerprints` | map `node_id -> hex` | `{}` | Pinned peer certificate fingerprints. |
| `tiebreak` | `random` / `roundrobin` / `progressive` | `random` | How to break ties between equally least-loaded nodes. |
| `cert_path` | path | `<storage.fs.path>/identity` | Identity directory. Must not equal `storage.fs.path`. |
| `heartbeat_interval_seconds` | integer | `5` | How often this node heartbeats its peers. |
| `peer_timeout_seconds` | integer | `15` | Peers that stop heartbeating within this window are treated as unhealthy. |

### `[log]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `level` | `trace` / `debug` / `info` / `warn` / `error` | `info` | The default tracing filter. An explicitly set `RUST_LOG` still wins. |
| `format` | `text` / `json` | `text` | `json` emits one JSON object per line for log shippers. |

## Environment overrides

Names use `CACHETTE__SECTION__KEY` with a double underscore between segments and
are case-insensitive. Nested sections keep their double underscores, e.g.
`CACHETTE__STORAGE__FS__PATH`.

| Shape | How to write it | Example |
|---|---|---|
| Scalar | the raw text | `CACHETTE__CACHE__MAX_SIZE="1024"` |
| Boolean | `true` or `false` | `CACHETTE__CLUSTER__ENABLED="true"` |
| Integer | an unsigned integer | `CACHETTE__V2__JWT_TTL_SECONDS="300"` |
| List | comma-separated; spaces trimmed; empty items dropped | `CACHETTE__AUTH__TOKENS="token-one, token-two"` |
| `min_free` | a number (fraction) or a string form | `CACHETTE__STORAGE__FS__MIN_FREE="20%"` |
| Map | a JSON object of string values | `CACHETTE__CLUSTER__SEED_FINGERPRINTS='{"cache-a":"AA11","cache-b":"BB22"}'` |

A variable with no section prefix that matches exactly one field name is also
accepted, e.g. `CACHETTE__LISTEN` or `CACHETTE__ENABLED`. A `CACHETTE__*`
variable that maps to no known key is a hard error naming the variable, while
non-`CACHETTE` variables are ignored.

```bash
# A complete override set for a container, with no config file at all:
export CACHETTE__SERVER__LISTEN="0.0.0.0:8080"
export CACHETTE__SERVER__EXTERNAL_URL="https://cache.example.com"
export CACHETTE__STORAGE__FS__PATH="/var/lib/cachette"
export CACHETTE__STORAGE__FS__MIN_FREE="2GiB"
export CACHETTE__CACHE__MAX_SIZE="0"
export CACHETTE__CACHE__EVICTION="lru"
export CACHETTE__AUTH__MODE="merge"
export CACHETTE__AUTH__SECRET="change-me-to-16-plus-chars"
export CACHETTE__AUTH__TOKENS="token-one,token-two"
export CACHETTE__LOG__LEVEL="info"
./cachette --print-config
```

## Validation rules

- `auth.secret` must be set and at least 16 characters before the server will
  serve. `--print-config` bypasses this check.
- `server.listen` must parse as `host:port` (IPv6 literals bracketed).
- `server.tls_cert` and `server.tls_key` must be set together.
- `storage.fs.path` must not be empty.
- `cache.reservation_ttl_seconds` must be greater than `0`.
- `cluster.cert_path` must not equal `storage.fs.path`.

## Inspecting the resolved configuration

`--print-config` resolves the file and environment, applies derived defaults,
and prints the result as JSON with every secret masked as `***`
(`auth.secret`, each item of `auth.tokens`, and `v2.jwt_secret`):

```bash
./cachette --config /etc/cachette/cachette.toml --print-config
```

## A fuller example

```toml
[server]
listen = "0.0.0.0:8080"
external_url = "https://cache.example.com"

[storage]
backend = "fs"

[storage.fs]
path = "/var/lib/cachette"
min_free = "2GiB"

[cache]
max_size = 0
eviction = "lru"
key_case = "lower"
reservation_ttl_seconds = 3600

[auth]
mode = "merge"
secret = "change-me-to-16-plus-chars"
tokens = []
hmac_max_age_seconds = 600

[v1]
signed_url_ttl_seconds = 900

[v2]
jwt_ttl_seconds = 300

[cluster]
enabled = false
mdns = true
seeds = []
seed_fingerprints = {}

[log]
level = "info"
format = "text"
```
</content>
</invoke>
