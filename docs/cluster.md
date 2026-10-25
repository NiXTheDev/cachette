# Cluster mode

By default cachette is a standalone node. With `[cluster] enabled = true`
several nodes form a cluster: they discover each other, track capacity, and
place each cache write on the least-loaded healthy owner. The upload is streamed
to that owner over pinned mTLS, so the entry node that received the request never
stores the blob itself.

## What clustering does

- **Discovery.** Nodes learn about each other from `seeds` (direct addresses)
  and, when `mdns = true`, from `_cachette._tcp.local.` on the local link.
- **Health.** Every `heartbeat_interval_seconds` each node posts its live
  capacity to its peers; a peer that stops heartbeating for
  `peer_timeout_seconds` is treated as unhealthy and left out of placement.
- **Placement.** A cache write is placed on the least-loaded healthy node,
  using the capacity model below.
- **Relay.** The entry node forwards a v1 reservation, its `PATCH` chunks, and
  the commit to the winning owner over mTLS. Blob bytes go straight to the
  owner.

## Enabling a cluster

```toml
[server]
listen = "0.0.0.0:8080"
external_url = "https://cache.example.com"

[auth]
mode = "merge"
secret = "a-shared-16-plus-char-secret"

[cluster]
enabled = true
node_id = "cache-a"
listen = "0.0.0.0:8081"
advertise_addr = "cache-a.internal:8081"
mdns = false
seeds = ["cache-b.internal:8081", "cache-c.internal:8081"]
seed_fingerprints = {
  "cache-b" = "AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11",
  "cache-c" = "BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22",
}
tiebreak = "roundrobin"

[log]
level = "info"
```

Every node shares the same `[auth] secret` (and any static `[auth] tokens`) so
that a capability URL minted on one node validates on another.

## Node identity and fingerprints

On the first boot a node mints an Ed25519 keypair and a self-signed certificate
under `cluster.cert_path` (default `<storage.fs.path>/identity`). The identity
is stable: restarts and storage-directory wipes do not change it, because the
key and certificate live outside the blob root.

The node fingerprint is the uppercase hex SHA-256 of the certificate's public
key, 64 characters. Print it with:

```bash
./cachette --config /etc/cachette/cachette.toml identity
# fingerprint: AA11AA11...AA11
# cert_path: /var/lib/cachette/identity
```

Use `cachette identity` on each node to collect the fingerprints you put in
`cluster.seed_fingerprints`.

### Certificate rotation

`cachette identity rotate` renews the node certificate: it re-issues a
self-signed certificate for the **same key** with a fresh validity window. The
fingerprint is the SHA-256 of the key's public key (the SPKI), not of the
certificate, and the pinned verifiers ignore the certificate's `notAfter`, so
every `cluster.seed_fingerprints` entry — and every TOFU-learned pin — stays
valid across a renewal. Rotation is therefore purely **local**: no re-seed, no
cluster coordination, no restart ordering. The command refuses to run when the
identity is missing, because minting a new key would change the fingerprint.

Only rotating the **key pair** would change the fingerprint, which requires
re-seeding every peer's `cluster.seed_fingerprints`. That is out of scope for
`identity rotate`.

## Seeds

`cluster.seeds` is a list of `host:port` addresses. A missing port defaults to
the port in `cluster.listen` (the dedicated peer listener; default `0.0.0.0:8081`).
Seeds are only addressing hints: a seed becomes a
full peer once discovery (mDNS or a peer hello) supplies its identity, so a
pinned fingerprint is what actually establishes trust.

## Pinning and trust-on-first-use

Peers authenticate with self-signed certificates; trust is a raw public-key
fingerprint, not a CA chain. There are two ways a fingerprint becomes trusted:

- **Pinned** (`cluster.seed_fingerprints`). Trusted from boot. This is the
  intended production path; pin every peer.
- **Learned (TOFU)**. While `[cluster] enabled = true`, the first certificate
  seen from an unseeded peer is admitted and remembered, with a one-time
  warning. This lets a fresh cluster bootstrap itself.

When cluster mode is off, TOFU is disabled and only seeded fingerprints are
accepted. Inbound peer requests are gated per route: a request to a peer route
without a pinned client certificate is `403 {"error":"peer auth required"}`.

## mDNS and the VPS warning

`cluster.mdns` defaults to `true`, which advertises this node as
`_cachette._tcp.local.` and browses for peers on the local link. mDNS is
link-local by nature.

On a typical VPS there is no usable multicast interface, so no mDNS events
arrive. That is **not an error**: cachette logs nothing fatal and continues with
`seeds` only. If your hosts are not on the same LAN segment, set `mdns = false`
and rely on `seeds` and pinned fingerprints.

## Placement

Placement answers "which healthy node should own this reservation?". Candidates
are filtered to those that can admit the write, ranked by fill percentage, and
ties are broken by `cluster.tiebreak` (`random`, `roundrobin`, or
`progressive`). The capacity model is:

- `total = cache.max_size` when set, otherwise the disk total of
  `storage.fs.path`.
- `used` = accounted bytes.
- `free = total - used`.
- Admission passes when `free >= blob_size` (size known) or `free >= min_free`
  (size unknown, e.g. a v1 reservation that omits the size).

The same model drives the capacity filter, the fill-percentage ranking, and
eviction, so a node never admits a write it cannot hold.

## Routing, relay, and retries

When a cache write arrives at an entry node that is not the placement winner,
the entry node relays it:

- **v1 uploads** are forwarded reservation-by-reservation, chunk-by-chunk, then
  committed on the owner. The entry node keeps only an in-memory session that
  maps the client-visible `cacheId` to the owner; the blob bytes never touch the
  entry node's disk.
- **Reads and finds** resolve against the placement owner. The client receives a
  signed capability URL for the node that actually holds the blob (the MAC binds
  the resource path), so downloads go straight to that node.

Capacity and failure handling:

- An owner re-checks its **own** live admission when it accepts a forwarded
  reservation. A stale placement estimate therefore never lets an over-floor
  write through. If the owner is below its free-space floor it refuses with
  `503 {"error":"insufficient capacity"}`.
- The entry node never returns `429` for overload. On a capacity refusal it
  tries the next healthy peer in its placement order, and only surfaces `503`
  when every candidate refuses.
- A transport failure (owner unreachable, TLS error, timeout, or a 5xx) fails
  the relay with `502` and marks the session failed. The owner's abandoned
  reservation is reclaimed by the reservation TTL, so no space leaks.
- The commit step is idempotent: re-forwarding a commit that already published
  the entry succeeds instead of duplicating it.

Client retry behavior differs, which is why the status codes matter: the
`@actions/cache` toolkit retries 5xx, while `go-actions-cache` (used by
`docker buildx --cache-to type=gha`) does not. A `502` mid-upload is
recoverable for the toolkit and a hard failure for buildx, so keep owners
healthy and pinned.

cachette does not replicate entries between nodes: each entry lives on the
single node that owns it. If an owner is lost, its entries are not available
from another node.

## Inspecting the cluster

`GET /_internal/peers` returns the peer table (identity, address, capacity, and
health) to a pinned peer. It is not reachable without a pinned client
certificate. Node startup and heartbeat activity are also visible in the logs.

## Inter-node transport

The inter-node leg has its own dedicated listener (`[cluster] listen`): mutual
TLS with pinned fingerprints, always on when clustering is enabled. It is a
separate layer from the runner-facing edge, which you can serve plaintext behind
a proxy or terminate TLS on. Both layers are described in [tls.md](tls.md).
</content>
</invoke>
