# Cachette v1 real-client fixtures (plan task 22)

These fixtures exercise cachette's v1 `artifactcache` API with the **two real
clients GitHub Actions runners use in production** â€” no protocol logic is
re-implemented and no client is stubbed:

- **`@actions/cache` v3** â€” the GitHub Actions toolkit (`toolkit.js` drives its
  public `saveCache` / `restoreCache` / `restoreCache({lookupOnly})` API).
- **`github.com/tonistiigi/go-actions-cache`** â€” the client
  `docker buildx --cache-to type=gha` uses (`gac/` links against the vendored
  reference `gac-reference/` at the pinned commit below).

`tests/v1_real_clients.rs` starts one in-process cachette router (the same
`cachette::routes::router` the binary serves) on an ephemeral loopback port in
`auth.mode = "merge"`, registers the plan's fixture token `tok-a` **and** a
self-minted JWT (the Go client's `New` rejects any token that is not
JWT-shaped), then runs both clients against it.

## Contents

- `package.json` / `package-lock.json` â€” pin `@actions/cache@^3.3.0`.
- `node_modules/` â€” installed on demand by the Rust test via
  `npm ci --no-audit --no-fund` when absent; **never committed** (see
  `.gitignore`).
- `toolkit.js` â€” thin Node harness over the toolkit's public API. Subcommands:
  `miss <key>`, `lookup <key> [path]` (`lookupOnly`, stops after the find),
  `save <key> <path>`, `restore <key> <path>`. It captures `core.warning`
  (the toolkit swallows non-validation cache errors) and prints a single
  machine-readable last line `__CACHETTE_JSON__{...}` for the Rust test.
- `gac/` â€” tiny Go program linking the vendored client. Subcommands:
  `miss <key>`, `save <key> <path>`, `restore <key> <path>`. It emits the same
  `__CACHETTE_JSON__{...}` marker. The Rust test builds it with `go build`
  into the scratch dir (the binary is never committed).
- `gac-reference/` â€” a byte-identical, `.git`-free copy of the **complete**
  tracked tree of `github.com/tonistiigi/go-actions-cache` at commit
  **`afe8013b5ac4e896742874e352edceff974e6fec`**
  (`2026-09-30T07:55:29-07:00`, *"Merge pull request #48 from
  crazy-max/v2-cache-error-message"*), all 20 upstream tracked files.
- `.gitignore` â€” excludes `node_modules/` and the built `gac/gac.exe`.

## How the Rust test drives them

The default test, `v1_real_clients_characterize_contract`, runs
`miss â†’ save â†’ lookup(hit) â†’ restore` for the toolkit and
`miss â†’ cross-client find â†’ cross-client restore â†’ save â†’ restore` for the Go
client, always prints the full transcripts, and asserts everything the server
does correctly **plus** either a byte-identical round trip or the precise known
gap (below). It never skips: missing `node`, `npm` or `go` fails the test.

The strict acceptance test, `v1_real_clients_byte_identical_round_trip`, asserts
byte-identical (`sha256`) restores through both real clients and runs by default:

```
cargo test --test v1_real_clients -- --nocapture
```

## v1 server compliance fixed for these real clients

Running the real clients surfaced three v1 server defects; all three are fixed:

1. **Absolute `archiveLocation` (`src/routes/v1.rs::find`).** `find` now prefixes
   `AppState::external_url` (production resolves it from `listen`). The toolkit's
   `new URL(archiveLocation)` and the Go client's verbatim
   `http.NewRequest("GET", ce.URL, nil)` both require an absolute URL.
2. **Numeric `cacheId` (`src/routes/v1.rs::reserve`).** `POST /caches` returns a
   positive integer (GitHub's v1 contract); `go-actions-cache` unmarshals it into
   `ReserveCacheResp.CacheID int` and rejects `0`. It is kept within
   `Number.MAX_SAFE_INTEGER` because the JS toolkit round-trips it through a
   `number` before `PATCH`ing the chunks.
3. **Signed-URL-only artifact download (`src/auth/mod.rs::require_auth`).** The
   gate now exempts `/_apis/artifactcache/artifacts/`; both clients issue a
   **bare** GET (no `Authorization`) and the signed URL alone authorizes the
   download (`v1::download` still enforces the signature).

## Pinned references

- `@actions/cache` `^3.3.0` (toolkit v1).
- `go-actions-cache` `afe8013b5ac4e896742874e352edceff974e6fec`
  (2026-09-30) â€” vendored verbatim into `gac-reference/`.
