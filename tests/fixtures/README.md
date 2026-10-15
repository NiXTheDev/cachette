# Cachette v1 real-client fixtures (plan task 22)

These fixtures exercise cachette's v1 `artifactcache` API with the **two real
clients GitHub Actions runners use in production** — no protocol logic is
re-implemented and no client is stubbed:

- **`@actions/cache` v3** — the GitHub Actions toolkit (`toolkit.js` drives its
  public `saveCache` / `restoreCache` / `restoreCache({lookupOnly})` API).
- **`github.com/tonistiigi/go-actions-cache`** — the client
  `docker buildx --cache-to type=gha` uses (`gac/` links against the vendored
  reference `gac-reference/` at the pinned commit below).

`tests/v1_real_clients.rs` starts one in-process cachette router (the same
`cachette::routes::router` the binary serves) on an ephemeral loopback port in
`auth.mode = "merge"`, registers the plan's fixture token `tok-a` **and** a
self-minted JWT (the Go client's `New` rejects any token that is not
JWT-shaped), then runs both clients against it.

## Contents

- `package.json` / `package-lock.json` — pin `@actions/cache@^3.3.0`.
- `node_modules/` — installed on demand by the Rust test via
  `npm ci --no-audit --no-fund` when absent; **never committed** (see
  `.gitignore`).
- `toolkit.js` — thin Node harness over the toolkit's public API. Subcommands:
  `miss <key>`, `lookup <key> [path]` (`lookupOnly`, stops after the find),
  `save <key> <path>`, `restore <key> <path>`. It captures `core.warning`
  (the toolkit swallows non-validation cache errors) and prints a single
  machine-readable last line `__CACHETTE_JSON__{...}` for the Rust test.
- `gac/` — tiny Go program linking the vendored client. Subcommands:
  `miss <key>`, `save <key> <path>`, `restore <key> <path>`. It emits the same
  `__CACHETTE_JSON__{...}` marker. The Rust test builds it with `go build`
  into the scratch dir (the binary is never committed).
- `gac-reference/` — a byte-identical, `.git`-free copy of the **complete**
  tracked tree of `github.com/tonistiigi/go-actions-cache` at commit
  **`afe8013b5ac4e896742874e352edceff974e6fec`**
  (`2026-09-30T07:55:29-07:00`, *"Merge pull request #48 from
  crazy-max/v2-cache-error-message"*), all 20 upstream tracked files.
- `.gitignore` — excludes `node_modules/` and the built `gac/gac.exe`.

## How the Rust test drives them

The default test, `v1_real_clients_characterize_contract`, runs
`miss → save → lookup(hit) → restore` for the toolkit and
`miss → cross-client find → cross-client restore → save → restore` for the Go
client, always prints the full transcripts, and asserts everything the server
does correctly **plus** either a byte-identical round trip or the precise known
gap (below). It never skips: missing `node`, `npm` or `go` fails the test.

The strict acceptance test, `v1_real_clients_byte_identical_round_trip`, is
`#[ignore]`d and asserts byte-identical (`sha256`) restores through both real
clients. It fails today for the server reasons listed below; run it with:

```
cargo test --test v1_real_clients -- --ignored --nocapture
```

## Known v1 server gaps (reproduced by the real clients)

These are **server** defects surfaced by running the real clients. Task 22 owns
only `tests/fixtures/**` and `tests/v1_real_clients.rs`, so they are *reported,
not fixed here*.

1. **Relative `archiveLocation` (`src/routes/v1.rs::find`).** `find` builds
   `/{ARTIFACT_PATH_PREFIX}{key}?id&exp&mac` without the `AppState::external_url`
   host.
   - Toolkit: `cacheHttpClient.js` runs `new URL(archiveLocation)`, which throws
     `Invalid URL`; `restoreCache` swallows it into
     `::warning::Failed to restore: Invalid URL` and returns `undefined`.
   - Go client: `Entry.Download` issues `http.NewRequest("GET", ce.URL, nil)`
     and the request fails with
     `unsupported protocol scheme ""`.
2. **String `cacheId` (`src/routes/v1.rs::reserve`).** `POST /caches` returns
   `"cacheId": "<32-hex>"`; go-actions-cache unmarshals it into
   `ReserveCacheResp.CacheID int` (`cache.go`), so `Save` fails with
   `json: cannot unmarshal string into Go struct field ReserveCacheResp.cacheId
   of type int`. GitHub's v1 contract uses a numeric `cacheId` (the toolkit
   treats it as opaque, so it is unaffected).
3. **Artifact download gated by bearer auth (`src/auth/mod.rs::require_auth`).**
   The layer rejects every `/_apis/artifactcache/*` request without a bearer
   token, including the signed artifact download. Both real clients issue a
   **bare** GET for the download (the toolkit's `HttpClient('actions/cache')`
   and `Entry.Download` send no `Authorization`), so a correctly-signed
   `archiveLocation` is still rejected with
   `401 {"error":"authentication required"}`. The signed URL alone is supposed
   to authorize the download.

Gaps 1 and 3 mask each other in the toolkit path (the relative URL fails before
the auth gate is reached); the Rust test issues one explicit raw GET with a
*correctly-signed* URL and no bearer to isolate gap 3.

## Pinned references

- `@actions/cache` `^3.3.0` (toolkit v1).
- `go-actions-cache` `afe8013b5ac4e896742874e352edceff974e6fec`
  (2026-09-30) — vendored verbatim into `gac-reference/`.
