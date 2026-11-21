# Design: server-side content-defined chunking (v1.1 workstream B)

Status: **implemented** in v1.1.0 (2026-11-15). Amended 2026-11-15 for
v1.2 - see "v1.2 amendments" at the end of this document. The v1.2 shape is
the contract for v1.2; the text above stays as the record of what shipped.

## Why

The v1 upload path stores artifacts whole: a cache entry is one
`blobs/{id}.blob` payload staged as a single `parts/{id}.part` file. Cache
keys that differ at one end - an incremental rebuild shifting a tail of the
archive - store their shared prefix twice (and twice on disk, twice across
the fleet, plus in every staged copy while an upload runs).

Server-side CDC fixes this **without touching the protocol**: when an entry is
 finalized, the payload is re-cut into content-defined chunks that are stored
 once each and referenced from a per-entry manifest. Two entries whose middle
 agrees end up referencing the same chunk files, so incremental rebuilds pay
 only for the delta - on disk, nowhere else. Wire traffic is unchanged on
 purpose: chunking at receipt would still ship the bytes, and client-side
 chunking would break stock `go-actions-cache`/`buildx` clients, which this
 design refuses to do.

`StorageBackend`'s trait signature stays byte-identical: `put_stream`,
 `get_range`, `commit_chunks`, `stat`, `list`, `finalize` all keep their
 contracts. All fs-level layout/metadata/accounting evolution stays inside
 `fs.rs` + the index schema. This keeps the biggest existing safety net -
 the whole fs storage test suite - passing verbatim.

## Chunking algorithm

FastCDC-style rolling-chunk (Gear hash + normalization levels), **hand-rolled
in-repo** - no new crate. The mask/content tables are generated at compiletime
from a fixed constant seed, so the algorithm is deterministic across nodes and
versions: identical content chunk-identically, which is the entire
dedup contract. The algorithm version gets a constant
(`CDC_ALGO = "gear-fastcdc-v1"`); should the algorithm ever change, chunk IDs
would be namespaced under the new version before any code rolls content
(nowhere do chunks mix attrs).

Fixed bounds (`avg` configurable, `min = avg/4`, `max = avg * 4`), so the
cutting window keeps finalize-time per-chunk buffering bounded (4 MiB at
the default average) and the tracked bounds carry real file-size meaning:

- default `avg_chunk_bytes = 131072` (128 KiB) -> min 32 KiB, max 512 KiB.

Chunk content IDs reuse the width already standardized by
`storage::digest` - **blake3-256 truncated to 16 bytes, lowercase hex (32
chars)** - computed from the same streaming hasher stack, so a single routine
and a single hex width (the docstring note about the task-41 chunk index)
already anticipated this.

## Storage layout

```text
<root>/blobs/{id}.blob        whole-blob entries (unchanged; pre-CDC entries and CDC-disabled upload class remain)
<root>/chunks/{id}.chunk      deduplicated chunk payloads, one file per chunk
<root>/parts/...              staged uploads (unchanged)
```

Index schema (SQLite, same file) gains:

```sql
CREATE TABLE IF NOT EXISTS chunks (
    id      TEXT PRIMARY KEY,     -- 32-hex content id
    size    INTEGER NOT NULL,
    refs    INTEGER NOT NULL DEFAULT 0,  -- live entries referencing this chunk
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entry_chunks (
    entry_id  TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    chunk_id  TEXT NOT NULL,
    PRIMARY KEY (entry_id, seq)
);
```

An entry row carries a `layout` flag (`whole` | `chunked`); pre-existing
entries and any pre-CDC format are `whole` and touched by nothing until
evicted. `entry_chunks` rows exist only for `chunked` entries. `digest`
keeps its meaning: the blake3 of the **whole payload** (chunked entries
recompute it from the chunk stream or at restore), so `cachette verify`
semantics don't change.

### Write path (chunking is a finalize-time pass)

The hot path - receipt of v1 chunk bytes, v2 PUT streams, staging into
`parts/` - is untouched, byte for byte. Chunking happens inside `finalize`
(well inside the atomic-commit seam that already exists):

1. stream the finalized parts payload through hasher+chunker;
   write each chunk to `chunks/{id}.chunk.tmp`, fsync, rename to final
   (dedup hit: `chunks/{id}.chunk` already exists - skip the write);
2. in ONE SQLite transaction: upsert `chunks` rows
   (`refs = refs+1` on the second-plus insert), insert `entry_chunks`,
   set the entry row's `layout='chunked'` + `complete=1`;
3. after commit: delete the `parts/` staging files.

Crash at any step still converges - see failure model below. The extra cost
is one additional read pass over the payload at finalize time (disk-bound,
in the background of the receipt that already wrote it once). Fine for
cache-size payloads; revisit only if profiles disagree.

### Read path

`get_range` on a `chunked` entry: resolve the entry's chunk list + per-chunk
offsets (prefix sums of `chunks.size`, cached on the `(entry_id, seq)` index),
binary-search the range start, then stream the affected chunks' slices,
stitching at boundaries. Range reads become chunk-granular - largely a wash
for whole-tail reads and a win for small-key seeks. `accessed_at` bump and
`used_bytes`' account update happen exactly as today (on the row).

### Accounting and eviction

`used_bytes` (existing SQLite accounting row) keeps its meaning: **bytes
counted once per unique payload at rest**. For `whole` entries that is the
blob size (unchanged code path). For `chunked` entries, shared chunks are
counted once across all referencing entries - the definitive post-CDC
invariant:

> `used_bytes == Σ size over chunks with refs > 0` (under CDC-enabled layouts)

Eviction (LRU/oldest entry eviction in `eviction.rs`) works on entry rows as
today, but the freed-bytes calculation per evicted entry changes from
`entry.size` to the chunk-level exclusive bytes — `Σ size over that entry's
chunks where refs == 1` before the decrement (decremented in the same
transaction as the row delete; chunks that hit `refs == 0` are removed from
the `chunks` table and their files unlinked by the post-commit GC step). This
is the single biggest behavioral seam in the design: an entry whose every
chunk is co-referenced frees 0 bytes, which is correct behavior, and audit
code asserts `accounting.used_bytes` against the chunk-level Σ invariant
after every mutation.

### Garbage collection / reaper

The existing sweep patterns extend, all under the blob sweep's 1h
`ORPHAN_BLOB_GRACE` (a fresh leftover may belong to a pass still in
flight):

- `chunks/{id}.chunk.tmp` finalize scratch (crash between write and
  rename) - age-out sweep. (The `tmp/{id}-{start}.chunk.tmp` PATCH-path
  scratch lives in `tmp/`, which boot reconciliation already wipes
  wholesale; the reaper stays out of `tmp/`.)
- a `chunks/{id}.chunk` with no live chunks-row - swept (the crash window
  of finalize's best-effort post-commit unlink);
- a `chunks` row with `refs = 0` - purged belt-and-braces (the normal
  release paths delete it in-tx, so this should never exist);
- a `blobs/{id}.blob` whose row is `chunked` - rowless for sweeping (only
  `whole` rows own a blob; this is the crash window of the whole→chunked
  conversion, the Migration section);
- `parts/` sweeps remain (staging that never finalized, per-reservation and
  global).

No sweep ever deletes a chunks-row with `refs > 0`, and a zero-ref purge
moves no accounting (only `refs > 0` bytes are counted). Reaper runs
in-process with the same cadence/idempotence guarantees as today.

### The failure model

- crash mid-finalize (before the tx commit): parts remain, `parts/` wipes on
  next sweep; no chunks rows; leaked `chunksNorm` files swept. The chunking
  pass reattempt is a plain retry on the same reservation.
- crash mid-commit: SQLite tx is atomic - either the manifest+refs exist or
  nothing does;
- crash post-commit: `parts/` delete is lost -> swept;
- a chunk file manually gone while refs>0 → `verify` reports the
  missing-file entry (same reporting family as `EntryHealth::MissingBlob`).

### Mixed layout and coexistence

Pre-CDC `whole` entries converge onto the chunked layout through the
background backfill walker (Migration) - never a boot-blocking bulk
re-chunk (a large index must not delay readiness by minutes). Until an
entry's turn it stays `whole`, so the index is legitimately mixed at rest
and every path branches on the row's `layout`; `verify_all` learns the
`layout` column. Cluster relay and peer_relay are untouched (chunking is
node-local at-rest state; the relay forwards receipts as today).

## Migration

v1.0 → v1.1 upgrades two independent halves, both crash-safe:

### Schema half (the index)

The index carries its schema version in a `meta` key-value table
(`schema_version`), stamped only after every pending migration step has
been applied AND verified - decoupled from the crate semver (a patch
release must never look like a schema event; the ledger lives beside
`SCHEMA_VERSION` in `fs.rs`). On every boot:

1. stored > the binary's schema version: refuse to open. An older binary
   never touches a newer index; the error names both versions and the
   index is left untouched (the downgrade tripwire - see the data half for
   why there is no in-place reverse path).
2. stored < the binary's: apply the pending steps (version-ordered ledger;
   bodies stay introspection-guarded so a re-run is a no-op on an
   already-current schema), verify the result, and stamp the new version -
   all in ONE transaction. SQLite DDL is transactional and these steps are
   constant-default `ALTER`s (O(1) metadata work regardless of index
   size), so a crash anywhere before the commit rolls back to exactly the
   old schema and the next boot re-runs cleanly.
3. verification (required tables + required column sets via
   `pragma_table_info`) runs unconditionally on every boot, not only after
   migrations: the stamp can lie (hand-mangled index, partial restore), so
   a gap refuses to open and names the missing piece.

An index that predates the meta table reads as version 0 and adopts
smoothly: every step is a guarded no-op on its already-present columns,
verify passes, the stamp lands.

### Data half (the at-rest payloads)

Schema-converted rows say `whole`; their payloads still are. A background
backfill walker converges them onto the chunked layout when
`[storage.cdc] enabled = true` and `backfill` is on (the default: turning
`enabled` on means "converge", not just "new writes chunk"):

- one entry per step, smallest first (`ORDER BY size ASC, id ASC`), paced
  by `backfill_delay_ms` - large entries last, so convergence proceeds in
  cheap increments and live traffic keeps most of the disk.
- the pick excludes rows with the legacy empty digest (`digest = ''`):
  their integrity cannot be checked, so they are never converted and stay
  whole.
- the connection mutex is NOT held during the chunking pass (the same
  bounded-memory cutter finalize uses), so live traffic interleaves; the
  commit is one transaction under the writer gate whose guarded
  `UPDATE ... WHERE id = ? AND layout = 'whole' AND complete = 1
  AND size = ? AND digest = ?` re-checks the row it picked - a delete or a
  re-put with different content between the pick and the commit matches no
  row, the pass is discarded, and its chunk files stay rowless for the
  sweeper (the same convergence as a finalize crash mid-pass).
- accounting moves in the same transaction: `used -= blob_bytes;
  used += added`, where `added` is the manifest's freshly-referenced
  bytes - size-neutral without dedup, smaller when the conversion hits
  content that is already chunked and referenced.
- the blob file is unlinked only after the commit (best-effort, like
  finalize); a missed unlink is safe because the sweeper counts a
  `chunked` row's blob as rowless after the grace (GC).
- a blob that is missing, or digests differently than its row claims, is
  corruption rather than a conversion failure: the walker warns, parks the
  id in an in-process skip set, and keeps converting. Nothing is deleted;
  the row stays whole; `cachette verify` still reports the entry.

A whole→chunked conversion is one-way; no reverse (chunked→whole)
re-materialization is implemented for v1.1. Downgrading a v1.1 index to a
v1.0 binary is refused at open (schema half above) - migrate by draining
and re-fetching from origins, or by re-replicating to a fresh node, not in
place.

## Config surface

```toml
[storage.cdc]          # off by default, all fields defaulted
enabled = false
avg_chunk_bytes = 131072
backfill = true             # converge whole entries once enabled = true
backfill_delay_ms = 100     # pause between single-entry conversions (>= 1)
```

`enabled = false` behaves byte-identically to v1.0 layout (writes `whole`
entries; the read path supports both layouts regardless of the current
flag, so flipping the flag off never orphans readable data).
`config::validate` caps `avg_chunk_bytes` to `[32768, 1048576]` and rejects
`backfill_delay_ms = 0` - both regardless of `enabled`/`backfill`, so a
bad value cannot hide until the flag flips on.

## Test plan

1. **Trait suite passes verbatim** - every existing `fs.rs` storage /
   protocol test runs unchanged (the trait's contract is the spec).
2. **Dedup:** two keys sharing a prefix (incremental rebuild); assert shared
   chunk ids + `refs = 2`, unique bytes < sum-of-entry-sizes,
   `used_bytes` respects the Σ invariant.
3. **get_range exactness:** ranges straddling chunk boundaries, tail ranges,
   `start == size`, out-of-range expected readings; compare byte-for-byte
   against whole-blob reference reads.
4. **Refcount math:** supersede an entry with same artifact_key; delete /
   evict; verify files unlinked exactly when `refs` reaches 0, shared chunks
   survive sibling deletes.
5. **Crash injection:** simulated aborts at each finalize step bound (files
   written no rows; tx committed no parts deletion; post-commit) each
   followed by reaper convergence and `used_bytes` consistency.
6. **verify_all mixed layouts:** whole + chunked entries coexisting;
   missing-file health reported for both classes.
7. **Layout-flag independence:** with `enabled = false`, pre-existing
   chunked entries read correctly; new writes take the `whole` path.
8. **Migration:** fresh boot stamps the schema version and a reboot is a
   no-op; a newer index refuses to open untouched; a lying stamp (version
   row vs. actual columns) is caught on every boot; a corrupt version value
   refuses instead of guessing. Backfill: one-step conversion keeps size
   and digest, unlinks the blob, and stays size-neutral in accounting; the
   drain converts smallest-first and ends `Exhausted` idempotently; corrupt
   rows (missing blob, digest mismatch) are parked and skipped, never
   deleted; a raced row discards the pass; `digest = ''` rows are never
   picked; live writes interleave with a conversion.

## Rollout

First release carrying the code **defaults to off**; flipping
`[storage.cdc] enabled` on a live node requires a restart and then applies
to new finalizations and starts the background backfill walker (Migration)
- no boot-blocking re-chunk. No protocol, client, image, or wire changes.

## v1.2 amendments (2026-11-15)

### Workstream B, commit 3: layout-aware zero-ref predicate + crash recovery

v1.1 shipped the CDC sweeper with a zero-ref predicate that counts distinct
referencing entries, and a conversion-crash window covered by
`sweep_orphan_blobs`. Two things are still open, and they are why workstream
B did not close in v1.1:

- **Layout-aware zero-ref.** A chunk row is referenced by an `entry_chunks`
  manifest of a **chunked** entry; a row of a **whole** entry holds a blob,
  not a manifest. The predicate must consult the `layout` column before
  deciding a chunk has no referrer, and the two row kinds must never be
  counted against each other. A whole entry whose blob was unlinked by a
  conversion is not a "zero-ref chunk"; a chunked entry's manifest row is
  not a "whole blob". With v1.2's namespaces (workstream F) the same
  predicate has to be namespace-scoped on top: a chunk referenced only from
  another namespace's manifest is still a referrer, and the sweeper must
  never touch another namespace's rows.
- **Crash recovery in the conversion window.** The conversion (whole entry
  -> chunked) stages chunks, then publishes the manifest and unlinks the
  blob. A crash between those steps must leave the entry readable (as its
  old whole layout or its new chunked one, never as neither), the staged
  chunks collectable by the sweeper, and the accounting correct. The staged
  chunks of an **in-flight** conversion must not be swept by a concurrent
  sweeper - the age grace plus the staged marker is what makes that safe.

Tests: mixed-layout fixtures where a chunk and a whole row coexist with
referrers in only one of them; crash injection at each conversion bound
(staged, published, unlinked) followed by a boot + sweep convergence check
and a `used_bytes` consistency check; a staged chunk surviving a concurrent
sweep; a zero-ref chunk of a chunked entry still being swept; a chunk
referenced across namespaces surviving the sweep.

**v1.2 status:** landed. The zero-ref purge in `sweep_orphan_chunks` consults the referring entry's `layout` (a live manifest of a complete
`chunked` entry is a referrer even if `refs` drifted to zero; a `whole` row
never owns a manifest), counts referrers from any namespace, and purges only
the unreferenced row. The guarded conversion transaction plus the age grace
on rowless staged files covers the three crash bounds; the `storage_fs`
tests drive each bound through boot + sweep and check `used_bytes` against
the at-rest invariant.
