# Roadmap

Ideas postponed out of the v1.0.0 scope, recorded so they don't get lost.
Nothing here is committed to a version yet.

## v1.1 candidates

- **Content-aware chunking (CDC).** The v1 upload path currently stores
  artifacts whole (chunked only by the fixed `max_chunk_bytes` staging unit).
  Content-defined chunking would let concurrent CI runs share deduplicated
  blocks for cache keys that differ at one end (incremental rebuilds),
  cutting both wire traffic and disk usage across the fleet.
- **OIDC auth.** Move the Clients leg from static bearers / minted tokens to
  short-lived OIDC tokens issued by the forge, scoped per run - so CI runs
  stop holding long-lived secrets.

## Also on the bench

- **Multi-arch digest-stitch publisher** — prototype-validated against hangar
  (2026-10-22); the full recipe, adoption shapes (release-only vs full), and
  implementation gotchas are written up in `docs/image-stitching.md`. Adopt
  when arm64-in-QEMU compile cost after builder-base bumps outweighs the
  atomicity of the current single-invocation `buildx --push`.
- *(extend this list as postponed ideas accumulate)*
