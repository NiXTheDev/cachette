# Roadmap

Ideas postponed out of the current scope, recorded so they don't get lost.
Nothing here is committed until its design doc says so.

## v1.2 candidates (design drafted 2026-11-15, awaiting approve/veto)

- **Multi-tenant shared cache** - `docs/shared-cache.md` (workstream F).
  One cachette deployment (and one cluster) serving several forges and
  every runner on them: tenant identity derived from the *credential*
  rather than the request, namespaced rows, per-namespace quotas, and
  eviction that cannot starve a tenant. Credential planes: OIDC per issuer
  (RS256 + JWKS), forge runtime tokens (HS256, per forge), and the existing
  HMAC plane - which stays single-tenant by definition, because the repo
  and run in its MAC payload are client-asserted.
- **OIDC config reshape + RFC 7519 conformance** - `docs/oidc.md` (workstream
  A amendment). Per-issuer blocks (`[auth.oidc."<issuer>"]`) so one
  deployment can trust many IdPs, each with its own audiences, claim pins and
  trust roots; `nbf` treated as optional, as RFC 7519 says it is.
- **CDC completion** - `docs/cdc.md` (workstream B, commit 3): the
  layout-aware zero-ref predicate and crash recovery in the
  whole-to-chunked conversion window.

## Shipped in v1.1

- **Content-aware chunking (CDC)** - server-side and opt-in; the
  `gear-fastcdc-v1` splitter, chunked manifests beside the v1.0 whole-blob
  layout, refs-counted accounting, the GC sweeper, the paced backfill
  walker, and schema-versioned verified migrations (`docs/cdc.md`).
- **OIDC bearer auth** - RS256-only verification against your own IdP, a
  JWKS cache that survives rotation, fail-closed gates throughout
  (`docs/oidc.md`).

## Also on the bench

- **Multi-arch digest-stitch publisher** - prototype-validated against hangar
  (2026-10-22); the full recipe, adoption shapes (release-only vs full), and
  implementation gotchas are written up in `docs/image-stitching.md`. Adopt
  when arm64-in-QEMU compile cost after builder-base bumps outweighs the
  atomicity of the current single-invocation `buildx --push`.
- **Rust toolchain bump** (zig 0.14.1 -> 0.17.x) - maintenance, not a
  feature: it lands as a separate release-branch PR with a cargo-zigbuild
  contract re-check, because the pin is a contract and not a preference.
- *(extend this list as postponed ideas accumulate)*
