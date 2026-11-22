# Roadmap

Ideas postponed out of the current scope, recorded so they don't get lost. Nothing here is committed until its design doc says so.

## Shipped in v1.2

- **Multi-tenant shared cache** - `docs/shared-cache.md` (workstream F). One cachette deployment (and one cluster) serving several forges and every runner on them: tenant identity derived from the *credential* rather than the request, namespaced rows, per-namespace quotas, and eviction that cannot starve a tenant. Credential planes: OIDC per issuer (RS256 + JWKS), forge runtime tokens (HS256, per forge), and the existing HMAC plane - which stays single-tenant by definition, because the repo and run in its MAC payload are client-asserted.
- **OIDC config reshape + RFC 7519 conformance** - `docs/oidc.md` (workstream A amendment). Per-issuer blocks (`[auth.oidc."<issuer>"]`) so one deployment can trust many IdPs, each with its own audiences, claim pins and trust roots; `nbf` treated as optional, as RFC 7519 says it is.
- **CDC completion** - `docs/cdc.md` (workstream B, commit 3): the layout-aware zero-ref predicate and crash recovery in the whole-to-chunked conversion window.

## v1.3 candidates (design drafted 2026-11-21, awaiting approve/veto)

- **Multiple storage backends** - `docs/multi-storage.md`. One process can connect several storages of the same type (two `fs` dirs, several S3 buckets), with `storage.min_free` as the default floor and per-instance overrides. Every storage option lands in v1.3: local fs roots, network mounts (SMB/NFS) and S3-compatible object storage. Namespaces route to instances; a separate repeatable quota plane caps instances and namespaces with byte-size limits. The cluster wire, accounting and offline commands follow.
- **Per-forge auth + tenant-yielding HMAC (Plane C+)** — **included in v1.3** — `docs/hmac-tenancy.md`. One `[auth.<forge>]` block holds every credential plane: HMAC via the signed `Forgejo-Cache-Repo`, the forge-issued runtime token, and OIDC. Lets `auth.mode = "merge"` stay valid, gives the runner proxy per-repo namespaces, and lets buildx drop `token=` and authenticate with the injected `ACTIONS_RUNTIME_TOKEN` instead of a long-lived JWT.
- **Generated example config** - emit `cachette.example.toml` from a single schema description (or `cachette config example`) so every knob and default stays present; replaces the hand-maintained file.

## Shipped in v1.1

- **Content-aware chunking (CDC)** - server-side and opt-in; the `gear-fastcdc-v1` splitter, chunked manifests beside the v1.0 whole-blob layout, refs-counted accounting, the GC sweeper, the paced backfill walker, and schema-versioned verified migrations (`docs/cdc.md`).
- **OIDC bearer auth** - RS256-only verification against your own IdP, a JWKS cache that survives rotation, fail-closed gates throughout (`docs/oidc.md`).

## Also on the bench

- **Multi-arch digest-stitch publisher** - prototype-validated against hangar (2026-10-22); the full recipe, adoption shapes (release-only vs full), and implementation gotchas are written up in `docs/image-stitching.md`. Adopt when arm64-in-QEMU compile cost after builder-base bumps outweighs the atomicity of the current single-invocation `buildx --push`.
- **Zig toolchain bump** (0.14.1 -> 0.17.1) - landed on the v1.2 branch (PR #13) instead of a separate release-branch PR, as its own commit next to the rust 1.100 bump; the cargo-zigbuild contract is re-checked empirically by the release legs and the docker leg.
- *(extend this list as postponed ideas accumulate)*
