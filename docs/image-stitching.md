# Multi-arch image stitching (parked recipe)

Status: **not in use**. The active image publisher is the single-invocation
`docker buildx build --push` in push-checks/pr-checks — atomically verified by
buildkit itself, with the map overlap we wanted. This page parks a
prototype-validated *alternative* — digest-addressed per-arch pushes stitched
server-side — for the day the arm64-in-QEMU compilation cost makes the active
path too painful.

## When to pick this up

- The active path cold-invalidates on every builder-base bump
  (e.g. `rust:1.98-alpine` -> `:1.99-alpine`) and then re-does the full
  cross-arch rust build under QEMU in each publishing workflow (push-checks
  dev rungs, pr-checks, release).
- The stitch eliminates the QEMU *compile* from the release path entirely:
  release.yml's binary matrix already cross-compiles static musl binaries for
  both arches via zigbuild, so the runtime image becomes a copy-in
  (`FROM scratch` + `COPY`) that builds in seconds with no emulation at all.
- Adoption shapes (from A to D on the trial):
  - **release-only stitch**: digest-stitch job in release.yml; push-checks'
    `release`-branch leg stops double-publishing (it becomes redundant with
    release.yml); dev/PR legs keep the atomic `buildx --push`.
  - **full stitch**: zigbuild introduced into push-checks/pr-checks as well;
    all schemas publish stitched lists; QEMU compilation retired from CI
    entirely. Bigger rewrite, unified binary source.

## What the prototype validated (2026-10-22, hangar.nixthedev.ru,
throwaway namespace `cachette-proto`, deleted after)

1. push-by-digest leaves **no tags or residue** in the namespace; failed or
   superseded attempts leave nothing to clean up (digests are
   content-addressed).
2. Per-arch objects are **plain image manifests**
   (`application/vnd.oci.image.manifest.v1+json`) — attestations must be
   suppressed (see gotchas).
3. `docker buildx imagetools create` on hangar yields a proper **2-entry**
   OCI index containing exactly the two pushed digests — no `--insecure`
   needed.
4. The legacy `docker manifest inspect` view lists amd64 AND arm64 (this is
   the same verify the workflows run today).
5. Mutable aliases created **after** verification resolve **byte-identical**
   to the verified version list (same index digest).
6. Per-arch configs are truthful: pulled by digest, the amd64 manifest's
   config reports `linux/amd64` and the arm64 manifest's reports `linux/arm64`.

## The recipe

`Dockerfile.dist` still needs writing at adoption time: a copy-in image
(`FROM scratch` + `COPY` of the zigbuild-built static binaries, see above), so
no compile ever runs inside the stitched path.

```bash
REG=hangar.nixthedev.ru
IMG="$REG/<owner>/cachette"
V="$(grep -m1 -E '^version[[:space:]]*=' Cargo.toml | sed -E 's/[^"]*"([^"]*)".*/\1/')"

# 1. per-arch, by digest; capture the MANIFEST digest via metadata file
for arch in amd64 arm64; do
  docker buildx build \
    --platform "linux/${arch}" \
    --provenance=false --sbom=false \
    -o "type=image,name=${IMG},push-by-digest=true,push=true" \
    --metadata-file "digests/${arch}.json" \
    -f Dockerfile.dist .
  sed -n 's/.*"containerimage.digest":[[:space:]]*"sha256:\([a-f0-9]*\)".*/sha256:\1/p' \
    "digests/${arch}.json" > "digests/${arch}.digest"
done

# 2. stitch the immutable version tag server-side from the two digests
docker buildx imagetools create --tag "$IMG:${V}" \
  "$IMG@$(cat digests/amd64.digest)" \
  "$IMG@$(cat digests/arm64.digest)"

# 3. verify BEFORE any mutable alias moves
docker manifest inspect "$IMG:${V}" | grep -q '"architecture": "amd64"'
docker manifest inspect "$IMG:${V}" | grep -q '"architecture": "arm64"'
docker run --rm --platform linux/amd64 "$IMG:${V}" --version
docker run --rm --platform linux/arm64 "$IMG:${V}" --version   # QEMU smoke run

# 4. only now alias the mutables FROM the verified list
docker buildx imagetools create --tag "$IMG:latest" "$IMG:${V}"
docker buildx imagetools create --tag "$IMG:release" "$IMG:${V}"
docker buildx imagetools create --tag "$IMG:1" "$IMG:${V}"     # truncations likewise
```

## Gotchas the prototype caught

- **Digest capture**: use `--metadata-file` -> `containerimage.digest`.
  `--iidfile` returns the **config** digest; feeding that into
  `imagetools create` produces the cryptic `unexpected end of JSON input`.
- **`--provenance=false --sbom=false` is mandatory** on the per-arch builds.
  Without them buildx wraps each output in an attestation index and the
  stitched list becomes an index-of-indexes.
- **Ordering is the cleanliness**: immutables first, verify, then aliases.
  `latest`/`release`/`dev` never point at anything unverified, all aliases are
  digest-verbatim copies of the verified version list.
- **Retries are free**: a half-finished attempt leaves only digest-addressed
  content nobody references; re-running overwrites identical digests.
- Docker Desktop's containerd image store (`Driver: overlayfs`) may keep
  binding its resident record for `--platform` pulls/creates of an index —
  a client display artifact; the registry-side descriptors/configs are
  correct, and CI runners verify the real thing with manifest-inspect + a
  fresh QEMU run smoke. Don't chase this on the workstation;
  trust the CI checks.

## Disposal of the trial artifacts

The prototype payload lived under the `cachette-proto` package on hangar;
delete it in the forge UI if it lingers. Scripts are scratch in `temp/`.
