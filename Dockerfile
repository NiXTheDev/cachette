# Multistage build for cachette (plan task 36).
#
# Builder: rust:1.100-alpine, run ONCE on the runner's own platform
#   (--platform=$BUILDPLATFORM), cross-compiling BOTH static musl binaries:
#     aarch64-unknown-linux-musl  (the image's own host target - std ships in
#                                  the rust image)
#     x86_64-unknown-linux-musl   (std added via rustup through the mirror
#                                  ladder; linker + C compiler = zig cc)
#   NO foreign-arch code is ever executed: rustc cross-compiles, zig cc
#   cross-compiles the C (bundled sqlite3.c, aws-lc-sys), and the scratch
#   runtime stages merely COPY per-arch outputs. No QEMU, no binfmt.
#
# Why cross-compile instead of the old per-`--platform` builder (which ran
# linux/amd64 under QEMU on the arm64 fleet):
#   * gcc 15.2.0 under QEMU deterministically SEGFAULTS (ICE in its GC,
#     cc1) compiling libsqlite3-sys' bundled sqlite3.c - three incidents,
#     same file, different lines (168163 whereAddIndexedExpr at -O3 on
#     runs 502/558; 156472 updateAccumulator at -O2 with libsqlite3-sys
#     0.39.1 on runs 125-129). The identical inputs compile FINE natively
#     (the arm64 docker leg passed at -O2 in 11m29s), so the trigger is
#     QEMU, not the source. A deterministic crash cannot be retried away.
#   * Emulation was also ~8x slower: the QEMU legs burned 95+ minutes on
#     a cold cache (and the docker job died at its 3h timeout mid-rung-3)
#     while the native leg finished in 11m29s.
#   * The builder's own libc/userland is irrelevant either way - the
#     runtime is `scratch` and both binaries are FULLY STATIC musl. Alpine
#     is kept only as a package source (gcc/musl-dev/file, tar/xz); any
#     musl-capable base would do.
#
# Toolchain: cargo-zigbuild + zig 0.17.1 - the SAME pair and pins the
#   release matrix runs (release.yml TOOLCHAIN JUSTIFICATION). zig cc
#   drives the linker AND the C compiler for both musl targets; zig ships
#   its own musl libc, so no cross libc packages are needed. The zig
#   tarball is sha256-pinned (checksums from ziglang.org/download/
#   index.json). The zig 0.17.x bump is a SEPARATE release-branch PR that
#   must bump this pin AND release.yml together and re-check the
#   cargo-zigbuild contract.
#
# Runtime: `scratch`. A musl-static binary needs NO libc at all - shipping it
#   in a glibc/debian/distroless-debian image would be exactly the mistake the
#   plan forbids ("must NOT ship a glibc image for the musl binary"), and
#   distroless-static (gVisor) would add a userspace we don't need for a fully
#   static binary. scratch = minimal attack surface, no shell to exec into.
#   (No shell also means no in-container healthcheck - readiness is the log:
#   `cachette listening on ...` for the cache port, plus
#   `cachette cluster listening on ...` once clustering is enabled.)
#
# Non-root: numeric `USER 65532:65532` works in scratch without /etc/passwd;
#   /config and /var/lib/cachette are chowned to 65532 so the compose
#   named volume is writable on first use.
#
# Entrypoint / command / ports:
#   ENTRYPOINT ["/usr/local/bin/cachette"]
#   CMD        ["--config", "/config/cachette.toml"]
#   8080: [server] listen - the runner-facing cache port. Plain HTTP unless the
#         mounted config sets [server] tls_cert/tls_key (public TLS is the
#         reverse proxy's job by default).
#   8081: [cluster] listen - the peer port. Always mTLS with the self-signed
#         node identity cert; bound only when [cluster] enabled = true.
#   (EXPOSE directives were dropped on purpose: publish host mappings per
#   deployment instead.)
#   docker run --rm cachette:local            -> cachette --config /config/cachette.toml
#   docker run --rm cachette:local --version  -> cachette 1.1.0   (replaces CMD)
#
# The baked /config/cachette.toml is the repo's cachette.example.toml - a
# DEMO default (secret = CHANGE_ME_*). Real deployments must override
# CACHETTE__AUTH__SECRET (compose does) or mount their own config.

# Digest-pinned on top of the tag: the docker jobs' last external-host
# dependency is docker.io's blob CDN (production.cloudfront.docker.com),
# which EOF'd the 1.0.0-class docker legs mid-build. The pin lets the
# workflows' pre-pull ladder warm the host store for the EXACT manifest
# buildkit needs, so a republished `1.100-alpine` upstream cannot revolve
# under us mid-fleet. To bump: `docker manifest inspect rust:1.100-alpine`,
# then replace the digest here AND in both workflows' pre-pull steps.
# Only the runner-arch variant of this index is ever pulled now - the
# builder stage is forced to $BUILDPLATFORM.
FROM --platform=$BUILDPLATFORM rust:1.100-alpine@sha256:de1e0058543a81ed7b046629167db587c67a94bdf37cce14eb27f0ec83baaffb AS builder

# BUILDARCH is a predefined buildkit arg (amd64 | arm64) = the builder
# stage's own platform. Predefined args are usable in FROM without a
# declaration (the --platform=$BUILDPLATFORM above) but a RUN only sees
# them once the stage re-declares them - hence this line. NOTE: the
# naming is Go/GOARCH style (amd64, arm64) - NOT the aarch64/x86_64
# spelling zig tarballs and rust targets use; case-branches on
# BUILDARCH must use the Go spelling and map to the target's spelling.
ARG BUILDARCH

# gcc/musl-dev: fallback C toolchain for the native target (zig cc covers
#   both targets; this stays only as a floor if a cc-rs crate refuses zig).
# file(1): build-time static-link assertion. tar/xz: unpack the zig tarball.
# curl: the zig tarball + rustup mirror-ladder fetches below.
RUN apk add --no-cache gcc musl-dev file tar xz curl

# zig 0.17.1 - sha256-pinned tarball (aarch64-linux / x86_64-linux variants
# per the builder's own arch). THE FETCH IS NOT FROM ZIGLANG.ORG FIRST:
# ziglang.org is a deliberate one-computer host whose 51 MiB tarballs stall
# mid-transfer on the fleet's egress path - pr-13 run #137 lost every docker
# rung to `curl (56) Recv failure: Operation timed out` three times in a
# row (~10 min per stall), 4 buildx invocations in a row (~2h wasted).
# So: the TARBALL is kept in a cache mount (a rerun with a warm download
# cache skips the network entirely), and a cold fetch walks the ZSF
# community-mirror list - shuffled so we don't hammer one mirror - with
# stall-killing curl flags (< 4 KiB/s for 30 s aborts the attempt, 10 min
# hard cap), ziglang.org itself last. The sha256 pin below is the trust
# anchor: mirrors are untrusted per the ZSF's own framing, and a tampered or
# truncated tarball fails the hash.
#
# The INSTALLED toolchain lives in the image layer (/usr/local/zig), NOT in
# the cache mount: buildkit cache mounts are visible ONLY to the RUN that
# declares --mount, so run #141's first cut (which extracted into the mount)
# left every later `cargo zigbuild` step looking at an empty PATH entry and
# dying instantly with `Error: Failed to find zig`.
ARG ZIG_VERSION=0.17.1
ARG ZIG_SHA_AARCH64=a1546d5646eb184437918d6635ca6b762a0e889eac09cef720ee7a1ed3fe7795
ARG ZIG_SHA_X86_64=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a
RUN --mount=type=cache,target=/opt/zig-cache,sharing=locked \
    set -eu; \
    case "$BUILDARCH" in \
      arm64)  ZIG_ASSET="zig-aarch64-linux-${ZIG_VERSION}.tar.xz"; ZIG_SHA="${ZIG_SHA_AARCH64}" ;; \
      amd64)  ZIG_ASSET="zig-x86_64-linux-${ZIG_VERSION}.tar.xz";  ZIG_SHA="${ZIG_SHA_X86_64}" ;; \
      *) echo "unsupported BUILDARCH for zig: ${BUILDARCH}"; exit 1 ;; \
    esac; \
    tarball="/opt/zig-cache/${ZIG_ASSET}"; \
    if [ -f "$tarball" ] && echo "${ZIG_SHA}  ${tarball}" | sha256sum -c - >/dev/null 2>&1; then \
      echo "zig ${ZIG_VERSION} tarball already in the download cache - skipping fetch"; \
    else \
      rm -f "$tarball" "${tarball}.part"; \
      mirrors=""; \
      if curl -fsSL --connect-timeout 15 --max-time 30 \
           -o /tmp/zig-mirrors.txt \
           "https://ziglang.org/download/community-mirrors.txt"; then \
        # busybox has no shuf(1); a Fisher-Yates pass in awk keeps the load
        # off whichever mirror happens to be first in the list (ZSF asks
        # automations to randomize).
        mirrors="$(awk 'BEGIN { srand(); n = 0 } \
          { a[n++] = $0 } \
          END { for (i = n - 1; i > 0; i--) { \
                  j = int(rand() * (i + 1)); t = a[i]; a[i] = a[j]; a[j] = t \
                } \
                for (i = 0; i < n; i++) print a[i] }' /tmp/zig-mirrors.txt)"; \
      fi; \
      got=0; \
      for m in $mirrors; do \
        echo "== zig mirror try: ${m} =="; \
        if curl -fL --connect-timeout 15 --max-time 600 \
                 --speed-limit 4096 --speed-time 30 \
                 -o "${tarball}.part" "${m}/${ZIG_ASSET}?source=cachette-docker"; then \
          got=1; break; \
        fi; \
        rm -f "${tarball}.part"; \
      done; \
      if [ "$got" -ne 1 ]; then \
        echo "no community mirror served ${ZIG_ASSET} - ziglang.org fallback"; \
        for attempt in 1 2 3; do \
          echo "== zig download attempt $attempt =="; \
          if curl -fL --connect-timeout 20 --max-time 600 \
                   --speed-limit 4096 --speed-time 30 \
                   -o "${tarball}.part" \
                   "https://ziglang.org/download/${ZIG_VERSION}/${ZIG_ASSET}?source=cachette-docker"; then \
            got=1; break; \
          fi; \
          sleep $((attempt * 5)); \
        done; \
      fi; \
      [ "$got" -eq 1 ] || { echo "zig tarball unavailable from every mirror: ${ZIG_ASSET}"; exit 1; }; \
      echo "${ZIG_SHA}  ${tarball}.part" | sha256sum -c -; \
      mv "${tarball}.part" "$tarball"; \
    fi; \
    mkdir -p /usr/local/zig; \
    find /usr/local/zig -mindepth 1 -delete 2>/dev/null || true; \
    tar -xJf "$tarball" -C /usr/local/zig --strip-components=1; \
    /usr/local/zig/zig version | grep -Fx "${ZIG_VERSION}"
ENV PATH="/usr/local/zig:${PATH}"

# cargo-zigbuild - the SAME driver command the release legs use. It sets
#   zig cc as linker AND as the cc-rs C compiler (with the right -target)
#   for the chosen rust target, which is what keeps gcc OFF the amd64
#   build path entirely.
RUN cargo install cargo-zigbuild --locked

# The x86_64 musl std for the cross target - fetched through the SAME
# mirror race the workflows use (.forgejo/actions/rustup-mirror): the
# runners' path to static.rust-lang.org dies at the TLS layer
# intermittently (the v1.1.0 cut lost run 108 to exactly this, before a
# single line was compiled). aarch64-unknown-linux-musl is the image's
# host target and ships preinstalled.
#
# The race mirrors the action: all four probes run at once, the FIRST one
# to answer wins via an atomic `ln` (EEXIST for everyone else), losers
# are killed, deadline 60s. Inside a single RUN this all stays one shell
# so `dist` reaches the rustup call below.
RUN set -eu; \
    race="/tmp/rustup-mirror-race"; rm -rf "$race"; mkdir -p "$race"; \
    i=0; pids=""; \
    for m in "https://rsproxy.cn" \
             "https://mirrors.ustc.edu.cn/rust-static" \
             "https://mirrors.tuna.tsinghua.edu.cn/rustup" \
             "https://static.rust-lang.org"; do \
      i=$((i + 1)); \
      printf '%s' "$m" > "$race/cand.$i"; \
      ( if curl -fsSL --connect-timeout 15 --max-time 45 \
                -o /dev/null "$m/dist/channel-rust-stable.toml.sha256"; then \
          ln "$race/cand.$i" "$race/winner" 2>/dev/null || true; \
        fi ) & \
      pids="$pids $!"; \
    done; \
    deadline=$(( $(date +%s) + 60 )); \
    while [ ! -e "$race/winner" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 1; done; \
    kill $pids 2>/dev/null || true; wait || true; \
    dist=""; \
    if [ -e "$race/winner" ]; then dist="$(cat "$race/winner")"; fi; \
    if [ -n "$dist" ] && [ "$dist" != "https://static.rust-lang.org" ]; then \
      echo "rust mirror picked (first to answer): $dist"; \
      export RUSTUP_DIST_SERVER="$dist"; \
    else \
      echo "no rust mirror answered - using the rustup defaults"; \
    fi; \
    rustup target add x86_64-unknown-linux-musl

# Optional crates.io source replacement for restricted networks (CI needs NONE;
# CI runners reach crates.io directly):
#   --build-arg CARGO_MIRROR=sparse+https://<registry-host>/crates.io-index/
ARG CARGO_MIRROR=''
RUN if [ -n "$CARGO_MIRROR" ]; then \
      printf '[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' \
        "$CARGO_MIRROR" > "$CARGO_HOME/config.toml"; \
      echo "cargo mirror enabled: $CARGO_MIRROR"; \
    fi

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY cachette.example.toml ./cachette.example.toml

# Cache mounts keep the ~190-crate dependency build cached across local
# iterations; both per-arch binaries are version- and static-checked before
# staging. (sharing=locked kept from the per-arch era: rungs can overlap on
# the shared pinned builder, and locked is correct always.)
#
# -O2 release cap + RUSTFLAGS -O3 reclaim: the gcc-15.2.0 -O3 ICE that
#   forced this pair is OFF the build path now (zig cc compiles the C), but
#   the pair is harmless (cc-rs C at -O2, rust codegen still at -O3 via
#   RUSTFLAGS) and changing it would churn every cached layer - keep until
#   the next dependency-migration sweep.
ENV CARGO_PROFILE_RELEASE_OPT_LEVEL=2
ENV RUSTFLAGS="-Copt-level=3"
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eu; \
    for t in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do \
      cargo zigbuild --release --locked --target "$t"; \
    done; \
    case "$BUILDARCH" in \
      arm64) NATIVE_BIN="target/aarch64-unknown-linux-musl/release/cachette" ;; \
      amd64) NATIVE_BIN="target/x86_64-unknown-linux-musl/release/cachette" ;; \
      *) echo "unsupported BUILDARCH for the version assert: ${BUILDARCH}"; exit 1 ;; \
    esac; \
    "./${NATIVE_BIN}" --version; \
    file target/aarch64-unknown-linux-musl/release/cachette \
         target/x86_64-unknown-linux-musl/release/cachette \
         | tee /dev/stderr \
         | grep -Eq 'statically linked|static-pie linked'; \
    mkdir -p /out/amd64 /out/arm64; \
    cp target/x86_64-unknown-linux-musl/release/cachette /out/amd64/cachette; \
    cp target/aarch64-unknown-linux-musl/release/cachette /out/arm64/cachette; \
    mkdir -p /rootfs/usr/local/bin /rootfs/config /rootfs/var/lib/cachette; \
    cp cachette.example.toml /rootfs/config/cachette.toml; \
    chown -R 65532:65532 /rootfs

FROM scratch AS runtime
# TARGETARCH is a predefined buildkit arg (amd64 | arm64); re-declared here
# so the runtime stage can pick its platform's binary out of /out.
ARG TARGETARCH
COPY --from=builder /rootfs /
COPY --from=builder --chown=65532:65532 /out/${TARGETARCH}/cachette /usr/local/bin/cachette
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cachette"]
CMD ["--config", "/config/cachette.toml"]
