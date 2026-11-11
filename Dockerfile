# Multistage build for cachette (plan task 36).
#
# Builder: rust:1.98-alpine -> emits a FULLY STATIC musl binary.
#   * rust's `*-unknown-linux-musl` targets are crt-static by default; alpine
#     IS a musl host, so plain `cargo build --release` targets
#     x86_64-unknown-linux-musl natively here.
#   * buildx runs this stage once per `--platform` (QEMU covers linux/arm64),
#     so each platform image contains its OWN native-arch static binary.
#   * Build-time assertions below prove: it runs, and `file` reports it static.
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
#   docker run --rm cachette:local --version  -> cachette 1.0.0   (replaces CMD)
#
# The baked /config/cachette.toml is the repo's cachette.example.toml - a
# DEMO default (secret = CHANGE_ME_*). Real deployments must override
# CACHETTE__AUTH__SECRET (compose does) or mount their own config.

# Why rust:1.98-alpine rather than :1.99-alpine (Oct 2026): the 1.99 base
# (same gcc 15.2.0, alpine 3.24.3 userland vs 3.24.2) ICE'd in gcc during the
# CI compile of libsqlite3-sys' bundled sqlite3.c with no standalone repro.
# Retry the bump on a fresh Alpine/gcc point release.
#
# Digest-pinned on top of the tag: the docker jobs' last external-host
# dependency is docker.io's blob CDN (production.cloudfront.docker.com),
# which EOF'd the 1.0.0-class docker legs mid-build. The pin lets the
# workflows' pre-pull ladder warm the host store for the EXACT manifest
# buildkit needs, so a republished `1.98-alpine` upstream cannot revolve
# under us mid-fleet. To bump: `docker manifest inspect rust:1.98-alpine`,
# then replace the digest here AND in both workflows' pre-pull steps.
FROM rust:1.98-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS builder

# gcc/musl-dev: C toolchain for rusqlite/bundled (SQLite C) + ring.
# file(1): build-time static-link assertion.
RUN apk add --no-cache gcc musl-dev file

# Optional crates.io source replacement for restricted networks (CI needs NONE;
# CI runners reach crates.io directly):
#   --build-arg CARGO_MIRROR=sparse+https://<registry-host>/crates.io-index/
ARG CARGO_MIRROR=
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
# iterations; the binary is version- and static-checked before staging.
#
# gcc-15.2.0 sqlite3.c ceiling (see the 1.99/1.98 base note above):
# cc-rs derives its -O from cargo's OPT_LEVEL; at -O3 the CI runners'
# gcc (Alpine) 15.2.0 segfaulted in cc1 on every cold amd64 attempt -
# four occurrences across runs 502/558, same file + line (168163,
# whereAddIndexedExpr). Not reproducible locally from toolchain+input
# alone (probe record in the PR body), so the trigger is taken as
# runner-environmental; the profile override caps cc-rs at -O2
# (structural: no -O3 is ever emitted) as a structured pressure
# reducer, while RUSTFLAGS re-claims -O3 for rustc itself - cargo
# appends RUSTFLAGS after the profile flags, so the shipped binary
# keeps -O3 codegen.
ENV CARGO_PROFILE_RELEASE_OPT_LEVEL=2
ENV RUSTFLAGS="-Copt-level=3"
#
# Both mounts carry sharing=locked: buildkit's shared default lets a
# multi-arch build's two platform workers run cargo CONCURRENTLY into
# one cache mount - the witness of the rung-3 deaths in 502/558
# ("failed to unpack ... .cargo-ok: File exists (os error 17)" after an
# earlier leg's cargo was killed mid-unpack). locked = the second
# mount claim waits behind the first; slower worst-case, correct always.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked && \
    ./target/release/cachette --version && \
    file target/release/cachette | tee /dev/stderr | grep -Eq 'statically linked|static-pie linked' && \
    mkdir -p /rootfs/usr/local/bin /rootfs/config /rootfs/var/lib/cachette && \
    cp target/release/cachette /rootfs/usr/local/bin/cachette && \
    cp cachette.example.toml /rootfs/config/cachette.toml && \
    chown -R 65532:65532 /rootfs

FROM scratch AS runtime
COPY --from=builder --chown=65532:65532 /rootfs /
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cachette"]
CMD ["--config", "/config/cachette.toml"]
