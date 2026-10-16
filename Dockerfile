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
#   (No shell also means no in-container healthcheck - watch
#   `cachette listening on ...` in the logs instead.)
#
# Non-root: numeric `USER 65532:65532` works in scratch without /etc/passwd;
#   /config and /var/lib/cachette are chowned to 65532 so the compose
#   named volume is writable on first use.
#
# Entrypoint / command / port:
#   ENTRYPOINT ["/usr/local/bin/cachette"]
#   CMD        ["--config", "/config/cachette.toml"]
#   EXPOSE     8080   # [server] listen = "0.0.0.0:8080" - always TLS
#                     # (self-signed Ed25519 identity cert when the mounted
#                     # config sets no tls_cert/tls_key)
#   docker run --rm cachette:local            -> cachette --config /config/cachette.toml
#   docker run --rm cachette:local --version  -> cachette 0.1.0   (replaces CMD)
#
# The baked /config/cachette.toml is the repo's cachette.example.toml - a
# DEMO default (secret = CHANGE_ME_*). Real deployments must override
# CACHETTE__AUTH__SECRET (compose does) or mount their own config.

FROM rust:1.98-alpine AS builder

# gcc/musl-dev: C toolchain for rusqlite/bundled (SQLite C) + ring.
# file(1): build-time static-link assertion.
RUN apk add --no-cache gcc musl-dev file

# Optional crates.io source replacement for restricted networks (CI needs NONE;
# GitHub runners reach crates.io directly):
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
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
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
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/cachette"]
CMD ["--config", "/config/cachette.toml"]
