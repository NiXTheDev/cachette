> "{{TAGLINE}}"
>
{{LEAD}}
>
> **What is cachette?** A self-hosted cache server for Actions-style CI. It speaks the real GitHub cache protocols end to end - the `actions/cache` toolkit's ArtifactCache (v1) and buildx's CacheService (v2, Twirp + Azure-style block blobs) - so your forge's Actions and your `type=gha` buildx exporter run against your own hardware with zero protocol adapters in between. Real clients round-trip byte-identically: @actions/cache, go-actions-cache, buildx. Not "compatible-ish" - the wire is the wire.
>
> **What's new in v{{VERSION}}:**
>
{{NOTES}}
>
> **Upgrading:**
{{UPGRADING}}
>
> **Binaries** - 8 targets, native builds where the runners allow it:
>
> - linux: gnu + musl, amd64 + arm64
> - windows: gnu x86_64 (zig cc mingw), msvc amd64 + arm64 (cargo-xwin, clang-cl), gnullvm arm64
> - `SHA256SUMS` attached - verify before running anything
