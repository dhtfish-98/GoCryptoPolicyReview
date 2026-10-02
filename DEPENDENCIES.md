# Dependency boundary

The only external runtime module is `golang.org/x/sys v0.48.0`, origin commit
`613e2570718ecde85c04e69ebd5585c3881c442c`, BSD-3-Clause with PATENTS. Its Unix
`Open`, `Openat`, `Fstat`, `Close` and constants support the descriptor-rooted
nonfollowing reader. The archive SHA-256 is
`3a47e06431ba1e24d5b2aca3a7ce31fd13faff34df3e5d8e63f105ff9d0c1786`.
`go.mod`/`go.sum` pin the module, with Go checksum-database validation separately
run from a fresh manifest/cache with no existing go.sum. Inspected wrapper
ranges and license hashes are in `third_party/x-sys/ORIGIN.json`; this is not
a complete dependency source audit. No x/sys source is vendored here.

The measured compiler and linked standard library are Go 1.26.2, Darwin arm64,
fixed source commit `9c8bf0e72a6fb3b415b591b124b59fbb7cf92252`. Selected TLS and
crypto random-source semantics were matched against that fixed remote source.
Only recorded ranges were reviewed, not the whole Go toolchain. Copyright,
BSD-3-Clause terms and PATENTS accompany binary distributions. No claim of
current latest version, complete dependency security or runtime certification
is made by this build evidence.

Unit tests use `go/types` on locally generated, import-free constant fixtures
as an independent reference. It checks trusted fixture declarations in memory
without executing them. The analyzer runtime uses `go/scanner`, `go/parser`,
`go/ast`, `go/constant`, and standard hashing/JSON libraries; it never imports
`go/packages`, an importer, SSA, `net/http` or `os/exec`. No original gosec,
AI SDK, scanner wrapper, parser regex replacement or target module resolver
is in the dependency graph.
