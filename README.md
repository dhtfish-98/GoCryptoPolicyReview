# GoCryptoPolicyReview


New implementation author: **dhtfish98**. Current project version: **0.1.2**.

Offline, bounded review of explicitly supplied Go source bytes. A new analyzer
uses Go's real scanner/parser, lexical AST bindings and `go/constant`; it does
not call gosec. It reviews declared TLS verification/minimum protocol, RSA key
size, and supported random source relationships to cryptographic APIs.

The analyzer never loads a module or package, invokes `go list`, `go get`,
`go build`, runs source or `init`, evaluates a Go function, performs a TLS
handshake, generates a key, probes credentials, queries an API or repairs code.
Building this analyzer itself is a separate developer action. Only the source
files explicitly named by the caller are read. Files are analyzed separately.

## Use

Go 1.26.x builds the program; the measured build uses Go 1.26.2. Linux and Darwin
provide the CLI reader. Other platforms return JSON `OPEN` for local reads.

```sh
go mod download
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-buildid= -o dist/gocrypto-policy-review ./cmd/gocrypto-policy-review
./dist/gocrypto-policy-review -- examples/declared-pass.go.txt
./dist/gocrypto-policy-review -- examples/policy-fail.go.txt
./dist/gocrypto-policy-review --go-minor 26 --tls-role server --tls-defaults standard --crypto-random standard -- examples/default-review.go.txt
```

`go mod download` above obtains this analyzer's pinned, trusted Unix library for
its build. It is never run on a checked project. An offline dependency archive
with a local Go module proxy is supplied beside measured artifacts; see
`VALIDATION.md`. Prebuilt binaries require no Go toolchain or module cache.
Flags precede file arguments. `--max-file-bytes` can lower the byte cap.
`--help` prints ordinary help; every other outcome prints one JSON report.

Exit 0 is `PASS` for all admitted checks in the frozen rule subset. Exit 1 is
`FAIL` for at least one declared policy violation. Exit 2 is `OPEN` when no
known violation exists and required information, supported syntax or budget is
missing. `FAIL` and `OPEN` may coexist: findings remain and `unknowns` records
unresolved work. A report also keeps compilation, runtime security, source
authenticity, cross-file resolution and CVP eligibility permanently `OPEN`.
Passing an AST rule does not prove that a program builds or that a path runs.

Library callers use `Review([][]byte{source}, Options{}, DefaultLimits())`.
The source module identity is `github.com/dhtfish-98/GoCryptoPolicyReview`;
remote publication and remote installation availability require separate evidence.
Input slices are not modified. `Limits` must be positive and may only lower
defaults; the report cap is at least 2048 bytes, including its final newline.
Invalid options are replaced with a fixed error report, without echoing them.
The supplied inventory is not asserted to be a complete package. Const values
are not merged across files; declared builtin-name collisions in another
supplied file with the same package name become `OPEN`. Unseen package files
and their possible bindings remain within permanent cross-file uncertainty.

## Frozen checks

| Area | Supported analysis | Unknown boundaries |
| --- | --- | --- |
| TLS | Keyed `crypto/tls.Config` literals, local syntactic type aliases, zero declarations, `new`, explicitly typed parameters and field assignments; constant `InsecureSkipVerify`; `MinVersion` TLS 1.2 minimum; literal maximum range consistency | Dynamic booleans/versions, defined types, type assertions, returned configs, unresolved receivers, unkeyed/duplicate fields and unsupported assignment shapes are `OPEN`. Cipher suites, maximum field assignments, server preference, trust roots, ECH, client-auth and custom verifier correctness are outside the rule subset. |
| RSA | Aliased imports, direct `GenerateKey` and `GenerateMultiPrimeKey`; constant requested bits below 2048 are policy `FAIL` | Nonpositive/unknown/invalid constants, bad arity, function values and cross-file/package constants are `OPEN`. A requested size below Go's accepted minimum is still a declared-policy finding; no generated key is claimed. Multi-prime count safety is unassessed. |
| Random readers | Immutable local initializer/alias chain from `math/rand.New(math/rand.NewSource(...))` into RSA, ECDSA (reader argument 2), Ed25519 and TLS `Rand`; direct `crypto/rand.Reader` and supported default-reader declarations | Assignment/address escape, custom sources, other packages, generic calls, caller return values and arbitrary `io.Reader` implementations are `OPEN`. `math/rand/v2` has purpose observations but no reader provenance model. |
| Random bytes | Same lexical byte-buffer object in one straight-line block: a single `math/rand.Read(buffer)` call followed by a single `crypto/aes.NewCipher(buffer)` call | Aliasing, mutation, another call, control flow, nested calls, returns, goroutines and defers invalidate this proof; unmodeled AES key sources stay `OPEN`. |

`math/rand`/`math/rand/v2` simulation calls are never automatically findings.
The finite call vocabulary in `random.go` yields purpose observations `OPEN`
unless a supported security relationship consumes the source. Names such as
"password" and source comments are not security-use evidence. Observations
do not certify a simulation's correctness. Function values and generic
random calls stay unresolved rather than silently disappearing.

Constant expressions support integer/rune literals, booleans, local `const`
bindings including repeated specs and `iota`, parentheses, integer arithmetic,
bounded shifts/bit operations, boolean operations/comparisons, the five TLS
version constants, and finite builtin integer/bool conversions. Typed widths
are retained through operations; overflow and incompatible typed operands do
not become policy values. `int`/`uint` representability conservatively uses
32-bit limits; unsigned `uint` complement stays `OPEN` because its result
depends on an unstated target architecture. Fixed-width unsigned complements
use their declared width. No target architecture is inferred from this tool's build.
Floats/complex/string constants, named conversion types, dynamic variables,
external constants, constants deeper than 64 references, shifts above 4096
and integers above 4096 bits stay `OPEN`.

## Declared version and environment assumptions

The frozen catalog covers standard Go 1.22 through 1.26 only. `--go-minor`
asserts the target runtime's version, rather than a `go.mod` language directive
or this analyzer's build version. It is not automatically discovered.

An omitted/zero TLS minimum requires an asserted version and client/server
role. In this catalog clients default to TLS 1.2. For servers the caller must
also assert effective `--tls-defaults standard` (TLS 1.2) or `server_legacy`
(TLS 1.0, a policy finding). These assertions include effective GODEBUG behavior
and compatibility defaults selected by the target program's build settings;
an absent environment variable alone does not prove the standard behavior.

Go 1.26 RSA and ECDSA key generation ignore the reader unless effective
`cryptocustomrand=1` restores custom behavior. With `--crypto-random standard`
the report records the asserted ignored-reader behavior; with `custom` the
proven weak reader is a policy finding. An unspecified effective mode stays
`OPEN` for weak readers. Go 1.22–1.25 retain the custom reader behavior.
Ed25519 with a nonnil reader still consumes it in the frozen 1.26 source. TLS
1.26.2 still uses `Config.Rand` for hello nonces; current unversioned package
documentation is not substituted for that frozen source.

Caller assertions are reported explicitly and are not attested. Runtime
execution, FIPS/boring variations, global reader overrides, compiler behavior,
and actual entropy quality remain outside these source-policy conclusions.
An asserted server role leaves a true `InsecureSkipVerify` field `OPEN`, because
that flag controls client verification rather than server-side client-auth.
Source `//go:debug` directives are recorded as unresolved build defaults.

## Input, coordinates, privacy and budgets

The CLI rejects raw `..` segments before path normalization. A descriptor-rooted
Unix `openat` walk uses `O_NOFOLLOW` on every path component, directory flags
for intermediate components, and `O_NONBLOCK` for the final file. It accepts
only a bounded regular file and checks size/device/inode/mode/mtime/ctime
before and after reading. Symlink components, directories, devices, FIFOs,
unreadable/changed files and excess paths return fixed JSON `OPEN` codes.
This metadata check does not attest file authenticity or defeat arbitrary
concurrent writers. No input is written. Empty paths, NUL, paths above 4096
bytes and paths above 128 components are rejected.

Reports contain file inventory numbers, physical 1-based line/byte columns,
fixed rule/reason vocabulary, recognized numeric policy values and SHA-256
digests of admitted input bytes. Paths, identifier names, comments, string
values, parser messages and argument text are not returned. `//line` source
directives do not replace physical positions. Oversized/unadmitted byte
slices are not hashed; their digest is `OPEN` with no hash. Admitted invalid
syntax may have a byte digest, which proves only which bytes were parsed.

Default caps are 32 files, 256 KiB per file, 2 MiB total, 32768 tokens per file,
8192 token bytes, 128 lexical nesting/operators, 256 AST depth, 50000 AST
nodes/evaluation steps per file, 2048 detailed results and 1 MiB JSON.
Analysis depth/shift caps are additional fixed conservative bounds. Budget
exhaustion cannot produce a clean `PASS`; detail omission retains known
finding counts and `FAIL`. Source files with build tags or cgo stay `OPEN`
because their build selection is not evaluated.

## Provenance and status

Conceptual source: `securego/gosec` at
`826f6f4fd18b7b0cf0a76b2df1994b3eb90da8f3`, Apache-2.0. The 18-file selected
entry/rule/side-effect review and exact hashes are in `SOURCE_REVIEW.json`.
This is a complete new implementation of the stated bounded subset; it is
not the complete gosec scanner, SSA analyzer, cipher policy or whole-repository
rewrite. No upstream runtime is vendored or invoked. Mature Go standard
library code and the pinned Unix syscall library are separate dependencies.

New implementation author: dhtfish98. Original Go/x-sys license and patent-grant
notices accompany the actual linked and offline dependency materials in
`third_party`. gosec is a fixed design reference only. Human ownership/review, applicant identity/organization, CVP
admission, remote publication and remote CI are not established by this local
artifact. Defensive topic fit is conditional on authorized source review.
No project count or passing test implies application approval.
