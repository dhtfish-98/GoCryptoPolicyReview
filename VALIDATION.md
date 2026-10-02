# Local engineering validation

Measured environment: Go 1.26.2, Darwin arm64, CGO disabled, local toolchain.
For testing/building after fetching the analyzer's one pinned dependency,
GOTOOLCHAIN=local, GOPROXY=off, GOSUMDB=off, GOWORK=off and GOFLAGS=-mod=readonly
were used. No reviewed source file was built, imported, run or modified.

Local source: 45 meaningful `Test` methods and four bounded-fuzz seed cases
pass. The constant reference compares 71 cases to actual `go/types`, including
typed overflow, incompatible operands and unsigned complements. Seven further
expressions are independently checked with both 386 and amd64 `go/types`
sizes (14 checks); architecture-dependent `uint` complement stays `OPEN`,
with fixed `uint32`/`uint64` controls. Go vet and gofmt pass. The final bounded
fuzz run completed 118,690 executions with two workers and no crash; earlier
runs completed 69,073, 36,302 and 43,724. The exact final frozen
source/file/artifact identities and consumer run results are in the external
engineering report; a different later hash is not covered automatically.

Cases cover lexical import/type aliases and shadowing, constant `iota` and
repeated specs, integer shifts/arithmetic and bounded typed widths, dynamic
booleans/values, invalid RSA arity, server/client TLS defaults and source debug
directives, effective Go 1.26 custom-reader behavior, Ed25519/TLS differences,
random simulation observations, reader mutation/escape, straight-line AES key
flow and invalidation, source privacy/physical `//line` positions, UTF-8,
malformed tokens/syntax, cgo/build tags, admission/digest/detail/report budgets,
input preservation and permanent `OPEN` boundaries. The local reader checks
real regular files, symlink components, parent segments, directories, devices
and FIFOs without blocking. CLI tests cover installed-contract statuses and
fixed argument/read failures without echoing paths or invalid values.

Fresh extracted source consumer validation uses a new module
cache seeded solely from the delivered offline dependency proxy, offline
45-method test/vet execution, installed CLI statuses 0/1/2/help/privacy/budget,
input-hash preservation, source archive inventory comparison and byte-identical
rebuild of the Darwin arm64 executable. Those final measurements are recorded
in the engineering report, separate from these source checks. A Linux amd64
cross-build is build evidence only; its runtime and remote CI are `OPEN`.

The offline dependency archive contains a `proxy/golang.org/x/sys/@v` tree
and license/origin metadata. Extract it beside the fresh source directory,
then use GOPROXY=file:///absolute/path/to/proxy, GOSUMDB=off and a new
GOMODCACHE for the developer-only `go mod download`; `go.sum` verifies the
version's content sums. Switch GOPROXY=off for test/vet/build/install. This
process only prepares this analyzer; target modules are never downloaded.

PASS applies to measured local engineering and the explicitly bounded rules.
No TLS handshake, generated key, credential, target build or actual execution
path is validated. Remote publication/Actions, applicant identity/organization,
human review/ownership and CVP approval remain `OPEN`.
