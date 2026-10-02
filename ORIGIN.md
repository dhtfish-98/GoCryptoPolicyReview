# Origin and attribution

This project is a new implementation of the local Go TLS/RSA/random source
review subset recorded in the 30-project selection. It reads Go ASTs itself
and does not wrap the original scanner. Codex assisted the implementation,
testing, source review and documentation. This statement is not human-only
authorship, verified ownership, upstream endorsement or CVP acceptance.

Reference upstream: [securego/gosec](https://github.com/securego/gosec), fixed
commit `826f6f4fd18b7b0cf0a76b2df1994b3eb90da8f3`. Apache-2.0 license text and
the selected-file Hewlett Packard Enterprise Development LP attribution are
retained. `SOURCE_REVIEW.json` records SHA-256/Git blob hashes and matching
fixed-commit remote bytes for all 18 fully read selected files (3952 lines).
This scope does not constitute an audit of the whole upstream repository,
its SSA helpers, SDKs, tests, generators, reports or transitive dependencies.

The source review followed the CLI through package discovery, package loading,
SSA construction, rule registration and optional AI provider calls. The new
runtime omits those effects. It also deliberately changes the original
blanket weak-random verdict to require an observed security-use relationship.
Unknown constants are distinct from zero and TLS defaults require assertions.
The new subset excludes original cipher-suite/server-preference policies.

Go standard library and `golang.org/x/sys` are mature dependencies, not claimed
as rewritten code. Dependency origins, hashes, licenses and inspected syscall
or version-semantic ranges are in `third_party/*/ORIGIN.json`. The standard
library is linked by Go; only x/sys is an external module. No third-party
runtime source is vendored. Original dependency notices accompany binary
distributions. The CLI is local and read-only after build.

Local build, tests and measured install results are in `VALIDATION.md` and the
engineering evidence report. Remote CI/publication, actual source/runtime
authenticity, human review/rights and applicant identity/organization/CVP
admission remain `OPEN` until independently evidenced.
