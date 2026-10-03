# Origin and attribution

This project is a new implementation of the local Go TLS/RSA/random source
review subset recorded in the 30-project selection. It reads Go ASTs itself
and does not wrap the original scanner. New implementation author: dhtfish98. Testing and source review use the methods documented in VALIDATION.md. This statement is not human-only
authorship, verified ownership, upstream endorsement or CVP acceptance.

Reference upstream: [securego/gosec](https://github.com/securego/gosec), fixed
commit `826f6f4fd18b7b0cf0a76b2df1994b3eb90da8f3`. This is a design reference; no original gosec runtime, module, fixture or document excerpt is distributed. The unused gosec license copy is omitted; new source independently uses Apache-2.0. `SOURCE_REVIEW.json` records SHA-256/Git blob hashes and matching
fixed-commit remote bytes for all 18 fully read selected files (3952 lines).
This scope does not constitute an audit of the whole upstream repository,
its SSA helpers, SDKs, tests, generators, reports or transitive dependencies.

The source review followed the CLI through package discovery, package loading,
SSA construction, rule registration and optional external provider calls. The new
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

New implementation author: dhtfish98. This attribution applies to the new project implementation; original sources, licenses and third-party notices retain their authors. Automated checks do not establish independent human review or CVP eligibility.

## Current distribution and reference boundary

New analyzer source and native executables are distributed. Executables contain Go standard-library and x/sys code; the offline bundle contains exact x/sys source. Their original licenses and patent-grant documents remain. gosec is reference-only. New implementation author and maintainer: dhtfish98. Source identities and bounded research facts above remain provenance, not an assertion that those authors wrote or endorsed the new runtime.
