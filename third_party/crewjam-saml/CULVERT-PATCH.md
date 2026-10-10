# Narrow runtime fixture exclusion

This directory is the complete `github.com/crewjam/saml v0.5.1` Go module,
tag commit `e3d0323a999e14876893e394b91573ba5e5cd453`. Upstream files and notices
are retained. No licensing policy or upstream notice is changed.

The **only change to an upstream file** prepends the following constraint and
blank line to `xmlenc/fuzz.go`, preserving every original byte after it:

```go
//go:build gofuzz
// +build gofuzz

```

The upstream companion `xmlenc/fuzz_test.go` already uses this constraint.
Normal builds now omit the fuzz-only `testKey` initializer and `Fuzz` entry point.
The normal XML-encryption and SAML implementation is byte-identical to upstream.
Deliberate `-tags=gofuzz` builds still include the legacy public fixture; they
are not release builds. This patch does not modernize or otherwise repair the
upstream legacy fuzz harness.

The motivating artifact scan found the public RSA fuzz fixture embedded in the
production executable. This is dependency test residue, not an operator signing
key. Upstream removal PR <https://github.com/crewjam/saml/pull/646> was open and
unmerged when this patch was created, and no released replacement was available.
That PR is reference material, not an unreviewed imported change.

`CULVERT-PROVENANCE.json` records the module checksum, downloaded zip SHA-256,
all 235 upstream file hashes, and both hashes for the one patched file. The zip
was independently retrieved from the Go module proxy and matched the verified
module-cache archive; the module checksum matches the pre-replacement root
`go.sum` entry. Go removes that unused sum after a local replacement; the exact
upstream sum remains in provenance rather than fighting `go mod tidy`.
The local `.gitattributes` prevents checkout newline conversion from changing
audited upstream bytes on Windows.

Verify from the repository root:

```text
python appliance/artifact-audit/verify_saml_patch.py
python appliance/artifact-audit/verify_saml_patch.py --upstream-zip <v0.5.1.zip> --binary <compiled-culvert>
```

The root module's explicit local replacement applies this patch to ordinary
Go builds and container builds without mutating the module cache. It adds a
small local dependency maintenance obligation: upgrades must replace the full
upstream tree, revisit whether the patch remains needed, regenerate provenance,
run upstream XML/SAML and Culvert signature/audience/replay tests, and scan the
resulting runtime artifact. A local replacement is recorded in Go build info;
consumers of SBOMs must retain the upstream version and this patch provenance.
