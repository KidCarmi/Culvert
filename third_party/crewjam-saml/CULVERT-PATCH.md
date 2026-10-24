# Narrow runtime fixture exclusion

This directory is the complete `github.com/crewjam/saml v0.5.1` Go module,
tag commit `e3d0323a999e14876893e394b91573ba5e5cd453`. Upstream files and notices
are retained. No licensing policy or upstream notice is changed.

The **only change to an upstream source file** prepends the following constraint
and blank line to `xmlenc/fuzz.go`, preserving every original byte after it. (A
second, test-data-only change is recorded under "Go 1.27 test goldens" below.)

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
all 235 upstream file hashes, both hashes for the one patched source file, and
both hashes for each of the 8 test-data files below. The zip
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

## Go 1.27 test goldens (test data only)

`TestSPCanProduceSignedRequestRedirectBinding` compares the exact signed
HTTP-Redirect query string against 8 upstream golden files
(`testdata/TestSPCanProduceSignedRequestRedirectBinding/*_queryString`). That
string carries DEFLATE-compressed bytes, and DEFLATE output is not canonical:
Go 1.27's `compress/flate` emits different, equally valid bytes, so the upstream
goldens fail under the repository's go1.27.3 toolchain while the same source
passes under go1.26.10. The decoded AuthnRequest goldens
(`*_decodedRequest`), which the same test also checks, are unchanged, and so is
every source file.

The 8 query-string goldens were regenerated under go1.27.3 with the test's own
golden-update flag:

```text
cd third_party/crewjam-saml
go test -mod=readonly -run '^TestSPCanProduceSignedRequestRedirectBinding$' . -test.update-golden
```

`CULVERT-PROVENANCE.json` records each file's upstream and regenerated hash under
`test_data_patch`. `verify_saml_patch.py` fixes the scope to exactly these 8
paths, pins the record by hash, and still requires every other file to match
upstream. Consequence: the root SAML package test now passes on go1.27.3 and,
for these 8 goldens only, fails on older compilers — the repository builds and
tests with go1.27.3 only (`toolchain_consistency_test.go`). Upstream v0.5.1 is
the latest release; a future upstream upgrade replaces the whole tree and
revisits this record.
