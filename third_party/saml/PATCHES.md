# Patched fork of github.com/crewjam/saml

This directory is a patched copy of `github.com/crewjam/saml`, wired in by a
directory replacement in the root `go.mod`:

    replace github.com/crewjam/saml => ./third_party/saml

It exists only to fix [GO-2026-6909](https://pkg.go.dev/vuln/GO-2026-6909),
which has no upstream fix ("Fixed in: N/A"). It is temporary.

## Upstream provenance

| | |
|---|---|
| Module | `github.com/crewjam/saml` |
| Version | `v0.5.1` (the version the root `go.mod` requires) |
| Module zip hash | `h1:g+mfp0CrLuLRZCK793PgJcZeg5dS/0CDwoeAX2zcwNI=` (root `go.sum` before the replacement) |
| go.mod hash | `h1:r0fDkmFe5URDgPrmtH0IYokva6fac3AUdstiPhyEolQ=` |
| License | BSD 2-Clause, `LICENSE` (kept verbatim) |

Copied from the verified module cache (`$(go env GOMODCACHE)/github.com/crewjam/saml@v0.5.1`).
Every file kept is byte-identical to that release except `schema.go`,
`service_provider.go` and `schema_test.go` (see "Patches"). `PATCHES.md` and
`go_2026_6909_test.go` are additions. `go.mod` and `go.sum` are unmodified, so
the dependency graph the root module resolves is the same one v0.5.1 produced.

## Files dropped from the upstream release

No package Culvert imports lost any non-test source. Dropped:

| Path | Why |
|---|---|
| `example/` | Demo `main` programs; not imported. They embed PEM private keys. |
| `xmlenc/fuzz.go`, `xmlenc/fuzz_test.go`, `xmlenc/corpus/`, `xmlenc/crashers/` | The go-fuzz harness. `fuzz.go` is compiled into the `xmlenc` package (no build tag) and hard-codes an RSA private key, parsed at package init. Only the harness's exported `Fuzz` function uses it, and nothing in Culvert does. |
| Every `*_test.go` except `duration_test.go`, `time_test.go`, `schema_test.go`; `testdata/`, `samlsp/testdata/`, `samlidp/testdata/`, `xmlenc/testdata/` | The dropped tests load PEM private keys and signed JWT fixtures from these trees. Committing real key material would trip the repository's secret scanning (Gate · gitleaks scans every commit of a PR). The three kept tests are self-contained. |
| `.github/`, `.golangci.yml`, `CODEOWNERS` | Upstream repository CI and ownership metadata; meaningless inside this repository. |

The complete upstream suite was run against the patched fork outside the
repository; see "Verification" below.

## Patches

Every patched line carries a `Culvert fork (GO-2026-6909)` comment.
`go_2026_6909_test.go` holds a regression test for each patch. Each one fails
or panics against unpatched v0.5.1.

### (a) `validateAssertion`: reject, never dereference, missing elements

`service_provider.go`, `(*ServiceProvider).validateAssertion`. This runs after
signature verification. The advisory describes a nil `assertion.Issuer`
dereference guarded by an `ExpectedIDPEntityID` field. That field does not
exist in v0.5.1, where `Assertion.Issuer` is a value. The same bug class is
present in v0.5.1 as nil dereferences of optional pointers. A signed assertion
that omits one of these elements panicked:

| Missing element | v0.5.1 | Patched |
|---|---|---|
| `<saml:Subject>` | panic (`assertion.Subject.SubjectConfirmations`) | `assertion has no Subject` |
| `<saml:SubjectConfirmationData>` in a `SubjectConfirmation` | panic (`.InResponseTo` / `.Recipient`) | `assertion SubjectConfirmation has no SubjectConfirmationData` |
| `<saml:Conditions>` | panic (`assertion.Conditions.NotBefore`) | `assertion has no Conditions` |
| `<saml:Issuer>` | rejected only because `"" != IDPMetadata.EntityID`; **accepted** when the IdP metadata has an empty `entityID` | `assertion has no Issuer`, checked before the entity comparison |

Each of the first three was a panic before, so no assertion that worked before
is now rejected. The Web Browser SSO profile requires all four elements.

Tests: `TestGO20266909ValidateAssertionRejectsMissingIssuer`,
`TestGO20266909ValidateAssertionRejectsMissingElementsWithoutPanic`, with
`TestGO20266909ValidateAssertionAcceptsWellFormedAssertion` as the positive
control.

### (b) Namespace-qualified identity fields in `schema.go`

encoding/xml matches a field with a bare tag (`xml:"NameID"`), or an untagged
field whose type has no namespaced `XMLName`, against an element of that local
name in **any** namespace, including no namespace. Where the field is a
pointer, a later match overwrites an earlier one. A signed assertion could
therefore carry a foreign-namespace `<x:NameID>` inside `<saml:Subject>`,
either instead of `<saml:NameID>` or *after* it, and it became
`Subject.NameID`. Changed tags:

| Field | v0.5.1 tag | Patched tag |
|---|---|---|
| `Subject.NameID` | *(none: matches any `NameID`)* | `urn:oasis:names:tc:SAML:2.0:assertion NameID` |
| `Assertion.AttributeStatements` | `AttributeStatement` | `urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement` |
| `AttributeStatement.Attributes` | `Attribute` | `urn:oasis:names:tc:SAML:2.0:assertion Attribute` |
| `Attribute.Values` | `AttributeValue` | `urn:oasis:names:tc:SAML:2.0:assertion AttributeValue` |

The attribute chain is fixed for the same reason as NameID. A service provider
takes identity (an email fallback when the NameID format is not stable) and
group claims from it. In Culvert those claims feed policy.
`auth_saml_go_2026_6909_test.go` shows both spoofs succeeding end to end against
v0.5.1. Prefixed, default-namespace and element-local-prefix forms of the SAML
namespace still bind.

Behavior notes:

- An unqualified `<NameID>` (no namespace at all) inside `<saml:Subject>` no
  longer binds. That form is not valid SAML.
- `xml.Marshal` of these structs now emits a redundant
  `xmlns="urn:oasis:names:tc:SAML:2.0:assertion"` on the four elements, as it
  already did for `Issuer` and `Subject`. The library builds its own XML with
  `Element()`, which is unchanged. Upstream `TestParseXMLArtifactResponse` (not
  vendored) compares an `xml.Marshal` golden. Against the patched code it
  differs only by those declarations, 20 of them, and the parsed content is
  identical.
- `schema_test.go` (`TestAttributeXMLRoundTrip`) is the one modified upstream
  file outside `schema.go` and `service_provider.go`. It unmarshalled an
  `Attribute.Element()` fragment whose `saml:` prefix is undeclared. It now
  declares the prefix, as every real assertion does. An undeclared prefix
  cannot reach the parser in production, because `findChildren` rejects it.

Tests: `TestGO20266909SubjectNameIDRequiresAssertionNamespace`,
`TestGO20266909AttributesRequireAssertionNamespace`,
`TestGO20266909NameIDPrefixDeclaredOnResponse`.

### (c) `unmarshalElement`: serialize with the in-scope namespaces only

`service_provider.go`, `unmarshalElement`. It used `elementToBytes`, which
copies the element and declares on the copy every `prefix → URI` pair found
**anywhere in the document** (`FindElements("//*")`, last one wins, in depth
order). A prefix that is foreign at the NameID could therefore be rebound to
the SAML namespace by an element elsewhere in the document. That defeated (b).

Attack shape (end to end in
`TestGO20266909SignedAssertionPrefixRebindingDoesNotSpoofNameID`):

1. The IdP signs only the assertion (exclusive c14n, as `IdentityProvider`
   does), and the assertion carries a foreign-namespace `p:NameID`. This is the
   advisory's own precondition.
2. Whoever relays the unsigned Response (the user's browser in the POST
   binding) moves `xmlns:p` from the NameID to the Response root. Exclusive
   c14n renders it on the NameID either way, so the signature still verifies.
3. The relay adds an element deeper in the document than the NameID that binds
   `p` to `urn:oasis:names:tc:SAML:2.0:assertion`.

With (a) and (b) only, `ParseXMLResponse` returned
`Subject.NameID = admin@example.com`. `unmarshalElement` now serializes with
`etreeutils.NSDetatch(etreeutils.NSBuildParentContext(el), el)`, which is the
bindings actually in scope at `el`. Descendants keep their own declarations.

The change is limited to the parse path. `elementToBytes` itself is unchanged,
so the outbound ArtifactResolve SOAP serialization and the `elementToString`
error text are unaffected. For any assertion whose signature verifies, every
prefix is declared in scope, because canonicalization fails on an undeclared
prefix. For those assertions the two serializations bind identically unless a
prefix is bound differently elsewhere in the document. In that case only the
new one is correct.

## Known remaining issues (not patched)

These look questionable but are not shown to be exploitable in the same way.
They were left unpatched to keep the fork minimal:

- Bare or untyped tags remain on fields the library uses only for validation:
  `Subject.SubjectConfirmations`, `SubjectConfirmation.NameID`,
  `SubjectConfirmation.SubjectConfirmationData`, `Assertion.Conditions`,
  `Conditions.AudienceRestrictions`, `AudienceRestriction.Audience`,
  `Assertion.AuthnStatements`, `AttributeValue.NameID` and
  `LogoutRequest.NameID`. Under the same precondition (an IdP-signed assertion
  carrying foreign-namespace elements), a foreign `<x:Conditions>` or
  `<x:SubjectConfirmationData>` placed after the real one would replace it
  (last match wins). That could relax audience, recipient or expiry checks
  rather than spoof identity.
- `elementToBytes` keeps the document-wide prefix map for its two remaining
  callers (outbound ArtifactResolve, `InvalidResponseError.Response` text).

## Verification

- Kept upstream tests plus `go_2026_6909_test.go`: `go test -race -count=2 ./...`
  in this directory.
- The complete v0.5.1 suite, including the dropped key-dependent tests, was run
  against the patched sources in a scratch copy of the release. Results match
  unpatched v0.5.1 exactly: 199 passes, plus one failure that is pre-existing
  and unrelated (`TestSPCanProduceSignedRequestRedirectBinding`, a DEFLATE
  output golden that differs under the current Go toolchain). The exception is
  the `TestParseXMLArtifactResponse` marshal-format change described in (b).

## Removal plan

Upstream has not shipped a fix. When a `github.com/crewjam/saml` release fixes
GO-2026-6909:

1. Delete the `replace` directive from the root `go.mod` and bump the
   `require` to the fixed release.
2. Delete `third_party/saml/` and the
   `COPY third_party/saml/go.mod third_party/saml/go.sum ./third_party/saml/` lines in
   `Dockerfile` and `test/e2e/maint-agent/Dockerfile.e2e`.
3. Run `go mod tidy`, `govulncheck ./...` and the root SAML tests
   (`go test -run 'SAML|Saml' .`). The GO-2026-6909 regression tests in
   `auth_saml_go_2026_6909_test.go` must keep passing against the upstream fix.
