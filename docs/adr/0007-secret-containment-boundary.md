# ADR-0007: Compiler-enforced secret-containment boundary (`internal/secret`)

- **Status**: Proposed (design recorded 2026-07-06; no code moved)
- **Date**: 2026-07-06
- **Deciders**: maintainer + engineering advisor session
- **Relates to**: ADR-0002 (flat-package decomposition — this is a *fresh recorded
  design*, not a continuation of that closed program), ADR-0003 (shared-foundation
  seam), `roadmap/CA-3-KEY-AT-REST-DESIGN.md` (the KEK/at-rest foundation),
  `roadmap/SECRET-CONTAINMENT-PLAN.md` (the migration plan)

## Context

The KEK / key-at-rest primitives live in the flat `package main`. `KEKProvider.KEK()`
(kek.go:58) returns raw `[]byte`; `decryptWithKEK` / `readEncryptedFile` (kek.go:90,
120) and the three `decrypt{ClusterCA,DPNode,CDRClient}Key` helpers all return
`plainPEM []byte`. Because everything is one package, any of the ~184 root files can
call these accessors and expose the bytes — e.g. write a KEK into a log line, an
audit entry, or an error string. The controlling invariant ("never log the KEK") is
enforced only by a comment (kek.go:22).

In Go, the **package is the unit of access control**: unexported identifiers are
compiler-enforced and the import graph is machine-checkable. ADR-0002 already used
this to extract 48 engines behind a no-back-import rule — but stopped short of the
crown-jewel secret material. An architecture review (PANW/AWS-caliber) identified
this as the single highest-severity structural finding: for secret-bearing code, a
package boundary is a **security control**, not tidiness.

A refactor-readiness review of the actual code established that the move is clean:

- The PSCA codec is **already** in `internal/ca` (`EncryptBundle`/`DecryptBundle`/
  `HasBundleMagic`); `kek.go` only *wraps* it. ⇒ `internal/secret` sits on top of
  `internal/ca`, never duplicating it.
- `kek.go`'s **only** `package main` dependency is `atomicWriteFile` (kek.go:111),
  itself a wrapper over `fileutil.AtomicWrite`. **No import cycle** — the seam exists.
- 5 consumer files; 3 byte-identical decrypt/verify families (consolidatable).
- The lone test landmine (`kek_test.go` raw-byte assertions) is defused by moving the
  test into `package secret` (whitebox keeps unexported-field access).

## Decision

Introduce `internal/secret`, housing the KEK provider and an **opaque-handle** API.
Secret plaintext never crosses the package boundary as an exported `[]byte`:

```go
type Sealed struct{ b []byte }              // no String(), no exported accessor
func Seal(plaintext []byte, p KEKProvider) ([]byte, error)
func Open(envelope []byte, p KEKProvider) (*Sealed, error)
func (s *Sealed) WithPlaintext(fn func([]byte) error) error   // zeroize after
func (s *Sealed) Destroy()
func ValidateProvider(p KEKProvider) error  // availability check, no bytes
```

`KEKProvider` moves into the package; `main` keeps `type KEKProvider =
secret.KEKProvider` (the established `CertManager`/`Session` alias pattern).
`KEK() []byte` stays on the interface but is internal-use only (consumed by
`Seal`/`Open` inside the package). Stdlib callers that require `[]byte`
(`pem.Decode`, `x509.ParseECPrivateKey`, `tls.X509KeyPair`) use the scoped
`WithPlaintext` escape hatch, which zeroizes on return.

Execution is strangler-fig (see the plan): PR-0 de-risks inside `main` (kill the
`atomicWriteFile` dep, consolidate the 3 families, introduce `WithPlaintext` first);
PR-1 lifts the primitive layer + moves the test; PR-2…N convert consumers one domain
per PR; PR-final documents and tightens. Every PR compiles green and is independently
revertible.

A fitness-function test asserts `internal/secret` exports no `[]byte`-returning
secret accessor — the same machine-checked-invariant discipline as the C1/C2 walls.

## Scope boundaries (explicit non-goals)

- **Not a package restructure of `package main`.** This encloses only secret-bearing
  primitives. The flat layout and the parity walls stand. ADR-0002's recorded
  rejections of `proxy.go`/`controlplane.go`/`configversion.go` extraction are
  unaffected.
- **`clusterCA` stays in `main`.** It tangles CA-crypto with enrollment state
  (enrollment.go:721); its `CAKeyPEM()` is a legitimate bytes-over-mTLS transport
  site. A future `internal/clusterca` is a separate decision.
- The CONNECT/relay hot path is never touched — this is startup/control-plane code.

## Consequences

**Positive**
- "Never log the KEK" becomes a **compile error**, not a review obligation. The HTTP
  handler layer structurally cannot obtain raw key material.
- Blast radius of secret exposure shrinks from "all 184 root files" to "one audited
  package + its explicit `WithPlaintext` call sites."
- The consolidation (3 families → 1 helper) removes duplication flagged as divergence
  risk in security code.

**Negative / cost**
- One new escape hatch (`WithPlaintext`) that must be reviewed carefully — it is the
  sole place plaintext surfaces; a closure retaining the slice would defeat the guard.
  Mitigated by contract documentation + `Destroy()` zeroize.
- ~3–4 focused days of low-risk work across ~6 PRs.

**Neutral**
- `main` gains one alias + a thin `resolveKEKProvider` shim, consistent with existing
  extracted-engine shims.

## Alternatives considered

1. **Keep discipline (status quo).** Rejected: the strongest guarantee for the most
   sensitive byte is prose, which is the ceiling of discipline. This is exactly the
   test that cannot be cheaply written in a flat package and becomes free with a
   package boundary.
2. **Extract the whole crypto/cluster domain at once.** Rejected: high blast radius on
   a security-critical service; `clusterCA`'s crypto/enrollment entanglement needs its
   own design. Deferred to a possible `internal/clusterca`.
3. **Name it `internal/kek`.** Rejected in favor of `internal/secret` — room for the
   `Sealed` handle to cover future secret types without a rename.
