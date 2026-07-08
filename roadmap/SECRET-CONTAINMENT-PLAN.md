# `internal/secret` — Compiler-Enforced KEK / Key-at-Rest Containment

- **Status:** PLANNED (design recorded; no code moved)
- **Date:** 2026-07-06
- **Relates to:** ADR-0002 (flat→internal decomposition), ADR-0003 (shared-foundation
  seam), `roadmap/CA-3-KEY-AT-REST-DESIGN.md` (the KEK/at-rest foundation this
  boundary encloses)
- **Companion ADR:** `docs/adr/0007-secret-containment-boundary.md`

## Problem

Secret bytes (KEK, decrypted private-key PEM) are handled by ordinary free
functions inside the flat `package main`. `KEKProvider.KEK()` returns raw
`[]byte`; `decryptWithKEK` / `readEncryptedFile` / `decrypt{ClusterCA,DPNode,
CDRClient}Key` all return `plainPEM []byte`. Any of the ~184 root files can call
them and, e.g., log the result. The invariant "never log the KEK" is enforced by
a **comment** (kek.go:22), not by the type system.

A package boundary is the Go unit of access control. Moving the KEK primitive
behind `internal/secret` with an **opaque handle** makes accidental exposure a
**compile error**, not a review miss — the highest-severity finding from the
architecture review.

## What the refactor-readiness review established (evidence)

- **The PSCA codec is ALREADY in `internal/ca`** (`EncryptBundle`/`DecryptBundle`/
  `HasBundleMagic`, internal/ca/ca.go:340-417). `kek.go` *wraps* it (kek.go:72-102),
  never re-implements. ⇒ `internal/secret` sits **on top of** `internal/ca`.
- **`kek.go`'s only `package main` dependency is `atomicWriteFile`** (kek.go:111),
  itself a one-line wrapper over `fileutil.AtomicWrite` (main.go:1134-1138). The
  seam already exists. **No import cycle.**
- **5 consumer files:** `cdr_client_keyatrest.go`, `cluster_ca_keyatrest.go`,
  `dp_node_keyatrest.go`, `enrollment.go`, `keyatrest_diagnostics.go`.
- **3 byte-identical families** (`decrypt{ClusterCA,DPNode,CDRClient}Key` + the
  matching `verifyEncrypted*Key`) — consolidatable to one generic helper.
- **The one landmine:** `kek_test.go` asserts on raw bytes (`bytes.Equal`,
  `kekEqual`, `p.KEK()` identity). Defused by moving the test **into** `package
  secret` (whitebox → keeps direct access to the unexported field).
- **Out of scope:** `clusterCA` (enrollment.go:721) tangles CA-crypto with
  enrollment state; its `CAKeyPEM()` is a legitimate bytes-over-mTLS transport
  site (class (c)). Future `internal/clusterca`, not this work.

**Verdict:** clean lift + a `WithPlaintext` seam. Not a deep refactor.

## Target boundary API (the entire external surface)

```go
package secret

// Sealed holds plaintext secret bytes. Redacting Format/String/GoString (so no
// fmt verb can reflect the buffer), and no exported byte accessor.
type Sealed struct{ b []byte }

// Provider is an OPAQUE handle to KEK material. It exposes NO exported method
// that returns the KEK — the raw-byte source is an unexported interface method
// (kek()), reachable only from inside internal/secret. `main` holds *Provider
// values but has no compile-legal path to the bytes.
type Provider struct{ src kekSource } // kekSource: unexported iface { kek() ([]byte, error); Name() string }

// Resolvers/constructors — the ONLY way main obtains a Provider.
func ResolveProvider(cfg ProviderConfig) (*Provider, error) // env→file precedence
func FileProvider(path string) (*Provider, error)
func EnvProvider(name string) (*Provider, error)

// Seal encrypts plaintext under the provider's KEK → at-rest envelope bytes.
func Seal(plaintext []byte, p *Provider) ([]byte, error)

// Open decrypts an at-rest envelope → an opaque handle (never raw bytes).
func Open(envelope []byte, p *Provider) (*Sealed, error)

// WithPlaintext runs fn with the plaintext, then zeroizes. The []byte is
// invalid once fn returns; fn MUST NOT retain it.
func (s *Sealed) WithPlaintext(fn func([]byte) error) error
func (s *Sealed) Destroy() // explicit zeroize

// ValidateProvider checks KEK availability WITHOUT returning bytes.
func ValidateProvider(p *Provider) error
```

**Provider is opaque, not an exported byte-returning interface.** The KEK source
is an *unexported* method (`kek() ([]byte, error)`) that only `internal/secret`
can call, so a `package main` file holding a `*Provider` has no compile-legal way
to read the KEK — `Seal`/`Open` consume it internally. `main` constructs providers
only via the exported resolvers (`ResolveProvider`/`FileProvider`/`EnvProvider`),
and `resolveKEKProvider` in `main` becomes a one-line call into
`secret.ResolveProvider`. **No `type KEKProvider = secret.KEKProvider` alias** —
main never names the raw-byte source. (An exported `KEK() []byte` on an aliased
interface would leave `p.KEK()` callable from every root file, defeating the whole
boundary; the unexported-method design is what makes "no raw KEK in main" a
compile error rather than a convention.)

Canonical consumer rewrite (parse-and-drop):

```go
sealed, err := secret.Open(raw, prov)
if err != nil { return err }
defer sealed.Destroy()
return sealed.WithPlaintext(func(pemBytes []byte) error {
    // hand to stdlib that demands []byte, then drop
    return loadFromPEM(pemBytes)
})
```

## PR sequence (each compiles green; each independently revertible)

### PR-0 — De-risk inside `main` (no new package)
Behavior-identical prep.
1. Redirect `writeEncryptedFile` off `atomicWriteFile` onto `fileutil.AtomicWrite`
   (kek.go:111) — removes the sole main dependency in advance.
2. Collapse the 3 parallel `decrypt*Key` + 3 `verifyEncrypted*Key` families onto
   one generic helper (`KEKProvider` + audit-object + parser). Shrinks the
   re-point surface from ~18 funcs to ~6.
3. Introduce `WithPlaintext(func([]byte) error)` **in main first** and route the 6
   decrypt/verify sites through it. Prove parse-and-drop before the type is opaque.
- Gate: `go build`, `go test -race -count=1 ./...`, coverage floors.

### PR-1 — Create `internal/secret`; lift the primitive layer
- Move in: `Sealed`, the opaque `Provider` + unexported `kekSource`/`kek()`, the
  exported `ResolveProvider`/`FileProvider`/`EnvProvider`, `Seal`/`Open`/
  `WithPlaintext`/`Destroy`/`ValidateProvider`, the `fileKEKProvider`/
  `envKEKProvider` impls, `encrypt/decrypt/read/writeEncryptedFile`,
  `kekLen`/`errKEKMissing`/`kekEqual`.
- `main` keeps: `resolveKEKProvider` as a one-line wrapper over
  `secret.ResolveProvider` (**no `KEKProvider` alias** — main never names the
  raw-byte source, so `p.KEK()` is not a compile-legal expression anywhere in
  `main`).
- Move `kek_test.go` → `internal/secret` as `package secret` (whitebox). Raw-byte
  assertions keep working against the unexported field. **Landmine defused.**
- Add a fitness-function test asserting `internal/secret` exports **no**
  `[]byte`-returning secret accessor (matches the C1/C2 wall style).
- Gate: `go test -race ./internal/secret ./...`; `golangci-lint ./internal/secret`.

### PR-2…N — Convert consumers, one domain per PR (WRAP sites)
`cluster_ca_keyatrest.go` → `dp_node_keyatrest.go` → `cdr_client_keyatrest.go` →
`keyatrest_diagnostics.go` (`processKEKSource` → `secret.ValidateProvider`). Each
domain's `*_keyatrest_test.go` **stays in main** (tests the orchestration shim).
- Gate per PR: `-race` + floors.

### PR-final — Tighten + document
Remove transitional accessors; land ADR-0007; update CLAUDE.md (fix the stale
"codec in ca.go" note + record the new package); append to the ADR-0002 log as a
*fresh recorded design*, not a continuation of the closed program.

## Call-site ledger (~10 sites)

| Site | Class | Action |
|---|---|---|
| `encryptWithKEK`, `writeEncryptedFile`, provider `kek()` impls (was exported `KEK()`), `ca.Encrypt/DecryptBundle` | **LIFT** (~4) | Move as-is; demote `KEK()`→unexported `kek()` |
| `decryptWithKEK`, `readEncryptedFile`, `decrypt{ClusterCA,DPNode,CDRClient}Key`, `verifyEncrypted*` ×3 | **WRAP** (~7) | Route through `Open`+`WithPlaintext` |
| `clusterCA` key/enrollment split, `CAKeyPEM()`→HA transport | **REFACTOR / out of scope** (~2) | Leave in main; future `internal/clusterca` |

## Risks & mitigation

- **Opaque handle vs whitebox tests** → tests move in-package (PR-1). *The trick.*
- **`WithPlaintext` closure retaining the slice** → contract doc + `Destroy()`
  zeroize; the escape hatch is the only place bytes surface — review it hard.
- **Coverage floors on moved files** → floors match on path substring; moved code
  carries its tests (same mechanism as the `totp` extraction).
- **Rollback**: every PR self-contained; reverting PR-N leaves N-1 green.

## Effort

PR-0 ~½ day · PR-1 ~½ day · PR-2…N ~1–2 hrs each · PR-final ~½ day. ≈3–4 focused
days, all low-risk (startup/control-plane; never the CONNECT hot path).

## Explicit non-goals

No wholesale re-packaging of `package main`. This encloses **only** secret-bearing
primitives. The flat layout, the parity walls, and ADR-0002's rejected extractions
(`proxy.go`/`controlplane.go`/`configversion.go`) stand.
