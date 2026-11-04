# Security Regression Review — 2026-11-04

**Scope.** `c65bbd2…2d03196` (`origin/main`) — the 24 h since the 2026-11-03
review, 5 merged pull requests (#1788 #1790 #1799 #1800 #1801), 22 files,
+2,156/−313. Five production Go files changed, one of them comment-only; the
rest is tests, `go.mod`/`go.sum`, CI/Docker digest pins, the CHANGELOG and the
previous review document.

| PR | Change | Security surface |
|---|---|---|
| **#1790** | dependabot: `sigstore-go` v1.3.0 → v1.4.0 (and the transitive tree it pulls) | release/feed signature verification, supply chain — **and, unannounced, the module's `go` language line** |
| **#1799** | `diag: compare saved vs serving UI cert for the pending row` + `fingerprint the full UI cert chain` | admin-UI TLS posture visibility, information disclosure, new file I/O on a report path |
| **#1800** | `perf(catoverride): make override suppression linear in the feed, not quadratic`, `security(feeds): accept a category-feed archive of exactly the ingest budget`, `diag: warn when a saved admin UI certificate is not yet serving` | **policy composition / category override precedence**, threat-intel ingest fail direction, DoS |
| **#1801** | `test(catoverride): move the suppression wall-clock ratio gate to benchgate` | test placement only |
| **#1788** | dependabot: `golang:1.27.3-alpine` digest bump (Dockerfile, E2E Dockerfile) | build provenance; same tag, same compiler |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against
`c65bbd2`, not against an ideal.

**Method.** The window's two highest-consequence changes were read in the
direction that can only fail quietly. For `catoverride` the question was whether
the rewritten suppression predicate can decide one host differently from the one
it replaced — a category override that stops suppressing is a feed category
resurrected over an operator's explicit decision, and one that starts
suppressing is a silent deny-list hole. The committed differential oracle was
not taken as the answer: the pre-change predicate was re-derived independently
and run against the new one over 400,000 randomized cases on an adversarial host
alphabet (trailing dots, leading dots, consecutive dots, empty labels, mixed
case, 0–8 labels), because the rewrite's correctness rests on a `maxLen`
short-circuit whose failure mode is exactly a length-dependent miss. For the
dependency bump the question was whether `sigstore-go` v1.4.0 changed the
meaning of the strict options this tree passes (`WithTransparencyLog(1)`,
`WithIntegratedTimestamps(1)`, `WithCertificateIdentity`), which was answered by
running the negative controls rather than by reading the changelog — a tampered
artifact, a wrong SAN, a wrong issuer, a wrong workflow file, a malformed bundle
and the no-Ed25519-fallback paths all still reject. That same bump was then read
for what a dependency bump is not supposed to be able to touch, which is where
this window's finding is.

**Four hypotheses were formed against the window's own claims. Three were
disproved; one survived.**

1. *The `catoverride` suppression rewrite decides some host differently from the
   predicate it replaced, because the new `maxLen` bound skips a probe the old
   list scan would have made.* **Disproved, with an independently re-derived
   oracle.** The union is exact: the old predicate was "covered by a tombstone
   OR covered by an assert key", and set membership distributes over that OR.
   The walk enumerates every dot-remainder of the host, and
   `strings.HasSuffix(host, "."+key)` holds exactly when `key` is one of those
   remainders, so the two decide the same predicate. The `maxLen` skip is sound
   in both places it appears (equality probe and walk) because every key in the
   set has length ≤ `maxLen`, so a longer candidate cannot be a member — a
   skipped probe is a probe that could only have missed. 400,000 randomized
   cases × 3 probes each: zero divergence. The `continue` rather than `break` is
   also correct, since remainders shrink as the walk advances.
2. *`sigstore-go` v1.4.0 relaxes a verification requirement, so the pinned
   identity and transparency-log policy no longer mean what they meant at
   `c65bbd2`.* **Disproved empirically.** The call sites did not change and the
   tree's negative controls are the real oracle:
   `TestSigstore_RejectsTamperedArtifact`, `RejectsWrongSAN`,
   `RejectsWrongIssuer`, `RejectsWrongWorkflowFile`, `MalformedBundle`,
   `RequiresFullIdentity`, `TestScheme_SigstorePresentInvalidNoEd25519Fallback`
   and `TestScheme_SigstoreUnreadableNoFallback` all pass against v1.4.0. The
   indirect tree lost `titanous/rocacheck` and `letsencrypt/boulder`, which is
   worth naming because both are weak-key checkers, but neither sat on a path
   this tree calls: Culvert uses `pkg/bundle`, `pkg/root` and `pkg/verify` only,
   and the identity/tlog policy it enforces is unchanged.
3. *The new admin-UI "pending certificate" row leaks a fact a viewer should not
   have, or changes TLS serving.* **Disproved on content and on structure.** The
   row carries no subject, path, fingerprint or key material — only the sentence
   that a saved pair is not the one being served, naming documented setting
   names. The chain fingerprints are computed and compared in process and never
   emitted. `noteAdminUITLSCertExpiry` gained one assignment under the existing
   `adminUITLSCertMu` and the serving path is otherwise untouched; the new state
   is read through `adminUITLSServingChainSHA256`, which takes the read lock.
   `certChainSHA256` length-prefixes each DER element, so two different chains
   cannot collide by concatenation.
4. *A dependency bump cannot change runtime security behaviour on its own.*
   **Disproved. This is S-1.**

---

## 1. Executive summary

**No authentication, authorization, policy-precedence, session, CSRF, audit,
proxy request/response-processing or secrets regression was introduced in this
window by any change that announced itself as one.** The policy-composition
rewrite — the one change in the window that could have moved a deny or an
override decision — is behaviour-identical, verified against an independently
re-derived oracle rather than the committed one. The third copy of the ingest
budget reader now matches its two siblings byte for byte, closing the divergence
the 2026-11-03 review opened as S-1.

One finding survived, and it did not come from a change that looked like a
security change. A dependabot dependency bump raised the root module's `go`
language line, which is the knob that selects GODEBUG compatibility defaults for
the whole binary, and thereby flipped a `crypto/x509` trust-store default on the
darwin and windows release binaries. **Fixed in this branch**, with the durable
half being a wall that makes the next such flip a failing test.

| ID | Finding | Severity | Regression risk | Status |
|---|---|---|---|---|
| **S-1** | A dependency bump raised the `go` line, flipping `x509sslcertoverrideplatform` 0 → 1: `SSL_CERT_FILE` can now displace the upstream-verification trust anchors on the darwin/windows binaries | **Medium** | In-window, introduced by a bot PR, invisible to every existing gate | **Fixed in this branch** |
| **S-2** | `uiCustomTLSCorrupt` is an unsynchronized `bool` written by an admin handler; this window adds a fourth reader | **Low** | In-window widening of the pre-existing race reported as S-3 on 2026-11-03 | Reported (unchanged) |
| **S-3** | The new pending-certificate row does an unbounded `os.ReadFile` + full PEM scan on every diagnostics render, reachable at `RoleViewer` | **Informational** | In-window; bounded at ~1 MiB by the upload limit | Reported |

---

## 2. Security findings

### S-1 — A dependency bump flipped a trust-store default on the darwin/windows release binaries

**Severity: Medium. CWE-295 (improper certificate validation), CWE-1104 (use of
unmaintained/unreviewed third-party components → unreviewed transitive
configuration change), CWE-453 (insecure default variable initialization).
OWASP A05:2021 Security Misconfiguration, A08:2021 Software and Data Integrity
Failures. Regression risk: in-window.**

**What changed.** `go.mod`'s `go` line moved from `1.26.6` to `1.27.0` in
PR #1790, a dependabot bump of `sigstore-go` to v1.4.0. That was not optional
and not a mistake by itself: `sigstore-go` v1.4.0 declares `go 1.27.0`, so the
main module's line had to rise with it. What is missing is the compensating
review of what else that line controls.

The `go` line is not only a language minimum. It selects the DEFAULT value of
every GODEBUG compatibility setting, and the compiler records the resulting
non-base defaults in the binary. Measured, not inferred — the same trivial
module built twice, changing only the `go` line:

```
main-module go line 1.26.6 → build DefaultGODEBUG=tracebacklabels=0,x509sslcertoverrideplatform=0
main-module go line 1.27.0 → (no DefaultGODEBUG line: toolchain base defaults)
```

So Culvert's binaries went from `x509sslcertoverrideplatform=0` to the Go 1.27
base default of `1`. Nothing else in the tree restores it: there is no `godebug`
directive in either `go.mod` and no `GODEBUG` in any Dockerfile, workflow or
script.

**What the setting does.** `crypto/x509/root.go`:

```go
func loadSystemRoots() (*CertPool, error) {
	certFilePath, certDirPath := os.Getenv(certFileEnv), os.Getenv(certDirEnv)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		if certFilePath == "" && certDirPath == "" {
			return &CertPool{systemPool: true}, nil
		}
		if x509sslcertoverrideplatform.Value() == "0" {
			x509sslcertoverrideplatform.IncNonDefault()
			return &CertPool{systemPool: true}, nil
		}
	}
	return loadOnDiskRoots(certFilePath, certDirPath)
}
```

At `0` the platform verifier stays authoritative on darwin/windows and
`SSL_CERT_FILE`/`SSL_CERT_DIR` are ignored there. At `1` either variable
short-circuits the platform verifier and the roots come from the file or
directory it names. The setting is read only inside the `GOOS` test, so **linux
is unaffected at either value** — it has always honoured both variables.

**Affected assets.** `upstreamVerifyRoots` (`proxy_tunnel.go:560`) is a
`sync.OnceValue` over `x509.SystemCertPool()`: one pool, loaded once, shared
read-only across every upstream `tls.Config` for SSL-inspected tunnels
(`proxy_tunnel.go:652`). That is the pool that verifies the REAL server's
certificate before the gateway re-signs the flow with its own CA. Also reached:
`mcp_live_production_deps.go:332` (`RootCAs: nil`, documented as "⇒ system
roots"), `diagnose.go:491`, and every `http.Client` that leaves `RootCAs` nil —
threat-intel and category feed downloads, the release catalog, OCSP.

**Attack scenario.** On a macOS or Windows install of Culvert, an actor who can
influence the process environment — a tampered launchd plist or Windows service
definition, a modified wrapper script, an account that controls how the service
starts, or an operator running the binary from a poisoned shell profile — sets
`SSL_CERT_FILE=/path/to/attacker-root.pem`. On the first inspected CONNECT,
`upstreamVerifyRoots` caches a pool containing only that root. From then on the
gateway verifies upstream certificates against the attacker's anchor and accepts
forged leaves for any origin; because it then re-signs with its own CA, every
client behind the gateway sees a valid padlock for every intercepted site. The
cache is a `sync.OnceValue`, so the substitution persists for the process
lifetime and does not heal. The same anchor set also governs feed and release
catalog fetches, though update integrity has independent protection: the sigstore
bundle verification does not rely on TLS roots, so the signed-update path still
fails closed. That is defence in depth working, and it is why this is Medium
rather than High.

**Preconditions and exploitability.** Requires local control of the process
environment on a darwin or windows host — not remotely exploitable, and not a
privilege boundary the product itself defines. **Likelihood: Low.** The primary
shipping vehicle is a Linux container, where nothing changes; the darwin and
windows binaries are more likely development and evaluation installs. The honest
framing is that this is not a new class of weakness for the main deployment
target, but a **widening to the two platforms where the OS trust store
previously could not be displaced at all** — and a posture change that no human
chose, in a product whose own doctrine is "prefer immutable configuration,
prefer deterministic behavior."

**Why no gate caught it.** `toolchain_consistency_test.go` is a thorough wall,
but it guards the `toolchain` line and the Dockerfile/CI pins that must agree
with it. The `toolchain` line did not move (`go1.27.3` before and after), so the
wall was silent and correct. No check related the `go` line to behaviour at all.
`go.mod`'s own comment block explains that the `go` line is the language minimum
and "is not raised to match" the toolchain — which is still accurate (1.27.0 ≠
1.27.3) but says nothing about the GODEBUG consequence, so a reader of that
comment would not know to look.

**Fix applied in this branch.** `go.mod` gains an explicit, documented pin:

```
godebug x509sslcertoverrideplatform=0
```

This restores exactly the behaviour that shipped at `c65bbd2` while keeping the
language version `sigstore-go` requires — reverting the `go` line is not an
option. It costs operators nothing they had before this window: on linux
`SSL_CERT_FILE` keeps working at either value, and on darwin/windows this is the
status quo, where a private root is installed into the platform store the normal
way. Verified end to end on both affected targets:

```
linux/amd64   → build DefaultGODEBUG=x509sslcertoverrideplatform=0
darwin/arm64  → build DefaultGODEBUG=x509sslcertoverrideplatform=0
```

**Safe implementation note.** The pin is deliberately surgical. The other
setting Go 1.27 changed, `tracebacklabels` (0 → 1), is left at the new default
because it is inert here: it affects how `runtime` renders pprof goroutine
labels in tracebacks, and this tree sets none (`pprof.Labels`, `pprof.Do` and
`pprof.SetGoroutineLabels` do not appear in any non-test file). Pinning inert
settings would make the list unreadable and dilute the review the list exists to
force. The `cmd/culvert-maint` module is deliberately untouched: its own `go`
line is `1.25`, so it still compiles with the old default, and the maintenance
agent ships for linux only, where the setting is inert in any case.

**Required tests — added.** `godebug_pins_test.go` is the durable half, and it
is two-sided because the two sources answer different questions. `go.mod` says
what the module claims to pin; the compiled `DefaultGODEBUG` says which pins are
load-bearing.

- `TestGODEBUG_GoModDeclaresExactlyTheReviewedPins` — `reviewedGODEBUGPins` is
  an exact allowlist, never a count, so BOTH an unreviewed pin appearing and a
  reviewed pin vanishing fail.
- `TestGODEBUG_ReviewedPinsAreCompiledIn` — a pin that drops out of
  `DefaultGODEBUG` is one the toolchain now defaults to on its own; the failure
  message says to re-read the rationale on the toolchain upgrade that caused it
  rather than years later.
- `TestGODEBUG_CompiledDefaultsCarryNoUnreviewedSetting` — **the check that
  would have caught this window's regression.** Any future `go` line movement
  that changes another default lands here.
- `TestGODEBUG_NegativeControl_ParserAndDiffRejectDisagreement` — feeds the
  parser each directive form (single-line, block, commented-out, trailing
  comment) and `diffPins` each of the three disagreement shapes (value drift,
  missing pin, extra pin), so none of the above is vacuous.

The wall was mutation-tested, not just run green. Deleting the pin from `go.mod`
fails two checks with the right messages. A misspelled setting name needs no
control and gets none, because the claim that it would slip through is false:
the go command refuses to load such a `go.mod` at all —
`go.mod:182: unknown godebug "x509sslcertoverrideplatfrom"` — verified against
go1.27.3 rather than assumed.

**Residual risk.** The wall covers the root module only. A future bump of
`cmd/culvert-maint`'s `go` line past a GODEBUG change would not be caught; that
module has no equivalent pin list, and adding one was out of scope for an
unattended regression review because it is currently inert on its only shipping
platform. Worth a deliberate follow-up rather than a drive-by. More generally,
the wall detects a changed default; it cannot judge whether the new default is
acceptable. That remains a human read of `go doc godebug` at each language bump,
which is what the failure now forces.

---

### S-2 — `uiCustomTLSCorrupt` is an unsynchronized `bool` with a fourth reader

**Severity: Low. CWE-362 (race condition). Regression risk: in-window widening
of a pre-existing defect.** Reported, not fixed here.

This is S-3 of the 2026-11-03 review, unchanged in substance and worse in reach.
`uiCustomTLSCorrupt` (`ui_tls_custom.go:66`) is a plain package-level `bool`. It
is written at startup by `resolveUITLSCertKey` (`ui_tls_custom.go:300`) and —
the part that makes it a race rather than a startup latch — written again at
runtime by the admin certificate upload handler (`ui_security.go:405`,
`uiCustomTLSCorrupt = false`), from whatever goroutine serves that request.

This window adds `uploadedUITLSCertPending()`
(`diagnostics_ui_tls_cert.go:84`), which reads it, bringing the reader count to
four alongside `checkAdminUITLSCert` and `ui_config.go:2287–2288`. Diagnostics
renderers are gated at `RoleViewer`, so the read happens on request-serving
goroutines concurrent with the upload handler's write. Under the Go memory model
this is a data race; in practice on the platforms Culvert ships it manifests as
a stale read, and the consequence is a wrong or missing WARNING row, not a TLS
serving change. `uploadedUITLSCertPending` reads `uiCustomTLSActive` the same
way, though that one is startup-only today.

Not fixed here for the same reason the previous review gave: the correct fix
changes a global's type across four call sites in the admin control plane,
including the API response shape's source in `ui_config.go`, which is wider than
an unattended regression review should change on its own. The contrast worth
noting is PR #1802, open at the time of writing, which introduces exactly this
kind of report-only latch and gets it right with `atomic.Int64` — the pattern
this one should converge on.

**Required tests when fixed.** A `-race` test that drives `apiCertsUpload`
concurrently with a diagnostics render and asserts no race and a coherent row;
plus the existing startup-latch assertions
(`TestPersistCustomUITLS_*`, `ui_tls_custom_test.go:286–326`) must keep passing
so the clear-on-valid-reupload behaviour is preserved.

---

### S-3 — The pending-certificate row reads and PEM-scans a file on every diagnostics render

**Severity: Informational. CWE-405 (asymmetric resource consumption).
Regression risk: in-window.** Reported, not fixed here.

`savedCustomUITLSChainSHA256` (`ui_tls_custom.go`) does
`os.ReadFile(customUITLSCertPath())` with no size bound and then loops
`pem.Decode` over the whole buffer. It runs from `uploadedUITLSCertPending()` on
every diagnostics render, and the renderers are gated at `RoleViewer` — so the
cheapest-privileged authenticated role can drive a file read plus a full PEM
scan per request. The file header comment on `diagnostics_ui_tls_cert.go` was
updated honestly in the same change ("no I/O" → "plus a read of the saved
certificate file"), so this is disclosed rather than hidden.

It is Informational and not Low because the magnitude is capped by the write
side: `apiCertsUpload` bounds the request body with
`http.MaxBytesReader(w, r.Body, 1<<20)` before `ParseMultipartForm`
(`ui_security.go:319–320`), so the persisted certificate cannot exceed roughly
1 MiB, and only an admin can write it. There is no untrusted-input path and no
amplification worth the name. Recorded because the honest fix is cheap if the
row ever moves to a hotter surface: cache the saved fingerprint against the
file's `ModTime`/`Size`, or compute it once in the upload handler. Not worth a
change on its own today.

---

## 3. Regression analysis — what was reviewed and found safe

Everything below was read and is reported as safe, with the reason, so that
"no finding" is a result rather than an absence.

- **`internal/catoverride` suppression rewrite (#1800).** Behaviour-identical;
  see hypothesis 1. The optimization also removes a real hazard rather than only
  adding speed: the old form was `O(feed × overrides)` with a `"."+key`
  concatenation per pair, walked on every activation, every override-only
  recompose and every bulk-apply validation. The new `maxLen` bound is what keeps
  the replacement from trading that quadratic for one in the host length, which
  the author documents and which the code honours in both probe sites.
  `SealedKeys` and the suppress-then-reinsert logic in `ComposeView` /
  `ComposeMembership` are untouched, so override precedence is unchanged.
- **`internal/feedsync` budget boundary (#1800).** The three copies of
  `boundedReader` in `internal/feedsync`, `internal/blocklistfeed` and
  `internal/threatfeed` are now byte-for-byte identical, which closes S-1 of the
  2026-11-03 review. The fail direction is right: `probeBoundary` reads one extra
  byte and a real byte is an overrun that fails the round, so an over-budget feed
  cannot be accepted, and a body of exactly the budget no longer fails. No data is
  discarded on the probe. S-2 of the previous review — a truncated round still
  being attested as a complete success on the health, metrics and diagnostics
  surfaces — is unchanged by this window and remains open.
- **`proxy_tunnel_h2_drain.go` (#1800).** Comment-only. The text now states that
  `base.Shutdown` dispatches the GOAWAY trigger asynchronously, so a return means
  the wave was started, not delivered. No executable change; `git diff` confirms
  the function body is untouched.
- **Admin-UI certificate diagnostics (#1799, #1800).** See hypothesis 3. Report-
  only, path-free and key-free, consistent with the contract the 2026-11-02
  review established. The two defects it surfaces are S-2 and S-3 above, neither
  of which is in the row's content or its RBAC.
- **CI and Docker digest pins (#1788).** `golang:1.27.3-alpine` moves to a new
  digest on the SAME tag in all three Dockerfiles, so the compiler does not
  change and `TestToolchain_OneCompilerEverywhere` passes. `GOTOOLCHAIN=local`
  and the in-build assertion against `go.mod` are intact.
- **benchgate package list (#1801).** `internal/catoverride` was added to the
  tagged command in all three workflows that run it AND in
  `docs/agent-context/workflows/verification.md`, honouring the tree's own rule
  that "a gate CI does not run is not a gate". No gate was weakened or removed.
- **PR #1802 (open, reviewed pre-merge).** Report-only visibility for a
  decompression ratio limit refused at load. Fail-closed and correct: the
  enforced bound stays at the in-range default, the latch is `atomic.Int64`
  (properly synchronized, unlike S-2), it is cleared at the top of every load
  and on a successful PUT, and the warning discloses only a ratio number. No
  finding.

---

## 4. Verification performed

Focused checks at `2d03196` plus this branch's change. These are not a hosted
CI result for this SHA.

| Check | Result |
|---|---|
| `go build ./...`, `go vet ./...` | clean |
| `go test ./internal/...` (all internal packages) | pass |
| `go test -count=1 -timeout=40m .` (full root package) | pass, 404 s |
| `go test . -run 'GODEBUG\|Toolchain\|TLS\|Cert\|Sigstore\|MITM\|Upstream\|Tunnel'` | pass (22.9 s) |
| `go test . -run 'TestGODEBUG_'` incl. negative controls | pass |
| GODEBUG wall mutation tests (pin deleted; setting misspelled) | both rejected, with the intended messages |
| Independent 400k-case differential oracle on `suffixSuppressor.covers` | zero divergence |
| `golangci-lint run --new-from-rev origin/main` (v2.15.0, the pinned gate version, built with the `go.mod` toolchain) | 0 issues |
| `python3 docs/agent-context/check.py` | exit 0 |
| `go version -m` on linux/amd64 and darwin/arm64 builds | both record the pin |

**Not run, and why.** The `benchgate`-tagged allocation gates, the
`-race -shuffle=on` determinism jobs, the E2E installer-lifecycle job and the
hosted aggregate gates were not run in this environment. The `go.mod` change is
inert on linux by construction — `crypto/x509` consults the setting only under
`GOOS=windows/darwin/ios` — so no linux-hosted gate can change behaviour because
of it, but that is an argument about the change, not a substitute for the gates.

---

## 5. Residual risk

- **S-2 remains open**, now with four readers. It is a stale-read defect on a
  warning row, not a serving-path defect, but it is the second review in a row
  to report it and the third surface to start depending on the value.
- **S-3 of the 2026-11-03 review remains open**: a truncated feed ingest round is
  still attested as a complete success on every health, metrics and diagnostics
  surface. Unchanged by this window, and the most consequential open item in the
  threat-intel path.
- **The `cmd/culvert-maint` module has no GODEBUG pin list.** Inert today at
  `go 1.25` and linux-only; a deliberate follow-up, not a drive-by.
- **The class of defect S-1 belongs to is not closed, only alarmed.** A bot PR
  can still change this module's language version, and with it any stdlib
  compatibility default. What changed is that the next one fails a test instead
  of shipping silently. Nothing here prevents a reviewer from updating
  `reviewedGODEBUGPins` to make a red test green without reading what flipped —
  the allowlist forces the question, it cannot force the answer.
