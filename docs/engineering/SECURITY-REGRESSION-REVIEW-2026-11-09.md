# Security Regression Review — 2026-11-09

**Scope.** `902f3c9…d11ed3a` (`origin/main`) — the window since the 2026-11-08
review, 18 merged pull requests (#1826 #1827 #1828 #1829 #1830 #1831 #1832
#1834 #1835 #1837 #1838 #1839 #1840 #1841 #1842 #1843, plus the two
main-merge rounds), 76 files, +4,897/−346.

| PRs | Change | Security surface |
|---|---|---|
| **#1826** | the 2026-11-08 review's own fix: `foldLogFieldToken` for the decision line's bare field-block values | **log injection** (CWE-117 / CWE-93), SIEM integrity, on the per-request hot path |
| **#1828** | `perf(tunnel)`: take the pooled relay buffer only when the copy will read it | CONNECT/WebSocket relay data path, **memory-exhaustion DoS** |
| **#1829** | CHAOS-114: page when the scan sidecar keeps binding and dying | **scanning fail-open**, alerting, `/healthz`, `/ready`, gauges |
| **#1827 #1830** | data-directory single-writer posture row; SAML + diagnostics comment corrections | multi-writer break-glass visibility, **viewer-level disclosure**, SAML contract documentation |
| **#1841 #1842** | IM-004: extract the backup settings sanitizer to `internal/upstream/backupstrip` | **secret stripping** on the backup path |
| **#1843 #1835** | `golang.org/x/net` v0.62.0 in the pinned gosec tool module (CVE-2026-78661); brotli v1.2.8 | dependency CVE, supply chain |
| **#1831 #1832 #1834 #1837 #1840** | SHA pin bumps: codeql-action, harden-runner, cosign-installer, action-gh-release, docker/login-action, golang image digest | **SAST coverage, release signing, supply chain** |
| **#1838 #1839** | pin the weekly race, Playwright UI and gosec/Trivy suites to `ubuntu-24.04` | CI gate availability (a timing-out gate is a gate that does not run) |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `902f3c9`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** This window's risk sits in three places that need different
treatment. #1828 edits the byte path of every tunneled connection for speed, so
it was read as a dispatch question first — does the predicate it introduces
agree with `io.copyBuffer`'s own, on every pair the tree can produce? #1842
moves a secret-stripping routine between packages, where the only interesting
question is whether anything changed in transit, so it was diffed
mechanically rather than re-reviewed. #1826 is the previous review's own fix to
the log-field-injection class, so it was checked for the thing a fix most often
gets wrong: completeness across the call sites it did *not* touch.

Claims that mattered were **executed, not reasoned about**. The field barrier
was driven end to end through the real emitter and the real encoder against a
hostile corpus in every slot, not just the one the shipped gate covers; the
sanitizer move was byte-diffed against its pre-move source; the module-version
alignment was checked against the root module's actual selection; and the new
negative control was mutation-tested against a widened bound to confirm it
fails when the property it guards is removed.

**No regression. Two documentation corrections, both fixed here. Three
residual risks recorded, none introduced by this window. Fourteen hypotheses
were tested; twelve were disproved outright and two became the corrections
below.**

---

## Executive Summary

**No security regression was introduced by this window, and two of its changes
are material improvements to posture.**

The log-field-injection fix (#1826) **holds, and it is complete.** The shipped
gate proves the `identity` slot, which is the one a federated user chooses. The
harder question is the four slots the fix deliberately left alone on the
argument that the encoder's `LAST " {"` anchor protects them structurally — an
argument that was stated in a comment and not tested. Driven through the real
emitter and the real encoder, 32 hostile values across `rule`, `host`, `cond`
and `clientIP` produced the correct key set every time, and 10 hostile
request-ids that the entry-point charset bound actually *admits* did too. The
barrier is closed on every slot of the decision line. Both facts are now
executable gates rather than prose.

The relay-buffer change (#1828) **changes no relayed byte and no dispatch
decision**, and it removes ~256 KiB of resident heap per open tunnel —
~2.4 GiB at 10,000 concurrent tunnels — from an **unauthenticated** data path.
That is a memory-exhaustion amplifier retired, not introduced. The predicate
mirrors `io.copyBuffer` exactly (`src` is an `io.WriterTo`, or `dst` is an
`io.ReaderFrom`), and because a buffer is withheld *only* when one of those two
delegations applies, the `io.Copy` call it falls through to takes the identical
path and never reaches the nil-buffer allocation. It is conservative in the
costly direction: a TLS-inspected relay, where neither end satisfies either
interface, still gets its pooled 128 KB buffer.

CHAOS-114 (#1829) closes a **measured** blind spot in a fail-open control. A
sidecar that bound and died every few seconds read `ready` on `/healthz` in
20/20 mid-serve samples and `up = 1` in 20/20, produced zero alerts, and
forwarded bodies **unscanned** throughout. The window gives that condition its
own predicate and wires every surface to it. Two things are worth stating
plainly: the fix improves **detection only** — enforcement is unchanged, and
callers still fail open while a flap lasts (residual risk R2) — and the
readiness row now reads `fail` during the first stable-window of a *recovered*
sidecar, which is a deliberate, self-clearing conservatism, not a false alarm.

The sanitizer extraction (#1842) is **byte-identical to its source** modulo the
package clause and two identifier renames, verified by direct diff. Every
moved RED matrix group kept its assertions, and the non-strip negative controls
that shared those files (DNS-length, bracket-pair, IPv4-mapped-IPv6 and the
case-variant *loader premise* test) were correctly left at root rather than
dropped — the files were trimmed, not deleted, which is the outcome the
"preserve negative controls" convention asks for and the one a careless
extraction would have missed.

The supply-chain bumps are all in the tightening direction, all SHA-pinned, and
all **internally consistent**: zero stale references to the superseded
codeql-action SHA or golang image digest remain anywhere in the tree, and all
`codeql-action/*` uses resolve to one pin, which is what
`codeql_action_pin_test.go` exists to enforce. No workflow `permissions:`
block, `egress-policy`, `secrets` reference, `continue-on-error`, `if:` guard
or `GOTOOLCHAIN` setting changed in the entire window — the diff is pins and
runner labels.

The two findings are **documentation**, and they are the kind this codebase
cannot afford to carry. Here the comments *are* the security contract handed to
the next reviewer, and this window's own `logger.go` note makes exactly that
argument: "leaving the blanket claim here would make the next reviewer trust a
guarantee the code stopped making." Both corrected comments did that.

---

## Security Findings

### SEC-2026-11-09-A — `apiDiagnostics` names the wrong protection for the IdP fingerprint (Low)

**Affected contract.** Viewer-level disclosure boundary on `GET /api/diagnostics`.

**What the code says.** #1830 corrected `apiDiagnostics`'s omission list to stop
claiming it withholds "IdP details", and added, as the reason no fingerprint
leaks: *"`dpLastGoodConfigSnapshotStatus.IdPProfilesFingerprint` is unexported,
carries no JSON tag and is never serialized or logged."*

**What is true.** The field is **exported** — `IdPProfilesFingerprint [32]byte`
at `controlplane_snapshot.go:673`, a capitalised field on an *unexported struct
type*. Being unexported is therefore not what protects it. Two of the three
stated reasons are load-bearing and one is simply wrong, and the wrong one is
the one a reader would rely on.

**Attack scenario.** Not directly exploitable today, which is why this is Low.
It is a trap laid for the next change. The substantive guarantee does hold: no
value of that struct is ever marshaled — `idp_persistence_health.go:111,115`
compares the fingerprint, `diagnostics.go:329` reads `SaveError`/`Loaded`/
`SavedVersion`, and every other access is field-by-field. But the struct carries
**no JSON tags at all**, so a future handler that returns the status struct
whole — the natural thing to do if you believe the sensitive field is
unexported — serialises the fingerprint as a 32-element array under its Go
field name, to a **viewer**. The fingerprint is a deterministic digest over the
canonicalised IdP profile set, so it is an offline-comparable identifier for a
tenant's federation configuration: it confirms whether two nodes carry the same
IdP set, and whether that set changed and when.

**Preconditions.** A future change serialises `dpLastGoodConfigSnapshotStatus`
(or embeds it in a response struct). No attacker action.

**Exploitability.** None today. **Likelihood** of the enabling change: moderate —
the comment actively invites it. **Impact** if made: low-moderate configuration
disclosure to the lowest authenticated role.

**Affected assets.** IdP registry configuration state; viewer/admin boundary.

**Fix (applied).** `diagnostics.go` — replace the "is unexported" clause with
the invariant that actually holds: the field is exported, the struct is never
marshaled, it carries no JSON tags, every reader takes individual fields, and
serialising it whole would emit the fingerprint with no gate catching it.

**CWE.** CWE-1059 (insufficient/incorrect documentation of a security property);
would-be CWE-200 if relied upon. **OWASP.** A09:2021 adjacent (the guarantee a
reviewer audits against), A01:2021 if the enabling change lands.
**Severity.** Low. **Regression risk of the fix.** None — comment only.

### SEC-2026-11-09-B — the field-barrier comment misdescribes why the message part is safe (Low)

**Affected contract.** CWE-117 / structured-field-forgery barrier on the policy
decision line (`proxy.go`, `emitPolicyDecision`).

**What the code says.** #1826's note on `policyDecision`'s bare set reads:
*"host, target and cond are %q-quoted in the MESSAGE part, which the encoder
escapes whole, and the real block always follows them, so neither forging nor
re-anchoring reaches them."*

**What is true.** `cond` is **not** quoted. `emitPolicyDecision` appends it bare
inside the `[…]` group:

```go
b = append(b, " ["...)
b = append(b, sanitizeLog(d.cond)...)
b = append(b, "] {req_id="...)
```

`host` and `target` do go through `appendQuotedForLog`; `cond` does not. The
conclusion in that sentence is nonetheless **correct**, and it is correct for
the *other* reason the same sentence gives: the encoder locates the field block
at the `LAST " {"` on the line and the real block is always emitted last, so a
`" {"` injected anywhere in the message part loses the anchor race, and a SPACE
there cannot create a token because the split only runs on what follows the
final anchor. Quoting is not what makes any of the three safe.

**Attack scenario.** None reachable — and that was verified rather than
assumed. All 32 hostile message-part cases produced the correct key set, exactly
one `"action":` key, and intact `req_id`/`identity`. The risk is again to the
*next* change: a reviewer who believes `cond` is quoted may move it, re-order
the emitter so the block is no longer last, or add a value after the block —
and the real protection would be gone with nothing stating it had been relied
on. `cond`'s own content is policy-configuration-derived (every
`appendMatchedCond` argument at `policy.go:1932-1963` is a `rule.*` field), not
request-derived, which further bounds this to Low.

**Preconditions.** A future change to the emitter's field order, or to what
follows the block. No attacker action.

**Exploitability.** None today. **Likelihood** of the enabling change: low-
moderate. **Impact** if made: forged structured fields in the SIEM record of a
policy decision — a first-wins field extractor reading an attacker-chosen
`action` (log integrity, incident-response reliability).

**Affected assets.** Process/decision log integrity; SIEM-derived detections.

**Fix (applied).** `proxy.go` — state that `host` and `target` are quoted and
`cond` is bare, and that the quoting is not the protection; name the anchor
ordering as the invariant, and point at the new gate that pins it.

**CWE.** CWE-1059; the guarded class is CWE-117 / CWE-93. **OWASP.**
A09:2021. **Severity.** Low. **Regression risk of the fix.** None — comment
plus added tests.

---

## Risk Rating

| ID | Finding | Severity | Exploitable now | Regression? |
|---|---|---|---|---|
| A | IdP fingerprint protection misnamed as "unexported" | Low | No | No — introduced as documentation in this window |
| B | `cond` described as `%q`-quoted; it is bare | Low | No | No — documentation of a correct behaviour |

**Window verdict: no security regression.** No finding at Medium or above. Both
findings are documentation of correct code, fixed here, with no behaviour
change.

---

## Regression Analysis

Measured against `902f3c9`, per surface.

**Authentication / SAML.** No behaviour change. `auth_saml.go` is comment-only.
The vendored fork's `go.mod` was raised to the versions the root module
*already* resolves (`beevik/etree` v1.8.1, `go-cmp` v0.7.0, `goxmldsig` v1.6.0,
`x/crypto` v0.58.0, `clockwork` v0.5.0), so minimal version selection is
unchanged — confirmed against the root `go.mod`, whose only in-window change is
brotli v1.2.7→v1.2.8. The fork's `go` line moved 1.22→1.26.0, below the root's
1.27.0, so it neither fails the build nor shifts GODEBUG defaults (those come
from the **main** module's `go.mod`, which still carries its explicit
`godebug x509sslcertoverrideplatform=0`). 92 SAML/identity tests pass, including
signature validation, replay rejection, audience mismatch, expiry, transient
NameID refusal and the five GO-2026-6909 namespace-confusion gates.

**Proxy / request processing.** `proxy.go`'s only behavioural edits swap
`sanitizeLog` for `sanitizeLogFieldToken` on four bare field-block values —
strictly more scrubbing, never less. The fold touches exactly SPACE and `{`, is
a no-op for any value containing neither, and `TestLogFieldToken_*` pins both
directions.

**Tunnel data path.** No relayed byte changes. `relayCopyReadsBuffer` reproduces
`io.copyBuffer`'s dispatch; `TestRelayCopyReadsBuffer_MirrorsIOCopyDispatch` is
the differential oracle and passes. Idle-timeout teardown is untouched —
deadlines are still armed around the copy, not via a reader wrapper, and the
predicate is evaluated once because both ends are captured for the relay's
lifetime. No cross-connection residue: the pooled buffer is read into before
`buf[0:n]` is written, as before.

**Scanning.** Enforcement unchanged (R2). Detection strictly improves: a new
predicate plus two gauges, an alert detail, a `/healthz` word, a `/ready` row
and a contract row. `Unavailable()` deliberately keeps its `Bound`
short-circuit, which is what stops a slow redeploy paging forever; the flap is a
separate episode. `Flapping()` requires three sub-stable serve generations **and**
30 s of run age **and** a current generation that has not proven stable, so
neither an ordinary redeploy nor the single-lost-socket fault CHAOS-113 heals
can trip it. The check-then-act on `flapAlerted` is reached only from the single
supervisor goroutine.

**Persistence / secrets.** The sanitizer is byte-identical to its pre-move
source — verified by diffing `902f3c9:upstream_backup_strip.go` against
`d11ed3a:internal/upstream/backupstrip/strip.go`: the only changes are
`package main` → `package backupstrip`, the header filename, and
`stripUpstreamCredentialsFromSettings` → `Strip` /
`countUpstreamCredentialsRequiringReplacement` → `CountRequiringReplacement`.
Every fail-closed refusal survives intact (duplicate keys, case variants,
null root, trailing data, malformed container shapes, unparseable legacy URLs,
prepared-downgrade). The two functions are now exported but only within an
`internal/` package, reachable from `backup.go` and `restore.go` alone.
Package tests and `go vet` pass.

**Admin control plane / UI.** `static/index.html` is comment-only — no new
rendered value, so no XSS surface. The new data-dir posture row carries no path
and no secret, only the env-var name, which keeps it inside the
"omits file paths" guarantee; it is posture information at the same tier as the
existing break-glass signature row, so there is no viewer-disclosure delta.
`apiDiagnostics` keeps its role gate; no `requireRole` check changed anywhere in
the window. No route, audit or `saveConfigVersion` behaviour changed, so the
audit-then-save ordering and its recorded exclusions are untouched.

**Test hygiene.** The new global `dataDirWriterPosture` is saved and restored in
`withFreshWriterLockState`'s `t.Cleanup`, as the global-test-cleanup convention
requires. The append-vs-Printf differential oracle in
`proxy_policylog_bench_test.go` moved *with* the barrier, which is correct — it
exists to prove the two renderings agree, not to freeze pre-fold bytes, and it
still bites if the fold is dropped from one rendering only. The sole test
deletion in the window is an unused `deadTCPAddr` helper (one definition
remains, three uses); no assertion was lost.

**CI / supply chain.** Pins only. `grep` confirms zero stale references to the
superseded codeql-action SHA or golang digest, and a single distinct pin for
each. No `permissions:`, `egress-policy`, `secrets`, `id-token`,
`continue-on-error`, `if:` or `GOTOOLCHAIN` line changed. The `ubuntu-24.04`
runner pins restore gates that had begun timing out — a gate that does not
finish is a gate that does not run, so this is availability of enforcement, not
a weakening of it.

---

## Attack Scenarios

Scenarios tested against this window. The first two are the findings; the rest
were hypotheses that did not hold.

1. **Federated user forges SIEM fields via an IdP-asserted claim.** Closed by
   #1826 for `identity`, and confirmed closed for every other slot (below).
2. **Policy author forges fields via a rule name or matched condition.** Not
   reachable: `rule` takes the fold inside the block, and the message-part
   copies lose the `LAST " {"` anchor race. 32/32 hostile cases correct.
3. **Client forges fields via `X-Request-Id`.** Not reachable. The bound admits
   `0x21..0x7e`, which **includes** `{` (0x7b) and excludes SPACE; re-anchoring
   needs the two-byte `" {"`, and inside a space-free value the byte before any
   `{` is a value byte or the `=` of `req_id=`. 10/10 admissible hostile ids
   correct. This is now a gate, and it fails if the bound ever admits SPACE.
4. **Cross-connection data leak through the pooled relay buffer.** Not
   reachable: a buffer is withheld only where it is never read, and where it is
   read only `buf[0:n]` is written — unchanged from before.
5. **Memory exhaustion via idle tunnels.** *Reduced* by this window, not
   introduced: ~256 KiB per tunnel of unauthenticated-path resident heap freed.
6. **Scanning bypass by inducing a sidecar flap.** Still works as a *bypass of
   scanning* (R2, pre-existing, fail-open), but no longer as a bypass of
   *detection*: it now alerts, fails `/ready`, and moves four surfaces.
7. **Backup exfiltration of sealed upstream credentials.** Not reachable; every
   refusal path survived the extraction byte-for-byte.
8. **Downgrade of SAML validation via the fork's dependency bump.** Not
   reachable: selection is unchanged, and the fork's `go` line is below the
   root's, so it cannot shift GODEBUG defaults.
9. **Viewer harvests IdP configuration from `/api/diagnostics`.** Not reachable
   today — a count and a persisted/not sentence, both already readable at
   `GET /api/idp` (`MinRole: RoleViewer`). Finding A is about the comment that
   would let a future change make it reachable.

---

## Suggested Fix

Both findings are corrected in this change; neither alters behaviour.

1. `diagnostics.go` — replace the "is unexported" clause with the invariant that
   holds (exported field, unexported type, never marshaled, no JSON tags, read
   field-by-field) and state what serialising the struct whole would leak.
2. `proxy.go` — state that `host`/`target` are `%q`-quoted and `cond` is bare,
   that quoting is not the protection, and that the anchor ordering is; point at
   the gate that now pins it.
3. `logger_json_field_injection_test.go` — add the gates that turn the
   previously-prose claims into executable ones (next section).

No change is recommended for R1–R3; they are recorded as residual risk with the
conditions under which each would have to be revisited.

---

## Files

**Reviewed (production code, this window):** `proxy.go`, `proxy_tunnel.go`,
`logger.go`, `scan_svc_listener.go`, `metrics.go`, `diagnostics.go`,
`auth_saml.go`, `backup.go`, `restore.go`,
`internal/upstream/backupstrip/strip.go`, `datadir_writer_lock.go`,
`datadir_writer_diagnostics.go`, `static/index.html`, `go.mod`/`go.sum`,
`third_party/saml/go.mod`, `tools/gosec/go.mod`, `Dockerfile`,
`test/e2e/maint-agent/Dockerfile.e2e`, and all 15 changed workflows.

**Also traced beyond the diff (callers and invariants the window relies on):**
`request_tracing_bounds.go`, `controlplane_snapshot.go`,
`idp_persistence_health.go`, `policy.go` (`appendMatchedCond`),
`ui_routes_meta.go`, `session_provider_bounds.go`, `session_revocation_bounds.go`,
`proxy_host_bounds.go`, `connlimit_observability.go`, `auth_cost_health.go`,
`third_party/saml/schema.go`.

**Changed by this review:**

- `diagnostics.go` — finding A correction (comment).
- `proxy.go` — finding B correction (comment).
- `logger_json_field_injection_test.go` — three gates and a shared assertion
  helper (+146).
- `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-09.md` — this document.
- `CHANGELOG.md` — Security entry.

---

## Required Tests

Added in `logger_json_field_injection_test.go`:

- `TestPolicyDecisionLine_MessagePartCannotForgeJSONFields` — **negative,
  malformed-input, boundary.** The hostile corpus (field forgery, block
  re-anchoring, a stray quote, a stray `}`, an embedded TAB, a leading `}`)
  through each of `rule`, `host`, `cond`, `clientIP` on the real emitter and the
  real encoder. Asserts the record parses, carries no forged key, carries the
  gateway's own `action`, carries **exactly one** `"action":` key in the bytes a
  first-wins extractor reads, and keeps `req_id` and `identity`. 32 cases.
- `TestPolicyDecisionLine_BoundedReqIDCannotForgeJSONFields` — **negative,
  boundary.** Ten hostile request-ids that `acceptableTracingHeaderValue`
  actually admits, so the gate tests the system rather than an input the wire
  cannot deliver. Asserts admissibility first, then the same record invariants.
- `TestTracingHeaderBound_StillExcludesTheGrammarSpace` — **negative control.**
  States the one property of the charset bound the reqID slot's safety rests on.
  **Mutation-tested:** widening the bound to `0x20` fails it with the remedy in
  the message; `{` remaining admissible is asserted too, so a tightening
  re-points the gate above instead of silently making it vacuous.

Already present and relied on (positive, regression and concurrency coverage
for this window): `TestPolicyDecisionLine_IdentityCannotForgeJSONFields`,
`TestPolicyDecisionLine_BenignIdentityIsUnchanged`,
`TestJSONLogRecord_BenignBlockIsUnchangedByKeyEscaping` (differential against
the pre-sweep encoder), `TestJSONLogRecord_MalformedFieldBlockStaysParseable`,
`TestRelayCopyReadsBuffer_MirrorsIOCopyDispatch`, `TestChaos114_*`, the
`backupstrip` RED matrix and `boundary_test.go`, and the root-retained
`TestUpstreamR{8,9,10}_Normalize*` / `TestUpstreamR13_LoaderReadsCaseVariantKeys`
controls.

**Commands run** (toolchain `go1.27.3`, matching `go.mod`'s `toolchain` line):

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `go test ./internal/upstream/backupstrip/...` | pass |
| `go test -run 'FieldInjection\|RelayBuf\|RelayCopy\|ScanSvcFlap\|Flapping\|SAML\|UpstreamR' .` | 92 pass, 0 fail, 1 skip |
| `go test -run 'JSONLog\|LogField\|PolicyDecisionLine\|Tunnel\|Relay\|ScanSvc\|Chaos114\|DataDirWriter\|Backup\|Restore\|Diagnostics' .` | pass |
| `go test -run 'MessagePartCannotForge\|BoundedReqIDCannotForge\|TracingHeaderBound' .` (new gates) | 45 pass, 0 fail |
| mutation: charset bound widened to admit SPACE | new control **fails** as designed; file restored |
| `gofmt -l` on changed files | clean |
| `python3 docs/agent-context/check.py` | pass |

**Checks not run, and why.** The full root-package suite and the aggregate CI
matrix were not run here: the unsharded suite is the one this window pinned to
`ubuntu-24.04` for exceeding a 40-minute budget, and it is not the right
instrument for a documentation-and-tests change. `golangci-lint` was not run —
per the current conventions the container's binary is older than this module's
language version and the gate's own pinned version is the only meaningful one.
**A passing local check is not a passing hosted review or merge gate**; the
PR's own gates remain authoritative for this SHA.

---

## Residual Risk

**R1 — the IdP's `SessionNotOnOrAfter` does not bound the Culvert session.**
Pre-existing; this window *documents* it rather than introducing it, and the
correction is accurate. Verified independently:
`third_party/saml/schema.go:746` declares
`AuthnStatements []AuthnStatement` on a **bare** `xml:"AuthnStatement"` tag, and
nothing outside the vendored marshalling code reads the field — the only
non-vendored references in the tree are the comment itself. A Culvert session
therefore lives for the local TTL regardless of the cap the IdP asserted, which
matters where an IdP shortens sessions deliberately (shared workstations, step-
up flows, de-provisioning). The bare tag is safe **only because the field is
unread**: a foreign-namespace `<x:AuthnStatement>` is appended to that slice
today. Namespace-qualify it before ever reading it, or the GO-2026-6909 class
reopens on the field that enforces session lifetime.

**R2 — scanning fails open while the sidecar listener is unavailable or
flapping.** Unchanged by this window, which improves detection only. Callers
forward bodies **unscanned** for the duration. There is no operator-selectable
fail-closed for *sidecar-unavailable*, unlike YARA timeout and saturation, which
do offer `fail_closed` (`ui_security.go`). An operator who believes the two are
configured alike will be wrong. Worth a deliberate decision on its own merits —
a fail-closed option here trades availability for containment and should not be
flipped as a side effect of an observability round.

**R3 — `{` is admissible in a client-supplied `X-Request-Id`.** Harmless today,
and now pinned as such. The safety is *conjunctive*: it depends on SPACE being
excluded by the charset bound **and** on the id being rendered immediately after
`req_id=`. Either changing — a widened bound, or an emitter that renders the id
after a space in some new context — reopens block re-anchoring.
`TestTracingHeaderBound_StillExcludesTheGrammarSpace` fails on the first; the
second has no gate, so prefer giving reqID the same `foldLogFieldToken`
treatment `identity` has if it is ever rendered in a new position.

**R4 — comment-stated security properties are not mechanically checked.** Both
findings this round, and two of the previous round's, were inaccuracies in
comments that carry the contract a reviewer audits against. Three of the four
were *correct conclusions supported by wrong reasons*, which is the failure mode
that survives review longest. The mitigation used here — converting the claim
into an executable gate and mutation-testing it — is worth preferring over
rewording wherever a claim is load-bearing.
