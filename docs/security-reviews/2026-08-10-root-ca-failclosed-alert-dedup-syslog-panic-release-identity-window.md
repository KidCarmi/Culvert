# Security Regression Review — CHAOS-28 Root-CA fail-closed, alert-dedup accounting, syslog panic observer, release runtime-version identity (window `1c24311` → `bc67b7b`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-10
> **Baseline:** `1c24311` — head of the previous review's window
> (`docs/security-reviews/2026-08-09-alert-rename-ingress-hostutil-fastpath-dedup-bound-window.md`)
> **Head:** `bc67b7b` (`main`)
> **Scope reviewed:** every code-bearing change in the window — 13 first-parent
> merges (PRs #1083–#1103), 57 files, +4,517 / −113; **18 non-test Go files**,
> +1,050 / −60.
>
> **Method.** Prioritised by *live blast radius*, not diff size:
>
> 1. **The TLS-interception trust root.** CHAOS-28 changes when the appliance
>    will and will not MITM. A change to the inspect-vs-bypass decision is the
>    single highest-consequence edit possible in this codebase: get it wrong in
>    one direction and inspected HTTPS breaks fleet-wide; get it wrong in the
>    other and DLP, AV, YARA, CDR and DPI all turn off silently, for every host
>    at once, with every dashboard still green.
> 2. **The security-alerting plane.** The dedup accounting fix and the syslog
>    panic observer both sit on detection paths, reviewed for *detection loss* —
>    the failure an operator cannot notice — rather than for enforcement.
> 3. **Release/build identity.** A `/healthz` version field is now a
>    release-blocking gate, so it was reviewed both as a supply-chain control
>    (does it actually fail closed?) and as an unauthenticated disclosure.
> 4. **Per-request primitives that changed.** `store_logclock.go` memoises a
>    render on the request-log chokepoint; `internal/alerts` changed an
>    eviction rule reached from the block path.
> 5. **Fail-closed config validation** — the `cdr.server_fingerprint` hex check.
>
> Because the prior two reviews' findings both landed in code that this window
> touches again (`internal/alerts/store.go`, the CHAOS-47 auth legs), the
> surrounding CHAOS-25/27/47 and MCP QUAL-4/5 material back to `6a2960e` was
> re-read adversarially rather than assumed clear on the strength of those
> reports. Findings below are scoped to the incremental window; the wider
> re-read is recorded under *Re-confirmed from earlier windows*.
>
> `internal/mcpacceptance` and `cmd/mcp-observe-acceptance` were re-confirmed
> **not reachable from the production binary** and reviewed as test tooling.

---

## Executive Summary

**One finding, fixed in this change:**

- **SR-2026-08-10-01 (LOW, latent; HIGH regression risk)** — `readTarball`'s
  zip-slip guard (`restore.go`, CWE-22) was **rewritten with no test behind it**.
  Its two sibling guards on the same loop — absolute path and duplicate entry —
  are both pinned; the traversal guard, the one that actually carries the
  path-traversal contract that `guardWithinDir` and D1.3b.2 extraction cite as
  their upstream, had no test at all. Closed here by a mutation-proven
  regression wall. **No behavior change.**

Everything else in the window is either neutral or a net security improvement.
There is **no authentication bypass, no authorization bypass, no default-allow,
no policy-precedence change, no missing signature validation, no weakened
certificate validation, no new SSRF or open-redirect primitive, no injection
primitive, and no secret exposure.**

Three changes deserve explicit *clearance* rather than silence, because each one
is the kind that looks like a regression until the alternative is written out.

---

## Cleared with reasoning

### 1. CHAOS-28 — refusing to inspect is the *safe* direction, and it was chosen

`internal/ca/validity.go`, `internal/ca/ca.go`, `proxy_tunnel.go`, `ca.go`,
`ca_health.go`, `ca_metrics.go`, `healthcheck.go`, `diagnostics.go`,
`decryption_observability.go`, `ui_security.go`.

Neither `x509.CreateCertificate` nor the ECDSA primitive checks the *parent's*
`NotBefore`/`NotAfter`, so an expired inspection CA kept minting well-formed
leaves that every client rejects. The window adds `Usable()` and refuses.

Three design decisions carry the security weight here, and all three are right:

- **`Usable()` is kept separate from `Ready()`.** `handleTunnel` still uses
  `Ready()` to choose inspect-vs-bypass. Folding validity into `Ready()` is the
  "obvious simplification" and it is the dangerous one: it routes the fault into
  the `inspect_unavailable` **bypass** branch, silently disabling every
  content-inspection control fleet-wide at the instant the CA expires. The code
  says so explicitly and the test `TestHandleTunnel_ExpiredCAFailsClosedNotBypass`
  pins it.
- **The refusal does not honour a decryption profile's `OnInspectError=fail-open`.**
  That contract is scoped to *per-origin* incompatibility and is gated behind a
  confirm-count for exactly that reason. An expired CA is host-independent, so
  routing it through the learner would promote every host requested during the
  outage into a persistent bypass — one fault poisoning the whole
  auto-exclusion cache.
- **502 before the 200.** The client gets an attributable proxy error instead of
  a hijacked connection that then fails its own handshake.

Checked the guard cannot be walked around via the leaf cache: `clampLeafValidity`
pins every leaf's `NotAfter` at or below the issuer's, so once the CA expires the
`GetCert` freshness check (`now.Before(entry.cert.Leaf.NotAfter)`) fails too —
and in any case the dispatcher gate fires before the cache is consulted.

Checked `clampLeafValidity` cannot produce an inverted window: the caller's guard
establishes `now ≤ ca.NotAfter` and `ca.NotBefore ≤ now + 5m`, so the clamped
range is non-empty on both ends.

**Rotation-success gating — cleared as observability-only.** `RotateIfNeeded` now
fires `RotationObserver` only when the bundle write succeeded. This *looks* like
suppressing a security signal. It is not: `RotationObserver` is the "rotated"
alert plus `culvert_ca_rotations_total`, both purely informational, and gating
them prevents one event emitting two contradictory pages. The
security-load-bearing observer — `CAChangedObserver`, which ends the client-facing
TLS resumption epoch so no client can resume a session authenticated under the
previous CA — is fired unconditionally from `InitCA` and is untouched. Verified
at both call sites.

**Immediate `checkRound()` at rotation-loop start — cleared for boot order.**
`clusterCA.RotateIfNeeded` and `CleanupSecondary` both nil-check their state, so
the pre-initialisation call is a no-op, and both halves run inside `runGuarded`.

**Disclosure discipline on the new surfaces — cleared, with one asymmetry noted.**
The `/readyz` row uses a fixed, detail-free string precisely because it is
unauthenticated on the proxy port, and the viewer-role operator-contract row
carries counts without the cause text. The full detail (which names the CA's
exact `NotAfter`) stays in the log, the alert, and the admin-role CA API. That is
the correct split. See Residual Risk #2 for the one place it is applied
inconsistently.

**Leaf-cache eviction (`cacheOrder`).** The change to append only for an
untracked host was checked for an eviction-correctness regression: duplicates
were previously skipped by the `if _, exists := cm.cache[h]; !exists` branch, so
the first insertion always governed and dropping them changes no eviction
decision. `ClearCache` clears `cacheOrder` alongside the map, so no duplicate
accumulation path is reintroduced.

### 2. Alert-dedup eviction — fails toward *more* delivery, never fewer

`internal/alerts/store.go`.

The dedup key embeds attacker-supplied host text, so the map is capped. The
security question is only ever "can this silence a real alert?", and it cannot:
evicting a live dedup key can only cause one **extra** delivery of a duplicate.
The `keep` exclusion guarantees the alert that triggered the eviction is never
the one dropped, and the "prune before charging" rule added this window stops a
quiet period's stale map from fabricating a saturation signal on a monotonic
counter. Fan-out remains bounded by the 10-slot delivery semaphore and the
500-cap retry queue.

**Shared delivery client — SSRF contract intact.** `ssrf.SafeDialContext` runs on
every **dial**; a pooled connection is by definition a connection to an address
that already passed the check, so reuse cannot reach an address that was never
validated, and `IdleConnTimeout: 90s` bounds how long a validated-then-rebound
host stays reachable. The newly added `ForceAttemptHTTP2` was checked for a
coalescing bypass: Go's HTTP/2 transport keys its connection pool strictly by
authority and does not implement cross-hostname coalescing, so there is no path
that reuses host A's connection for host B around the dial guard.

### 3. Release runtime-version identity — a real fail-closed supply-chain gate

`ha.go`, `.github/scripts/assert-release-ref.sh`,
`.github/scripts/assert-runtime-version.sh`, `ci.yml`.

`apiHealthz` now surfaces the linker-stamped `main.version`, and CI gates on it
from two directions: the release ref must be a `vX.Y.Z` tag before anything is
built or signed, and the built binary is booted and its `/healthz` version
asserted equal to the tag. Both scripts `exit 1` on the empty/missing case rather
than skipping, which is the property that matters — a gate that passes when its
input is absent is not a gate. Confirmed the "no version field" branch fails
rather than defaulting.

The action-pin bumps in the window are all full-SHA pins with version comments;
no tag-floating references were introduced.

---

## Finding

### SR-2026-08-10-01 — `readTarball`'s zip-slip guard had no regression test

| | |
| --- | --- |
| **Severity** | LOW (latent — the guard is present and correct today) |
| **Regression risk** | **HIGH** — this is why it is reported |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / zip-slip) |
| **OWASP** | A01:2021 — Broken Access Control |
| **Files** | `restore.go` (guard), `restore_traversal_guard_test.go` (added) |

**What.** `readTarball` applies three guards to every tar entry name: absolute
path, path traversal, duplicate name. Two were pinned
(`TestRestore_DryRun_AbsoluteTarPathRejected`,
`TestRestore_DryRun_DuplicateTarEntryRejected`). The traversal guard had **no
test**, and it was rewritten in place during this review's wider window
(per-component `part == ".."` → `strings.Contains(name, "..")`, commit in the
CodeQL-sanitiser-visibility change).

**Attack scenario.** An operator restores a backup tarball from a compromised
mirror, a shared artifact store, or an attacker-influenced support bundle. With
the guard weakened or absent, an entry named `data/../../etc/...` survives
`readTarball` and reaches the extraction path, writing outside the data directory
as the restore process's user.

**Preconditions.** A future edit that narrows or removes the guard, plus a
restore of a hostile archive. **Exploitability:** none today — the guard holds.
**Likelihood of the regression itself:** elevated. A rewritten guard with no test
is the standard shape of a silent reintroduction, and the natural response to a
false positive on `..` inside a filename is to narrow the check back to
per-component — which also quietly gives up the `strings.Contains` form that
CodeQL recognises as a sanitiser, so the SAST gate stops covering it at the same
moment the test suite stops noticing. **Impact:** arbitrary file write outside
`/data` → privilege escalation. **Affected assets:** the appliance filesystem,
and by extension every credential, session key and CA artifact beneath it.

**Fix applied — regression wall only, no behavior change:**

| Class | Cases |
| --- | --- |
| Negative | classic zip-slip (`data/../../etc/passwd`), leading traversal, deep interleaved traversal, bare parent component, traversal appended to a valid artifact name |
| Boundary | `data/config..json` — pins the substring rejection as a **deliberate** widening, so narrowing it back becomes a visible decision rather than a quiet edit |
| Positive | `data/.hidden.json`, `data/v1.0.json`, `data/config_versions/v99.json`, `data/threat.feed.snapshot.json` — a guard that rejects everything is an outage, not a guard |
| Malformed / fail-closed | a rejection returns `nil` files **and** `nil` order — never a partially-read archive a caller could iterate |
| Authorization / end-to-end | rejection propagates through `runRestoreDryRun`, and `assertNoDataMutation` confirms `/data` is untouched |
| Concurrency | 16 concurrent readers of the same hostile archive all reject — pins that the guard stays stateless, so a future change that hoisted shared state cannot turn "every caller rejects" into "the first caller rejects and the rest race" |

**Mutation-proven.** Removing the guard fails the negative, end-to-end and
concurrency tests; reverting it to the narrower per-component form fails the
boundary test. The wall is load-bearing, not decorative.

**Safe implementation note.** The guard itself was deliberately **not** touched.
It is correct, and the review's own rule — never change security behavior unless
required — applies to the reviewer first.

---

## Re-confirmed from earlier windows (adversarial re-read, no findings)

- **Stage-1 subject-CIDR precompute** (`authpolicy.go`, `policy.go`). Fast path
  and fallback are exactly equivalent: `nets[i]` is populated only where
  `matchIPOrCIDRAddr` would have taken the same `ParseCIDR` → `Contains` branch,
  index alignment with `Values` holds, and bare IPs / unparseable CIDRs keep a
  `nil` element and fall through. Stale-precompute-after-edit is closed by
  `copyPolicyRuleForPublication` nilling `nets` and by `sortLocked` cloning
  before precomputing. A rule that reaches the evaluator without `sortLocked`
  still matches identically, so correctness never depends on the precompute.
- **`authScheduleParseable` via the shared timezone cache.** The new
  `scheduleLoc{loc, ok}` preserves the distinction the Stage-1 gate needs — an
  unparseable timezone still returns `ok == false` and still **fails closed**
  rather than resolving to UTC.
- **CHAOS-47 auth legs.** Re-read for a deny→allow inversion; there is none.
  Every failure path still denies, including the gated one. The LDAP code-49-only
  password-rejection boundary and the OIDC 4xx carve-out (with 429/408 correctly
  excluded) both keep attacker-provokable, account-scoped states out of the
  provider-wide cooldown, and both **clear** the cooldown on an authoritative
  answer — without which an attacker's rejection would eat each half-open probe
  and hold a recovered backend in a permanent outage.
- **MCP QUAL-5 tenant isolation.** Exact equality, no prefix/case-fold/wildcard;
  empty `OwnerScope` fails closed rather than reading as "owned by every tenant";
  evaluated **first** among server-level overrides so a cross-tenant request can
  neither be laundered into an ALLOW by a later rule nor learn the foreign
  server's verification or enabled state.
- **MCP QUAL-4 policy composition.** Atomic and fail-closed (read → compile →
  verify capability is `gateway` → publish); a Management-capability source is
  rejected, the Management store is never published to, and
  `gatewayPolicyProvider` returns `nil` for any non-Gateway capability, which the
  runtime treats as `SNAPSHOT_UNAVAILABLE` rather than permissive.
- **YARA per-scan regex worker.** Per-string ReDoS budget preserved; timeout
  still fails closed via the unchanged `yaraTimeoutResult`; the `yaraInflight`
  charge tracks the **match** (not the worker), with a CAS making release
  exactly-once across the normal and abandoned paths; buffered `jobs`/`results`
  prevent either side wedging the other; `abandon()` nils the scan's runner so a
  closed channel is never reused or double-closed; the per-job panic guard
  resolves through the same admin-selected posture as a timeout rather than
  defaulting to "clean".
- **`hostutil.StripHostPort` fast path.** Re-verified the equivalence argument
  for `""`, `"[abc"`, `"abc]"` and bare IPv6. Host parsing feeds policy matching,
  so a divergence here would be a policy-matching difference; there is none.
- **HA standby containment.** The per-round guard deliberately does not charge a
  panicking round to the failure streak — the fail-closed direction, since
  charging it would auto-promote a standby whose only fault is its own parser,
  which in legacy (unfenced) mode is a remotely-triggerable split brain against a
  healthy leader. `onMaxFail` returning `IsLeader()` instead of an unconditional
  `true` closes a path where a failed promotion ended both replication and leader
  monitoring on a node that never became leader.
- **`store_logclock.go`.** Memo keyed on `(unix second, *time.Location)`; the
  one-second layout makes the cached render byte-identical to `Format`. One clock
  read now feeds both `TS` and `Time`, removing a straddle where the two fields
  could disagree.
- **`internal/syslog` panic observer.** Itself panic-contained, and it runs after
  `deliverLine`'s deferred unlock during unwind, so it can neither deadlock nor
  crash the drain goroutine. The root shim routes the recovered value through
  `sanitizeLog` with `%q` (CWE-117).
- **`config.go` / `saas_feed_download.go`.** Both tighten: hex validation on
  `cdr.server_fingerprint` at config-load time (mirroring what
  `buildCDRTLSConfig` already enforced at connect time), and an inline
  scheme+host re-check at the SaaS feed dial site so the SSRF contract is visible
  to CodeQL at the call site.
- **Admin API additions** (`ui_security.go`, `ui_config.go`, `ui_mcp.go`,
  `cdr_ui.go`). All read-only fields on existing role-gated handlers. No route,
  no `MinRole`, and no `requireRole` call changed; `apiCARotate`'s new
  not-persisted branch still emits its audit event.

---

## Residual Risk

1. **`/healthz` now discloses the build version unauthenticated.** `apiHealthz`
   is `Public: true` in `uiRoutes`. This is not a new *product-level* disclosure
   — the proxy-port `/health` handler has always returned `Version` to any
   unauthenticated client — and the field was added deliberately to make the
   release-identity gate assertable. Recorded so that a future decision to stop
   fingerprinting the admin plane has both call sites in view rather than one.
2. **`/health` and `/readyz` apply different reticence to the same fact.**
   `/health` (proxy port, unauthenticated) now reports
   `ssl_inspection: "expired"`, while `/readyz` was deliberately given a fixed,
   detail-free string for exactly this reason. `/health` already exposed
   `load_failed`, `unavailable`, `ca_expires_days` and `version`, so the new
   state adds no *class* of information — but the asymmetry is worth resolving
   deliberately rather than by accretion.
3. **`caEverUnusable` is never cleared.** After the first CA-usability fault,
   every subsequent inspected CONNECT takes the `caUsability` mutex in
   `noteCAUsable()` for the life of the process. Cost only, and only after a
   fault has already occurred — noted so it is not later mistaken for a hot-path
   lock on a healthy node.
4. **`assert-runtime-version.sh` boots the release binary with a fixed
   credential** (`-user gate -pass GateProbe123`, `-ui-no-tls`) on the CI runner.
   GitHub-hosted runners are ephemeral and single-tenant and the probe is
   loopback-only, so this is acceptable; flagged because the same pattern on a
   self-hosted or shared runner would not be.
5. **Not covered.** `internal/mcpacceptance` and `cmd/mcp-observe-acceptance`
   were reviewed only to re-confirm they do not reach the production binary. The
   packaging/installer shell changes were reviewed as diffs, not executed.

---

## Verification

- `go build ./...` — clean.
- `go test ./...` — green (`-count=1`, full suite, with the new tests).
- Mutation check on the added wall — guard removed ⇒ negative/end-to-end/
  concurrency tests fail; guard narrowed to per-component ⇒ boundary test fails.

## Files

| File | Change |
| --- | --- |
| `restore_traversal_guard_test.go` | **added** — SR-2026-08-10-01 regression wall (negative / boundary / positive / fail-closed / end-to-end / concurrency) |
| `docs/security-reviews/2026-08-10-…-window.md` | this report |
