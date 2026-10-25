# Security review — the open pull-request fleet, and two recorded fail-open gaps closed

**Date:** 2026-10-18
**Reviewer role:** Security Regression Engineer (scheduled run)
**Base revision:** `dec66e1` (`origin/main`)
**Previous record in this series:** [`2026-10-17-session-audience-and-policy-fail-open-window.md`](2026-10-17-session-audience-and-policy-fail-open-window.md) (PR #1651, open)

---

## 1. Executive summary

`main` has not moved since the 2026-10-17 record: that review covered
`83328fd..dec66e1`, and `dec66e1` is still the tip. There is therefore no new
*merged* window to review. What **is** new is the 28 pull requests waiting to
merge into it, so this run reviewed the fleet — the changes that will reach
production next — plus the backlog that review deliberately deferred.

Two things came out of it.

**One open PR introduces a fail-open regression, and four pairs of open PRs are
mutually incompatible remediations of the same defect over the same lines.**
The single-PR regression (#1638) flips a fail-closed installer gate to
fail-open for one valid TOML spelling. The pairs matter more than either half:
in each case both PRs are individually sound, and the hazard is entirely in how
they combine. The worst of them is the CHAOS-71 pair, where the *basis* of a
timestamp is an implicit contract between a writer and a reader in different
functions, and a plausible textual merge resolution pairs a wall-clock writer
with a monotonic reader — which does not fail to compile, and does not fail a
test that exercises either half alone.

**Two recorded-not-fixed defects are closed here**, chosen because they need no
product decision and collide with nothing in flight:

| ID | Severity | What was wrong |
|---|---|---|
| **SEC-C2WILDCARD-1** | 🟡 Medium (defence in depth) | All ten `{id}`/`{name}` admin routes resolved to the **public `/` catch-all** in the C2 metadata index, silently disabling the second RBAC layer, the C4 divergence observation and the C2c audit-gap check — invisibly, because the lookup still answered "found" |
| **SEC-ENROLLAUDIT-1** | 🟡 Medium | Revoking a cluster **enrollment token** — destroying cluster trust material — recorded **no audit entry**, while the route metadata declared `"audit delegated"` for a method that had no delegate |

Neither is an authentication bypass: every affected handler keeps its own
`requireRole`, and the token DELETE is admin-only. What was lost in both cases
is the layer that is supposed to *catch* a mistake in the first layer, and in
both cases the loss was structurally invisible — no counter moved, no gate went
red. That is the shape worth fixing early, because nothing will report it later.

---

## 2. Findings fixed here

### SEC-C2WILDCARD-1 — every wildcard admin route resolved to the public catch-all {#sec-c2wildcard-1}

**Affected contract.** `metadataIndex` "mirrors `*http.ServeMux`'s resolution so
the C2 middleware sees the same route dispatch decision as the mux"
(`ui_metadata_enforcement.go`).

**Evidence.** Ten routes are registered with Go 1.22 ServeMux wildcards
(`ui_support.go:93-108`):

```go
mux.HandleFunc("/api/support/bundles/{id}", apiSupportBundleItem)
mux.HandleFunc("/api/support/bundles/{id}/download-sealed", apiSupportBundleExportSealed)
mux.HandleFunc("/api/support/recipients/{name}", apiSupportRecipientItem)
```

`buildMetadataIndex` classified a pattern three ways — `"/"`, trailing-slash
prefix, or *exact* — so each of those went into the **exact map under its
literal pattern text**:

```go
default:
    idx.exact[r.Path] = r
```

A real request carries `/api/support/bundles/csb_a1b2…`, which never equals the
string `/api/support/bundles/{id}`. `Lookup` missed the exact map, fell through
the prefix list, and matched `"/"` — the SPA shell, `Public: true`,
`RolePublic`. Measured against the pre-fix tree, all ten resolve that way:

```
DEFECT: Lookup("/api/support/bundles/concreteid") resolved to "/" (public=true)
DEFECT: Lookup("/api/support/bundles/concreteid/download-sealed") resolved to "/" (public=true)
DEFECT: Lookup("/api/support/recipients/concretename") resolved to "/" (public=true)
… 10 of 10
```

**Attack scenario.** An operator (or a future change) relaxes or mis-states the
handler-level `requireRole` on a support-bundle route — say the sealed-export
download. C2 exists precisely to catch that: it resolves the route's declared
`MinRole` and, in enforce mode, denies. Here it resolves `RolePublic` instead
and permits, C4 never reports the divergence between declared and demanded
role, and C2c never notices the absent audit entry. The affected surfaces are
the support-bundle **download, sealed export, delete, manifest and
upload-consent** routes — the ones that move a diagnostic bundle containing
internal configuration off the box.

**Preconditions.** None for the metadata loss itself: it is unconditional on
every request to those paths. Exploiting it additionally requires a defect in
the handler's own `requireRole`.

**Exploitability.** Not exploitable as it stood — all ten handlers carry a
correct handler-level check, verified by hand in the 2026-10-17 review. The
realistic cost is the next change: a one-line RBAC slip on these routes would
ship with every automated backstop silently disabled.

**Likelihood.** Certain to be *present*; dependent on a second defect to *bite*.
**Impact if it bites.** Unauthenticated reach to a support bundle →
configuration and topology disclosure.
**Affected assets.** Support bundles, sealed exports, recipient roster.
**CWE.** CWE-863 (incorrect authorization), CWE-1220 (insufficient granularity
of access control). **OWASP.** A01:2021 Broken Access Control.
**Severity.** Medium (defence in depth). **Regression risk of the fix.** Low —
see §6.

**Why `TestC2_MetadataIndex_ResolvesEveryRoute` did not catch it.** It iterates
the pattern **literals**, which do hit the exact map, so it passes vacuously.
The new gate substitutes a concrete value for each `{…}` segment, which is the
only shape a request can actually have.

**Fix.** `buildMetadataIndex` now routes a pattern containing `{` into a
`wildcard` list of pre-split segments (and keeps it in the exact map, so a
lookup of the literal still resolves to its own route). Resolution tries exact,
then the most specific wildcard, then the prefix list. Matching uses ServeMux's
own segment semantics: a literal segment must match byte-for-byte, `{name}`
matches exactly one **non-empty** segment, `{name...}` matches the trailing
segments. Most-specific ordering is more segments → more literal segments →
longer pattern.

**A second half, found in review (Codex P2 and CodeRabbit, independently).**
The first version of the fix matched segments split from the *decoded*
`r.URL.Path`, which reopens the same hole for one percent-encoded character.
Measured against go1.26.9's own mux:

| request target | `r.URL.Path` | mux routes to |
|---|---|---|
| `/api/support/bundles/foo%2Fbar` | `/api/support/bundles/foo/bar` | `{id}`, `id="foo/bar"` |
| `/api/support/bundles/csb_abc/appro%76e` | `…/csb_abc/approve` | `{id}/approve` |

The mux matches on the **escaped** path and unescapes each segment *on its
own*, so `%2F` stays inside one wildcard value; the decoded path reads as one
segment too many, matched nothing, and fell through to `"/"` — verified on the
built index, which answered `("/", public=true)` for all three affected
shapes. Matching the *raw* escaped text would have been wrong in the opposite
direction, because `appro%76e` really does reach the literal `approve` route.
So resolution for a live request now goes through `LookupEscaped`, which
splits `r.URL.EscapedPath()` and unescapes each segment separately; the
decoded path still feeds the exact and prefix tiers, leaving their behaviour
untouched. A malformed escape leaves its segment as-is, so the worst case is a
miss, never a wrong route.

**Files.** `ui_metadata_enforcement.go`, `ui_metadata_wildcard_route_test.go`.

### SEC-ENROLLAUDIT-1 — revoking a cluster enrollment token left no audit record {#sec-enrollaudit-1}

**Affected contract.** Versioned/trust-affecting admin mutations audit;
`uiRoutes` declares `AuditExpected` so C2c can flag a mutation that answered 200
without emitting one.

**Evidence.** `ui_cluster.go`, the `http.MethodDelete` branch of
`apiClusterTokens`, pre-fix:

```go
if !globalClusterStore.DeleteToken(tokenHash) { … 404 … }
if err := globalClusterStore.Save(); err != nil { … 500 … }
jsonOK(w, map[string]any{"ok": true})
```

No `auditEvent` on any path. Its siblings all audit: `apiClusterTokenCreate`
emits `enrollment.token_created` (`ui_cluster.go:234`), node revocation emits
`enrollment.node_revoked` (`:302`), CA import, label and mode changes each emit
their own. The route metadata said:

```go
{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, Note: "audit delegated"},
```

— true of POST, which delegates to `apiClusterTokenCreate`; false of DELETE,
which has no delegate. With no `AuditExpected: true`, C2c's runtime audit-gap
check never fires, so the omission produced no warning and no counter either.
`api/route-classification.yaml` carried the same `audit_expected: false`.

**Attack scenario.** An attacker who has obtained an admin session — or a
malicious insider with the admin role — revokes the pending enrollment tokens.
New nodes can no longer join; a planned capacity expansion or a node rebuild
fails, and the incident review finds no record of who removed them or when. The
same erasure hides the *reconnaissance* half: an attacker enumerating cluster
trust material via `GET` and then destroying the evidence of their interest
leaves the audit trail showing only the (audited) read-side nothing.

**Preconditions.** An admin-role session on the control plane.
**Exploitability.** Trivial once admin is held — one `DELETE` with a `hash`
query parameter. **Likelihood.** Low (requires admin). **Impact.** Loss of
accountability on a cluster-trust mutation, and loss of the signal an
investigation needs; the mutation is also durable (`Save()`).
**Affected assets.** Cluster enrollment tokens, the audit trail.
**CWE.** CWE-778 (insufficient logging). **OWASP.** A09:2021 Security Logging
and Monitoring Failures. **Severity.** Medium. **Regression risk.** Low.

**Fix.** `auditEvent(r, "enrollment.token_revoked", sanitizeLog(tokenHash),
"cluster enrollment token revoked")`, emitted **after** the store has persisted
so the record cannot claim a revocation that did not survive the write; the
DELETE metadata entry becomes `AuditExpected: true` with the false
`"audit delegated"` note removed; the manifest row is corrected to match.
`saveConfigVersion` is deliberately **not** added — enrollment tokens are
outside the rollback surface for the reason already recorded on
`apiClusterTokenCreate`, and rolling one back could resurrect a consumed token.

**The write-failure path, found in review (CodeRabbit, CWE-778).**
`DeleteToken()` runs before `Save()`, so when the store write fails the token
is *already* gone from memory — this node has stopped honouring it whatever
the 500 says, and a later successful `Save()` makes that deletion durable with
no record of the revocation at all. A distinct `enrollment.token_revoke_unpersisted`
event now covers that path. The token is **not** restored: putting live
enrollment material back because a disk write failed is the less safe of the
two directions, and the 500 already tells the operator to retry.

**Files.** `ui_cluster.go`, `ui_routes_meta.go`, `api/route-classification.yaml`,
`cluster_token_revoke_audit_test.go`.

---

## 3. Findings in open pull requests — regressions caught before merge

These are reported here rather than fixed: they belong to their authors'
branches. Severity is "if merged as-is".

### F1 — PR #1638 turns a fail-closed installer gate into a fail-open one (Medium)

`scripts/install.sh` `maint_toml_string` gains single-quoted TOML literal
support. For a **triple**-quoted value it strips one quote and then finds the
next quote at position 1, yielding the empty string:

```awk
if (substr(line, 1, 1) == q) { line = substr(line, 2); idx = index(line, q); if (idx > 0) line = substr(line, 1, idx - 1) }
```

The callers treat empty as "not configured" and substitute the default
(`scripts/install.sh:2338-2339`):

```sh
[[ -n "$cfg_socket" ]] || cfg_socket="$socket_path"
[[ -n "$cfg_repo" ]]   || cfg_repo="$default_repo"
```

so the three gates at `:2342-2353` compare the default against itself and
**pass**. On `main` the same input yields the literal `'''…'''`, which is
non-empty, mismatches, and makes the installer skip Release-Management
auto-wiring — which is the whole purpose of those gates.

*Scenario:* an operator whose `/etc/culvert-maint/config.toml` spells
`socket_path` or `proxy_repo` as a multi-line literal. The installer then
authorizes the proxy UID on the maintenance agent's `allow_peers`, appends the
compose override and re-renders sudoers against an agent that is actually
listening on a **different socket** or pinned to a **different image
repository** than the one being authorized. *Preconditions:* a valid but
unusual TOML spelling in a root-owned `0640` file. *Exploitability:* low — not
attacker-supplied input; this is a fail-open **direction** change, not a reachable
exploit. *Severity:* Medium. *CWE:* CWE-636 (not failing securely).
*Recommendation:* take **#1628** instead — it parses `'''…'''` correctly — and
port the same branch to the canonical `extract_toml_string` in
`packaging/culvert-maint/install.sh` so the two extractors do not diverge.
Both PRs also return empty for a literal that genuinely spans lines, which
lands on the same default-fallback path; a sentinel (or `exit 1`) would make
"unknown" distinguishable from "default". *Test:* #1628's
`TestInstallScript_MaintTomlString_TripleSingleQuoted`, plus a
multiline-literal case.

### F2 — PRs #1644 and #1650 are incompatible CHAOS-71 remediations over the same lines (Medium, merge hazard)

Both change the same three files — `proxy_tunnel.go`, `readyz_dp_health.go`,
`roster_persist_durability.go` — and each is internally coherent:

- **#1644** moves the stamps to a **monotonic basis** (`monotime.go`:
  `monoNanos()` / `monoSince()`).
- **#1650** keeps **wall-clock** stamps and adds sign/magnitude guards
  (`relayEpoch`, `tunnelIdleFor`, `d.Abs()`).

They are alternatives, not complements. The basis of each stamp is an implicit
contract between a writer and a reader in different functions, and a textual
merge resolution can pair them wrongly without breaking the build:

- wall-clock **store** with monotonic **read** → idle reads as ~56 years →
  **every tunnel is torn down at its first deadline pop**, including live,
  quiet ones (an idle SSH session, a long-poll);
- monotonic **store** with wall-clock **read** → idle reads hugely negative →
  **no tunnel is ever reaped**, so half-open tunnels hold two FDs, two
  goroutines, a pooled relay buffer and a conn-limiter slot each.

The same mixing in `readyz_dp_health.go` makes a single transient CP-poll
failure trip `/ready?strict=1` with no grace (pulling a healthy node out of
rotation), and in `roster_persist_durability.go` it defeats the CAS rate limit
on a log line that `internal/logsink` can **block** a producer on — a
request-path amplifier.

*Severity:* Medium (availability). *Recommendation:* pick one and close the
other; if the magnitude-guard approach is preferred for the two log gates, keep
the monotonic basis for the tunnel reaper. Either way add a structural test
pinning that every writer and every reader of each stamp uses the same basis —
that is the invariant a merge can break and nothing currently checks.

### F3 — PR #1641 renames a security signal with no alias; #1630 does the same rename *with* one (Medium, detection regression)

Both rename `culvert_ui_roster_role_clamped_total` →
`culvert_admin_roster_role_clamped_total` and the JSON key
`uiRosterRoleClamped` → `adminRosterRoleClamped` (`events.go`, `ha.go`,
`ui_config.go`). **#1630 keeps the old names as deprecated aliases for one
release window; #1641 removes them outright.**

That series is the SEC-RBAC-ROLE-1 signal: non-zero means `ui_users.json` names
a role this build cannot grant and an account was clamped to viewer — i.e. a
restored, hand-edited or tampered roster attempting an unenrollable (often
higher) role. A Prometheus alert on a renamed series does not error; it simply
never fires again. So merging #1641 silently blinds every existing dashboard and
alert rule watching an attempted privilege escalation via the roster file, for
as long as nobody notices.

`docs/agent-context/conventions.md` is explicit: *"do not blindly rename an
existing public JSON/wire/config contract… Preserve compatibility."*

*Severity:* Medium (detection, not enforcement — the clamp itself still
happens). *Recommendation:* merge **#1630** and close **#1641**. If both are
merged in order, #1641 deletes the alias in the same release that introduced
it, which is worse than either alone.

### F4 — PRs #1640 and #1623 add two disagreeing diagnostics rows for one condition (Low/Medium, operator-misleading)

Both report dangling file-profile references from the same sources
(`globalProfileStore.GetByID`, `statFileProfileUnresolvedBlocked`) under
different codes (`policy_file_profile_unresolved` vs `file_profile_resolution`).
They merge cleanly, so both rows would ship. Their predicates disagree:
#1640's omits rule type and action (`diagnostics_file_profile.go:23-26`), but
file profiles are only evaluated on the **Allow** arm (`proxy.go:718-725`). A
Drop / block-page / redirect / auth rule carrying a stale `FileProfileID` would
raise a standing WARN claiming downloads are *BLOCKED* on rules that never
reach `fileProfileBlockedByID`, and would raise the rolled-up verdict with it.
*Recommendation:* land **#1623** (whose predicate is correctly scoped and whose
`TestCheckFileProfileResolution_ClearsAfterRepair` already asserts the negative
controls) and fold in #1640's 5-name cap. Separately, PRs **#1648** and **#1629**
conflict textually in `diagnostics.go` (both insert after the same line) —
a trivial rebase, no semantic clash.

### F5 — merging #1624 after #1642 can delete the only gates on the IDNA memo's value bound (Medium, merge hazard)

Both rewrite the same comment block and the same region of
`internal/hostutil/idnamemo_test.go`. **#1624** does not contain
`TestIDNMemo_PunycodeExpansionIsNotRetained` or
`TestIDNMemo_ExpansionCannotBreachTheCeiling` — the only tests covering the
`len(norm) > maxMemoHostLen` value bound. Resolving the conflict in #1624's
favour drops them exactly when #1624's new long tier makes that bound
load-bearing rather than defensive. *Recommendation:* merge **#1642** first,
rebase #1624 onto it, and assert both tests are present in the merged tree.
Neither PR has a memory-growth, key-collision or missed-eviction defect: both
tiers are fixed-size arrays with a single insertion path behind both bounds,
every hit re-verifies the full key, and slot selection uses a per-process
`maphash` seed.

### F6 — PR #1635 adds the right primitive and leaves two call sites using the broken sequence (Medium, incomplete fix)

#1635 introduces `IPFilter.Replace(mode, entries)` — one writer lock, one
published view — and converts the CP→DP snapshot apply to it. Its own docstring
names the hazard it removes: *"a SetMode / ClearAll / AddAll sequence publishes
three views, and the middle one is an empty allowlist that denies everything or
an empty blocklist that admits everything."* Two production paths still run
exactly that sequence:

- `configversion.go:731-733` — config-version **rollback**, at runtime, while
  serving;
- `ui_config.go:1336-1345` — config import **replace** mode, likewise.

In `block` mode the window after `ClearAll()` is an empty blocklist: **every
blocked address is admitted** for its duration. In `allow` mode it denies
everything. The window is two lock acquisitions wide and admin-triggered, which
is why it is Low on its own — but it is now a one-line change at each site
(`ipf.Replace(mode, list)`), the risk-register claim that "every production
configuration path mutates the installed owner in place" is about pointer
identity rather than atomicity, and leaving two call sites on the old shape is
how the primitive rots. *Recommendation:* fold both into #1635.
*Test:* a reader goroutine spinning `ipf.Allowed(x)` across a rollback,
asserting no verdict flip for an address whose membership is identical in both
generations. (This is R6 from the 2026-10-17 record, now with a second call
site and an available primitive.)

### F7 — PR #1626: a process-global apply-depth counter has two writers and one consumer (Low, observability)

`configSnapshotApplyDepth` (`configsnapshot_apply_health.go:117-131`) is
bracketed by `applyConfigSnapshot`, which is reached both from the DP config
poll **and** from the HA standby sync loop (`ha.go:466` → `applyHABundle`), but
consumed only by the DP loop (`controlplane_client.go:313-320`). On a combined
standby+DP node a standby apply in flight while the DP round panics
pre-mutation latches `markConfigSnapshotApplyRejected()` indefinitely; a
contained standby panic leaves depth ≥ 1 and is never reported at all. Impact
is observability-only today — `lastConfigSnapshotApplyOK` feeds diagnostics and
telemetry, not readiness — and becomes severity-relevant the moment the
readiness row the file anticipates is added.

**Also worth stating explicitly as the review decision #1626 asks for:**
`guardedConfigRound` converts "panic mid-apply ⇒ process death" into "panic
mid-apply ⇒ keep serving a blend of two config generations", and
`applySnapshotMutations` has no rollback. A deterministic fault can leave a new
blocklist paired with the old policy rule set, re-applied every poll because
`lastVersion` never advances. That is a defensible trade against a crash loop,
but the compensating surface is report-only and F7 makes it unreliable on one
role combination — the two should land together.

### F8 — PR #1632 (inner-host pin): sound, two residuals (Low)

The pin is the first statement of `runInspectExchange`, re-evaluated per
keep-alive iteration, and covers both the H1 and H2 forwarding sites. Measured
evasion attempts — absolute-form URI with a conflicting `Host`, duplicate or
absent `Host`, case variation, IDN/punycode, an ACE label decoding to ASCII,
bracket abuse, `host:port@evil`, `host:port/evil` — all either match the
authorized host or fail closed. Two residuals: a trailing-root-dot `Host` passes
the pin (`NormalizeHostStrict` trims it) but is **forwarded verbatim**, so a
front end that does not normalise it may answer from its default vhost — fixed
by forwarding the authorized spelling after a successful pin; and the refusal
increments counters and logs but does not call `recordInspectBlock`, so the
block is absent from the traffic log the PR's own motivation cites.

### F9 — PRs reviewed with no regression found

**#1633** (identity-cache fairness): the lookup key is unchanged, so no
cross-client verdict reuse; eviction is credential-agnostic, so no preferential
eviction of denials; expired entries are now removed rather than leaked; OIDC
nonce/state/issuer/audience validation is untouched; the new counter is
unlabelled. The fairness key comes from `realClientIP`, which honours XFF only
from a configured trusted proxy. Two notes: `authCacheStore.frontLocked` still
lacks the generation check its new sibling adds, and an attacker with many
source addresses can still displace honest entries — inherent to the CHAOS-57
design, no worse than before.
**#1649** (reqlog lock-free fast path): the flag only ever lets a caller *skip*;
every sender that can still reach `ch <- e` went through `persistMu` and
registered there. The one new drop window is inside `startPersist`'s critical
section — three cheap operations, with the file already opened outside it.
**#1643** (published policy revision): identity is the backing array's slot-0
address **plus** length, and the marker holds an interior pointer so the
allocator cannot reuse the range; no code assigns into `ps.rules[i]`, which is
the only shape that could keep both identifiers while changing a definition;
`deleteAtLocked` carries the mark onto a subset of already-published rules.
**#1637** (broadcast freshness): the new branch is entered only when the stamp
is ahead of the caller's sample and still returns 0 for a genuine rollback, so
the accept window strictly narrows.
**#1635** (`Replace` itself): one lock, one publication, no aliasing, fail-closed
`default` preserved — see F6 for the call sites it did not convert.
**#1646** (legacy redaction toggle): both paths are registered to the same
handler with identical `requireRole` and identical metadata.
**#1634** (test isolation): the SOCKS5 change publishes the server before
recording the bind, so no surface reports a ready listener with a nil address —
fail-safe.
**#1652 / #1648 / #1640 / #1629 / #1623** (diagnostics): all read-only, all at
`RoleViewer`, and in every case the newly surfaced value is already reachable at
`RoleViewer` through an existing route; the PAC and SaaS-feed rows deliberately
omit the fields that could carry an internal hostname (`Entry`) or a URL.
**#1621 / #1627 / #1639 / #1647 / #1653** (docs): no secret values, no
behaviour change.

---

## 4. Findings on merged `main` — recorded, not fixed

### M1 — CDR is bypassed by size, and `fail_mode: closed` does not cover it (Medium, deliberate — needs a decision)

`cdrGateOversize` returns `cdrPassSkipped("SKIPPED_OVERSIZE")` when the body
exceeds the effective per-file cap (`cdr_proxy.go:255-267`), and
`cdrHandleCallError` does the same for Sluice's own `file_too_large`
(`:443-450`). Both are `cdrPass` — the original bytes are delivered — and
`fail_mode` is explicitly **not** consulted on either path. Separately, CDR only
ever sees the scan prefix: `scanInspectBody` buffers `maxScanBufferBytes()`
(5 MiB by default) and relays the remainder (`proxy_tunnel.go:1294-1324`), so a
file larger than the window is sanitized only up to the cut.

*Scenario:* an attacker-controlled origin pads a macro-bearing document past
the per-file cap, or past the scan window, and it is delivered with its active
content intact — on a deployment whose operator set `fail_mode: "closed"`
specifically so that CDR failures block. *Preconditions:* TLS inspection on,
CDR on, a destination the attacker controls (or any site hosting the payload).
*Exploitability:* high — padding a file is trivial and requires no protocol
trick. *Impact:* content-disarm bypass → macro/OLE/JS delivery to the endpoint.
*CWE:* CWE-693 (protection mechanism failure). *OWASP:* A04:2021 Insecure
Design.

*Why not fixed here.* It is deliberate and documented in the code ("the client
deserves to see it — same behaviour as any other scan being skipped"), it is
observable (`culvert_cdr_oversize_skipped_total`, a log line, and the
scan-window alert), and whether an oversize download should be **blocked** is a
product decision with real availability consequences. The right shape is an
explicit `cdr.oversize_action: pass | block` rather than silently overloading
`fail_mode`; the operator-facing documentation should also state plainly that
`fail_mode` does not cover the oversize path, which the pending docs PR #1621
now does.

### M2 — `jose.Thumbprint` emits JSON string values without escaping (Informational)

`internal/mcp/jose/jose.go` builds the RFC 7638 canonical form with
`q(s) = "\"" + s + "\""` and no escaping. Two distinct member sets can therefore
produce one canonical string — e.g. `crv="a"`, `x="b\",\"kty\":\"OKP\",\"x\":\"c"`
collides with `crv="a\",\"kty\":\"OKP\",\"x\":\"b"`, `x="c"` — which is a
thumbprint collision without a hash collision.

*Not reachable today:* the only caller (`senderconstraint/dpop.go:76`) runs
`jose.ParsePublicJWK` first, which constrains every thumbprinted member to a
fixed curve name or a base64url string, so a quote cannot survive. Recorded
because `Thumbprint` is exported from a general-purpose package and a future
caller that thumbprints an unparsed JWK inherits the collision. *Cheap guard:*
escape in `q`, or a test asserting no member reaching `q` contains `"`.

### Carried forward from 2026-10-17, still open

**R1** — the plain-HTTP forward path runs no private/internal destination check
while CONNECT, WebSocket and SOCKS5 all do. **This remains the most important
open item and still needs an owner decision**; nothing in this window changed
it. **R3** (`/api/security`'s documented `ipList` is declared and never read),
**R5** (SOCKS5 does not run the policy engine — undocumented in README's
"Limitations & Known Gaps"), **R7** (non-minimal punycode re-canonicalisation),
**R8** (an action-less rule silently allows) are unchanged. **R6** is superseded
by **F6** above. **R2** and **R4** are closed by this change.

---

## 5. Invariants spot-checked and found holding

Beyond the 2026-10-17 list, re-checked at this revision:

- **OCSP fails closed on an indeterminate verdict.** A verdict must be
  affirmative (Good or Revoked); "all responders unreachable" produces a
  *fail-closed* block with a short `indeterminateTTL`, counted and timestamped;
  the verdict cache is keyed on the full RFC 6960 CertID (serial **plus** issuer
  name and key hashes), so one issuer's verdict cannot answer for another's. The
  one fail-open branch — no resolvable issuer — needs both an empty
  `VerifiedChains` and a leaf-only presentation, which normal chain
  verification does not produce.
- **JOSE rejects algorithm confusion.** Asymmetric allowlist only; `alg=none`
  and HMAC have no code path; every verifier re-asserts the key type before
  use; EC keys are built through `ecdsa.ParseUncompressedPublicKey` so an
  off-curve point cannot be assembled; a JWK carrying `d` is refused.
- **mTLS sender constraint.** Both thumbprints must be present and canonically
  encoded (round-trip checked), compared in constant time; the observed
  thumbprint comes only from `r.TLS.PeerCertificates[0]`, never from a
  client-supplied header.
- **The audit-first ordering and its recorded exclusions** are intact at the
  one site this change touches; `saveConfigVersion` is correctly *absent* from
  the enrollment-token path.

---

## 6. Regression analysis of this change

**SEC-C2WILDCARD-1.** The index is consulted on every admin-UI request, so the
blast radius is the question. Three properties bound it:

1. **Exact lookups are unchanged.** The exact map is tried first and wildcard
   patterns are still registered in it, so every literal path — including the
   pattern text itself, which `TestC2_MetadataIndex_ResolvesEveryRoute` relies
   on — resolves exactly as before. Pinned by
   `TestC2WildcardRoute_LiteralPatternStillResolves`.
2. **The catch-all fallback is unchanged.** Paths owned by no route still reach
   `"/"`. Pinned by `TestC2WildcardRoute_UnknownPathStillFallsToTheCatchAll`.
3. **The new matcher cannot over-claim.** `{name}` requires a non-empty
   segment, segment counts must agree, and literals must match byte-for-byte —
   so `/api/support/bundles/` (no id) and
   `/api/support/bundles/x/approve/extra` are *not* claimed. Pinned by
   `TestC2WildcardRoute_NegativeControls`.

Direction of change: ten paths move from `RolePublic` to their own declared
role. In **shadow** mode that can newly log a would-deny; in **enforce** mode
(the default, `CULVERT_C2_ENFORCE`) C2 can now deny a request that the
handler's own `requireRole` would have denied anyway — the two agree, which is
what the C4 divergence check exists to confirm. No path becomes *more*
permissive. Cost: ≤10 segment comparisons, only on an exact-map miss, replacing
a full scan of the prefix list for those paths.

**SEC-ENROLLAUDIT-1.** Two audit emissions, one per outcome of the same
mutation. Status codes, response bodies and the store's behaviour are
untouched; the 404 and 400 paths emit nothing (pinned by two negative
controls). The audit ring is bounded, so a new entry can evict an older one —
which is why every gate asserts on unique content, never on a length delta,
and why each one mints a **fresh** token hash per invocation: `go test -count=2`
re-enters a test in the same process, and a fixed hash would let the positive
assertion match the previous run's entry and pass without the handler emitting
anything (CodeRabbit).

---

## 7. Verification

```
go build ./...                                  pass
go vet .                                        pass
gofmt -l <every changed file>                   clean
go test ./internal/...                          109/109 packages pass
go test -run 'TestC2WildcardRoute|TestEnrollAudit' .   pass
python3 docs/agent-context/check.py             pass
```

**Both gates were verified FAILING against the pre-fix tree.** The three
production files were replaced with their `origin/main` versions and the suites
re-run:

| Gate | Pre-fix result |
|---|---|
| `TestC2WildcardRoute_ConcretePathResolvesToItsOwnRoute` | FAIL — 10 of 10 wildcard routes resolve to `"/"` with `public=true` |
| `TestC2WildcardRoute_NeverResolvesToThePublicCatchAll` | FAIL — same 10, named as the enforcement loss |
| `TestC2WildcardRoute_LongerPatternWinsOverShorter` | FAIL — all four concrete paths resolve to `"/"` |
| `TestEnrollAudit_TokenRevokeIsAudited` | FAIL — `no "enrollment.token_revoked" audit entry for the revoked token` |
| `TestEnrollAudit_RouteMetadataDeclaresTheAudit` | FAIL — `AuditExpected` false and the note still claims a delegate |
| `TestC2WildcardRoute_NegativeControls` · `…_LiteralPatternStillResolves` · `…_UnknownPathStillFallsToTheCatchAll` · `TestEnrollAudit_FailedRevokeIsNotAudited` · `…_MissingHashIsNotAudited` | **PASS pre-fix** — which is what a control must do |

The gate that caught the manifest half was CI's own: `TestOpenAPI_Gate3_RouteCoverage`
reported `AUDIT DRIFT: DELETE /api/cluster/tokens manifest audit_expected=false
but router=true` until `api/route-classification.yaml` was corrected.

**Pre-existing failures.** The root package has a known environmental failure
family — the IdP/SAML/OIDC fixtures whose issuer host resolves to a private
address and is refused by the URL validator. Confirmed identical on a pristine
`origin/main` worktree in this sandbox:

```
--- FAIL: TestAPIIdPItem_PutClearsInlineSAMLMetadataWhenExplicitlyEmptyWithURL
--- FAIL: TestAPIIdPItem_PutURLMetadataClearsInlineSAMLMetadataWhenXMLIsOmitted
--- FAIL: TestAPIIdPAudit_RedactsWriteOnlyFields
```

**Not run, and why.** `golangci-lint` — the installed binary predates the
toolchain this tree requires; the toolchain pin was **not** touched to work
around it (`conventions.md` forbids it), so CI's lint gate is authoritative.
The browser E2E lane and the hosted CodeQL/gosec/govulncheck lanes are likewise
CI-only. A passing local check is not a passing merge gate.

---

## 8. Residual risk

- **R1 is still open.** The plain-HTTP forward path still has no
  private/internal destination guard. Nothing here changes that, and it remains
  the single most valuable decision on this list.
- **M1 is still open and reachable.** CDR can be bypassed by padding a file
  past the scan window or the per-file cap, and `fail_mode: closed` does not
  cover it.
- **SEC-C2WILDCARD-1's fix restores the second layer, it does not add a first
  one.** The handler-level `requireRole` on those ten routes is still what
  actually enforces; C2 is now able to notice if one goes wrong.
- **SEC-ENROLLAUDIT-1 records the revocation; it does not prevent it.** An
  admin-session holder can still destroy enrollment tokens — now traceably.
  There is still no second-person control on that mutation.
- **The fleet hazards in §3 are not fixed by this change.** F2, F3 and F5 are
  merge-order hazards: they get worse, not better, with time, and they are not
  visible to any gate that tests one branch at a time.
- **The metadata index is still a mirror.** It reproduces ServeMux's resolution
  in a second implementation. The wildcard half now agrees, including the
  escaped-path handling — but that half took two review findings to get right,
  which is itself the argument. The structural answer — asking the mux itself —
  remains unbuilt, and a future Go routing change could desynchronise them
  again. A differential test that registers
  every `uiRoutes` pattern on a real `*http.ServeMux` and compares its
  resolution against `Lookup` for a corpus of concrete paths would close that
  class rather than this instance.
