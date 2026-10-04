# Security regression review — admission/shutdown package extraction + the diagnostics roster window

**Date:** 2026-10-03
**Reviewer role:** Security Regression Engineer (standing scheduled review)
**Head reviewed:** `3fcc07e` (`main`)
**Base reviewed:** `f13479b` — covers PRs **#1490, #1522, #1523, #1524, #1525**
**Verdict:** one **LOW** finding in the reviewed window, fixed in this change. The package
extraction itself is a faithful, well-gated move with **no** security regression. One further
**MEDIUM** finding (F-2) was found *outside* the window during this review and is reported, not
fixed — it is pre-existing and its correct fix is a behaviour decision of its own.

---

## 1. Executive summary

The window's dominant change is the highest-risk class this role exists to police: a refactor
that relocated the two **per-request admission gates** — the IP filter and the rate limiter,
including distributed (cluster-aware) rate limiting — out of `security.go` and into a new
`internal/admission` package (ADR-0038/ADR-0039), plus the shutdown hook registry into
`internal/shutdown` (ADR-0037).

**That extraction is clean.** Every allow/deny decision body is byte-identical to its
pre-move form, the gossip wire format is preserved field-for-field, all 17 CHAOS-61 freshness
gates survived, zero tests were lost repo-wide (29 added), and the CI contracts that protect
these paths were **extended rather than left behind** — CodeQL path filters, per-file coverage
floors, and the `benchgate` allocation gates were all pointed at the new package in the same
change. The refactor also *removes* two production test seams (`resetForTest`,
`applyAtForTest`) and replaces process-global cluster state with instance-owned state.

One genuine regression was found, and it is **not** in the refactor. PR #1490 added an
operator-contract row (`admin_username_length`) derived from the **admin-only** roster to
`GET /api/diagnostics`, which is **viewer**-readable. The row's remediation text disclosed
whether an admin account has **TOTP enrolled**, the legacy login's **effective role**, the
affected **count** and the longest username's **byte length** to viewers and operators —
facts otherwise gated at `RoleAdmin` via `GET /api/auth/users`.

**A second, unrelated finding surfaced while driving this PR's CI and is reported rather than
fixed.** Porting PR #1544's lint-timeout fix switched on the frontend verification gate (the diff
classifier sets `frontend=true` for any `pr-fast-gate.yml` change), which failed on a dev-only npm
advisory. One of those advisories describes a NAT64 address-classifier gap; checking Culvert's own
Go classifier for the same class found that `internal/ssrf` does **not** treat the RFC 8215
local-use NAT64 prefix `64:ff9b:1::/48` as private, so the same cloud-metadata address that is
correctly refused through the well-known prefix is **admitted** through the local-use one (F-2,
MEDIUM). Two process observations ride along: the frontend vulnerability gate has **no scheduled
run**, so a newly published advisory is invisible until someone happens to touch a frontend path;
and `npm audit` verdicts change with no code change at all, which is exactly the shape a
diff-triggered-only gate cannot catch.

---

## 2. Security findings

### F-1 (LOW) — Admin-roster metadata disclosed on the viewer-readable operator contract

| | |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-497 (Exposure of Sensitive System Information to an Unauthorized Control Sphere); CWE-200; CWE-1220 (Insufficient Granularity of Access Control) |
| **OWASP** | A01:2021 Broken Access Control |
| **Introduced by** | PR #1490 (`1f7f42c`) |
| **Status** | **Fixed in this change** |

**What leaked.** `checkOversizeConfiguredUsernames` (`diagnostics.go`) builds its row from
`cfg.ListUIUsers()`, `cfg.GetUser()` and `cfg.UserHasTOTP()`. `GET /api/diagnostics` requires
only `RoleViewer` (`diagnostics.go`, and `MinRole: RoleViewer` in `ui_routes_meta.go`), and
the handler passed `buildOperatorContract()` straight to `jsonOK` with **no role filtering**.
When the warn condition held, any viewer or operator could read:

1. the **count** of admin accounts whose username exceeds the 64-byte account limit;
2. the **longest** such username's byte length;
3. that a **legacy single-user login** (`cfg.user`) exists and is oversize;
4. whether that login is **mirrored** into the roster (distinguishable from which of two
   remediation branches is rendered);
5. that login's **effective role**, interpolated verbatim (`"set its role back to operator"`);
6. that **at least one affected account has TOTP enrolled**.

**Why it is a cross-role flow and not already-public information.** `GET /api/auth/users` is
`RoleAdmin` on **every** method, so the roster is otherwise unavailable below admin. Before
#1490 the only signal was a one-shot boot log line
(`warnOversizeConfiguredUsernames`, `auth_startup.go`) — not reachable through the API at all.
The row therefore moved roster-derived facts from *admin-only / process log* to
*viewer-readable API*.

**Attack scenario.** An authenticated low-privilege insider (or anyone holding a stolen
viewer/operator session — the role a read-only monitoring integration is normally given) polls
`GET /api/diagnostics`. Item **6** is the one with direct attacker value: it tells them whether
a specific high-value admin account is **single-factor**, which is precisely the input to
deciding whether credential stuffing or phishing against that administrator is worth
attempting. Item **5** maps privilege; items **3–4** reveal the admin-plane topology (a legacy
`cfg.user` login that `Admin Users` cannot manage); items **1–2** are a weak username oracle.

**Preconditions.** (a) an admin username longer than 64 bytes exists — reachable only via
`-user` / `auth.user` / `--reset-password`, which (unlike setup and the Admin Users API) do not
cap the name; and (b) an authenticated session at viewer or above.

**Exploitability / likelihood.** Low. The precondition is an unusual configuration and the
disclosure is reconnaissance metadata, not credentials — no username, hash, or secret is
rendered (the check deliberately reports only lengths). **Impact:** low-moderate, because
knowing an admin is single-factor meaningfully improves target selection against the
management plane.

**Affected assets.** Admin-plane identity metadata; second-factor posture of administrator
accounts; admin-plane topology.

**Why the existing wall did not catch it.** `TestApiDiagnostics_NoSensitiveValues` is a
*secret-material* wall — it forbids session-secret symbols, PEM blocks, `/data/` paths and
32+ char hex runs. Identity and authorization metadata was simply outside its scope, so the
new row passed it legitimately. This is a coverage gap, not a vacuous test.

**Note on how it was pinned.** The five tests #1490 shipped for this row drove the handler with
`viewerCtx(...)` and asserted the sensitive strings **are present** — i.e. they pinned the
disclosure as intended behaviour. They have been deliberately re-pointed at `adminCtx(...)`,
the role that legitimately receives that content, exactly as this repository has handled
defect-pinning tests before (`TestRunShutdownSequence_EarlyCtxHasNoDeadline_LateCtxDoes`,
`TestRequestTracing_SanitisesClientRequestID`). Their remediation-content assertions are
valuable and are kept in full.

---

### F-2 (MEDIUM) — NAT64 local-use prefix `64:ff9b:1::/48` is not classified as private (REPORTED, not fixed)

| | |
|---|---|
| **Severity** | Medium (High impact × Low–Medium likelihood) |
| **CWE** | CWE-918 (SSRF); CWE-1286 (Improper Validation of Syntactic Correctness of Input); CWE-184 (Incomplete List of Disallowed Inputs) |
| **OWASP** | A10:2021 Server-Side Request Forgery |
| **Status** | **Reported, deliberately NOT fixed in this PR** — pre-existing, unrelated to the reviewed window, and the correct fix is not a one-liner (see below) |
| **Register** | `RISK-030` (OPEN) in [TECHNICAL-RISK-REGISTER.md](../TECHNICAL-RISK-REGISTER.md) |

**How it was found.** Not from the reviewed diff. The frontend verification gate (switched on in this
branch by the ported lint-timeout change) surfaced npm advisory
[GHSA-2vr4-cq9g-pvrc](https://github.com/advisories/GHSA-2vr4-cq9g-pvrc) against the dev-only
`ip-address` package: *"no classifier recognizes the NAT64 local-use range 64:ff9b:1::/48, allowing
SSRF and trust-boundary bypass."* That npm package is unrelated to Go code and never ships, but the
**class** of bug is directly relevant to Culvert's own classifier, so it was checked.

**The finding.** `internal/ssrf/ssrf.go`'s `privateRanges` — the documented *"SINGLE source of truth
for the guard table"* — lists the RFC 6052 well-known NAT64 prefix `64:ff9b::/96` but **not** the
RFC 8215 local-use translation prefix `64:ff9b:1::/48`. The two are disjoint (they differ in the
third 16-bit group), so the local-use prefix is classified **public**.

Measured against the real `PrivateAddr`:

| probe | embedded IPv4 | `PrivateAddr` |
|---|---|---|
| `64:ff9b::7f00:1` | 127.0.0.1 | `true` ✅ |
| `64:ff9b::a9fe:a9fe` | 169.254.169.254 | `true` ✅ |
| `64:ff9b:1::7f00:1` | 127.0.0.1 | **`false`** ❌ |
| `64:ff9b:1::a9fe:a9fe` | 169.254.169.254 | **`false`** ❌ |
| `64:ff9b:1::a00:1` | 10.0.0.1 | **`false`** ❌ |
| `64:ff9b:1:0:0:0:c0a8:1` | 192.168.0.1 | **`false`** ❌ |

**The coverage is inverted, which is what makes this more than a missing row.** RFC 6052 §3.1 states
the well-known prefix MUST NOT be used to represent non-global IPv4 addresses. So the prefix Culvert
*does* block is the one that cannot legitimately carry `127.0.0.1` or `169.254.169.254`, while
RFC 8215's local-use prefix — which exists precisely so operators can translate non-global IPv4 —
is the one left open.

**Attack scenario.** On a deployment whose egress path includes a NAT64 translator configured with a
local-use prefix (RFC 8215's stated purpose), a client asks the proxy for
`[64:ff9b:1::a9fe:a9fe]:80`, or a hostname whose AAAA answer is that address. `PrivateAddr` reports
public, the guard admits it, and the NAT64 gateway translates it to `169.254.169.254` — the cloud
metadata endpoint `169.254.0.0/16` is in the table specifically to protect. The same route reaches
loopback and RFC 1918.

**Preconditions.** A NAT64 translator on the egress path using a prefix inside `64:ff9b:1::/48`.
Not universal, but standardised and real in IPv6-first enterprise and mobile networks — which is
Culvert's market. No authentication is needed beyond whatever the proxy already requires, and
nothing exotic: the address is an ordinary literal or DNS answer.

**Exploitability.** Trivial once the precondition holds (one request). **Likelihood** Low–Medium.
**Impact** High — SSRF to metadata/loopback/RFC 1918.

**Affected assets.** `internal/ssrf` is the single SSRF trust boundary for the proxy data path
(`proxy.go`, `proxy_tunnel.go`, `socks5.go`, `proxy_portal.go`) and for every outbound fetcher —
OCSP, threat feed, blocklist feed, SaaS feed, alert webhooks, OTLP, release catalog, support upload —
plus MCP destination inspection. One classification gap affects all of them.

**Recommended fix — NOT simply adding the prefix to the list.** Blocking all of `64:ff9b:1::/48`
would be wrong in the other direction: a /48 holds the /96 a translator actually uses, and the
embedded IPv4 may be **public**. On an IPv6-only network NAT64 is how clients reach the IPv4
internet, so a blanket block would deny legitimate egress — and the same over-blocking already
applies to `64:ff9b::/96`, where Culvert blocks public-IPv4 embeddings too (safe direction, but it
means NAT64 egress does not work at all today).

The correct shape is to **decode the embedded IPv4 from a recognised NAT64 prefix and classify
that**, so `64:ff9b:1::a9fe:a9fe` is refused (embeds link-local) while `64:ff9b:1::<public v4>` is
allowed. That is a behaviour change in both directions and needs its own design decision — which is
why this is reported rather than patched inside a review about diagnostics redaction. The repo's
own rule applies: *never change security behavior unless required.*

**Required tests** (for whoever takes it): positive (every RFC 1918/loopback/link-local/CGN
embedding refused through both the well-known and local-use prefixes); negative (a public-IPv4
embedding still allowed, if the decode approach is taken); boundary (the `/48` and `/96` edges, and
`64:ff9b:2::` which is *outside* the local-use prefix); malformed (truncated and zone-bearing
forms); plus the existing `privateaddr_test.go` table extended so the guard table and the test
enumerate the same prefixes.

**Regression risk of the fix.** Medium — it changes which destinations the proxy will reach. The
decode approach must not accidentally widen `64:ff9b::/96` (currently fully blocked) without that
being an explicit, recorded decision.

## 3. Suggested fix (implemented)

`redactContractForRole(contract, isAdmin)` withholds the roster-derived detail below admin and
is wired into `apiDiagnostics`:

```go
jsonOK(w, redactContractForRole(buildOperatorContract(), uiRole(r).HasRole(RoleAdmin)))
```

Four properties make it the right shape rather than the cheapest one:

- **The row stays visible at every role.** Code and `warn` status are untouched, so the
  condition remains observable to monitoring and the SPA, and the contract verdict still rolls
  up. Only the detail is withheld. This matches the convention the repository already applies
  to viewer-role rows — the identity-backend row "carries the backend name and counts, never
  the cause", and `/readyz` uses fixed detail strings so a lower-privileged reader cannot
  fingerprint node state. *Hiding the row would have been a worse outcome than the leak.*
- **The redacted message is a constant.** It carries no roster-derived value at all — not the
  count, not the longest length. Nothing has to be re-derived, so the redacted and full
  renderings cannot disagree.
- **Fail-closed by construction.** The only input that un-redacts is a proven admin, so a role
  added below admin later, an unenrolled role, or a caller whose role cannot be resolved is
  withheld without this function being revisited.
- **An `ok` row is never redacted.** Replacing a healthy row with the warn message would report
  a condition that does not exist and send an operator hunting an account that is fine.

The redaction **copies** the row slice before mutating, so a redacted render can never alter
the caller's contract and leak back into a later admin render through a shared backing array.

---

## 3b. Review round — F-1 was bypassable (P1, fixed)

Codex found the fix **incomplete, and the miss is the same class the fix was
written to close.** `redactContractForRole` was wired into `apiDiagnostics`
alone, but `apiHealthExplain` (`ui_support.go`, `GET /api/health/explain`)
renders the **same** `OperatorContract` at the **same** `RoleViewer` floor and
returned `buildOperatorContract()` raw — so every fact in F-1 remained readable
by a viewer through the alternate endpoint. The fix was defeated in full by an
endpoint one file over.

**Why it was missed, stated plainly.** SEC-DIAG-ROSTER-1 has **two** primitives:
which rows carry roster state (`ListUIUsers` / `UserHasTOTP` / `GetUser`) and
**who renders the contract** (`buildOperatorContract`). §6 enumerated the first
and built a wall anchored on `diagnostics.go`, which structurally cannot see a
second renderer in another file. The governance lesson this review quoted from
CHAOS-70 — *enumerate the class from the primitive, not from the file being
edited* — was applied to one primitive and not the other. The transferable form:
**enumerating one primitive of a two-primitive class is not enumerating the
class** (cf. CHAOS-69's "enforcing one tier of a two-tier contract is not
enforcing the contract").

**Fixed:** both renderers redact. `TestWall_EveryOperatorContractRendererIsClassified`
now scans every production file for callers of `buildOperatorContract` and
requires each to be classified — a `redacted` renderer must actually call
`redactContractForRole` **and** gate on `HasRole(RoleAdmin)` (so a widened
threshold fails the wall, not only the behavioural gate), and anything else
needs a recorded reason. The support-bundle collector (`support_collectors.go`)
is the one stated exception: a different trust boundary, writing through
`in.Redactor.Classify` under the struct's `redact:"internal"` tags with a
declared `MaxClass: ClassInternal`, behind an admin-created, admin-approved,
capture-level-gated lifecycle. The wall carries a not-vacuous check and a floor
of two verified redacted renderers, so deleting or renaming one fails rather
than passing against a shrinking surface.

Gates added: `TestApiHealthExplain_UsernameRowDetailIsAdminOnly` (behavioural,
positive + negative, with its own not-vacuous check) and
`TestApiHealthExplain_UsernameRowStaysVisible` (control — the alternate renderer
must keep reporting the condition). Four mutations each verified failing: the
pre-fix bare render, the threshold widened to `RoleOperator`, a new unclassified
renderer added in an unrelated file, and the primitive renamed.

---

## 4. Regression analysis of the extraction (no findings)

Each claim below was verified mechanically, not by reading intent.

| Property | Method | Result |
|---|---|---|
| IP filter decision path (`Allowed`, `contains`, `SetMode`, `Add`, `addLocked`, `Remove`, `ClearAll`, `AddAll`) | normalized body diff vs `f13479b:security.go` | **byte-identical** |
| Rate limiter (`Allow`, `IsExempt`, window `expire`/`add`/`grow`, exempt view + publish) | normalized whole-file diff | **byte-identical** |
| `PrefixFromIPNet` family normalization (the fail-open direction for a blocklist: `::ffff:10.0.0.0/104` must behave as `10.0.0.0/8`) | body diff + retained differential/fuzz suites | preserved (rename only) |
| `IsExempt` raw-string keying — deliberately **not** canonicalized, since canonicalizing would make an IPv4-mapped probe hit a plain-v4 exemption and hand out a rate-limit bypass | `TestRLExemptView_MappedProbeStaysNonExempt` retained | preserved |
| CHAOS-61 freshness: `Armed` needs **both** halves (`ClusterEnabled() && Enabled()`); negative age is **stale**; un-armed is **never** stale | body diff of `ClusterFreshness` | all three preserved |
| CHAOS-61 gate inventory | name-set comparison | **17/17 retained**, 1 added |
| Gossip wire format (`json:"ip"`, `"count"`, `"node_id"`, `"deltas"`, `"remote_counts"`) and `nil`→JSON `null` | `cluster_ratelimit_wire.go` vs the removed DTOs | **identical**; mixed-version fleet compatibility intact |
| Cluster globals → instance state (`clusterRateLimitEnabled`, `clusterCounts`) | all 5 production call sites traced | migrated 1:1; both the gossip loop and `ui_cluster.go` bind the **same `rl` singleton** the request path consults, so no split-brain / silent fail-open |
| Republish contract ("a mutator without `publishView()` is a silent security failure") | moved **with** the engine; hook is now per-instance; proof is a **runtime** stack-walk attribution, so it cannot go vacuous from a file move | preserved and slightly stronger |
| Exempt mutator-inventory completeness wall | reflection over the live `*RateLimiter`, scoped by the `Exempt` name token — the six new cluster methods touch `clusterEnabled`/`remoteCounts`, never the exempt set, so no republish obligation is skipped | correct, not weakened |
| Snapshot apply (`applySnapshotAdmission`) incl. `RateLimitExempt != nil` empty-slice wipe semantics | diff + `config_surfaces_test.go` registry updated | preserved |
| Shutdown CHAOS-56 invariants: shared phase **horizon** (`phaseEnd + grace`), recursive reserve (`behind × minSlice`), min-slice floor, abandonment logged at the point of abandonment | normalized diff | preserved; `PartitionAt` uses `New(r.options)` so a partitioned registry keeps its diagnostic sink and abandonment lines are not lost |
| Test coverage | repo-wide `Test`/`Fuzz`/`Benchmark` name-set diff | **0 removed**, 29 added |
| SAST reach | `codeql.yml` | engine covered via the pre-existing `internal/**` path; root shims added explicitly |
| Coverage contract | `coverage-floor.sh` + `qa_gate_coverage_test.go` | `internal/admission/{engine,freshness}.go` added at **70%**, matching `security.go`'s retained floor |
| Allocation gates | `pr-fast-gate.yml`, `qa-gate.yml`, `proxy-weekly-stress.yml` | all three extended to `./internal/admission` — without this the relocated `TestBenchGate_*` would have silently stopped running |
| Engine isolation (ADR-0039) | `boundary_test.go`: stdlib-only import allowlist, no `init()`, no package state, not-vacuous check + regression control | enforced structurally |
| Dependency locks (#1525) | 4 entries | forward-only bumps, **dev-only**, canonical registry, integrity hashes intact; no runtime exposure change (`frontend/dist` unaffected) |
| CI workflow edits | reviewed for `continue-on-error`, dropped `needs`, softened conditions | **none**; annotation steps are `if: failure()` only, and `set -o pipefail` was added so `… | tee` still propagates failure |

Two incidental improvements worth recording: the extraction **deleted** `resetForTest` /
`applyAtForTest` from production files (instance-owned state removed the need for an exported
reset path), and `main.go` now builds the shutdown registries via `newShutdownRegistry()`
rather than a zero value — a zero-value registry would have carried a `nil` `Logf` and
silently dropped the hook-abandonment log line.

---

## 5. Files

- `diagnostics.go` — `adminUsernameLengthCode`, `diagnosticsRedactedUsernameMessage`,
  `redactContractForRole`; `apiDiagnostics` wired.
- `diagnostics_username_role_test.go` — new gates (below).
- `diagnostics_test.go` — the five roster-detail tests re-pointed from `viewerCtx` to
  `adminCtx`, each annotated with why.

## 6. Required tests (implemented)

| Test | Class |
|---|---|
| `TestApiDiagnostics_UsernameRowDetailIsAdminOnly` | authorization / positive + negative — admin keeps the remediation; viewer **and operator** get neither it nor any disclosure phrase. Carries a **not-vacuous** assertion that the admin rendering really contains every phrase the negative half forbids. |
| `TestApiDiagnostics_UsernameRowStaysVisibleToViewer` | **control** — the cheapest wrong fix (dropping the row) must fail: code, `warn` status and the rolled-up verdict must survive. |
| `TestApiDiagnostics_OkUsernameRowIsNotRedacted` | boundary — a healthy row is untouched at every role. |
| `TestRedactContractForRole_FailsClosedForEveryNonAdminRole` | boundary / malformed input — every enrolled role plus `RolePublic`, `""`, `"none"`, `"Admin"`, `"superuser"`. |
| `TestRedactContractForRole_DoesNotMutateInput` | aliasing — a redacted render must not alter its input, and a following admin render must still be complete. |
| `TestApiDiagnostics_ConcurrentMixedRoleReadsDoNotLeak` | concurrency (`-race`) — parallel admin and viewer readers; no viewer row may ever carry the detail. |
| `TestApiDiagnostics_MalformedRoleValueIsRedacted` | malformed input — whitespace/case/control-byte/oversize/JSON-ish role values may 403, but must never answer 200 with the detail. |
| `TestWall_RosterDerivedDiagnosticsAreEnumerated` | **governance wall**, enumerated from the **primitive** (`ListUIUsers` / `UserHasTOTP` / `GetUser`) rather than from the row that happened to be edited — a *new* roster-reading check fails the build until it is redacted or granted a stated exception. `hasCredentialCapableProvider` is the one recorded exception (boolean existence probe only). Carries its own not-vacuous check. |

**Mutation testing** — every gate was verified failing against the shape it targets:

| Mutation | Gate that caught it |
|---|---|
| pre-fix handler (no redaction) | `UsernameRowDetailIsAdminOnly`, `ConcurrentMixedRoleReadsDoNotLeak` |
| threshold widened to `RoleViewer` | `UsernameRowDetailIsAdminOnly` |
| in-place mutation (no slice copy) | `RedactContractForRole_DoesNotMutateInput` |
| row hidden instead of redacted | `UsernameRowStaysVisibleToViewer` |
| `ok` row also redacted | `OkUsernameRowIsNotRedacted` |
| a new roster-reading check added | `Wall_RosterDerivedDiagnosticsAreEnumerated` |

Validation run: `go build ./...`, `go vet`, the full root suite (**green**),
`go test -race ./internal/admission ./internal/shutdown` (**green**), `-race` on the new gates,
and a shuffled full-module run. The repo's own `TestTestFileReadsAreCWDIndependent` wall caught
a CWD-relative source read in the first draft of the governance wall; it is now anchored to
`pkgSourceDir()`.

---

## 7. Residual risk

1. **The row still tells a viewer that *a* condition exists** (code + `warn` status). That is
   deliberate — withholding it would hide a live management-plane problem from monitoring — and
   it carries no roster-derived value.
2. **The exempt mutator-inventory wall is name-token scoped** (`containsExemptToken`): a future
   mutator of the exemption set *not* named `*Exempt*` would escape the republish wall. This is
   pre-existing design, unchanged by this window, and recorded here rather than altered inside a
   review about something else.
3. **`redactContractForRole` is row-scoped, not capability-scoped.** It redacts by `Code`. The
   new governance wall is what keeps that honest: it forces any *future* roster-derived row to be
   classified. A row derived from some *other* admin-only store would not be covered by the
   wall's current primitive list.
4. **Oversize admin usernames remain creatable** via `-user` / `auth.user` /
   `--reset-password`, which do not bound the name (CHAOS-63 keeps the boot warning non-fatal
   deliberately: failing the boot would brick an appliance whose config was legal when written).
   Unchanged here.
5. The fix does not change any allow/deny decision, the proxy data path, or the admission
   engine. It is confined to the rendering of one management-plane diagnostic row.
6. **F-2 (NAT64 local-use prefix) is open.** It is pre-existing, outside the reviewed window, and
   deliberately not patched here because the correct fix changes which destinations the proxy will
   reach in both directions. Until it is taken, a deployment whose egress path runs a NAT64
   translator on an RFC 8215 local-use prefix has an SSRF route past `internal/ssrf`.
7. **The frontend vulnerability gate is effectively dormant** (no `schedule:` trigger; PR runs only
   when the classifier flags the frontend surface, main runs only on `frontend/**` pushes). A
   weekly scheduled run is recommended. Until then the 11 HIGH dev-tree advisories found here can
   recur unnoticed.
