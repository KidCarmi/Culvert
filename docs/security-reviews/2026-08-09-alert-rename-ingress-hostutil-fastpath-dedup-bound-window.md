# Security Regression Review — alert event-name rename, `StripHostPort` fast path, CHAOS-27 alert-plane bounding, CodeQL gate realignment (window `d2c5a51` → `1c24311`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-09
> **Baseline:** `d2c5a51` — head of the previous review's window
> (`docs/security-reviews/2026-08-07-chaos47-identity-backend-mcp-tenant-isolation-window.md`)
> **Head:** `1c24311` (`main`)
> **Scope reviewed:** every code-bearing change in the window — 8 first-parent
> merges (PRs #1073–#1081), 45 files, +5,312 / −274.
>
> **Method.** Prioritised by *live blast radius*, not diff size:
>
> 1. **Enabled-by-default authentication code that changed** — the LDAP
>    user-bind classifier and the OIDC 4xx branch, both of which now decide
>    whether a per-request failure is allowed to arm the process-wide CHAOS-47
>    identity-backend cooldown. This is the same code the previous window's two
>    HIGH findings were in, so it was re-reviewed adversarially rather than
>    diffed.
> 2. **Enabled-by-default request-path primitives that changed** —
>    `hostutil.StripHostPort`, which every proxied request runs several times
>    across the threat feed, DPI scanner, scan-exclusion matcher, autoexclude
>    cache and traffic redactor. A behavioural difference here is a policy
>    matching difference.
> 3. **Security-alerting plane** — the CHAOS-27 dedup bound and shared delivery
>    client, and the `idp_unreachable` → `identity_backend_unreachable` rename,
>    reviewed for *detection loss* (the failure mode an operator cannot see)
>    rather than for enforcement.
> 4. **CI/SAST gate** — the CodeQL action pin realignment, because a gate that
>    fails as a configuration error is indistinguishable from a gate that passed.
> 5. **Privileged/operator surface** — the `cli` compose service gaining
>    `CULVERT_CA_PASSPHRASE`.
>
> `internal/mcpacceptance` (≈2,000 new lines this window) and
> `cmd/mcp-observe-acceptance` were re-confirmed **not reachable from the
> production binary** — nothing outside those two trees imports them, and the
> `Dockerfile` builds only `.` and `cmd/culvert-maint` — so they were reviewed
> as test tooling, not runtime attack surface.

---

## Executive Summary

**One finding, fixed in this change:**

- **SR-2026-08-09-01 (LOW/MEDIUM, detection)** — the `idp_unreachable` →
  `identity_backend_unreachable` alert rename (PRs #1078/#1080) migrated
  subscriptions at **one** of the alert store's **three** ingresses. A config
  export taken before the rename and restored after it — the exact artifact a
  disaster-recovery restore or an upgrade rehearsal replays — came back
  **permanently unsubscribed** from the alert that fires when proxy
  authentication is failing closed fleet-wide. The webhook stays visible in the
  admin UI; it simply never fires again.

Everything else in the window is either neutral or a net security improvement.
There is **no authentication bypass, no authorization bypass, no default-allow,
no policy-precedence change, no missing signature validation, no weakened
certificate validation, no new SSRF or open-redirect primitive, no injection
primitive, and no secret exposure.**

Two changes deserve explicit *clearance* rather than silence, because both look
like the kind of optimisation that usually costs security and in this case does
not:

- **`StripHostPort`'s new fast path is exactly equivalent**, not approximately
  so — proven below by construction and pinned by a differential fuzz target
  against the pre-change body.
- **The CHAOS-27 dedup cap fails toward MORE alert deliveries, never fewer** —
  the correct direction for a security control, and the only direction that is
  acceptable for one.

---

## Security Findings

### SR-2026-08-09-01 — the alert event rename migrated one ingress out of three, so a restored pre-rename config silently loses identity-backend alerting

| | |
|---|---|
| **Severity** | **LOW** (MEDIUM for a deployment whose incident response depends on webhook alerting) |
| **CWE** | CWE-778 (Insufficient Logging & Monitoring), with CWE-440 (Expected Behavior Violation) as the mechanism |
| **OWASP** | A09:2021 — Security Logging and Monitoring Failures |
| **Regression risk** | **Introduced in this window** (PRs #1078 / #1080, commits `5982f44` + `92c3352`). Not present before the rename. |
| **Status** | **FIXED in this change** |

#### What changed

The 2026-08-07 terminology review (T-40) renamed the CHAOS-47 alert event
`idp_unreachable` → `identity_backend_unreachable`, because "IdP" is reserved in
Culvert's vocabulary for the *federated Identity Provider registry*
(`auth_idp.go`), a different and uncached subsystem. The rename itself is
correct and is a readability improvement.

Because `HasSubscriber` compares event names **exactly**, the rename would have
orphaned every existing subscription, so `92c3352` added a migration table and
applied it in `Store.Init` — the disk-load path:

```go
var legacyEventNames = map[string]string{"idp_unreachable": "identity_backend_unreachable"}
// ... in Init, after json.Unmarshal:
for i := range as.hooks {
    for j, ev := range as.hooks[i].Events {
        if renamed, ok := legacyEventNames[ev]; ok { as.hooks[i].Events[j] = renamed }
    }
}
```

That covers a straightforward in-place upgrade. It does not cover the other two
ingresses, which write to the same store without passing through `Init`:

| Ingress | Reaches the store via | Migrated before this change |
|---|---|---|
| `alert_webhooks.json` on boot | `Store.Init` | ✅ |
| `POST /api/config/import` | `Store.Add` (`ui_config.go:1160-1170`) | ❌ |
| `POST` / `PUT /api/alerts/webhooks` | `Store.Add` / `Store.Update` | ❌ |

#### Attack scenario

This is an **operational** failure mode rather than an attacker-driven one, and
it is scored accordingly — but its consequence is an attacker-relevant blind
spot, so it is treated as a security regression, not a compatibility bug.

1. An operator running a pre-rename build configures a webhook to their SIEM
   subscribed to `idp_unreachable`, and takes a config export
   (`GET /api/config/export`) as their documented backup artifact.
2. The fleet upgrades past `92c3352`. In-place, the subscription migrates
   correctly on boot.
3. Later — a node rebuild, a DR restore, a staging refresh, a config rollback
   rehearsal — that stored export is replayed through
   `POST /api/config/import`. `apiConfigImport` reconstructs each webhook with
   `globalAlertStore.Add(wh)`, writing `idp_unreachable` straight back into the
   live store.
4. From that moment the deployment has **no subscriber** for
   `identity_backend_unreachable`. In `replace` mode it is worse: the import
   deletes the live (correctly migrated) webhooks first, so the deployment is
   left with *zero* identity-backend alerting.
5. The directory or IdP later becomes unreachable. Proxy authentication fails
   closed fleet-wide — the enforcement posture is correct — and **no alert is
   delivered**. The operator's webhook row is still listed in the admin UI with
   the box rendered unchecked (the UI's checkbox value is now the new name), so
   the surface reads as "configured".

**Preconditions:** a webhook subscribed to the retired name before the rename,
plus one config import of a pre-rename export. No attacker access required.

**Exploitability:** not directly attacker-triggerable. An attacker who is
already causing an identity-backend outage (see the previous window's
SR-…-01/01b, both fixed) *benefits* from it: the outage they cause becomes
silent.

**Likelihood:** moderate. Export/import is the documented backup path and is on
the config-surface registry; a restore is a routine operation.

**Impact:** loss of detection for a fleet-wide authentication outage. **No loss
of enforcement** — the gateway still fails closed on every request. Integrity
and confidentiality are unaffected.

**Affected assets:** the alerting/monitoring plane
(`internal/alerts.Store`), and by extension incident-response time for any
identity-backend outage.

#### Why the wildcard does not save it

`HasSubscriber` also matches `"*"`, so a deployment with a catch-all webhook is
unaffected. That narrows the blast radius but does not close it: a catch-all
webhook is exactly what a security-conscious operator avoids, because it floods
the receiver with unrelated events. The operators most likely to hit this are
the ones who subscribed *precisely*.

#### Fix

Move the migration from `Init` to a single normalization chokepoint applied at
**every** ingress:

```go
func normalizeEventNames(events []string) []string  // internal/alerts/store.go
```

applied in `Init` (unchanged behaviour), `Add`, and `Update`.

**Why this is the safe implementation:**

- **The mapping is one-way and closed.** It can only carry a subscription
  forward to the *same event* under its current name. It never adds an event
  the caller did not ask for and never removes one, so it cannot widen or
  narrow what a webhook receives. Pinned by
  `TestNormalizeEventNames_DoesNotSubscribeAnUnrelatedEvent` and
  `TestConfigImport_PreRenameWebhookDoesNotWidenSubscription`.
- **It is idempotent and order-preserving.** `Init` runs on every boot and
  `Update` on every edit, so a non-idempotent mapping would compound.
- **It does not alias the caller's slice.** `Add`/`Update` take a `Webhook` by
  value, but the `Events` slice *header* is copied — writing through it would
  mutate the decoded config backup in the import path. `normalizeEventNames`
  returns fresh storage.
- **It preserves the enabled/disabled boundary.** A disabled hook does not
  become a subscriber through migration.
- **Duplicates the migration itself creates are collapsed**, order-preserving,
  so a hook listing both aliases shows one checkbox rather than two names for
  one event. `Dispatch` already stops at the first match, so no delivery
  behaviour changes — only what the operator sees.
- **Persistence is unchanged**: like the legacy-cleartext-secret migration one
  function below it, normalization does not force a resave; the next legitimate
  mutation persists the current name.

A catalog invariant (`TestLegacyEventNames_MapForward`) additionally forbids a
row that maps to itself (a no-op that reads as coverage) or to another retired
name (`normalizeEventNames` is single-pass, so a chained rename would strand the
subscription on an intermediate name nothing dispatches).

#### Files

- `internal/alerts/store.go` — `normalizeEventNames`; applied in `Init`, `Add`, `Update`.
- `internal/alerts/store_eventname_migration_test.go` *(new)* — store-level invariants.
- `alerts_event_rename_import_test.go` *(new)* — end-to-end proof through `apiConfigImport`.

#### Required tests — all present

| Class | Test |
|---|---|
| Positive (each ingress) | `TestNormalizeEventNames_MigratesAt{Add,Update,Init}Ingress` |
| Regression (the actual defect) | `TestConfigImport_PreRenameAlertWebhookKeepsSubscription`, `TestConfigImport_ReplaceModePreRenameWebhookKeepsSubscription` |
| Negative (must not widen) | `TestNormalizeEventNames_DoesNotSubscribeAnUnrelatedEvent`, `TestConfigImport_PreRenameWebhookDoesNotWidenSubscription`, `TestNormalizeEventNames_LeavesCurrentNamesUntouched`, `TestConfigImport_CurrentAlertWebhookIsUnchanged` |
| Authorization/state boundary | `TestNormalizeEventNames_DisabledHookStaysDisabled`, `TestNormalizeEventNames_WildcardIsNotRewritten` |
| Boundary / malformed input | `TestNormalizeEventNames_Boundaries` (nil, empty, empty string, case-variant, substring, leading whitespace, both aliases, reverse order, pre-existing duplicates) |
| Idempotence / aliasing | `TestNormalizeEventNames_Idempotent`, `TestNormalizeEventNames_DoesNotAliasCallerSlice` |
| Concurrency | `TestNormalizeEventNames_ConcurrentIngress` (three ingresses against one store, `-race`) |
| Anti-drift | `TestLegacyEventNames_MapForward` |

Each regression test was verified to **fail** against the pre-fix tree and pass
against the fixed one.

---

## Regression Analysis — everything else in the window

### 1. `hostutil.StripHostPort` fast path (`edde479`, `135b907`) — **CLEARED**

`StripHostPort` runs several times per proxied request. The change adds an
already-portless fast path that returns the input verbatim, skipping
`net.SplitHostPort` (which allocated an `*net.AddrError` for every portless
host and discarded it on the next line).

A silent behavioural difference here would be a **policy-matching** difference —
the threat feed, DPI scanner, scan-exclusion matcher and autoexclude cache all
key on the result — so the equivalence was verified by construction, not by
inspection:

The body is `SplitHostPort` (reassigns only on success) then
`strings.Trim(host, "[]")`. The fast path fires when `hasHostPortSyntax(host)`
is false, i.e. `host == ""`, or the string contains no `':'` **and** neither its
first nor its last byte is a bracket.

- Without a `':'`, `net.SplitHostPort` cannot succeed (it locates the port by
  the last colon and otherwise returns `missing port in address`), so `host` is
  never reassigned. For `""`, it errors likewise.
- `strings.Trim` cuts only from the **ends**, so with neither end a bracket it
  is the identity. Brackets are ASCII, so the byte comparison is correct for
  arbitrary UTF-8 input.

Both statements are therefore no-ops on exactly the set the fast path skips.
The repo pins this the right way — `FuzzStripHostPort` is a **differential**
fuzz target against a preserved copy of the pre-change body
(`referenceStripHostPort`), plus a direct proof
(`TestStripHostPort_FastPathOnlySkipsNoOps`) and a concurrency stress run. No
finding.

### 2. LDAP user-bind classifier (`ae59e26`) and OIDC 4xx cooldown clear (`38ce79e`) — **CLEARED**

These are the previous window's HIGH fixes, re-reviewed adversarially rather
than accepted.

**`ldapUserBindIsUnreachable` boundary check.** The classifier treats result
codes `[ldap.ErrorNetwork(200), ldap.ErrorEmptyPassword(206)]` plus
`LDAPResultBusy(51)` / `LDAPResultUnavailable(52)` as "backend unreachable"
(gates), and everything else as "the directory answered" (does not gate). Against
`go-ldap/ldap/v3@v3.4.14` this range is exact: `200..206` is the complete
client-space (`ErrorNetwork`, `ErrorFilterCompile`, `ErrorFilterDecompile`,
`ErrorDebugging`, `ErrorUnexpectedMessage`, `ErrorUnexpectedResponse`,
`ErrorEmptyPassword`), and every transport fault reachable from `conn.Bind` —
closed connection, closed response channel, read timeout, TLS handshake failure
— is raised as `ErrorNetwork`, inside the range.

**The one code in that range an attacker could aim for is `ErrorEmptyPassword`
(206),** which `go-ldap` raises *client-side, without contacting the directory*.
If reachable, an unauthenticated client supplying a known username with an empty
password would arm the provider-wide cooldown on every attempt — a fresh
instance of the exact SR-…-01 class. **It is not reachable:** `LDAPAuth.Verify`
short-circuits `password == ""` before `verify()` is ever called
(`auth_ldap.go:176-178`), and the step-1 service bind uses the operator's
configured credential, not an attacker's. Confirmed, no finding — but this is
the sharp edge of the classifier and is recorded here so a future change that
relaxes the empty-password guard is understood to reopen it.

**`recordReachable` on a non-gating answer cannot be abused to clear a genuine
cooldown.** On both legs, reaching the clearing branch *requires* evidence of a
reach: the LDAP branch is only reachable after a successful dial, service bind
and search, and the OIDC branch requires the endpoint to have returned an HTTP
status. During a genuine outage neither is obtainable. And clearing the gate can
only cause **more** round trips, never more access — every path still returns
deny.

**CWE-117.** The server-controlled diagnostic on the new
`errLDAPAccountRejected` branch goes through `sanitizeLog` with `%q`, and
`noteAuthBackendUnavailable` applies the barrier once at ingress before the
value enters shared state. The viewer-role operator-contract row still carries
only the backend name and counts, never the cause. No leak.

### 3. CHAOS-27 alert-plane bounding (`53367bc`) — **CLEARED**, with one accepted residual

Three sub-changes:

**(a) Dedup map hard cap (4096) + amortised expiry scan.** The dedup key embeds
`payload.Detail`, which on the request path carries the attacker-chosen host, so
the key space is attacker-controlled — the same reason `topHosts` is capped. The
security-relevant question is the *direction* of the failure: eviction removes a
**suppression** key, so the next identical alert is **delivered** rather than
suppressed. It fails toward more deliveries, never fewer. That is the only
acceptable direction for a security control, and it is what the code does.
Bounds are verified: `evictOverCapLocked` skips the just-inserted key and cannot
under-delete (`over = len − cap`, and non-`keep` entries number `len − 1 ≥ over`
for any `cap ≥ 1`).

**(b) Delivery fan-out remains bounded.** Degraded suppression means more
deliveries, so the bound matters. `Dispatch` acquires `webhookSem` (10) with a
**non-blocking** `select` and spills to the 500-entry retry queue, which drops
at capacity. Goroutines are therefore bounded at 10 regardless of alert rate —
no unbounded spawn, no amplification vector against the operator's SIEM beyond
the pre-existing rate.

**(c) Shared pooled `deliveryClient` replacing a per-attempt `http.Client`.**
The SSRF guard is **not** weakened: `ssrf.SafeDialContext` runs on every dial,
and Go's `http.Transport` keys idle connections by `(scheme, host:port)`, so a
pooled connection can only be reused for the authority it was validated for.
Go's bundled HTTP/2 client does **not** perform cross-hostname connection
coalescing, so the newly added `ForceAttemptHTTP2: true` does not introduce one
either. Redirect targets are dialed fresh and therefore re-validated.

*Accepted residual:* `IdleConnTimeout: 90s` means a webhook host that passed the
SSRF check and is subsequently re-pointed keeps receiving over the already-open
connection for up to 90s. The connection is to the previously-validated address,
so this cannot reach a private-network destination — the exposure is bounded to
continued delivery to a stale, already-authorised, admin-configured endpoint. It
matches the posture of the existing pooled feed and OTLP clients
(`internal/blocklistfeed`, `internal/otlp`) and is documented at the call site.

### 4. CodeQL action pin realignment (`26182cb`) — **NET IMPROVEMENT**

This closes the previous window's SR-…-02. `github/codeql-action` is a monorepo
whose `init`/`analyze`/`upload-sarif` are not independently compatible; a split
pin makes the job fail as a *configuration error* — red, but with **zero queries
executed**, so the gate looks like it ran. Dependabot treats each sub-action path
as its own ecosystem, which is how the split happened twice. All three are now
on `f205ea1c…`, and `codeql_action_pin_test.go` pins them equal on the immutable
SHA (not the stale `# v3` comment). Verified: the workflow contains exactly three
`codeql-action` uses, all on one SHA.

### 5. `cli` compose service gains `CULVERT_CA_PASSPHRASE` (`5a33a39`) — **ACCEPTED**

Restore validation — dry-run and commit alike — hard-fails without the
passphrase when the backup's `ca.bundle` is encrypted, which it always is for an
SSL-inspecting deployment. The `cli` service already runs the same image as
`proxy` and already mounts `/data` (which holds `ca.bundle`), so the passphrase
grants no capability the container did not structurally have; what is new is
that one ephemeral `run --rm` container now holds both `/backup` and the
decryption passphrase. That combination is inherent to the operation being
performed and is the documented D1.5 operator path. `${CULVERT_CA_PASSPHRASE:-}`
degrades to empty when unset, so non-inspecting deployments are unaffected. The
D1.5 invariants that actually carry the trust boundary are intact: `/backup` is
still mounted **only** in `cli`, and `cli` still does not mount the Docker
socket.

### 6. `internal/mcpacceptance` / `cmd/mcp-observe-acceptance` (PRs #1079, #1081) — **OUT OF RUNTIME SCOPE**

≈2,000 lines of acceptance harness. Re-confirmed unreachable from the production
binary: no file outside those two trees imports them, and the `Dockerfile` builds
only `.` (the proxy) and `cmd/culvert-maint`. Every `#nosec`/`filepath.Join`/
`exec.Command` hit in this window's diff lands in that tree or in `_test.go`
files. The harness's own TLS client uses an explicit trust root with no
`InsecureSkipVerify`.

### 7. Observability additions (`events.go`, `ui_security.go`, `static/index.html`, OpenAPI) — **CLEARED**

`dedup_tracked` / `dedup_evictions_total` are counters with no sensitive
content, added to an existing viewer-role endpoint and the Prometheus exposition
alongside the existing alert-plane counters. No new route, so no `uiRoutes` /
C1 / C2 metadata surface changed and no RBAC drift is possible. The
`static/index.html` change updates the webhook checkbox value to the new event
name — consistent with the migration, and the reason the restored-hook checkbox
would have rendered unchecked under SR-2026-08-09-01.

---

## Risk Rating

| ID | Finding | Severity | Exploitability | Likelihood | Impact | Status |
|---|---|---|---|---|---|---|
| SR-2026-08-09-01 | Alert event rename migrated one ingress of three | LOW (MEDIUM in alert-dependent deployments) | Not directly attacker-triggerable | Moderate | Detection loss for a fleet-wide auth outage; no enforcement loss | **Fixed** |

No HIGH or CRITICAL findings in this window.

---

## Residual Risk

1. **Pre-rename webhooks already restored on a running node** are not
   retroactively repaired by this change until the store is re-read or the hook
   is edited. The `Init` migration repairs them on the next restart, and any
   subsequent `Add`/`Update` repairs them immediately. Operators who imported a
   pre-rename config between `92c3352` and this change should confirm the
   Identity-backend checkbox in the Alerts panel, or restart the node.
2. **Pooled webhook-delivery idle window (90s)** — accepted above; delivery to a
   previously-validated, admin-configured endpoint may continue briefly after the
   destination is re-pointed. Cannot reach a private-network address.
3. **Webhook delivery follows redirects**, so an admin-configured endpoint can
   redirect the alert payload and its HMAC signature to another *public* host.
   Pre-existing (the per-attempt client behaved identically); SSRF dial guard
   still applies to every redirect hop. Not a regression in this window; recorded
   for a future hardening pass.
4. **`dedupEvicted` is a package-level counter** while `DedupTracked` is
   per-store. Production has a single store so the exported metric is correct;
   the asymmetry is only a test-isolation nit (`ResetDedupForTest` does not clear
   it). No security consequence.
5. **`ldapUserBindIsUnreachable` depends on `go-ldap`'s 200–206 client-error
   space** staying the complete client-side range. A dependency bump that adds a
   client-space code outside it would mis-classify a transport fault as an
   authoritative answer (detection loss, not a bypass — the request still fails
   closed). Worth a pin if the classifier is extended.

---

## What Was Reviewed and Found Safe (explicit)

For the avoidance of doubt, the following were examined in this window and found
**not** to regress security posture:

- Authentication: LDAP two-step bind ordering, code-49 handling, empty-password
  short-circuit, OIDC RFC 7662 active/inactive split, negative-caching rules.
- Authorization: no `uiRoutes` entry, `MinRole`, `requireRole` call, or
  middleware-chain ordering changed; C1/C1.5/C2/C2c/C4 surfaces untouched.
- Policy: no rule-evaluation, precedence, default-deny, or category/GeoIP
  matching change. `StripHostPort` proven equivalent.
- TLS / crypto: no cipher, version, verification, or signature-validation change;
  no new `InsecureSkipVerify` in shipped code.
- Proxy request/response processing: unchanged apart from the proven-equivalent
  host strip. No header, hop-by-hop, smuggling, or desync surface touched.
- Persistence & secrets: no new file write path; RISK-003 webhook-secret
  encryption untouched; no secret added to a viewer-role response or a log line.
- Sessions / CSRF / XSS: untouched. The one `static/index.html` change is a
  literal attribute value.
- SSRF / open redirect: guard preserved across the delivery-client refactor;
  no new outbound-fetch primitive.
- Audit: no audit-emitting handler added or removed.

**Verification run for this change:** `go build ./...`, `go vet`, `gofmt -l`
clean; `go test -race -count=1 ./internal/alerts/...` and
`go test -race -count=1 -run 'Alert|Webhook|ConfigImport|ConfigExport|ConfigSurface' .`
green; every new regression test confirmed failing against the pre-fix tree.
