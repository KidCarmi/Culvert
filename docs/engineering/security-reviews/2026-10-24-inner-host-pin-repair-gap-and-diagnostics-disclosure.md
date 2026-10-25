# Security review — the inner-host pin's repair gap, a viewer-readable admin allowlist posture, and a fail-closed guarantee the README still denied

**Date:** 2026-10-24
**Reviewer role:** Security Regression Engineer (scheduled run)
**Base reviewed:** `266e684` (the revision the 2026-10-19 review closed on)
**Head reviewed:** `a27cffb` (`origin/main` at the time of the run)

**Window size.** 79 pull requests merged into `main` between those two
revisions — 102 non-test Go files, ~5 690 insertions / ~579 deletions,
plus workflow, installer, frontend and documentation changes. This run
reviewed the whole non-test Go diff across seven slices (six delegated with
bounded file lists and explicit regression classes, one taken directly), and
verified every reported finding against primary evidence before acting on it.

**Three findings, all introduced or left behind by this window.** One is an
authorization bypass on the inspected-tunnel path, in the gate added to close
that very bypass. One is an information disclosure in a Diagnostics row added
this window. One is operator documentation that still asserts the *opposite* of
a fail-closed guarantee the same window shipped. All three are fixed here, each
with a negative control that fails without the fix.

---

## 1. Executive summary

| # | Finding | Severity | Introduced by | Status |
|---|---|---|---|---|
| F1 | Inspected-tunnel inner-host pin accepts an authority net/http will **not** send, so the upstream receives an empty or differently-named authority | **High** | #1632 (SEC-TUNHOST-1), this window | Fixed |
| F2 | New `access_cidr_lists` Diagnostics row serves the admin-only UI allowlist posture to RoleViewer | **Medium** | #1596, this window | Fixed |
| F3 | `README.md` still documents CDR's unavailable path as "passes through in either mode", which #1668 made false | **Low** (documentation of a security posture) | #1668, this window | Fixed |

**What the window did well, stated plainly, because it is most of the diff.**
This window is dominated by *correct* fail-closed hardening, and the review
confirmed each piece rather than assuming it:

- **#1609 (SEC-UISESS-1)** collapsed two divergent copies of the admin-session
  admission decision into `resolveUISession`, and closed a real
  privilege-reporting gap: `/api/auth/status` is on the public allowlist, so the
  middleware never ran for it, and it reported a proxy-plane `ps_session`
  replayed under the admin cookie name as `role: admin`. The three-state verdict
  (absent / refused / valid) is the right shape, and `session.Decode` returns
  `nil` on every failure path, so the `sess != nil` premise the sibling
  SEC-REVOKE-1 logout fix rests on actually holds (verified in
  `internal/session`).
- **#1651** closed two policy fail-opens: an unrecognized `Action` fell out of
  `applyPolicyDecision`'s switch and was **allowed** while shadowing every
  lower-priority deny rule under first-match-wins (SEC-POLICYACTION-1), and a
  policy file whose every rule the load gate refused counted as "no policy
  configured" and selected passthrough Allow (SEC-POLICYDROP-1). It also moved
  the HA `deploy_cmd` — which embeds the live join token, the sole credential
  for the HASync RPC that returns the cluster CA private key — behind an
  admin-role check. `uiRole` defaults to `RoleViewer`, and the Basic-auth branch
  sets the role context, so that gate is fail-closed without locking out CLI
  admins.
- **#1668** closed the CDR fail-closed bypass on the *unavailable* path and, in
  `initCDRClient`, stopped a boot during a Sluice outage from leaving
  `cdrActiveCfg` at its zero value (`Enabled: false`) — which had made a
  fail-closed appliance read itself as disabled. Verified that every CDR data-
  path entry (`safeCDRSanitize`, `runCDRStage`, `cdrPickPooledReserved`,
  `cdrAnyInstanceAvailable`) now routes through `cdrUnavailableOutcome`.
- **#1537** *tightened* the scanner gates rather than loosening them: the
  repository-wide `G704` exclusion is gone, `G703`/`G704` are enforced in the
  maintenance module, `.trivyignore` entries now require owner/claim/scope/
  evidence metadata with a validated expiry, and the expired `CVE-2026-14456`
  suppression was removed rather than renewed. It also set `Proxy = nil` on the
  OIDC transports, so the dial-time SSRF guard inspects the IdP's resolved
  address instead of an egress proxy's.
- **#1676 / #1533** replaced a genuine data race (an unsynchronized read of
  `g.catSet` on the policy hot path) with copy-on-write ownership. Confirmed
  that **all ten** category-group writers publish through `bumpRevLocked`, that
  `ReplaceAll`/`restoreSnapshot` copy rather than alias the caller's backing
  array, and that every `ReplaceAll` caller persists from the store (so the
  dropped in-place ID backfill loses nothing).
- **#1642 / #1624** bound the host-normalization memo's memory and compare the
  **full key**, not a hash — so there is no collision-poisoning path from a
  crafted host to another host's normalization.

Three independent slices (proxy plane, fileutil/roster, support/telemetry,
admission/connlimit, MCP) reported no regressions of their own beyond F1; their
sub-threshold observations are recorded in §7.

---

## 2. F1 — the inner-host pin compares a repaired authority while the wire carries the unrepaired one

**Severity: High.** Authorization bypass on the TLS-inspected tunnel path.
**CWE-444** (inconsistent interpretation of HTTP requests) → **CWE-863**
(incorrect authorization). OWASP **A01:2021 Broken Access Control**.
**Regression risk of the fix: low** — it narrows an accepted set, adds no new
module dependency, and every pre-existing accepted spelling still pins.

### Affected contract

A CONNECT tunnel is authorized **once**, against the authority in the CONNECT
line. Policy evaluated that host, the forged leaf was issued for it, the
upstream `ServerName` is it, and every log row, scan verdict and CDR decision is
attributed to it. `innerHostPinnedToTunnel` (`inspect_host_pin.go`, added by
#1632) exists so that the inner request's `Host` / `:authority` cannot name a
*different* destination on an already-authorized tunnel.

The gate's own documentation states the invariant it must hold, and names the
exact failure mode: an **empty** inner host is refused because
`Request.Write` serializes a literal `Host: ` and "a shared front end with a
default or fallback virtual host answers such a request from that vhost — a
destination policy never evaluated, with the scan verdicts and the log row still
attributed to the CONNECT host."

### The defect

`#1632`'s own review caught one instance of the underlying class — "the pin
compares a REPAIRED value while the origin receives an UNREPAIRED one" — and
fixed it for square brackets (`innerAuthorityBracketsValid`). **Two further
repairs do the same thing, and were not covered:**

1. **The port is never validated.** `hostutil.StripHostPort` ends in
   `net.SplitHostPort`, which splits on the *last* colon and accepts any bytes
   after it. So `allowed.example.com:0/x` reduces to the authorized host and
   **pins**. `Request.write` then applies `httpguts.ValidHostHeader` to the same
   value, finds the `/`, and — because `Request.Write` passes
   `usingProxy=false` — **zeroes the authority entirely** and emits `Host: `
   (`net/http/request.go`, go1.27; go.dev/issue/61431 replaced the older
   truncate-at-`/` behaviour with this zeroing). That is byte-for-byte the state
   the empty-inner-host branch refuses, reached **through** the comparison
   instead of around it.

2. **IDNA case is not preserved through punycode.**
   `hostutil.NormalizeHostStrict` lowercases *before* `idna.ToASCII`, while
   `httpguts.PunycodeHostPort` does not, and punycode encodes case in its
   payload. The gate's comment asserted a U-label inner host was safe because
   the wire carries the same A-label; that holds only for an already-lowercase
   one.

### Measured evidence

Driven through the repo's own `innerHostPinnedToTunnel` and the real stdlib
path — `http.ReadRequest` exactly as `runH1InspectLoop` reads an inner request,
then `Request.Write` exactly as the H1 leg serializes it — on go1.27.3 at
`a27cffb`. Production passes `ex.req.Host` (`proxy_tunnel.go:1137`), the same
value `Request.Write` serializes, so that is what was fed to the pin:

| tunnel | inner `Host` | pinned (before) | authority on the wire |
|---|---|---|---|
| `allowed.example.com` | `allowed.example.com:0/x` | **true** | *(empty)* |
| `allowed.example.com` | `allowed.example.com:@blocked.example.com` | **true** | *(empty)* |
| `allowed.example.com` | `allowed.example.com:443?x` | **true** | *(empty)* |
| `xn--bcher-kva.example.com` | `BÜCHER.example.com` | **true** | `xn--BCHER-2pa.example.com` |

The last row is a genuinely different DNS name, not a case variant:
`bcher-2pa` ≠ `bcher-kva` after folding. (`Bücher.example.com` → wire
`xn--Bcher-kva.example.com` **is** only an ASCII-case variant of the authorized
A-label, so it remains correctly pinned — see the boundary case in the table.)

### Attack scenario

- **Preconditions.** A policy rule authorizing a destination by *name* with SSL
  inspection enabled (not an IP-literal CONNECT target); the inner leg
  negotiates HTTP/1.1 (the ALPN-strip path always does; the native path does
  whenever either end declines h2); and the origin or front end routes an empty
  or unmatched `Host` to a default/catch-all vhost (`server_name _`, a CDN
  catch-all) — the same premise the gate was built on.
- **Steps.** `CONNECT allowed.example.com:443` → authorized, MITM established →
  `GET /secret HTTP/1.1` with `Host: allowed.example.com:0/x` → the pin passes →
  the inner request is forwarded with **no authority** → the front end serves its
  default vhost.
- **Exploitability.** Trivial and deterministic once a tunnel is authorized; no
  race, no special client (`curl` with a crafted `Host` over the tunnel is
  enough). **Likelihood:** moderate — it requires an insider or malware on an
  endpoint that already has proxy access, which is precisely the threat model a
  secure web gateway exists for.
- **Impact.** A request reaches a destination policy never evaluated, while the
  request log, scan verdicts and CDR decisions all still name the authorized
  host — so the bypass is invisible to the operator. Reach is bounded to the
  *default* vhost of that front end (net/http zeroes rather than truncates, so
  the attacker cannot name an arbitrary second vhost); the IDNA variant reaches
  one specific other name.
- **Affected assets.** Policy enforcement integrity, the decryption/scanning
  audit trail, and any internal service sharing a front end with an allowed one.
- **Not affected:** the HTTP/2 leg's own serializer rejects an invalid authority
  before encoding `:authority`, so that leg already failed closed to a 502 for
  case 1. Case 2 affected both legs. Both are now refused before the request is
  sent, for both legs, since the pin is in the shared `runInspectExchange`.

### Fix

`innerAuthorityAsSent` (`inspect_host_pin.go`) canonicalizes the inner authority
through **the same two helpers net/http and the HTTP/2 header encoder use**, and
refuses anything they would not forward verbatim:

```go
canon, err := httpguts.PunycodeHostPort(authority)   // what the wire will carry
if err != nil { return "", false }
if canon == "" || !httpguts.ValidHostHeader(canon) { return "", false }
return canon, true
```

The pin then compares `canon`, not the client's bytes. This is deliberately
**not** a list of refused spellings and deliberately **not** a hand-rolled port
or character check: the pin cannot drift from the wire because it now reads the
wire's own definition. The bracket check stays ahead of it, on the raw value,
because canonicalization de-brackets and would hide it. `golang.org/x/net` is
already a direct dependency, so `go.mod`/`go.sum` are unchanged.

Rejected alternative: `internal/bootstrap.SafeAuthority` — it de-brackets
`[allowed.example.com]` and returns ok, reintroducing the bracket defect.

The stale comment that asserted the U-label case was safe is corrected in place,
because a stale rationale on a security gate invites a later maintainer to
"correct" the code back toward the hole.

### Required tests (all added, all verified failing without the fix)

- **Table cases** in `TestInnerHostPinnedToTunnel_Equivalences`: invalid
  pseudo-port with `/`, userinfo-shaped pseudo-port naming another host,
  query-shaped pseudo-port, an invalid pseudo-port against an address tunnel
  (so the refusal stays ahead of the IP-literal scope skip), and the mixed-case
  U-label.
- **Boundary cases, both directions:** the ASCII-case A-label variant and the
  empty port must still **pin** (they are the same destination), so the fix
  cannot be "tightened" into refusing conforming clients.
- **`TestInnerHostPin_WireAgreesWithWhatWasPinned`** — the differential oracle,
  and the reason this is not a spelling list: for a corpus of inner
  authorities it drives the real `ReadRequest` → `Request.Write` path and
  asserts that **whenever the pin accepts, the serialized `Host` still
  canonicalizes to the tunnel host**. It carries a non-vacuity guard (a corpus
  that pinned nothing would assert nothing). A future repair on either side of
  the comparison fails here even if no one adds its spelling to the table.

All pre-existing pin tests pass unchanged — the fix narrows nothing a conforming
client sends.

---

## 3. F2 — the new access-list Diagnostics row serves an admin-only posture to a viewer

**Severity: Medium.** Information disclosure. **CWE-200**. OWASP
**A01:2021**. **Regression risk of the fix: low.**

### Affected contract

`apiDiagnostics` and `apiHealthExplain` serve the operator contract at
**RoleViewer**. `redactContractForRole` is the API-layer gate for rows derived
from admin-only state, and `apiDiagnostics`' own docstring commits to it: "Any
field added in the future that could leak sensitive data must be redacted to
admin-only at the API layer."

### The defect

`checkAccessCIDRLists` (`access_cidr_diag.go`, new in **#1596**) joined the
contract at `diagnostics.go:166` but was **not** classified in
`redactContractForRole`, which handled only `admin_username_length` and
`admin_roster_durability`. Its warn row therefore reached a viewer verbatim,
carrying two facts that are RoleAdmin everywhere else:

- the **verbatim rejected entry**, because the message embeds
  `SetUIAllowedCIDRs`' error, which is `fmt.Errorf("invalid IP/CIDR: %s", c)`
  over the configured value; and
- whether the allowlist **in force** is empty — spelled out as "which is empty,
  so the admin UI accepts every client IP" — or else its entry count.

`GET /api/ui-allow-ips` enforces `requireRole(RoleAdmin)` in **both** methods
(verified in the handler body, not only in the route metadata), and nothing else
reads that list.

### Attack scenario

- **Preconditions.** One malformed entry in `ui_allow_ips` (startup load or a
  settings save) and any authenticated session at RoleViewer or RoleOperator.
- **Steps.** `GET /api/diagnostics` → row `access_cidr_lists` →
  `Admin UI IP allowlist was rejected (invalid IP/CIDR: 10.20.30.0/33); the
  previous list stays in force, which is empty, so the admin UI accepts every
  client IP.`
- **Exploitability.** Trivial once the precondition holds: one authenticated GET,
  no race, no crafted input. **Likelihood:** low-moderate — it needs a
  misconfiguration to be present, but that is exactly the state the row exists
  to report.
- **Impact.** An internal network range leaks to the lowest authenticated role,
  and — more useful to an attacker — the row answers "is admin-UI IP
  restriction in force on this node at all?". That is the question asked before
  trying a stolen or low-privilege console credential from off-network.
- **Affected assets.** The admin UI's network access-control posture; configured
  internal CIDRs.

### Scope correction (why the fix is narrower than the first reading)

Two independent reviewers flagged this row; one asserted the trusted-proxy list
"has no read API at all". **That is wrong**, and it was checked rather than
accepted: `GET /api/settings/network` is **RoleViewer** and returns
`trusted_proxy_cidrs` and `trust_forwarded_headers` in full. The trusted-proxy
clause therefore discloses nothing a viewer cannot read directly, and redacting
it would cost an operator actionable remediation detail for no confidentiality
gain. **The finding is the UI-allowlist half only.**

### Fix

`accessCIDRListsRows` renders the row **twice from one read** of the rejection
state — the same single-read discipline as `rosterViewerRow`, so the two
renderings cannot straddle a settings save and disagree (which would be a
disclosure oracle of its own). `redactContractForRole` gains an
`accessCIDRListsCode` case that swaps in the non-admin rendering. Below admin:

- the **status stays `warn`** — a non-admin must still see that a network list
  is misconfigured and escalate;
- the UI-allowlist clause becomes a fixed "shown to administrators only" notice;
- the trusted-proxy clause is carried through **verbatim**;
- an **ok** row is returned identical to both roles, following the
  `admin_username_length` precedent (redacting a healthy row would report a
  condition that does not exist).

The new contract field is unexported, so it is never serialized and the
support-bundle redactor skips it, exactly as `rosterViewerRow` is handled.

### Required tests (added; verified failing without the fix)

- `TestAccessCIDRRow_RejectedEntryIsAdminOnly` — disclosure control at
  RoleViewer **and** RoleOperator (the entry, the "accepts every client IP"
  clause and the in-force/count detail must all be absent), with a **positive
  control** that the admin still receives every one of them, so the redaction
  cannot silently cost an admin the evidence the row exists to deliver.
- `TestAccessCIDRRow_HealthyRowIsNotRedacted` — the ok row is byte-identical
  across roles.
- `TestAccessCIDRRow_TrustedProxyHalfStaysVisible` — the **over-redaction**
  control, in both the trusted-proxy-only and both-halves-rejected shapes.

### Recommended follow-up (not done here — out of this fix's scope)

There is **no** test asserting that every contract row derived from admin-only
state is classified in `redactContractForRole`; this row's omission is what that
wall would have caught. A wall test in the style of
`operator_contract_wall_test.go` is the durable fix for the class, and should be
a separate change with its own review.

---

## 4. F3 — the README still denied a fail-closed guarantee the same window shipped

**Severity: Low** as code, but it is operator documentation of a security
posture, and it asserted the **opposite** of the behaviour.
**Regression risk: none** (documentation + a doc-contract test).

**#1668** made `cdr.fail_mode: closed` refuse a document when no Sluice instance
can be called at all. It updated `docs/OPERATIONS.md` §6 and
`config.example.yaml`, and left `README.md:198` saying: "when no Sluice instance
is available at all, for example after a failed initial dial, CDR is skipped and
the file passes through in either mode."

Per AGENTS.md's evidence order (source → tests → CI → configuration →
deployment → prose), the prose is what must change. An operator reading it
concludes that `fail_mode: closed` does *not* cover a Sluice outage — the one
case the setting exists for — and either plans a compensating control the
appliance already applies, or mis-diagnoses the resulting `CDR_BLOCKED` events.

**Fix.** The row now states that the same mode applies when no instance can be
called (initial dial failed, nothing enrolled, every breaker open), that `open`
passes the file through unsanitized, and that `closed` refuses it with block
reason `cdr_unavailable`, counted in `culvert_cdr_fail_closed_total`.

**Required test (added).** `TestREADMEDocumentsCDRUnavailableFailMode` asserts
the row against the **code's own** `cdrUnavailableBlockReason` constant — with
negative controls for three spellings of the retired claim and a positive
control that the fail-**open** half is still documented, so the fix cannot be
misread as "closed is now the default". Verified failing on the pre-fix README.
It deliberately adds no second copy of the behavioural assertions, which live in
`cdr_fail_closed_unavailable_test.go` and assert absolute values of
`statCDRFailClosed` that a doc test would perturb.

---

## 5. Fourth change in this PR — an installer predicate that had drifted

Not a finding against this window's security posture (the failure is
availability, not a weakened control), but it is a drift between two copies of
one security-relevant predicate, found while reviewing #1655/#1667, and it is
cheap to close.

`scripts/install.sh` had **two** answers to "is this secret already configured
in `.env`?". `secret_already_set` was taught (#1655) what docker compose
actually resolves: `VAR=`, `VAR=""`, `VAR=''`, `VAR=` + an inline comment and a
CRLF-only value are all **empty**. `persist_host_env_session_secret` kept its own
`grep -Eq '^VAR=.+'`, which matches every one of those shapes — the quote
characters, the `#` and the lone CR are all `.+`.

**Measured** (the real function extracted from both revisions): for all four
empty shapes, the pre-fix function reports "already configured" and declines to
persist the operator's `CULVERT_SESSION_SECRET`. Compose then interpolates
`${CULVERT_SESSION_SECRET:-}` to `""`, and every node falls back to its own
random per-process signing key (`session.InitRandomKey`) instead of the shared
cluster key — admin sessions silently stop validating across nodes, with no
error and no log line. That is precisely the failure the function's own header
comment exists to prevent.

**Not a weak-key issue:** the fallback is a fresh random 32-byte key, confirmed
in `initSessionSecret` (an empty env value takes the random path; a
present-but-invalid one panics).

**Fix.** Both callers now delegate to one predicate, `env_file_value_set`, which
reports 0 = set, 1 = absent/empty, **2 = could not read**. That third code is
load-bearing and preserved: `persist_host_env_session_secret` must be able to
tell "no entry, safe to add" from "could not look", because confusing them
overwrites a signing key it was unable to read (the hazard PR #1310's review
identified). An empty entry is not a key to protect, so it is overwritten; a
non-empty one is still never touched.

**Required tests (added).** Positive, negative, boundary and malformed tables:
ten empty/absent shapes must be replaced, eight non-empty spellings (including
the multiline and inline-comment forms) must be untouched, and the three exit
codes are pinned directly. Verified before/after against both revisions of the
script. The existing `secret_already_set` and session-secret suites were updated
to assemble the shared predicate and all pass unchanged.

---

## 6. Regression analysis

**What each fix can and cannot break.**

- **F1** narrows the set of inner authorities the pin accepts. The risk is
  over-restriction — refusing a conforming client. Bounded three ways: every
  pre-existing case in the equivalence table still pins (verified); the two
  boundary cases that *look* divergent but are the same destination (an ASCII-
  case A-label variant, an empty port) are pinned and now pinned *explicitly*
  by the table; and the accept predicate is the stdlib's own, so anything
  net/http will send verbatim is accepted by construction. A client sending a
  `Host` net/http refuses to forward was already getting a request with no
  authority, so it was never working.
- **F2** changes only what a **non**-admin sees, and only for a `warn` row. The
  admin rendering is asserted unchanged by a positive control; the ok row is
  asserted identical across roles; the already-public trusted-proxy clause is
  asserted still visible. Status is `warn` in both renderings, so no verdict
  roll-up changes and the `Verdict` recomputation path is untouched.
- **F3** is documentation plus a test that reads a code constant.
- **§5** makes an installer predicate stricter in the direction of persisting
  the operator's explicit key. The never-overwrite contract for a real value is
  pinned by eight cases, and the unreadable-file verdict is pinned separately.

**Backward/wire compatibility:** none of the four touches a persisted format, a
wire message, a JSON field name, a route, a role, or an audit action. `go.mod`
and `go.sum` are unchanged.

---

## 7. Sub-threshold observations (recorded, not fixed here)

Each was judged below the reporting bar after checking it; none is claimed as a
defect. They are written down so a later run does not re-derive them.

1. **No wall test ties contract rows to `redactContractForRole`** — the class
   gap behind F2. See §3's follow-up.
2. **The support bundle writes the operator contract unredacted, and bundle
   *download* is RoleOperator** while creation and approval are admin. The
   recorded exception in `operator_contract_wall_test.go` states its own
   invalidating premise ("if that lifecycle ever widens to a lower role, this
   exception is wrong"); the premise holds for the creator, not for the reader.
   Not fixed here because the remedies (redact the collector's contract, raise
   the download role, or raise the collector's sensitivity) each change
   support-bundle behaviour and belong in their own reviewed change. **This is
   the most promising item for the next run.**
3. **`fileProfileEnforced` (`file_profile_health.go:59`) compares
   `r.Action == ActionAllow` raw**, so after #1651's case folding a rule stored
   as `"allow"` now *does* get its file profile enforced on the request path
   while the dangling-profile Diagnostics row stays silent about it. Safe
   direction (enforcement stricter than the diagnostic claims) and only
   reachable from a hand-edited or skewed policy file. `plRuleMatchesTranslation`
   and `ui_helpers.go`'s redirect check share the shape; the Redirect dispatch
   re-checks `isSafeRedirectURL` at use, so there is no open-redirect path.
4. **The inspected H1 inner leg bounds neither header bytes nor header count**
   (`http.ReadRequest` is `readRequestLimit(b, math.MaxInt64)`), while the H2 leg
   caps the header list at 1 MiB. Identical at `266e684`, so not this window's
   regression, but worth a ticket given that this window's h2 work was
   specifically about preserving that cap.
5. **`mcperr.ReasonPeerObservationNotFresh` escapes the hard-failure
   anti-drift wall** (`hardfail_test.go` pins an older `lastReason`), so a
   freshness denial is stamped `HardFailure: false` in durable evidence. Not a
   fail-open — the mode-affecting input is inspection + policy override, never
   the gate reason — and ~14 reasons already sit past that bound. Evidence
   fidelity only (CWE-778).
6. **`POST /api/mcp/servers/refresh` does not consult the MCP emergency kill
   switch**, so it can still dial a registered peer after an operator trips it.
   Admin-only, no credential attached, SPKI-pinned, private/loopback/metadata
   refused; `PREREQ-MCP-KILL-1` is scoped to tool execution. Worth one line in
   the kill-switch runbook.
7. **`AtomicWrite` falls back to a pre-rename `FileInfo`** if the post-rename
   `fstat` fails, which would make the roster row report `changedExternally`
   forever. Over-warning, and `fstat` on a live descriptor essentially cannot
   fail.
8. **`dataDir/support` mode depends on which writer creates it first**
   (`0o750` vs `0o700`); files inside are all `0600` and the mismatch predates
   the window.
9. **Session-TTL overflow now resolves to 7 days** rather than wrapping negative
   and flooring to 15 minutes (#1673) — a permissive direction, reachable only
   from a hand-edited `admin_settings.json`, and 168h is a value an admin can
   set directly. Recorded so the choice is conscious (CWE-613).
10. **`ui_access_policy_startup.go:30,50` log a config-sourced CIDR error with
    bare `%v`**, no `sanitizeLog`/`%q`. Identical pre-change and the source is
    operator-authored config.
11. **Stale prose** in `internal/mcp/canary/readiness.go` (says "ten
    activation-level rows"; there are now eleven) and in
    `internal/catgroup`'s displaced-writer drop counters becoming unreachable
    on a syslog retarget (bounded to the swap window, same loss pre-change).

---

## 8. Scope NOT reviewed — read this before treating the window as closed

- **Frontend bundles.** `frontend/dist/*` was rebuilt by three dependabot
  merges. The committed bundles were **not** verified to be reproducible from
  `frontend/src` at this revision. A tampered or stale `dist` is a supply-chain
  and XSS surface that source review does not cover.
- **The 2026-10-19 review's own unreviewed backlog.** That run deep-reviewed 5
  of 40 merges; the other 35 have still had no review in this role, and this run
  did not reach back past `266e684`.
- **Non-Go, non-installer changes**: the OpenAPI/`route-classification` churn in
  #1439 and #1601 was read only where a slice's contract touched it.
- **Hosted gates.** Everything below is a *local, focused* result for this
  working tree. No full aggregate CI run, no golangci-lint, no CodeQL, no DAST.
  A passing local check is not a passing merge gate.

---

## 9. Verification performed

Toolchain `go1.27.3` (from `go.mod`'s `toolchain` line), on this working tree.

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `go test ./...` (full tree) | see the PR body for the run on the pushed SHA |
| `go test -run 'TestInnerHostPin' .` | ok — new cases + oracle + all pre-existing |
| `go test -run 'TestAccessCIDR' .` | ok |
| `go test -run 'TestREADMEDocumentsCDR' .` | ok |
| `go test -run 'TestInstallScript' .` | ok |
| `go test -run 'TestApiDiagnostics\|TestRedact\|TestWall_\|TestOperatorContract\|Durability' .` | ok |
| `go test -run 'TestH2Inspect\|TestMITM\|TestTunnel\|TestInspect' .` | ok |
| `bash -n scripts/install.sh` | clean (shellcheck not available in this environment) |
| `go.mod` / `go.sum` diff | empty |

**Negative controls — every fix was verified to fail without itself:**

- F1: reverting the three-line canonicalization makes all five new table cases
  **and** the differential oracle fail, with the measured wire values in the
  failure output.
- F2: removing the `redactContractForRole` case makes the viewer and operator
  assertions fail, printing the disclosed row.
- F3: restoring `origin/main`'s README makes all four assertions fail.
- §5: the extracted pre-fix `persist_host_env_session_secret` declines to
  persist for all four empty shapes; the fixed one persists for all four.

**Method note.** Six slices were delegated with bounded file lists and explicit
regression classes; one was taken directly (auth/session, policy/default action,
CDR, SSRF, host normalization, category groups, suppression/CI gates, installer).
Every finding acted on was re-verified against primary evidence before any code
changed — which is how F2's scope was narrowed (a reviewer's claim that the
trusted-proxy list had no API surface was checked and found wrong) and how F1
was confirmed (re-measured against the real stdlib path rather than accepted
from a summary).

---

## 10. Residual risk

- **F1's class is closed by an oracle, not by enumeration**, which is the
  stronger form — but the oracle covers the **H1** serializer. The H2 header
  encoder shares `PunycodeHostPort`/`ValidHostHeader`, so the same canonical
  form governs it, and the pin runs before either leg sends; an h2-specific
  wire-level oracle would still be a worthwhile addition.
- **The pin anchors on the CONNECT authority alone.** That remains the right
  choice (documented in the gate), but it means a destination reachable under
  *two* names that share a front end is still reachable under the authorized
  one — the pin prevents naming a different destination, not the front end's own
  internal routing.
- **F2's class remains open** until a wall test ties contract rows to the
  redactor (§7.1). A future row can repeat the omission.
- **§7.2 (the support-bundle contract read at RoleOperator) is unresolved** and
  is the top candidate for the next run.
- **Frontend `dist` provenance is unverified** (§8).
- **35 merges from the 2026-10-19 window and everything before `266e684`**
  remain unreviewed in this role.
