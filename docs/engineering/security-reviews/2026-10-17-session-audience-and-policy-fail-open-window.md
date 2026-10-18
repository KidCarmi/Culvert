# Security review — admin session audience and the policy/admission fail-open class

**Date:** 2026-10-17
**Reviewer role:** Security Regression Engineer (scheduled run)
**Scope reviewed:** `83328fd..dec66e1` — everything merged to `main` since the
2026-09-24 record (which landed in `83328fd`). 115 Go files, +15,953/−2,715:
48 non-test production files, the React policy surface, `api/openapi/*`,
`api/route-classification.yaml`, five CI workflows, the `Dockerfile` and
`go.mod`. Plus targeted invariant-drift checks across the product tree (§5).

---

## 1. Executive summary

**The reviewed window itself is clean. Every finding below is pre-existing.**
The window's substantive changes — the `internal/admission` extraction
(#1522–#1525), the memoized IDNA slow path in `internal/hostutil` (#1598), the
SEC-SECRETWRITE-1 secret-write hardening, CHAOS-70 roster durability, the
CHAOS-05/07 state-file quarantine surface and the new backup trigger/poll API —
were each checked against their own contracts and found sound. The admission
refactors are mechanically pure moves; the IDNA memo cannot return one host's
canonical form for another (§5).

What the run found instead is **six reachable defects of one shape: a security
decision that fails OPEN on a value it does not recognise.** They were found by
asking the inverse of the usual question — not "is the check present?" but
"what happens to an input the check does not understand?"

The most serious is not a missing check; it is a check made *conditional on an
attacker-controlled field*. `ps_ui_session` (admin) and `ps_session`
(captive-portal proxy user) are the same signed token type under the same HMAC
key, and the MAC covers the payload, **not the cookie name**. The payload has no
audience claim. The admin gate's roster-existence test was gated on
`Provider == "local"` — the one field that distinguishes the two — so a portal
token replayed under the admin cookie's name skipped the test entirely, and
because the portal minter sets no `Role`, the documented empty-role pre-RBAC
compatibility branch then resolved it to **`RoleAdmin`**. Any directory user who
can complete captive-portal SSO held full control-plane admin, bypassing admin
TOTP and admin lockout, with no forgery and no key — the appliance signs the
token itself. The IdP callbacks that mint that token are registered on the admin
UI mux and are on the public allowlist, so reaching the admin port is a
precondition the SSO feature supplies by itself.

Two findings are remotely exploitable by an unauthenticated or ordinary client
(SEC-GEOHOST-1, SEC-REVOKE-1); one escalates a read-only viewer to cluster-trust
compromise (SEC-HATOKEN-1); one is triggered by routine operator clicks and
silently disables a configured admission control (SEC-SECPARTIAL-1).

**Verdict: no security regression in the reviewed delta. Six pre-existing
fail-open defects, all closed fail-closed in this change, each with a defect
gate verified failing against the verbatim pre-fix body (§6).** A further seven
findings are recorded in §3 rather than fixed, because each needs an owner
decision or a migration larger than this change should carry.

| ID | Severity | What fails open |
|---|---|---|
| [SEC-UISESSION-AUD-1](#sec-uisession-aud-1) | **Critical** | Portal token replayed as the admin cookie resolves to `RoleAdmin` |
| [SEC-HATOKEN-1](#sec-hatoken-1) | **High** | A viewer reads the HA join token → cluster CA private key |
| [SEC-GEOHOST-1](#sec-geohost-1) | **High** | Host-header case variation evades every `destCountry` deny rule |
| [SEC-POLICYACTION-1](#sec-policyaction-1) | **High** | An unrecognised rule action allows, and shadows every deny rule under it |
| [SEC-REVOKE-1](#sec-revoke-1) | **High** | Unauthenticated logout writes attacker-chosen entries into the revocation list |
| [SEC-SECPARTIAL-1](#sec-secpartial-1) | **Medium** | A partial `/api/security` update disables the per-IP rate limiter, durably |

---

## 2. Security findings

### SEC-UISESSION-AUD-1 — A proxy-user portal token replayed under the admin cookie's name yields `RoleAdmin` {#sec-uisession-aud-1}

| | |
|---|---|
| **Severity** | **Critical** (Critical impact × Medium likelihood) |
| **CWE** | CWE-287 Improper Authentication; CWE-345 Insufficient Verification of Data Authenticity (missing audience binding / token confusion); CWE-269 Improper Privilege Management |
| **OWASP** | A01:2021 Broken Access Control; A07:2021 Identification and Authentication Failures |
| **Regression risk** | Pre-existing; **not** introduced by this window |
| **Status** | Fixed in this change |

#### Mechanism

Four facts compose into the escalation. Each is individually reasonable.

1. **One key, two audiences, no binding.** `session.Encode`/`Decode`
   (`internal/session/session.go`) sign the payload with one process-wide HMAC
   key. Nothing binds a token to a cookie name, and `Session` carries no `aud`
   or `typ` field.
2. **The portal minter sets no role.** `setSessionCookie` (`session.go`) mints
   `ps_session` with `Provider: id.Provider` — the IdP profile id, from
   `auth_oidc_flow.go` `Provider: p.profile.ID` and `auth_saml.go` `providerID`
   — and **never sets `Role`**.
3. **The admin gate's existence check was conditional on that provider.**
   `ui_middleware.go`:
   ```go
   if sess.Provider == "local" && !cfg.UIUserExists(sess.Sub) { /* 401 */ }
   role, ok := sessionRoleOrReject(sess.Role)
   ```
   For any non-`local` provider the roster-existence requirement is skipped.
4. **Empty role means admin.** `sessionRoleOrReject("")` returns
   `RoleAdmin, true` — the deliberate, test-pinned pre-RBAC compatibility case,
   written for admin-UI cookies minted before the `Role` field existed. It was
   never considered against an IdP token.

So a verified portal token presented as `ps_ui_session` passes (3) by virtue of
its provider and is promoted by (4) to admin.

#### Attack scenario

Preconditions: at least one enabled OIDC or SAML IdP profile (the captive-portal
SSO feature), and an attacker who is any ordinary directory user able to
complete that IdP login. No admin credential, no TOTP enrolment, no roster
entry, no key.

1. Mallory completes the normal captive-portal SSO flow and captures
   `Set-Cookie: ps_session=<payload>.<mac>`.
2. She replays the **same value** under the admin cookie's name:
   `curl -b 'ps_ui_session=<payload>.<mac>' https://appliance:9090/api/auth/users`.
3. The signature verifies — the appliance minted it. `Provider != "local"`, so
   the roster check is skipped; `Role == ""`, so the role resolves to
   `RoleAdmin`.

Admin-port reachability is not an extra assumption: `/auth/oidc/callback` and
`/auth/saml/callback` are registered on the admin UI mux (`ui_auth.go`
`registerAuthRoutes`) and `/auth/` is on the public allowlist
(`ui_middleware.go` `isPublicUIAuthPath`), so the SSO flow *requires* end users
to reach that port.

#### Exploitability and impact

Trivial once a portal session exists — a copy-paste, with no forgery. Full
`RoleAdmin` on the control plane: roster and RBAC writes, policy, CA, cluster,
CDR, IdP secrets, config-version rollback. It bypasses admin **TOTP** and admin
**lockout** entirely, because both live in the login handler and are never
consulted on the cookie path. Audit attribution records the portal identity
(`sessionAdmin`), so the action is traceable but not prevented.

Three sibling surfaces shared the same predicate or lacked it altogether:
`apiAuthStatus` (on the **public** allowlist, so it answered
`{"loggedIn":true,"role":"admin"}` and the console rendered the whole admin
surface), `sseAuthStillValid` (mid-stream SSE re-check), and `mcpLivePrincipal`
(which supplies one of the two eyes for MCP live-execution trust).

#### Affected assets

The admin control plane in its entirety; the cluster CA and config via the admin
surfaces; MCP four-eyes separation of duties.

#### Fix

One predicate, in the owner position, used by every consumer that makes a trust
decision. `ui_session.go` gains `uiSessionProvider` (shared with the minter, so
the two cannot disagree) and:

```go
func uiSessionAdmissible(sess *Session) bool {
	if sess == nil || sess.Provider != uiSessionProvider {
		return false
	}
	return cfg.UIUserExists(sess.Sub)
}
```

Both conditions are now required at every surface that resolves a **role** from
the cookie: `ui_middleware.go`, `events.go`, and `ui_auth.go`
(`apiAuthStatus` **and** `apiAuthLogout`).

`uiSessionAudience` is the audience half on its own, for a surface that needs
the audience and nothing more because it already runs **behind** the gate that
applied the roster half. `mcpLivePrincipal` uses it. Applying full
admissibility there would re-test roster existence inside a handler the gate had
already admitted, and it broke `TestLiveTrustHTTP_FourEyesAndRBAC` — the live
four-eyes flow legitimately names principals that are not rows in the caller's
roster view. That failure is what distinguished the two halves; the wall test
below accepts either predicate and records which surface may use which.

**This is behaviour-preserving for every legitimate admin session.**
`ps_ui_session` has exactly one minter (`setUISessionCookie`, two call sites),
it hard-codes `uiSessionProvider`, and a local session whose `Sub` is absent
from the roster was already refused. Only the non-local branch tightens. There
is no admin-SSO path through `ps_ui_session` in this build.

Attribution is deliberately **not** routed through the predicate:
`sessionAdmin` and `auditActor` gate nothing, and recording the identity a
refused session claimed is more useful than recording `unknown`.

#### Required tests — `ui_session_audience_test.go`

Portal tokens over five IdP-shaped providers × four roles × three subjects
(including a subject colliding with a real admin's name) refused at the
middleware; refused end-to-end by `apiAuthUsers` with the roster unchanged;
positive controls that a local roster session still passes **at its exact
role**, the pre-RBAC empty-role case still resolves to admin, and a local
session for an absent user is still refused; exact-comparison boundary rows
(`""`, `Local`, `LOCAL`, ` local`, `local `, `local\t`, `locale`, `loca`,
`local\x00`, `local\n`); the predicate's own nil/empty-subject shapes;
`apiAuthStatus`, `sseAuthStillValid` and `mcpLivePrincipal` each with a defect
gate and a positive control; a 400-way concurrent mixed-token run (meaningful
under `-race`); and two structural walls — every `readUISessionCookie` consumer
must be classified gating-or-attribution, and `encodeSession` must have exactly
two minters, one per audience.

---

### SEC-HATOKEN-1 — A read-only viewer reads the HA join token, which yields the cluster CA private key {#sec-hatoken-1}

| | |
|---|---|
| **Severity** | **High** (Critical impact × Low likelihood — requires an authenticated insider) |
| **CWE** | CWE-200 Exposure of Sensitive Information to an Unauthorized Actor; CWE-522 Insufficiently Protected Credentials; CWE-269 Improper Privilege Management |
| **OWASP** | A01:2021 Broken Access Control; A04:2021 Insecure Design |
| **Regression risk** | Pre-existing |
| **Status** | Fixed in this change |

#### Mechanism and attack scenario

`GET /api/cluster/ha` is gated at `RoleViewer` — correctly, it is a read-only
dashboard — and on a leader it unconditionally included
`resp["deploy_cmd"] = haDeployCommand()`. That string interpolates the live
`--ha-token`, plus `--cp-grpc-addr` and the CP TLS cert/key/CA paths.

That token is the **sole** credential for the `HASync` RPC:
`controlplane_server.go` gates it on `globalHA.VerifyToken(req.Token)` alone,
and `controlplane_tls.go` sets `tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven`,
so **no client certificate is required**. `HASync` answers with the exported
cluster state, the full published `ConfigSnapshot`, and the cluster CA
**private key** — wrapped by `haEncryptKey` under
`pbkdf2.Key([]byte(token), …)`, i.e. under the secret the caller now holds.

1. A viewer (or a phished viewer account) calls `GET /api/cluster/ha` and reads
   `deploy_cmd`. The same response tells them where to connect.
2. They call `HASync` with `{"token":"…","standby_addr":"…"}`.
3. They decrypt the cluster CA private key with the token they already have.
4. The CP appends `globalClusterCA.AllCACertsPEM()` to its `ClientCAs`, so with
   that key they mint node certificates the Control Plane trusts and enroll as a
   data plane.

Preconditions: HA enabled and this node the leader (the documented HA
deployment); any authenticated role ≥ viewer; network reach to the CP gRPC port,
whose address step 1 discloses.

#### Impact

Privilege escalation from read-only viewer to cluster-trust compromise: cluster
CA private key, the entire configuration snapshot, and fleet-node impersonation.
Plus disclosure of the CP's on-disk TLS material paths.

#### Fix

The **field** is admin material, not the route. `ha.go`:

```go
if status.Enabled && status.Role == "leader" && uiRole(r).HasRole(RoleAdmin) {
	resp["deploy_cmd"] = haDeployCommand()
}
```

Field-level suppression rather than raising the route's `MinRole`, which would
remove the HA panel from operators and viewers — a GUI-parity regression. The
POST path's own `deploy_cmd` is already behind `requireRole(RoleAdmin)` and is
unchanged. `HasRole` is the fail-closed enrolled-role lattice, so a role from a
newer build cannot reach the field either.

#### The client half, added in review

The server fix alone does not complete the privilege boundary in a single-page
app, which **Codex caught on the PR (P1) and I verified**. The HA panel's
`<pre id="ha-deploy-cmd">` keeps whatever was last written into it across a
logout and the next sign-in, because `static/index.html` only ever *assigned*
that element when the response carried `deploy_cmd` and never cleared it
otherwise. So an admin who opened the Cluster panel and logged out left their
join token in the DOM — and in the click-to-copy handler — for whoever signed in
next in that tab.

Two guards close it, both `textContent`: the render path clears on an **absent**
field, and `applySession` — the one chokepoint both login and `doLogout` go
through — clears on any non-admin session, so the token cannot outlive the
session allowed to see it even if the panel is never re-rendered.

#### Required tests — `ha_deploy_token_role_test.go`

Viewer and operator receive 200 with the HA status fields but no `deploy_cmd`,
no `--ha-token` and no token value (not-vacuous: the panel's own fields must
still be served, so the fix is a narrowing and not a 403); admin still receives
a `deploy_cmd` carrying the token; unenrolled roles (`""`, `superuser`, `Admin`,
`ADMIN`, `root`, `owner`) see nothing; and standby/disabled states emit no token
to any role. Plus `SPAClearsTheDeployCommand`, a structural gate over
`static/index.html` for the two client-side guards, with a not-vacuous check
that the element and its render path still exist and an assertion that the value
is never written through `innerHTML`. (A static assertion rather than a browser
test: the browser e2e lane is advisory and does not cover a cross-session DOM
carry-over; what has to hold is that neither guard is deleted.)

---

### SEC-GEOHOST-1 — Host-header case variation evades every country-scoped deny rule {#sec-geohost-1}

| | |
|---|---|
| **Severity** | **High** (High impact × High likelihood — client-side only, no credentials) |
| **CWE** | CWE-178 Improper Handling of Case Sensitivity; CWE-180 Incorrect Behavior Order: Validate Before Canonicalize; CWE-693 Protection Mechanism Failure |
| **OWASP** | A01:2021 Broken Access Control |
| **Regression risk** | Pre-existing |
| **Status** | Fixed in this change |

#### Mechanism

`geoHostKey` (`geoip.go`) stripped a port and nothing else — no lowercasing, no
IDNA, no trailing-dot trim:

```go
func geoHostKey(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil { return h }
	return host
}
```

It is the key for the host→IP cache behind `geoResolver.LookupCached`, and
`matchDestNorm` (`policy.go`) hands the country branch the **raw** host. The
comment there — *"Country checks keep using the raw host (they normalize
internally and are far less common)"* — was false. Every other destination
matcher normalises: `internal/blocklist`, `internal/urlcat`, and policy FQDN via
`MatchFQDNNorm`.

On a cache miss the country is unknown and the rule does **not** match. That is
fail-closed for an *allow* rule, but for a **deny** rule it means the rule is
skipped and evaluation falls through to a lower-priority rule.

#### Attack scenario

Policy: `P1: Deny destCountry:[RU,CN]` / `P2: Allow *` — the canonical shape for
geo rules.

The client varies the case of the `Host` header or CONNECT authority on every
request: `BLOCKED.Example.com`, `bLocked.example.COM`, … Each spelling is a
distinct cache key, the warm is off the request path, so each first request is a
miss, `P1` does not match, and `P2` allows it. A 19-character hostname has
~2^15 spellings and the resolved-host cache is capped with arbitrary eviction,
so the supply of "first requests" is effectively unlimited. DNS is
case-insensitive, so the connection reaches the real blocked destination. The
operator's only signal is `culvert_geo_policy_unresolved_total` ticking.

#### Impact

A full, repeatable, unauthenticated bypass of every `destCountry`-scoped rule —
the control an enterprise buys a Secure Web Gateway for. The same key feeds
`maybeTrackDestinationCountry`, so dashboard country attribution is split across
spellings too.

#### Fix

Normalise at the one chokepoint all four call sites share (`resolveHostCached`,
`resolveHost`, `warmGeoHost`), so put and get can never disagree and the
resolver receives the canonical A-label form:

```go
func geoHostKey(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return hostutil.NormalizeHost(h)
	}
	return hostutil.NormalizeHost(host)
}
```

`NormalizeHost` is the fail-open variant, which is correct for a cache key: it
is many→one and consistent between writer and reader, and it returns IP literals
verbatim. This closes case, trailing-dot and IDN U-label/A-label variance at
once, and makes `matchDestNorm`'s comment true.

#### Required tests — `geoip_hostkey_normalization_test.go`

Nine spellings of one destination collapse to one key; U-label/A-label pairs
fold; IP literals (v4, v6, bracketed v6, with and without ports) survive
byte-for-byte and still parse as IPs — the regression control for the resolver
path; the geo key agrees with `hostutil.NormalizeHost`, the form every other
matcher uses; and an end-to-end gate on the layer `matchDestNorm` actually
consults — warm the cache once under the canonical name, then hit it under each
attacker spelling.

---

### SEC-POLICYACTION-1 — An unrecognised rule action allows the request and shadows every deny rule beneath it {#sec-policyaction-1}

| | |
|---|---|
| **Severity** | **High** (High impact × Low likelihood) |
| **CWE** | CWE-636 Not Failing Securely ("Failing Open"); CWE-20 Improper Input Validation; CWE-693 Protection Mechanism Failure |
| **OWASP** | A01:2021 Broken Access Control; A08:2021 Software and Data Integrity Failures |
| **Regression risk** | Pre-existing |
| **Status** | Fixed in this change |

#### Mechanism

`applyPolicyDecision` (`proxy.go`) dispatches `switch match.Action` with cases
for `ActionDrop`, `ActionBlockPage`, `ActionRedirect` and `ActionAllow` — and
**no `default:`**. Falling out of the switch reaches the function's trailing
`return "OK", false`: the request proceeds upstream, no decision is recorded,
and because the rule scan is first-match-wins (`evalAccessRules`), **no
lower-priority deny rule is consulted either**. One unrecognised action on a
priority-1 `destFqdn: "*"` rule disables the whole rulebase under it, silently.

`Action` was validated only on the **API ingress** path (`validateAccessRule`,
`ui_helpers.go`). The durable and bulk paths used `policyRulePersistable`
(`authpolicy.go`), which checked `SubjectMatch` and `Auth` but not `Action`:
`PolicyStore.Load` (the operator-managed `proxy.policy_file`) and
`PolicyStore.ReplaceAll` (the CP→DP snapshot apply and replace-mode config
import, the latter with no per-rule validation at all).

#### Attack scenario

No hand-editing required: a Control Plane on a newer build pushes a rule whose
action this data plane does not know; an older DP receives a renamed action; a
restored backup or a hand-authored `policy.json` says `"Block"` instead of
`"Block_Page"`. The rule installs, matches at priority 1, and every request it
matches is allowed and unlogged.

This is a defect and not an intended posture: the sibling gate in the same
engine fails **closed** for exactly this class — `IPFilter.Allowed` denies all
traffic on an unrecognised mode — and `policyRulePersistable`'s own doc says the
gate exists so that "a hand-edited or newer-version policy.json" cannot fail
open. `Action` was simply missed.

#### Fix (both halves, and the tolerance the first attempt got wrong)

`canonicalPolicyAction` folds a **stored** action onto the constant the
dispatcher switches on, reporting false when this build has no branch for it:

1. **Runtime.** `applyPolicyDecision` resolves the action once and fails
   **closed** when it cannot: charges `statBlocked`, records a `POLICY_BLOCK`
   decision, logs `POLICY_UNKNOWN_ACTION` with the action sanitised and
   `%q`-quoted, serves the block page, terminal. It then switches on the
   canonical constant.
2. **Install gate.** `policyRulePersistable` refuses a rule whose action cannot
   be resolved, with the warn-and-skip it already applies to a source-scoped
   access rule — so Load / ReplaceAll / replace-import drop it **per rule** and
   keep the valid ones.

Both halves are needed together, and the order matters: blocking at dispatch
*without* dropping at install would turn a rule that previously allowed into one
that blocks **and shadows everything beneath it** — for a `destFqdn: "*"` rule,
a total outage on upgrade. Dropping it at install instead lets evaluation
continue to the remaining rules.

**The first attempt at this fix was too strict, and the test suite caught it.**
Two tolerances were missing, and both are now explicit, neither ever more
permissive than the pre-fix fall-through:

- **Case is folded.** Operator-managed policy files and in-tree snapshot
  fixtures carry lowercase spellings (`"allow"`), and pre-fix those fell out of
  the switch and were **allowed**. Rejecting them would have dropped rules an
  operator plainly meant to keep. Folding resolves them to the intended action:
  `"allow"` keeps allowing (unchanged), while `"drop"` and `"block_page"` start
  **blocking** where they previously allowed — strictly fail-closed.
- **Unset is not unrecognised.** An empty action resolves to `Allow`, which is
  exactly what the fall-through did, so no deployment's traffic changes
  direction. It is a historical shape, not a version skew:
  `validateAccessRule` has always required an explicit action, and whoever can
  write the policy file could equally have written `"Allow"`, so honouring it
  adds no attack surface. The hole being closed is the version-skew case, which
  is never empty. (Requiring an explicit action on load is a defensible
  tightening — recorded as **R8** below, because it is a migration, not a
  security fix.)

The API ingress validator (`validateAccessRule`) deliberately keeps its
**exact-spelling** contract. The two have different jobs: ingress refuses sloppy
input at the door, where there is a caller to tell; `canonicalPolicyAction`
decides what to do with data already on disk or already arriving in a snapshot,
where the only choices are to honour it or to drop it.

One in-tree fixture used `Action: "block"` — not a Culvert action at all, and it
survived only because of this fail-open. It now names `ActionBlockPage`; the
test's subject (ReplaceAll's bookkeeping) is unchanged.

#### Required tests — `policy_unknown_action_test.go`

Eleven unresolvable shapes (`"Block"`, `"Deny"`, `"Quarantine"`, `"Isolate"`,
whitespace-padded near-misses) are terminal and non-`OK` at dispatch, and are
refused by `policyRulePersistable` with a non-empty reason; a control that
`Allow`/`Block_Page`/`Redirect` still produce their exact `(status, terminal)`
pairs; `ReplaceAll` drops the bad rule and **keeps the valid one**, so the gate
is per-rule rather than a whole-rulebase discard.

Then the two tests that pin the tolerance, which is what makes this fix safe to
ship: `ResolutionIsNeverMorePermissiveThanPreFix` asserts every tolerated
spelling resolves to an action at least as strict as the pre-fix `allow` (and
that the unresolvable set stays unresolvable, so a version-skew action is never
*guessed at*); `ResolvedActionsDispatchToTheirBranch` closes the loop by
checking a tolerated spelling reaches the same branch its canonical form does,
so resolution is not a lie told only to the load gate; and
`ToleratedSpellingsStillInstall` is the availability control — a policy file
already carrying empty or lowercase actions keeps **all** of its rules.

**A second consumer, found in review.** CodeRabbit pointed out that `proxy.go`
canonicalises before the dispatch switch but a *second* site — the pre-abort
policy-learning observation — still compared `match.Action` directly with
`ActionDrop`. Verified and correct: a rule stored as `"drop"` reaches the Drop
branch in the dispatch, so the raw comparison would have skipped that
observation for exactly that rule and lost it (the Drop branch's HTTP/2 fallback
aborts via `panic(http.ErrAbortHandler)` before `applyPolicyDecision` returns,
which is why the observation is emitted there at all). It now canonicalises too.
An observability gap rather than a security one, but one this change introduced.

**And a second fixture.** `ui_import_preview_e2e_test.go` built its import
fixture with a per-rule `"action":"deny"` — like `"block"`, not a Culvert action
at all, surviving only because of this fail-open. It now uses `Block_Page`. That
failure appeared only in the advisory browser-e2e lane, which the local root
suite does not execute, so CI caught it rather than the pre-push checks.

---

### SEC-REVOKE-1 — An unauthenticated logout writes attacker-chosen entries into the persisted, cluster-gossiped revocation list {#sec-revoke-1}

| | |
|---|---|
| **Severity** | **High** (Medium impact × High likelihood — unauthenticated and remote) |
| **CWE** | CWE-345 Insufficient Verification of Data Authenticity; CWE-770 Allocation of Resources Without Limits or Throttling; CWE-400 Uncontrolled Resource Consumption |
| **OWASP** | A04:2021 Insecure Design; A08:2021 Software and Data Integrity Failures |
| **Regression risk** | Pre-existing |
| **Status** | Fixed in this change |

#### Mechanism

`apiAuthLogout` (`ui_auth.go`) discarded the decode error and then revoked
unconditionally:

```go
sess, _ := readUISessionCookie(r)          // decode error DISCARDED
if sess != nil { auditEvent(…) }
revokeSessionCookie(uiSessionCookieName, r) // runs even when the decode FAILED
```

`revokeSessionCookie` (`session.go`) does its own base64+JSON decode with **no
signature check**, on the stated premise *"HMAC already verified by
decodeSession"* — false on this path, because the error was thrown away.
`/api/auth/logout` is on the public allowlist (`isPublicUIAuthPath`), so no
session, credential or role is required.

`RevocationList.Revoke` (`internal/session/session.go`) is an unbounded
`map[string]time.Time` insert; eviction is lazy and **only on expiry** — and the
attacker chooses the expiry.

#### Attack scenario and impact

`POST /api/auth/logout` with
`Cookie: ps_ui_session=<base64url({"sub":"AAA…","exp":9999999999})>.garbage`.
The key is the whole cookie payload, retained permanently because `exp` is in
2286.

- **Rate and size.** `securityMiddleware`'s `apiLimiter` allows 60 mutating
  `/api/` requests per minute per IP. The 1 MiB `MaxBytesReader` bounds the
  **body**, not the `Cookie` header — and the admin server sets no
  `MaxHeaderBytes`, so net/http's 1 MiB default is the only ceiling. Up to
  ~60 MB/min/IP of permanently retained heap, trivially distributed across IPs.
- **Disk amplification.** Every request calls `SaveRevocations`, which marshals
  the **whole** list and performs an atomic write + fsync — O(n) per insert over
  a set the attacker is growing, i.e. quadratic.
- **Cluster amplification.** `revocationSyncLoop` exports the list to the
  Control Plane every few seconds and every node `MergeRevocations` and persists
  it. One unauthenticated client against one data plane's admin port pollutes
  the whole fleet's revocation memory, sync payload and revocations file.

Forced logout of a *specific* victim is **not** practical: the key is the
victim's exact payload, which contains a 128-bit random `jti`. The realistic
impact is unauthenticated resource exhaustion and write amplification across the
cluster — the same class the repository already treats as a defect in CHAOS-63,
CHAOS-69 and SEC-REQID-1.

#### Fix

Act only on a session this plane may honour, reusing the SEC-UISESSION-AUD-1
predicate — which also stops logout acting **across audiences** (a portal token
replayed under this cookie's name must not revoke the real portal session that
shares its payload):

```go
sess, err := readUISessionCookie(r)
if err == nil && uiSessionAdmissible(sess) {
	auditEvent(r, "auth.logout", sess.Sub, "admin UI logout")
	revokeSessionCookie(uiSessionCookieName, r)
}
clearUISessionCookie(w, r)   // UNCONDITIONAL
```

Clearing stays unconditional and the answer stays 200: a browser holding a junk
or foreign cookie must still be able to get rid of it, and a logout that
reported why it refused would be an oracle.

#### Required tests — `auth_logout_revocation_test.go`

25 forged 2 KB-subject logouts add zero entries while still answering 200 and
still clearing the cookie; a forged payload prefix never reads back as revoked;
nine malformed cookie shapes plus the no-cookie case are absorbed with no
entries; a not-vacuous control that a genuine admin logout **does** revoke and
its cookie then fails `decodeSession` with `"revoked"`; and a cross-audience
control that a replayed portal token revokes nothing and leaves the portal
session usable.

---

### SEC-SECPARTIAL-1 — A partial `POST /api/security` disables the per-IP rate limiter, and persists it {#sec-secpartial-1}

| | |
|---|---|
| **Severity** | **Medium** (High impact × High likelihood, but operator-triggered, not attacker-triggered) |
| **CWE** | CWE-1188 Insecure Default Initialization of Resource; CWE-20 Improper Input Validation; CWE-693 Protection Mechanism Failure |
| **OWASP** | A05:2021 Security Misconfiguration; A04:2021 Insecure Design |
| **Regression risk** | Pre-existing (present since `ui_security.go` was created) |
| **Status** | Fixed in this change |

#### Mechanism

```go
RateLimitRPM int `json:"rateLimitRPM"`   // 0 = disable
…
if body.RateLimitRPM >= 0 { rl.Configure(body.RateLimitRPM, time.Minute) }
```

A plain `int` cannot distinguish an absent field from an explicit `0`: an
omitted `rateLimitRPM` decodes to `0`, and `0 >= 0` is **tautologically true**.
So every body that omits the field calls `rl.Configure(0, …)` =
**disabled** — and `adminSettingsSave()` plus
`saveConfigVersion(…)` on the next lines make it durable and record it as a
config version.

The endpoint's **own published contract** declares the body a *"Partial update —
supply only the fields to change"* with `rateLimitRPM` optional
(`api/openapi` `SecurityUpdate`). Every other field in the handler honours
that; `rateLimitRPM` was the one that did not. And three of the shipped admin
UI's own buttons send exactly such bodies: `secAddIP` → `{ipAdd}`,
`secRemoveIP` → `{ipRemove}`, `saveSecurity` → `{ipFilterMode}`.

The codebase already knows the idiom — `backups_api.go` uses `Encrypt *bool`
"so an OMITTED choice is distinguishable from an explicit false", for exactly
this reason.

#### Failure scenario and impact

An operator with rate limiting at 600 rpm adds one IP to the IP filter from the
Security panel. The response is `200 {"ok":true}` and the toast says
"Added <ip>". Per-IP rate limiting is now **off process-wide and off after
restart**. `ExportHotDeltas` returns nil behind the `Enabled()` gate, so the
cluster stops seeing this node's hot IPs too.

Per CHAOS-69's own analysis the rate limiter is one of three front-door limiters
that bound pre-authentication CPU cost on the proxy path, where a 1 KiB
destination authority already costs ~1.3 ms of a core. Losing it silently is the
loss of a configured admission control.

Secondary: `if body.RateLimitRPM >= 0` also meant a **negative** value was
silently ignored rather than refused.

#### Fix

```go
RateLimitRPM *int `json:"rateLimitRPM"`   // nil = unchanged, 0 = disable
…
if body.RateLimitRPM != nil && *body.RateLimitRPM < 0 {   // before ANY mutation
	http.Error(w, "rateLimitRPM must be >= 0 (0 disables the rate limiter)", 400)
	return
}
…
if body.RateLimitRPM != nil { rl.Configure(*body.RateLimitRPM, time.Minute) }
```

An explicit `0` still disables, which is what the panel's "Disable rate
limiting" button sends. The negative check is placed **before any field is
applied**, so a refused request leaves the whole security configuration
untouched. No OpenAPI change is needed — the spec already describes the fixed
behaviour.

#### Required tests — `ui_security_partial_update_test.go`

Seven partial-body shapes (including the three the shipped UI sends, and the
empty object) leave the limiter at its configured value; explicit `0`, `1` and
`120` still apply; negative values are refused **and** leave `ipFilterMode`
unmoved, proving the all-or-nothing property; four wrong-type values still 400
and change nothing (preserving the contract
`apicontract_request_slice3i_test.go` pins); and explicit JSON `null` is treated
as absent — the one shape a pointer field newly admits.

---

## 3. Findings recorded, not fixed here

Each needs an owner decision or a migration larger than this change should
carry. Recorded with full evidence so none is lost.

### R1 — The plain-HTTP forward path performs no private/internal destination check (High)

CONNECT (`proxy_tunnel.go` `handleTunnelBypass` and the inspect path),
WebSocket, and SOCKS5 each run `isPrivateHost(...)` plus `ssrfControl` /
`ssrfSafeDialContext` before dialling. `handleHTTP` (`proxy_http.go`) runs
**neither**, and the shared transport it uses (`upstream_transport.go`
`newBaseUpstreamTransport`) installs no `DialContext`; none of the three
`swapUpstreamTransport` callers adds one. So
`GET http://169.254.169.254/latest/meta-data/… HTTP/1.1` through the proxy port
is forwarded, while the same destination over CONNECT is refused 403 and logged
as `CONNECT SSRF block`. Reproduced through the real `handleRequest` with no
loopback test exemption: a loopback origin returned 200 with the internal
backend's body. Default install is reachable — auth, IP filter and rate limiter
all ship disabled, and zero rules with an empty `default_action` means allow.

**Why not fixed here.** Two reasons, both honest. First, it is a product
decision, not only a bug: one of the two halves is wrong, and whether a forward
proxy may reach RFC-1918 on plain HTTP is the owner's call — the gosec exclusion
in `roadmap/CI-REDESIGN.md` ("SSRF/forward-proxy-by-design") shows the question
has been touched but not settled for this path. Second, adding the guard turns a
large family of root tests red (`policy_ruleid_logentry_test.go`, the
`authpolicy_phase*`, `authz_matrix_e2e`, `client_class` and `fileblock`
families), each of which drives `handleRequest` at an `httptest` loopback
origin; they need the existing `ssrf.AllowLoopbackForTest()` seam. That is very
likely why the guard was never added. A staged fix is proposed: (1) inline
`isPrivateHost(r.Host)` in `handleHTTP` before `tr.RoundTrip`, at the call site
so CodeQL sees it; (2) a connect-layer rebinding backstop as `DialContext`,
gated on `!upstreamPool.Enabled()` because a configured parent proxy is
legitimately private; (3) migrate the loopback tests. Tests must assert
**all four** entry points refuse the same destination, so the asymmetry cannot
reappear in one branch.

### R2 — The C2 metadata index resolves wildcard routes to the public `/` catch-all (Medium — defence in depth)

`buildMetadataIndex` (`ui_metadata_enforcement.go`) stores the literal pattern
`"/api/support/bundles/{id}"` in its **exact** map, so a real request path never
matches and falls through to `"/"`, whose entry is `Public: true`. Measured:
`/api/support/bundles/csb_…` and `/api/support/bundles/csb_…/approve` both
resolve to `metaPath="/" public=true`. For all ten wildcard routes (the
support-bundle download, sealed export, delete and TAC upload-consent surfaces,
plus `/api/support/recipients/{name}`) this silently disables C2 role
enforcement, C4 role-divergence observation and the C2c audit-gap check — and
`c2ShadowMissingMetaTotal` never increments, so the drift is invisible in
metrics too. **Not exploitable:** every one of those handlers has its own
`requireRole`, so the loss is the second layer, not the only one.
`TestC2_MetadataIndex_ResolvesEveryRoute` iterates the pattern literals and so
passes vacuously. Fix: make the index pattern-aware (segment match on `{…}`),
and add a test that substitutes a concrete value for each `{…}` segment and
asserts `Lookup` returns that route's own metadata rather than `"/"`.

### R3 — `/api/security`'s documented `ipList` field is declared and never read (Medium)

`IPList []string // full replace` is in the request struct and in the published
OpenAPI schema, but no code reads it. Because `decodeJSON` sets
`DisallowUnknownFields`, *declaring* it is exactly what makes
`{"ipList":[…]}` a **200** instead of a 400 — so an operator or IaC client using
the documented field to shrink an allowlist receives `{"ok":true}` and no
change, leaving revoked IPs admitted in `allow` mode. Needs an
implement-or-remove decision (`ipf.ClearAll()` + `AddAll`, or delete the field
so the request is rejected); either way it changes a published contract, which
is why it is not folded into this change.

### R4 — Revoking a cluster enrollment token is unaudited, and its metadata claims otherwise (Low/Medium)

The DELETE branch of `apiClusterTokens` (`ui_cluster.go`) destroys cluster trust
material and persists with no `auditEvent` on any path, while
`ui_routes_meta.go` declares `Note: "audit delegated"` for that method — true
for POST, but DELETE has no delegate at all. With `AuditExpected: false`, C2c's
runtime audit-gap warning never fires. The `saveConfigVersion` omission is
**correct** (enrollment tokens are deliberately outside the rollback surface).
Only the audit record is missing. Fix: add
`auditEvent(r, "enrollment.token_revoked", tokenHash, "")`, flip the entry to
`AuditExpected: true`, and correct the false `Note` — a `uiRoutes` edit that
touches the count-locked C1 metadata tests, so it belongs in its own change.

### R5 — SOCKS5 does not run the policy engine (recorded, deliberate)

`handleSOCKS5` enforces conn-limit → IP filter → rate limit → auth → IDNA gate →
blocklist → plugin → SSRF → dial, and contains **zero** references to
`policyStore`, `Evaluate` or `defaultPolicyActionState`. So FQDN, category,
country and identity rules — and zero-trust default-deny — are unenforced on
that listener. This is already a recorded roadmap limitation
(`roadmap/AUTH-POLICY-PHASE1-PLAN.md`: "no SOCKS5 exemption may ship before
SOCKS5 runs the engine"; `AUTHENTICATION-POLICY-SPEC.md`: "runs only blocklist +
plugin + SSRF"). Noted here only because `README.md`'s "Limitations & Known
Gaps" lists only the UDP-ASSOCIATE gap, so the enforcement asymmetry is
undocumented in the operator-facing place.

### R6 — Config-version rollback briefly mixes the new IP-filter mode with the old entry set (Low)

`configversion.go` does `ipf.SetMode(…)`, `ipf.ClearAll()`, `ipf.AddAll(…)` as
three separate publications. Between the first two the published view is new
mode + old entries (rolling back `block`→`allow` makes a blocked address
*allowed* for that window); between the second and third, `allow` with an empty
list denies everything. Both windows are two lock acquisitions wide and occur
only during an admin rollback. The snapshot path already does it correctly —
build a fresh filter, `SetMode` + `AddAll` on it, then swap
(`controlplane_snapshot.go`). Fix is free; test with a mutator-order assertion
that no intermediate published view mixes the two.

### R8 — Requiring an explicit rule action on load (Low — a migration, not a fix)

SEC-POLICYACTION-1 resolves an **empty** action to `Allow`, preserving the
pre-fix fall-through exactly so that no deployment's traffic changes direction.
That is the right call for a security fix, but it leaves a rule with no `action`
field silently allowing. Requiring an explicit action on load — dropping
action-less rules with the same warn-and-skip, after a release that warns
without dropping — would close it. It needs a migration window and an operator
note, and in-tree fixtures use the shape today
(`config_import_preview_test.go` seeds `PolicyRule{Name: "keep-me"}`), so it is
recorded rather than folded in here.

**A related operator-experience gap, also worth a follow-up.** The install gate
uses the warn-and-skip this function already applies elsewhere, which is
fail-closed and loud in the log — but on the **config-import** path it means an
import carrying an unrecognised action answers success while silently dropping
that rule. Two in-tree fixtures used such values (`"block"`, `"deny"`), weak
evidence that hand-written or older exported import JSON may too. Refusing the
import with a 400 naming the offending rule would be a better answer than
dropping it quietly; that is a change to the import contract rather than a
security fix, so it is recorded here instead.

### R7 — Non-minimal punycode re-canonicalisation (Informational)

There is a class of pure-ASCII, DNS-valid hosts where
`normalizeHostStrict(H) != H` and both forms are DNS-valid — e.g.
`xn--jy9b.example.com` → `xn--zn7c.example.com` under x/net/idna v0.60.0. Every
engine decides on the normalised form while the dialler, `Host:` header and SNI
use the raw one. **Not exploitable as written:** the mapping is strictly
many→one and canonicalising, so it can only make a block match *more* often, and
because only ACE labels can differ, the two forms are always siblings under the
same parent zone as the permitted name — which the attacker does not control.
The one shape that would escape (an ACE label decoding to pure ASCII, e.g.
`xn--example-` → `example`) is rejected by this x/net version, and the strict
gate then refuses the request. Recorded because a future x/net that re-admits
the empty-extended-part decode would turn it into a live allowlist bypass. Cheap
guard: a differential test pinning "no ASCII host normalises to a *different*
ASCII host that is also resolvable".

---

## 4. Regression analysis

**Nothing in `83328fd..dec66e1` introduced any of the six findings.** Each was
traced to its origin:

- SEC-UISESSION-AUD-1 — the `Provider == "local" &&` conditional predates the
  window; the window's own RBAC work (#1448, `sessionRoleOrReject`) *narrowed*
  the compat branch and is what made the remaining hole analysable.
- SEC-SECPARTIAL-1 — `git log -L` puts the `>= 0` guard in `ui_security.go`'s
  creating commit (PR #1256).
- SEC-HATOKEN-1, SEC-GEOHOST-1, SEC-POLICYACTION-1, SEC-REVOKE-1 — all older
  than the window; untouched by it.

The window's substantive changes were each checked against their own contract
and found sound:

- **`internal/admission` extraction (#1522–#1525).** Mechanically diffed
  `security.go`→`internal/admission/engine.go`: the non-comment delta is renames
  plus the removal of unrelated wrappers. `ExportHotDeltas` is byte-identical.
  Per-limiter distributed state (`fb2cf33`) moved globals to instance fields
  with `AllowAuto`/`AllowClusterAware`/`FreshCount` unchanged; nothing that
  should be per-instance was left shared or vice versa. `228be80` is a pure
  extraction of `applySnapshotAdmission`, still called first and reached by both
  the full and the delta snapshot path.
- **The IDNA memo (#1598).** Direct-mapped with a per-process `maphash` seed;
  every hit re-verifies the full post-lower/post-trim key, so a collision is a
  recomputation and never a wrong answer; `ok` is memoized with `norm`, failures
  included; the key is `strings.Clone`d so no request buffer is pinned; entries
  over `maxMemoHostLen` are normalized but not retained, on both the input and
  the punycode-expanded output. No path by which one host receives another
  host's canonical form.
- **SEC-SECRETWRITE-1 (#1467).** `fileutil.WriteFileExclusive` removes any
  pre-existing entry then creates with `O_CREATE|O_EXCL`, so a symlink
  re-planted in the window makes the open fail rather than redirect; `f.Chmod`
  defeats umask; the failure path verifies the unlink and re-syncs the parent.
- **CHAOS-70 roster durability (#1469).** `mutateRosterDurably` holds
  `saveUIUsersMu` across mutate-then-persist and rolls back only when the write
  did not land; `ErrReplacedNotSynced` is deliberately not rolled back; the
  login-path fail-open on the TOTP replay counter and backup-code consumption is
  a documented, counted and logged posture decision, not an oversight.
- **CHAOS-05/07 quarantine surface.** Viewer-facing rows are path-free with
  bounded cause classes; `globEscapeLiteral` keeps a metacharacter in
  `CULVERT_DATA_DIR` from dropping the residual record.
- **The new backup API.** `apiBackups` keeps per-verb `requireRole`, audits the
  trigger, single-flights and caches the agent listing so a viewer cannot spawn
  unbounded containers, and `apiBackupOperationStatus` answers any non-backup op
  kind exactly like an unknown id so a viewer cannot read upgrade/restore ops.
- **Legacy UI additions.** Every interpolation in the new backup panel goes
  through `escHtml` into text-node or double-quoted-attribute context; CSP
  carries no `unsafe-inline`.
- **`28a43ef`** raises the golangci-lint *timeout* from 5m to 10m after a
  cold-cache expiry at 0 issues — not a weakened gate — and moves the toolchain
  to Go 1.26.9 / x/net v0.60.0 to clear twelve stdlib advisories and GO-2026-6617.

---

## 5. Invariants verified as holding

Checked at this revision, with the evidence that holds them:

- **Default-action contract.** `loadRewriteAndDefaultAction` allows on
  `""`+0 rules and denies on `""`+rules; `setDefaultPolicyAction` treats
  anything other than `"allow"` as deny and packs value+revision in one
  monotonic word. Every restore path either guards on non-empty or applies
  unconditionally toward **deny**. No default-allow regression. Validation of a
  bad value produces a warning and then resolves to deny — fail-closed.
- **IP filter fails closed on a corrupt mode**; every mutator publishes an
  immutable view under the writer lock; `buildPrefixSet` never aliases the
  writer's slice; the deliberate exact-address asymmetry between filter singles
  and exemption singles is preserved.
- **Release-catalog authenticity kernel.** ed25519 over the raw index bytes,
  verified before the index is parsed; the verified buffer *is* the parsed
  buffer; key length validated at `TrustStore` construction so
  `ed25519.Verify` cannot panic; enforce mode refuses an empty trust ring;
  artifact-owns-outcome composition closes the strip-one-signature downgrade;
  manifests are hash-bound over raw bytes; `catalogReadBounded` uses
  `Lstat` + `O_NOFOLLOW` + a size bound and refuses symlinks and irregular
  files.
- **Session cryptography.** Constant-time `hmac.Equal` on the recomputed MAC,
  checked **before** base64/JSON decode and before the revocation lookup;
  expiry inside the signed payload and enforced after verification; a 128-bit
  random `jti` per mint; env > config > random key priority with `<32` bytes
  refused on all three inputs and whitespace-only env treated as invalid; key
  reads/writes RWMutex-guarded so the runtime CP rotation is race-free.
- **Role lattice fails closed on both sides.** An unenrolled *requirement* is
  unsatisfiable; `sessionRoleOrReject` refuses every non-empty unenrolled value;
  the roster loader clamps an unenrolled on-disk role to `RoleViewer` while
  preserving the raw value for write-back, so a restored or hand-edited
  `ui_users.json` cannot reach admin.
- **Basic auth has one chokepoint.** `verifyUIBasicAuth` applies, in login
  order, a per-IP reservation, the two-tier lockout, bcrypt, and a hard refusal
  for TOTP-enrolled accounts, with the enrolment check after the password check
  to avoid an enrolment oracle. No request path calls `cfg.VerifyUIUser`
  directly, and a wall test fails the build if a fourth caller appears.
- **TOTP and lockout.** Empty/undecodable secrets never validate; codes compared
  with `hmac.Equal`; the ±1-step counter rejects `candidate <= lastCounter`; one
  canonicalisation serves verify/`SameKey`/`Usable`; backup codes are
  bcrypt-compared and removed on use. The lockout username clamp is injective,
  so an over-long configured name cannot be aliased into a victim's counter;
  `realClientIP` trusts XFF only from a configured trusted proxy.
- **`requireRole` on every non-public route**, including the 3-arg delegates the
  C1.6 resolver cannot follow, verified by hand. No handler checks a role lower
  than its metadata declares.
- **`auditEvent` before `saveConfigVersion`** at every call site; the recorded
  exclusions (password change, CDR hygiene, CDR revoke, YARA rule files, cluster
  mode/tokens/HA, CDR toggle) are intact and correct.
- **No reachable path traversal.** Every filename/path parameter is validated
  before use: `sanitizeYARAName` plus a post-join directory check, bundle ids
  against `^csb_[a-z2-7]{26}$`, cluster cert paths rejecting `..`/`/`/`\`, an
  exact-match allowlist for frontend assets.
- **No secret in a lower-privileged response** other than SEC-HATOKEN-1: every
  other viewer-floor GET reduces credential material to a boolean or a hash.
- **Request smuggling and response splitting.** Both parse boundaries are
  stdlib; the inspect loop re-serialises from the parsed `ContentLength`/
  `TransferEncoding` fields rather than hand-rolled framing;
  `trailerRescrubBody` re-applies identity/topology header deletion at body EOF
  so scrubbed keys cannot ride as late trailers.
- **Destination-authority bounds (CHAOS-69)** are all three reachable and
  correctly ordered: the raw pre-cap ahead of the conn limiter, IP filter, rate
  limiter and auth; the canonical tier ahead of every matcher; the
  unnormalizable fallback closing the band between them.
- **Host-canonicalisation consistency.** Every component that makes a security
  decision about the destination derives it from the same bytes the dialler
  uses; absolute-form proxy requests cannot produce Host/authority confusion;
  inspected tunnels pin enforcement to the CONNECT target, so an inner
  `Host:`/`:authority` cannot redirect off that connection. **The one gap in
  this invariant was the geo key — SEC-GEOHOST-1 — now closed.**
- **Bounded buffering** on the data path: 64 MB request body, bounded scan
  prefix, per-codec decompression bound, pinned H2 frame/header/stream limits,
  pooled relay buffers, an LRU-bounded leaf-cert cache with single-flight
  signing.

---

## 6. Verification

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet .` | pass |
| `gofmt -l` on every changed and added file | clean |
| `go test ./...` — every `internal/...` package | pass (85 packages) |
| `go test .` — root package | 9 failures, **all pre-existing**: the `IdP`/`SAML`/`OIDC` family, which fails identically on a pristine `origin/main` worktree in this sandbox because the fixtures' issuer host resolves to a private address and the URL validator refuses it (`idp oidc issuer: URL must be https:// and must not point to a private address`). **Zero new failures.** |
| `go test -race -count=1 ./internal/hostutil` | pass |
| `go test ./internal/{admission,hostutil,fileutil,alerts,upstream,lockout,logstore,shutdown,blocklistfeed}` | pass |
| `python3 docs/agent-context/check.py` | pass (108 blocks, 450 links, 117 route edges) |

**Every defect gate was verified failing against the verbatim pre-fix body**, by
reverting the production file(s) for each finding in turn and re-running that
finding's suite:

| Finding | Pre-fix result |
|---|---|
| SEC-UISESSION-AUD-1 | eight gates FAIL, led by `DEFECT: handler reached with injected role "admin"` for every portal provider × `role=""` row — and the explicit-role rows came through at their requested role too. The three positive controls PASS pre-fix, which is what a control must do. |
| SEC-HATOKEN-1 | `NonAdminRolesNeverSeeTheJoinToken` and `UnenrolledRoleSeesNoToken` both FAIL |
| SEC-GEOHOST-1 | all four canonicalisation/cache suites FAIL |
| SEC-POLICYACTION-1 | `UnknownActionBlocksAndIsTerminal` and `ResolvedActionsDispatchToTheirBranch` FAIL with `proxy.go` taken from `origin/main`; `PersistableRefusesUnknownAction` and `ReplaceAllDropsUnknownActionKeepsValid` FAIL with the install check disabled |
| SEC-REVOKE-1 | `UnsignedCookieIsNotRevoked`, `ForgedPayloadNeverBecomesRevoked` and `PortalTokenDoesNotRevokeAcrossAudiences` all FAIL |
| SEC-SECPARTIAL-1 | `PartialUpdateLeavesTheRateLimiterAlone`, `NegativeLimitIsRefusedAndChangesNothing` and `ExplicitNullIsTreatedAsAbsent` all FAIL |

Each revert was taken from `origin/main` rather than from the index — an earlier
pass used `git checkout --`, which restores the *committed* file and therefore
compared the fix against itself. That pass is superseded by the numbers above.

Two defects in the first attempt were caught by the full suite and corrected
before this change was finished, and both are worth recording because they are
the kind a narrower run would have shipped:

1. The action gate rejected empty and lowercase actions, which dropped rules
   from three in-tree fixtures — evidence that those spellings are a real shape,
   not a hypothetical. Fixed by `canonicalPolicyAction` (above).
2. `mcpLivePrincipal` was given full admissibility rather than the audience
   half, which refused a four-eyes principal the gate had already admitted
   (`TestLiveTrustHTTP_FourEyesAndRBAC`). Fixed by splitting the predicate.

A third was a flaw in the new tests rather than the fix: `apiAuthUsers`' DELETE
calls `sessionRevoked.RevokeUser`, and that list is a package singleton, so when
the roster-endpoint gate ran against a pre-fix tree its successful delete left
`"bob"` user-revoked and a later positive control failed for the wrong reason.
The audience suite now swaps the revocation list per test
(`conventions.md`, global-test cleanup).

**What CI caught that the local run did not**, recorded because it marks the
limit of the pre-push checks: the `golangci-lint` gate (three findings in the
new test files — the local binary predates the required toolchain and bails out
before analysing anything) and the advisory `Admin-UI RBAC` browser-e2e lane
(the `"action":"deny"` import fixture above, which the local root suite does not
execute). Both are fixed; `staticcheck`'s failure on the first head was the same
unused function `golangci-lint` reported, and cleared with it. `AegisDiff`
reported `ERROR` on both heads with "All LLM providers exhausted … 404 from
api.groq.com" — its own provider outage, no finding, and not a blocking check.

Not run, and therefore not claimed: the hosted Fast/Deep gates, CodeQL, the
benchgate lane, the frontend verify gates and the coverage floor. A passing
local check is not a passing merge gate.

---

## 7. Residual risk

- **R1 (plain-HTTP SSRF) is the largest open item** and the one to decide next.
  Until it is settled, the appliance refuses private destinations on CONNECT,
  WebSocket and SOCKS5 while forwarding them on plain HTTP, and the operator's
  observable signal (`CONNECT SSRF block`) suggests the control is working.
- **The revocation list is still unbounded by construction.** SEC-REVOKE-1
  closes the unauthenticated writer, which was the reachable vector, but
  `RevocationList.tokens` has no entry-count or key-length cap and
  `MergeRevocations` validates nothing it receives from the Control Plane. A
  structural bound — the argument `lockout.MaxUsernameKeyLen` already makes for
  its attacker-keyed maps — would be the defence in depth. Not added here
  because an eviction policy that can drop a *live* revocation would itself be a
  security regression, so it needs its own design.
- **The IDNA memo is a per-process timing oracle.** A hit costs ~54 ns against
  ~719 ns for a miss, so an observer could in principle learn whether a given
  internationalized host was recently normalized by this process. Remote
  measurement through a full proxy pipeline is dominated by far larger variance,
  the table is only 1024 overwritable slots, and no verdict depends on it.
  Informational.
- **An in-DNS-limit IDN sent as a U-label longer than 253 raw bytes is never
  memoized**, so it pays the ~10× per-request IDNA fan-out (~7 µs rather than
  ~0.55 µs). `maxMemoHostLen`'s comment justifies the refusal by saying such a
  host "never reaches the fan-out", which is not true for this shape — it is
  accepted, just not cached. Bounded and far below the ~1.3 ms that CHAOS-69
  already accepts at the 1 KiB raw cap, so no change is proposed; the comment is
  what is imprecise.
- **SEC-UISESSION-AUD-1's fix rests on `Provider` identifying the audience.**
  That holds while each cookie has exactly one minter; the two structural walls
  added here fail the build if a third minter or an unclassified
  `readUISessionCookie` consumer appears. The stronger form — an explicit
  `aud` claim on `Session`, accepted as empty only on the `Provider=="local"`
  path for the pre-RBAC window — remains the right follow-up, and would let the
  empty-role compat branch be retired.
- **R2 means ten support-bundle routes run on a single RBAC layer.** Their
  handler checks are present and correct, so this is a defence-in-depth loss,
  but the C2 counters cannot see it.
