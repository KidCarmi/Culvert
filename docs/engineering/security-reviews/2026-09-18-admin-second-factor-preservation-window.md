# Security regression review — admin second-factor preservation (SEC-TOTP-1)

> **Window:** 2026-09-18 · **Scope:** admin-plane authentication, authorization, session, and
> request-processing surfaces at `origin/main` (`e21e673`).
> **Outcome:** one MEDIUM regression found, reproduced against the real handlers, fixed, and
> walled. Everything else reviewed in this window is recorded below as reviewed-and-safe, with
> the reason it is safe, so the next reviewer does not re-derive it.

---

## 1. Executive summary

Culvert's admin plane enforces TOTP as a genuine second factor: `apiAuthLogin` refuses to issue a
session for an enrolled user until `verifyLoginTOTP` accepts a code, and `verifyLoginTOTP` feeds
failures into the two-tier lockout so the 6-digit space cannot be brute-forced (`ui_auth.go`).

**A password change silently destroyed that second factor.** `Config.SetUIUser` and `Config.SetAuth`
both assigned a freshly-constructed `&uiAdminUser{passHash, role}` over the existing roster entry,
so every credential write dropped `totpSecret`, `backupCodes` and `totpLastCounter`. The removal was
durable (the next `SaveUIUsersFile` persisted it), unaudited, unannounced, and required no proof of
possession of the authenticator.

This inverts what the second factor is for. TOTP exists precisely so that a compromised password is
not sufficient — and here, whoever held the current password could permanently remove the control
that outranks it.

Fixed by carrying the enrolment across the credential write through a single constructor,
`newUIAdminUserPreservingTOTP`. De-enrolment stays the job of the explicit `ClearTOTP` primitive.
The one path that legitimately still removes a second factor — the `--reset-password` break-glass —
keeps its outcome, but now does it deliberately and says so on stdout.

## 2. Finding SEC-TOTP-1 — credential write silently de-enrols the second factor

| | |
|---|---|
| **Severity** | MEDIUM (HIGH where TOTP is provisioned) |
| **CWE** | CWE-304 (missing critical step in authentication); CWE-620-adjacent (unverified credential change); CWE-778 (the removal was not logged) |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **Regression risk** | HIGH — three independent call paths, no test pinned the invariant, and the destructive write looked like ordinary struct construction |
| **Status** | ✅ CLOSED |

### Affected assets
The admin-plane roster (`/data/ui_users.json`): `totpSecret`, `backupCodes`, and the
`totpLastCounter` replay guard, for any admin, operator or viewer account.

### Reachable paths (all three reproduced)

| Path | Who can call it | Primitive |
|---|---|---|
| `POST /api/auth/change-password` | any principal from **viewer** up, for its own account | `SetUIUser` |
| `POST /api/auth/users` | admin, for **any** account | `SetUIUser` |
| `POST /api/settings/auth` | admin (runtime, not boot-only) | `SetAuth` |
| `--reset-password` (host shell) | operator with container access | `SetUIUser` — **intended**, see below |

### Attack scenario

1. An attacker obtains an authenticated admin-plane session for an enrolled account together with
   its current password — a stolen or replayed session cookie, an unlocked workstation, or (per the
   separately-tracked HTTP Basic path) a credential-only authentication that never reaches
   `verifyLoginTOTP`.
2. The attacker calls `POST /api/auth/change-password` with the current password and any new one —
   or simply the *same* value re-entered, which the handler accepts.
3. The account's TOTP secret, backup codes and replay counter are gone and persisted as gone.
   Every later login for that account is single-factor.

**Preconditions:** an authenticated session plus knowledge of the current password.
**Exploitability:** trivial — one ordinary API call, no race, no malformed input, no privilege
needed beyond viewer-for-self.
**Impact:** a *temporary* credential/session compromise is converted into *durable* password-only
access to the admin plane of an in-line security gateway. The victim has no signal: the change is
audited as `auth.password_change`, which says nothing about 2FA.

### The counter is a finding on its own

Even where the secret is re-provisioned out of band with the same value, resetting
`totpLastCounter` to `0` reopens the OTP replay window that `SetTOTPLastCounter` exists to close
(RFC 6238 §5.2). The project already treats that regression as security-relevant elsewhere: the
restore path refuses a TOTP counter rollback unless the operator passes `--allow-counter-rollback`
(`restore.go`, `docs/operator/docker-compose-backup-restore.md`). A password change performed it
silently and unconditionally.

### Why this was invisible

`ClearTOTP` — the explicit, intended de-enrolment primitive — **has no production call site at
all**. Reading the code for "where does a second factor get removed?" therefore returns nothing,
because the only removal in the tree was an unintended consequence of struct replacement. The
`--reset-password` hardening comment in `main.go` already worried about "destroying … TOTP
enrollment", but only in the roster-wide sense; nobody looked at the single-account case.

### Fix

`store.go`:
- `newUIAdminUserPreservingTOTP(prior, hash, role)` is now the **only** way a credential write
  reaches the roster. It sets the new hash and role and carries `totpSecret`, `backupCodes` and
  `totpLastCounter` over from the prior record (nil ⇒ a brand-new account starts un-enrolled).
- `SetUIUser` and `SetAuth` both go through it.

A **new record is constructed** rather than the stored one mutated in place, deliberately:
`VerifyUIUser` takes the entry pointer under `RLock` and dereferences `passHash` after releasing
it, so an in-place credential write would be a data race on the authentication hot path. The
copy-construct shape preserves the existing publication contract exactly.

`main.go` (`runResetPasswordCommand`): `--reset-password` is the documented sole admin-recovery
break-glass (GAP-IAM-01) and an operator who has lost the authenticator as well as the password
depends on it dropping the enrolment. That **outcome** is unchanged — but it is now an explicit
`ClearTOTP` call rather than a side effect, and it prints a warning naming the account and stating
that it is now single-factor. This is the one place a second factor may be removed without proving
possession of it; it requires host access, and it now says so.

### Correction round — the replay counter belongs to the secret (Codex review, PR #1429)

The first version of this fix claimed the break-glass path was "byte-for-byte unchanged". **That was
wrong on one field, and the review caught it.**

`ClearTOTP` cleared `totpSecret` and `backupCodes` but not `totpLastCounter`. That omission was
harmless only because the very next credential write replaced the whole record and zeroed the
counter as a side effect — the exact side effect this change removes. Once a credential write
PRESERVES the enrolment, the counter outlives de-enrolment, and `verifyTOTPAt` skips every candidate
with `candidate <= lastCounter` (`internal/totp/totp.go`). So the re-enrolment the break-glass
warning explicitly instructs the operator to perform is **refused** until wall-clock time passes a
counter belonging to the authenticator they no longer have — and indefinitely after a clock
rollback. A fix for a security defect had introduced an availability defect on the one path that
exists to restore availability.

Two changes close it, and the second is the security half:

- `ClearTOTP` clears the counter too. With no secret installed the value protects nothing, so
  keeping it can only cost availability.
- `SetTOTPSecret` resets the counter **only when the secret actually changes**. A caller re-issuing
  BACKUP CODES for the same secret must keep it: zeroing it there would reopen the replay window for
  a *live* secret. Resetting unconditionally is the cheapest way to pass the first gate and is
  strictly worse than the lockout it fixes, so it is pinned as a CONTROL
  (`TestSetTOTPSecret_SameSecretKeepsCounter`, verified failing against the unconditional shape).

**The lesson, recorded because it generalises:** a field that was only ever cleared as a *side
effect* has no owner, and the change that removes the side effect inherits it. When a fix makes
state survive where it used to be destroyed, enumerate every field that now survives and ask which
of them was relying on the destruction. Here `totpSecret` and `backupCodes` had an explicit owner
(`ClearTOTP`) and `totpLastCounter` did not — and that asymmetry is invisible until something
preserves the record.

**No new configuration surface, no new flag, no GUI-parity obligation, no change to any
authentication decision.**

### Required tests — all present

`auth_totp_preservation_test.go` (17 gates). Every defect gate was verified **failing** against the
unfixed tree before the fix, and the fix was then mutated twice to prove the gates are not
decorative:

| Category | Gate |
|---|---|
| Negative (defect) | `TestSetUIUser_PasswordChangePreservesTOTP`, `TestSetAuth_PreservesTOTPOfMirroredUser` |
| Negative (defect, real handler) | `TestAPIChangePassword_PreservesTOTP`, `TestAPIAuthUsers_AdminPasswordSetPreservesTOTP` |
| Positive control | `TestSetUIUser_RoleChangePreservesTOTP` (password-empty branch unmoved) |
| Boundary — create | `TestSetUIUser_NewUserHasNoTOTP`, `TestSetAuth_NewUserHasNoTOTP` |
| Malformed input | `TestSetUIUser_RejectedPasswordLeavesTOTPIntact` (a rejected password changes nothing) |
| Durability | `TestSetUIUser_PreservationSurvivesPersistence` (real Save/Load round-trip) |
| Concurrency (`-race`) | `TestSetUIUser_ConcurrentWithTOTPMutators` (credential writer × counter advance × reader × `VerifyUIUser`) |
| Break-glass | `TestRunResetPasswordCommand_ClearsTOTPExplicitlyAndSaysSo` + its silent-when-unenrolled control |
| Structural wall | `TestWall_CredentialWritesGoThroughTOTPPreservingConstructor` |
| Counter lifecycle (correction round) | `TestClearTOTP_ResetsReplayCounter`, `TestSetTOTPSecret_NewSecretResetsCounter`, `TestRunResetPasswordCommand_LeavesNoStaleReplayCounter` |
| Counter lifecycle — CONTROL | `TestSetTOTPSecret_SameSecretKeepsCounter` (an unconditional reset reopens the replay window for a live secret) |

**Mutation evidence.**
Reintroducing the bare `&uiAdminUser{passHash, role}` literal in `SetUIUser` fails the wall **and**
three behavioural gates. Dropping only `totpLastCounter` from the constructor slips past the wall
(which exempts the constructor by design) and is caught by the password-change gate and the
concurrency gate — the two layers are not redundant.

## 3. Adjacent observation — the inert `/api/auth/totp` public prefix

`uiAuthMiddleware`'s public allowlist carries `strings.HasPrefix(path, "/api/auth/totp")`
(`ui_middleware.go`), but **no route is registered under it**. It is inert today, so this is a
latent trap and not a live defect — and it is left in place rather than removed, because removing
it silently would discard whatever forward intent put it there.

Why it matters: a self-service TOTP enrolment/de-enrolment endpoint is naturally viewer-level, and
with no session `uiRole` defaults to `RoleViewer` — so neither the C2 metadata gate nor the
handler's own `requireRole(RoleViewer)` would stop an **anonymous** caller from adding or removing
a second factor. `TestWall_TOTPPublicPrefixIsInert` fails the moment a route lands under the prefix,
forcing that decision to be made on purpose. `TestWall_PublicAllowlistRoutesAreDeclaredPublic` pins
the general form: anything the middleware serves unauthenticated must say `Public: true` in
`uiRoutes`, so metadata can never read "authenticated" while the middleware reads "open".

Note that there is **no TOTP enrolment surface at all** today (no API, no GUI; `SetTOTPSecret` has
no production caller). Enrolment reaches a running appliance only through a restored or
hand-provisioned `ui_users.json`. That is a product gap, not a regression, and is out of scope here
— but it is why this finding is scored MEDIUM rather than HIGH: the blast radius is the set of
deployments that provision 2FA out of band, which is exactly the set the restore path's TOTP
counter guard was built for.

## 4. Reviewed and found safe

Recorded so the next reviewer does not repeat the work. Each line states the property and why it
holds, not merely that it was looked at.

- **Admin-plane path confusion / auth bypass.** `isPublicUIAuthPath` matches the DECODED
  `r.URL.Path` while `http.ServeMux` routes on the ESCAPED path, so `/auth/%2e%2e/api/config`
  reads as public in the middleware. Measured against a real mux: it does **not** reach
  `/api/config` — `%2e%2e` is not `..` to `path.Clean`, so no pattern matches and the request falls
  through to the public static shell. `http.FileServer` cleans its own path, so there is no
  traversal either. Safe, but the divergence is real and worth re-testing if route patterns change.
- **`realClientIP` / X-Forwarded-For spoofing** (`realclientip.go`). XFF is consulted **only** when
  the direct peer is in the configured trusted set; with no trusted proxies it is ignored entirely.
  The right-to-left walk returns the rightmost untrusted hop, `Header.Values` joins repeated field
  lines (so a separate-line append cannot hide the real client), and the result is canonicalised
  via `ip.String()` so two spellings of one address cannot fork a lockout key. Correct.
- **CSRF / CORS** (`securityMiddleware`). Same-origin `Origin` check on POST/PUT/DELETE. The
  `X-Forwarded-Host` alternative match cannot be reached cross-site: a custom header forces a CORS
  preflight, the preflight does not carry it, so `isSameOrigin` is false and no
  `Access-Control-Allow-Origin` is emitted. No PATCH handler exists anywhere in the tree, so the
  `isMutating` set has no gap. Exactly one route is metadata-marked mutating under `MethodAny`
  (`apiIdPRouter`), which is a documented dispatcher.
- **Identity-header spoofing on every forward path.** `X-User-Identity` is deleted at ingress
  (`proxy.go`) and again at egress; the egress scrub reaches the plain-HTTP path
  (`proxy_http.go`), the WebSocket path and the CONNECT-inspect path, and the H1 and H2 inspected
  paths **share** it via `runInspectExchange`, which scrubs the decrypted inner request before the
  round trip. Trailers are re-scrubbed at body EOF. No unscrubbed forward path.
- **Session tokens** (`internal/session`). `Decode` verifies the MAC in constant time before any
  parse, checks the revocation list, then expiry, then user-level revocation — all fail-closed.
  `mac()` does not itself check that a key is installed, but every install path
  (`initSessionSecret`, `initSessionSecretFromConfig`, `applySnapshotSessionSecret`,
  `apiSessionSecret`) enforces ≥32 bytes, and `initSession` runs in the startup init block well
  before `startUI`, so an all-zero-key forging window is not reachable. A defensive
  `HasSigningKey` guard in `Encode`/`Decode` would be cheap belt-and-braces; recorded, not filed.
- **Redirect validation.** `isSafeRedirectURL` requires an absolute http(s) URL whose host resolves
  public (DNS failure is fail-closed); `isSafeCaptiveRedirect` rejects `//` and `/\` protocol-
  relative forms. Both are applied inline at the `http.Redirect` call sites.
- **CLI/YAML validation parity.** The recurring "validated in `config.yaml`, unvalidated on the CLI
  flag" class was swept. `-cdr-default-mode` is the remaining unvalidated security-relevant enum,
  and it fails **closed**: `normalizeMode` maps any unrecognised value to `ENFORCE`. The only cost
  is that the startup banner prints the bogus string while the engine enforces ENFORCE — an
  observability mismatch, not a posture one. Not filed.
- **RBAC.** `uiRole` defaults to `RoleViewer` with nothing in context; `requireRole` writes the 403
  itself and C4 divergence recording never touches the response. Role escalation through
  `apiAuthUsers` is admin-gated and `DeleteUIUser` refuses to remove the last admin.

## 5. Residual risk

- Deployments that already performed a password change on an enrolled account have **already lost**
  that enrolment; this fix prevents recurrence but cannot restore what is gone. Operators who
  provisioned 2FA out of band should re-check `totpEnabled` on `GET /api/auth/users`.
- `--reset-password` still removes a second factor, now including the replay counter so the account
  is immediately re-enrollable. That is deliberate and required for recovery; it is host-access-gated
  and now announced.
- There is no in-band TOTP enrolment surface (§3). Until there is, the `totpEnabled` flag on the
  user list is the only in-band signal that an account is enrolled.
- The HTTP Basic fallback in `uiAuthMiddleware` does not consult `verifyLoginTOTP`. That is tracked
  separately (open PR #1420) and is **not** addressed here; it is, however, what makes the attack
  scenario in §2 cheapest, so the two fixes compose.
