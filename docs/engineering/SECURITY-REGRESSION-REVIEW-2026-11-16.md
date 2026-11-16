# Security Regression Review — 2026-11-16

**Scope.** `0b11474…881abf0` (`origin/main`) — the window since the 2026-11-15
review, 15 merged pull requests (#1893 #1895 #1898 #1899 #1900 #1902 #1903 #1905
#1906 #1907 #1908 #1909 #1912 #1918 #1919), 63 files, +6,012/−199.

| PR / round | Change | Security surface |
|---|---|---|
| **#1903** | `perf(ssrf)`: the tunnel pre-flight guard's miss-path DNS lookup is bounded by the request context and a 10 s budget. New `ssrf.PrivateHostBudget`, `ErrLookupBudget`, a `lookupHostFn` test seam, and `isPrivateHostBounded` over the four data-plane tunnel paths | **SSRF guard** — the one change in the window that could have turned a refusal into an allow |
| **#1919 / #1909 / #1898** | `fix(install)`: `SEC-INSTALL-ENVLINK-1` — `env_put` refuses a dangling link at `$file`, never hands a live link to `sudo`, refuses a linked lock path, and fails closed when an at-rest secret never reaches `.env` | **privileged installer file handling**; `.env` holds the stack's secrets. **Finding A is here** |
| **#1899** | `perf(syslog)`: each SIEM line is assembled in one pooled buffer by a retained `json.Encoder`; the drain borrows from the same pool to write the socket. New `internal/syslog/lineformat.go`, plus a benchgate added to three workflows | **audit/request egress integrity** — a pooled buffer that leaks between lines is cross-record disclosure, and a rewritten assembler can drop CWE-117 framing |
| **#1893** | `fix(syslog)`: a SIEM collector unreachable at boot is re-dialled on a bounded backoff. New `syslog_intent_retry.go`; `applyAdminSyslog` split out of `applyAdminServices` | **audit-feed destination control** — a retry that outlives its intent would redirect the audit egress to a superseded collector |
| **#1900 / CHAOS-120** | `fix(crashguard)`: the crash sink fires a `panic_contained` alert for all 63 components; ten previously dark alerts reopened, with twelve new checkboxes in the Alerts panel | **unsafe panic recovery**, **secret egress** (a recovered panic value can embed a credential and a webhook is an egress), alert-plane feedback loops. **Finding B's sink is the panel this extends** |
| **#1907** | `feat(diagnostics)`: an operator-contract row for configuration changes applied without a rollback point. New `diagnostics_config_version_capture.go`; `saveConfigVersionNoteResult` gains a named return | **viewer-readable disclosure** and config-versioning integrity |
| **#1912** | `perf(idp)`: `DisableKeepAlives` on the one-shot OIDC/SAML discovery transports | **authentication** — an IdP document fetch is an SSRF-guarded outbound on the login path |
| **#1908** | `fix(install)`: the RHEL/Fedora cleanup step stops removing `containerd.io`, so a re-run no longer uninstalls the engine running the gateway | **package-source trust** and availability of a security control on a privileged installer path |
| **#1895 #1902 #1905 #1906 #1918** | Diagnostics prose (the `clamav_scan` row and a corrected side-effect claim), three admin API endpoints that do not exist removed from operator docs, the terminology governance record, and test isolation (logstore size accounting, stress-client idle connections) | operator remediation accuracy and test hygiene (no runtime behavior) |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `0b11474`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** Three of this window's changes are of the shape "a security
control's shape changed but its decision did not", which is only worth what the
invariant behind it is worth. Each was checked against the invariant rather than
against its commit message, and the load-bearing assertions in comments were
**re-derived from source**:

- *"Verdicts, caching and fail-closed behaviour are identical"* — the premise of
  the SSRF budget. Confirmed at `internal/ssrf/ssrf.go:265-305`: the cache is
  consulted BEFORE the timer exists, so the hot path is untouched; the budget
  error returns before any `dnsCache.Store`, so **failures are still never
  cached**; and every one of the four call sites treats *any* error as deny
  (`proxy_tunnel.go:95,529,737` return 403; `socks5.go:556` replies `0x02`). The
  deliberate choice NOT to wrap the budget error in `ErrBlocked` is therefore
  safe *because* no caller branches on `ErrBlocked` to decide allow — which is
  the thing that had to be checked, not assumed. The connect-time
  `ssrf.Control` guard still runs immediately before `connect(2)`, so the
  DNS-rebinding TOCTOU window the pre-flight cannot close is still closed where
  it always was.
- *"The payload carries the component and the crash id and NOTHING else"* — the
  premise of `panic_contained` being safe to egress. Confirmed at
  `crashguard.go:260-266`: `Detail` is built from `component` and `rec.ID` only.
  The panic value reaches `rec.Summary` (local, truncated, `sanitizeLog`-scrubbed)
  and never the payload. `component` is a compile-time constant at every call
  site and `rec.ID` is `generateRequestID()`, so no client-supplied byte enters
  the webhook body. `notePanicContained` fires AFTER the record, log line and
  audit entry are committed and past `crashThrottleAllow`, so the alert can
  neither delay nor displace the durable evidence, and `crashAlertLast`'s key
  set is a subset of the throttle's — bounded by `maxCrashLabels`.
- *"A dial in flight when the operator changed their mind is discarded, never
  published"* — the premise that the SIEM retry cannot redirect the audit feed.
  Confirmed: `publishRetriedSyslogWriter` re-reads the pending record under
  `syslogPublishMu` after the dial returns, and **both** transitions that can
  change the answer clear it in the same critical section
  (`disableActiveSyslog` at `syslog.go:188`, `publishSyslogWriterLocked` at
  `syslog.go:253`). The predicate is `syslogConfiguredAddr == addr`, so a
  re-point supersedes a stale dial by identity rather than by timing. The loop
  is a single goroutine, so no retry can race another to publish. Separately
  verified that the live admin re-point does **not** arm a retry — only the two
  boot paths call `armSyslogIntentRetry` — so a 400-refused re-point cannot be
  silently completed in the background later.

Two further assertions were checked and found harmless rather than true as
stated: `applyAdminSyslog`'s comment says it was split out "unchanged" when it
also adds the retry arming (the behavior change is the PR's point, the comment
is simply stale); and `attemptSyslogIntentRetry` interpolates `sw.Format()` into
an audit `Detail` without `sanitizeLog`, where the sibling log line sanitizes it
— safe only because the format is allowlisted to two literals at **both**
ingresses (`ui_config.go:2011` rejects anything else with 400, `config.go:637`
fails validation), so no operator-controlled byte reaches the audit record.
Noted so that a future change which relaxes either allowlist knows it also owns
that audit sink.

**No security regression in the window.** The SSRF budget, the syslog
assembler, the SIEM retry, the crash-plane alert, the diagnostics row, the IdP
transports and the CI benchgate additions all preserve or improve the posture at
`0b11474`. **Two findings, both fixed here**, are pre-existing or incomplete
rather than newly introduced: an installer hardening that did not reach its own
threat (Finding A, High) and an unescaped admin-UI sink reachable from the panel
this window extends (Finding B, High). Five residual risks recorded.

---

## Finding A — `SEC-INSTALL-ENVLINK-1` is enforced only at the site that runs last (High)

**Risk rating: High.** Unprivileged → root, no race required.
**CWE-59 / CWE-61 (link following) → CWE-269 (improper privilege management).**
OWASP A01 (Broken Access Control). **Regression risk: this is an incomplete fix
of a contract landed in this window, so the window shipped the appearance of a
mitigation without its effect.**

### What the contract says

The guard landed in #1919 and records its owner decision as PR #1898/#1909. It
states, in `scripts/install.sh` itself, that `sudo` must never act THROUGH a
symlink at `$INSTALL_DIR/.env`:

> `sudo chown` on a live link hands the TARGET to the invoking sudoer
> (`.env -> /etc/shadow`). Whoever can write the stack dir can plant either.

It enforced that inside `env_put`. Two other functions took ownership of the
**same path** with the **same primitive**, guarded only by `-e`/`! -r` — both of
which FOLLOW symlinks, so only `-L` sees the case:

- `persist_host_env_session_secret` (`scripts/install.sh:1813`, pre-fix)
- `setup_at_rest_encryption` (`scripts/install.sh:1867`, pre-fix)

### Why the existing guard could not help

Top-level call order:

```
2087: setup_at_rest_encryption         <- unguarded sudo chown
2088: persist_host_env_session_secret  <- unguarded sudo chown
2099: env_put … "$INSTALL_DIR/.env"    <- the guarded site
```

By the time the hardened `env_put` inspected the link, the escalation had
already happened.

### Attack scenario

**Preconditions** — exactly the topology the contract's own comments declare in
scope ("a stack dir belonging to ANOTHER user"): `$INSTALL_DIR` (default
`/srv/culvert`, or any `CULVERT_DIR`) is writable by an unprivileged attacker —
a group-writable dir, a shared `CULVERT_DIR`, or a prior install performed by a
different unprivileged user. The attacker needs no `sudo` of their own.

1. Attacker runs `ln -sf /etc/shadow /srv/culvert/.env`.
2. A sudo-capable operator re-runs `install.sh` — the documented, routine path.
3. `setup_at_rest_encryption` evaluates `-e "$envfile"` (true: `/etc/shadow`
   exists) and `! -r "$envfile"` (true: `0640 root:shadow`), and runs
   `sudo chown <operator> /etc/shadow`.
4. The very next line's "Cannot read `$envfile`" warning **no longer fires**,
   because the `chown` just made it readable — so the installer continues and
   the only operator-visible signal is nothing at all.

**Exploitability: high.** A single pre-planted symlink and one ordinary
re-run — no race, no timing window, no PID guessing. The target is
attacker-chosen and arbitrary (`/etc/shadow`, `/etc/sudoers`, `/etc/cron.d/*`,
a systemd unit, `/root/.ssh/authorized_keys`).
**Impact:** the attacker-chosen root-owned file becomes owned by a non-root
account; root's password hash can then be replaced. **Affected assets:** host
root, and through it the gateway's CA key, session HMAC and at-rest passphrases.

### The same root cause, third site

`carry_forward_prior_secrets` early-returns on
`[[ -f "$INSTALL_DIR/.env" ]]`, which is **false for a dangling link**, so a
planted `.env -> /etc/cron.d/x` fell through to
`sudo install -m 600 -o "$(id -un)" "$prior/.env" "$INSTALL_DIR/.env"`. `install`
opens its destination `O_CREAT|O_TRUNC`, which follows the link, so the prior
stack's secrets were written as root to a planter-chosen path. Content is
`KEY=VALUE` lines the planter does not control and mode is `0600`, so this is an
arbitrary-root-write / integrity-and-DoS primitive rather than a clean
escalation — **Medium** on its own, fixed with the same guard.

### Fix applied

All three sites test `-L` **first**. A link is left alone and the existing
warn-and-degrade path takes over, so behavior for a regular file is unchanged:

```bash
if [[ -L "$envfile" ]]; then
  :
elif [[ -e "$envfile" && ! -r "$envfile" ]]; then
  sudo chown "$(id -un)" "$envfile" 2>/dev/null || true
fi
```

`carry_forward_prior_secrets` refuses any link at the destination outright,
since it only ever creates a `.env` that is absent. Fail-closed in every case:
`setup_at_rest_encryption` leaves the passphrases unchanged, and
`persist_host_env_session_secret` takes its documented "could not read" branch.

---

## Finding B — webhook event names reach the Alerts panel unescaped (High)

**Risk rating: High.** `RoleOperator` → `RoleAdmin` session takeover.
**CWE-79 (stored XSS)**, OWASP A03 (Injection) with A01 as the outcome.
**Regression risk: pre-existing.** Reported here because this window adds twelve
new subscribable events to that exact panel (`static/index.html:20102-20159`,
CHAOS-120), so the window increases traffic through an unescaped sink.

### The chain, verified end to end

1. **Ingress is unvalidated.** `POST /api/alerts/webhooks` requires only
   `requireRole(w, r, RoleOperator)` and validates `h.URL` — never `h.Events`
   (`ui_security.go:45-65`).
2. **Nothing downstream constrains it.** `normalizeEventNames`
   (`internal/alerts/store.go:345-362`) maps one retired alias and de-dupes; it
   applies no allowlist and no character check. `NewWriter`-style normalization
   does not exist here.
3. **It is persisted verbatim.** `Store.Add` (`:586`) and `Store.Update` (`:606`)
   write what they are given to the webhook file.
4. **The sink is unescaped.** `static/index.html:11584` interpolates
   `${(h.events||[]).join(', ')}` into `tbody.innerHTML` — while `h.name` and
   `h.url` on the two lines above it both go through `escHtml`
   (`:11582-11583`). That inconsistency is the whole defect.
5. **Every role reads it.** `GET` needs only `RoleViewer`, and the panel is the
   same one admins use.

### Attack scenario

An operator-role account — the lower-privileged role, which exists precisely so
that day-to-day work does not need admin — POSTs a webhook whose `events`
contains `<img src=x onerror="fetch('/api/users',{method:'POST',…})">`. The next
admin to open **Alerts** executes it in their own session: an admin session
carries full configuration and RBAC authority, so the payload can create an
admin user, relax policy, disable scanning or read configuration the operator
cannot. **Preconditions:** one operator-role credential and an admin who opens a
panel they routinely open. **Exploitability: high** — no race, no user
interaction beyond normal navigation, and the payload persists on disk until
removed. **Affected assets:** the admin control plane, and through it policy
enforcement, the roster and the stored secrets its endpoints expose.

### Fix applied — both halves

- **Sink:** `static/index.html:11584` renders through `escHtml`, consistent with
  its sibling cells. This is the authoritative fix, and the only one that helps
  a name **already persisted** before today.
- **Ingress:** `alerts.ValidateEventNames` (new,
  `internal/alerts/store.go`) is applied at both operator-reachable endpoints
  (`ui_security.go`, `POST` and `PUT`), returning 400, so the value never
  reaches the webhook file, a support bundle or any other consumer.

Two deliberate design decisions in the validator, both recorded because the
obvious stricter choice is the wrong one here:

- **A character class, not an allowlist of known events.** The catalog grows as
  rounds add alerts and is discovered by a differential oracle rather than
  declared in one list, so an allowlist would reject a legitimate new event the
  moment it shipped — a silent subscription loss, which is the one failure
  `normalizeEventNames` exists to prevent. Every catalog name and the one legacy
  alias is lowercase ASCII with underscores; the class admits all of them and no
  markup, quote, angle bracket, control byte or newline.
- **The `*` catch-all is admitted as a WHOLE name.** It is a real subscription
  shape honoured by `HasSubscriber` (`:619`) and the dispatch walk (`:742`), and
  it is how an operator subscribes to events added later. Refusing it would
  cause exactly the detection loss above. It is rejected as a character inside a
  longer name, so it cannot smuggle a glob or markup into a string.
- **`Init` (disk) deliberately does not validate**, so a name already persisted
  keeps dispatching instead of being dropped on load. The escaped sink is what
  makes that safe — which is why the sink fix, not the ingress check, is the
  load-bearing half.

---

## Files

| File | Change |
|---|---|
| `scripts/install.sh` | `-L` guard before the self-heal `sudo chown` in `persist_host_env_session_secret` and `setup_at_rest_encryption`; link refused at the `carry_forward_prior_secrets` destination |
| `static/index.html` | webhook events cell rendered through `escHtml` |
| `internal/alerts/store.go` | new `ValidateEventNames`, `maxEventNameLen`, `catchAllEvent` |
| `alerts.go` | `validateWebhookEvents` re-exposed for the admin handlers |
| `ui_security.go` | event-name validation on `POST` and `PUT /api/alerts/webhooks` |
| `install_script_env_selfheal_symlink_test.go` | new — Finding A |
| `alerts_webhook_eventname_injection_test.go` | new — Finding B |
| `internal/alerts/eventname_validation_test.go` | new — Finding B, white-box |

## Required tests — and what each one is worth

Every test below was **mutation-checked**: the fix was reverted and the test
observed to fail with the exploit it claims to prove, then restored. A test that
passes without its fix proves nothing, and this repository has been bitten by
exactly that (the 2026-11-15 review's first harness ran its `sudo` stub at the
test's own dropped privileges and so could not carry out the root action whose
absence it asserted).

- **Finding A, behavioural** —
  `TestInstallScript_PersistSecret_LiveEnvSymlink_IsNeverHandedToSudo`. A live
  `.env` link to a target the invoker cannot read; asserts on the recorded
  `sudo` calls, because the stub runs at the test's own dropped privileges and
  cannot perform the root action. Reverted, it reproduces the escalation
  verbatim: `chown nobody …/stack/.env` where `.env -> …/shadow-stand-in`.
- **Finding A, positive control** —
  `TestInstallScript_PersistSecret_RegularUnreadableEnv_StillSelfHeals`. A
  REGULAR unreadable `.env` must still be repaired, so the guard is narrow
  rather than a disabled feature. This control is also what proves the suite is
  not vacuous: it only passes at a privilege where mode `0000` is genuinely
  unreadable, so the harness drops to uid 65534 via `setpriv` under root and
  skips if that is unavailable.
- **Finding A, drift guard** —
  `TestInstallScript_EnvSelfHealChownSitesAreLinkGuarded` asserts structurally
  that *every* `sudo chown … "$envfile"` in the script has an `-L "$envfile"`
  test above it, and fails if it ever finds no such site (so it cannot pass
  vacuously). `setup_at_rest_encryption` does not extract cleanly for a
  behavioural harness — its first unindented brace falls past the top-level call
  site — and the failure mode here was precisely "honoured at one site, not the
  others", so the contract is pinned over the whole file rather than per
  function. Reverted, it names both sites by line.
- **Finding A, third site** —
  `TestInstallScript_CarryForward_DanglingEnvSymlink_WritesNothingThrough`, with
  `…_NoEnv_StillCarriesForward` as its positive control. The `sudo` stub
  performs the copy with `cp`, which follows a symlinked destination exactly as
  `install` does, so the assertion is on the file system and the effect is real
  at the test's own privilege.
- **Finding B, ingress** — `TestWebhookEventNames_POSTRejectsInjection` (seven
  payload shapes: tag and attribute breakouts, newline, NUL, case, space) and
  `…_PUTRejectsInjection`, each asserting both the 400 **and** that nothing was
  persisted — a 400 that still stored the value would leave it for every later
  reader.
- **Finding B, positive control** — `…_POSTAcceptsCatalogName` and
  `TestValidateEventNames_AcceptsCatalogShapes`, which validate the entire real
  catalog plus the retired alias, individually so a failure names the offender.
  `TestValidateEventNames_AcceptsCatchAll` additionally proves a subscriber is
  still *matched* through `*`, so the shape the validator admits is the shape
  dispatch honours.
- **Finding B, authorization** — `…_AuthorizationStillEnforced` drives a viewer
  with both a clean and a poisoned payload and requires 403 for each: the new
  check must not have become the first gate, and role refusal must still precede
  input inspection.
- **Finding B, concurrency** —
  `…_ConcurrentCreatesRefuseEveryPoisonedOne` interleaves 24 clean and poisoned
  creates across goroutines and asserts no interleaving lets one through, and
  that the store holds no poisoned name afterwards.
- **Finding B, boundary and malformed** —
  `TestValidateEventNames_LengthBoundary` pins both sides of
  `maxEventNameLen` so the bound cannot drift to "no bound" (CWE-770);
  `…_RejectsAnyBadMemberOfAGoodList` proves one poisoned entry refuses the whole
  list rather than being skipped; `…_ErrorNamesTheOffender` keeps the 400
  debuggable; `TestNormalizeEventNames_StillMigratesRetiredAlias` proves the
  validator did not displace the rename migration.
- **Finding B, sink regression** — `TestWebhookEventsCell_IsEscapedInAdminUI`
  pins the render site against the source, because the panel has no JS harness
  and the defect was an escaping inconsistency between adjacent cells.

## Verification

Run at `881abf0` plus the changes above, with the `go.mod` `toolchain`
(`go1.27.4`), not the container default:

- `go build ./...` — clean.
- `go vet ./internal/ssrf/ ./internal/syslog/` — clean.
- `gofmt -l` on every changed Go file — clean.
- `bash -n scripts/install.sh` — clean.
- `go test ./internal/ssrf/ ./internal/syslog/` — pass (includes the
  `TestLineFormat_ByteIdentity_*` differential oracles that pin the rewritten
  SIEM assembler's bytes against the `fmt.Sprintf`+`json.Marshal` form it
  replaces, and the new `lookup_budget` suite).
- `go test ./internal/alerts/` — pass, full package.
- `go test . -run 'InstallScript'` — pass.
- `go test . -run 'Alert|Webhook|Syslog|GUIParity|Parity'` — pass.
- `go test .` (full root package) — see the PR body for the result at the pushed
  SHA.

**Not run, and why:** `golangci-lint` is not run locally — the container's
binary is older than this module's language version and refuses it, which is the
recorded "local lint is unavailable" condition; the gate installs its own pinned
version built with the `go.mod` toolchain. CodeQL, the race suite and the
hosted aggregate gates run in CI. A passing local check is not a passing hosted
review or merge gate. `docs/agent-context/check.py` was not run because
`docs/engineering/*` is not a guidance path in the Fast PR Gate's classifier —
only `AGENTS.md`/`CLAUDE.md`/skill/`docs/agent-context/*` paths are.

## Residual risk

1. **Hardlink at the guarded paths (Low, not fixed).** The `-L` tests cover
   symbolic links only; `-f` is true for a hard link to a regular file. An
   attacker owning the stack dir on a host where `fs.protected_hardlinks` has
   been disabled could hardlink a root-owned regular file on the same filesystem
   to `.env` or `.env.lock` and reach the same `sudo chown`. That sysctl is 1 by
   default on every currently supported Ubuntu/Debian/RHEL/Fedora kernel and
   forbids hardlinking a file you neither own nor can write, which blocks the
   interesting targets. Closing it properly means a link-count check
   (`stat -c %h`) at each site, which is a separate change.
2. **TOCTOU between guard and privileged action (Low, disclosed in-tree).** The
   window between the `-L` test and the `sudo`/redirection that follows is real
   and documented at `scripts/install.sh:1613-1617`; bash has no `O_NOFOLLOW`. It
   requires the attacker to win a race inside a single installer pass rather than
   simply pre-planting, and a genuine close needs the privileged step performed
   by a helper that opens with `O_NOFOLLOW`.
3. **`${file}.tmp.$$` staging fallback (Low, pre-existing).** Reachable only if
   `mktemp` fails in a directory that is writable; a planted symlink there would
   leak `.env` to a chosen path at the ambient umask. Every other secret-bearing
   path is `mktemp`-created or explicitly `chmod 600`.
4. **Config import does not validate event names (accepted).**
   `ui_config.go:1512` reaches `Store.Add` directly, so a hand-crafted import can
   still persist an unusual name. Left deliberately: import is admin-level and
   restores an operator's own prior export, and adding a refusal there risks
   failing a disaster-recovery restore — a worse outcome now that the sink is
   escaped. The escaped sink, not the ingress check, is the security boundary.
5. **`sw.Format()` is unsanitized in the auto-connect audit Detail
   (accepted).** Safe only because the format is allowlisted to two literals at
   both ingresses. A change that relaxes `ui_config.go:2011` or
   `config.go:637` also owns that audit sink.
6. **One unescaped attribute remains adjacent to Finding B's sink (accepted).**
   `static/index.html:11584` also interpolates `${h.id}` into `data-arg`
   unescaped; `h.id` is server-generated (`fmt.Sprintf("%d", time.Now().UnixNano())`,
   `internal/alerts/store.go:589`), so it carries no caller-supplied byte today.
   Noted so a future change that lets a client choose an id knows the sink.
