# Security Regression Review — MCP Observe activation + durable telemetry, CHAOS-24 panic containment, async process log (window `3d13f7a` → `6a2960e`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-06
> **Baseline:** `3d13f7a` — head of the previous review's window
> (`docs/security-reviews/2026-08-04-mcp-gateway-signed-feed-category-resolution-window.md`)
> **Head:** `6a2960e` (`main` == `claude/epic-bardeen-1bn4ji`)
> **Scope reviewed:** every code-bearing change in the window — 27 first-parent
> merges (PRs #806–#1059), 171 files, +16,184 / −540.
>
> **Method.** Review was prioritised by *live blast radius*, not diff size:
>
> 1. **Enabled-by-default enforcement code that changed** — the DPI content
>    scanner (runs on every SSL-inspected response body), the process-log write
>    path (runs on every proxied request), audit/request-log persistence, the
>    HA fencing-lease keepalive, config-version integrity, the unauthenticated
>    cluster-bootstrap handler, and every background worker that gained a panic
>    guard.
> 2. **New operator-activatable surface** — the MCP Gateway "Observe" listener
>    (QUAL-1), its static qualification inventory (QUAL-2), and the durable
>    encrypted telemetry plane + local archive exporter (QUAL-3). Reviewed for
>    *inertness of the default*, then for fail-closed correctness of the
>    activation path, then for confidentiality of what it writes to disk.
> 3. **Privileged host tooling** — the quick-start installer's new
>    `heal_maint_proxy_repo` path, which now writes the maintenance agent's
>    image allowlist.
> 4. **Admin-UI surface** — new API fields and ~1,690 lines of new SPA markup,
>    checked for RBAC drift, route/metadata parity and DOM-sink XSS.
>
> Dependency bumps, docs and UX-audit assets were read for intent and checked
> for trust-material changes, but not treated as runtime attack surface.

---

## Executive Summary

**No CRITICAL or HIGH regressions were found in this window.** There is no
authentication bypass, no authorization bypass, no default-allow, no missing
signature validation, no weakened certificate validation, no new SSRF or
open-redirect primitive, and no secret exposure. The build is green and the
governance anti-drift walls (C1/C1.5/C2 route-metadata parity, D0 route
inventory, the config-surface registry, the startup-slice contract) all pass on
the head commit.

The window is dominated by **defensive work**, and most of it is a net security
*improvement*:

- **The DPI ReDoS budget refactor preserves its fail-closed contract exactly.**
  The per-pattern timeout harness was hoisted into one worker, but the budget is
  still charged **per pattern** and is now enforced from **both** sides — the
  parent catches a match still *running* past budget, the worker catches one that
  *finished* past budget. The previously-possible "descheduled parent forgets a
  completed overrun" window (which would have admitted suspicious input instead
  of blocking it) is closed. The pattern set became immutable + copy-on-write,
  removing a real data race between an abandoned worker and a config edit.
- **Audit-log write loss is no longer silent** (CWE-778 / OWASP A09). Every entry
  that fails to reach the durable JSONL file is counted and routed into the
  storage-health plane; a partial write now repairs the line boundary instead of
  corrupting the following record. This directly closes an anti-forensics
  primitive: an attacker able to fill the volume could previously switch off
  durable audit logging with no counter, metric, alert or log line. (The
  guarantee is single-writer only — **F-4** records the concurrent gap.)
- **CHAOS-24 panic containment is correctly scoped.** Every one of the 22 call
  sites guards a *loop body*, never a goroutine, and none is on the request path.
  The one place where containment is a safety rather than an availability
  decision — the etcd fencing-lease keepalive — treats a panicking round as an
  *unconfirmed* round and self-fences when the last confirmed validity window
  closes, so containment can never manufacture the split brain ADR-0005 exists
  to prevent.
- **Two genuine fail-open bugs were fixed inside the window**: `-cdr-fail-mode`
  typos are now rejected on the CLI path (previously any value other than the
  exact string `closed` silently resolved to fail-**open**, the opposite of what
  an operator hardening CDR intended), and an empty MCP policy condition `value`
  is now rejected at compile time (`prefix ""` is vacuously true for every
  present value, so an omitted value silently widened a scope-limited ALLOW into
  an unconditional one).
- **An unauthenticated crash was fixed**: `/api/cluster/bootstrap/compose` with
  no token segment satisfied both the prefix and suffix test but sliced past the
  end of the string, panicking a handler reachable without session auth.
- **The MCP Gateway Observe listener is fail-closed on activation.** Blank values
  resolve to the strongest posture (`client_cert_mode=require`,
  `sender_constraint=mtls`, `min_assurance=high`), a non-HTTPS canonical resource
  is rejected, zero trusted keys is rejected, a JWKS carrying private material is
  rejected, `required_scopes` must be non-empty after empty-string filtering,
  `allowed_hosts` is mandatory and non-empty, `InsecureSkipVerify` is never set,
  `MinVersion` is TLS 1.2, and `ClientAuth` is genuinely wired to
  `RequireAndVerifyClientCert`. Every failure yields an empty runtime config
  (nothing binds) plus a bounded, secret-free classification code.

**Five LOW findings and one carried-forward MEDIUM are recorded below.** None
is exploitable by an unauthenticated remote attacker against a default
deployment. Two of the five (**F-4**, **F-5**) were surfaced by automated review
of this report and confirmed against the code: in each, a durability guarantee
the window set out to establish holds in the single-threaded or steady-state
case but reports a loss to the caller as a success at its edges — a concurrent
audit write, and a log line enqueued after the sink stops draining.

The most important item in this report is **not new**: the MEDIUM
`matchCategory` narrowing found in the previous window (F-1) was re-verified
here and is **still unremediated**.

---

## Risk Rating

| ID | Finding | Severity | Status | Exploitable by |
|----|---------|----------|--------|----------------|
| **C-1** | Source-aware category resolution silently narrows `matchCategory` (carried forward from 2026-08-04 F-1) | **MEDIUM** | **OPEN — unremediated** | No attacker needed; triggered by an operator PUT to a built-in category or legacy feed residue |
| **F-1** | Operator-supplied registry value written into the maintenance-agent `image_allowlist` regex with only `.` escaped, and validated only *after* the privileged config is rewritten | **LOW** | New in window | Local operator misconfiguration (no privilege boundary crossed) |
| **F-2** | QUAL-3 archive exporter writes event envelopes in plaintext while the source spool is KEK-encrypted | **LOW** | New in window | Local read of the archive directory; forward-looking exposure grows when Policy is composed |
| **F-3** | CHAOS-24 containment converts a repeatable background-worker panic from a loud process crash into a metric-only condition — no alert | **LOW** | New in window | Attacker-influenced third-party feed content (threat feed / blocklist / SaaS category feed) |
| **F-4** | Audit boundary-repair state is published outside the writer's mutex, so a concurrent `Add` can corrupt a record and be counted as a **success** | **LOW** | New in window | Requires a failing volume plus concurrent admin-plane writes |
| **F-5** | `logsink.Writer.Write` reports success for lines enqueued after the drain goroutine has stopped — a silent post-`Close` drop | **LOW** | New in window | Shutdown-window only |
| **I-1** | `initCDR` uses stdlib `log.Fatalf` instead of `logFatalf` | INFO | New in window | n/a |
| **I-2** | `syslog.Writer.Panics()` counter added but surfaced nowhere | INFO | New in window | n/a |
| **I-3** | Process-log lines in flight are lost on abrupt process death (SIGKILL/OOM) | INFO | Accepted, documented | n/a |

> **F-4 and F-5 were raised by automated review on this report and confirmed
> against the code.** Both are narrow, but both are cases where a loss is
> reported to the caller as a success — the precise property the window's
> durability work set out to establish — so they are recorded as findings
> rather than as corrections to the prose.

---

## Security Findings

### C-1 — CARRIED FORWARD (MEDIUM, still open): source-aware category resolution silently narrows `matchCategory`

**Status.** Re-verified in this window at `policy.go:1540` and
`internal/urlcat/urlcat.go:398`. **The code is unchanged and the finding stands.**
No remediation landed between `3d13f7a` and `6a2960e`.

**The defect.** When the signed-feed effective view is installed (the default on
every node), `matchCategory` serves the built-in SaaS taxonomy exclusively from
`view.LookupHost(host)` — a `host → single category` map with longest-suffix-wins
resolution. The store it replaced was `category → host-set`. Two properties are
lost:

1. **Multi-membership.** `Store.BuiltInHostCategories()`
   (`internal/urlcat/urlcat.go:407`) flattens every built-in entry into one map
   where *later keys win* on collision. A host legitimately in two built-in
   categories is now in exactly one.
2. **Ancestor shadowing.** `effectiveCategoryView.LookupHost`
   (`saas_feed_view.go:120`) walks labels off the front and returns the first
   hit. A nested key registered under one built-in category shadows an ancestor
   key registered under another, so the ancestor category stops matching for the
   whole subtree.

**Both directions are fail-open**: a policy rule keyed on the shadowed category
silently stops matching, with no log line, metric or audit entry.

**Preconditions / exploitability.** The compiled seed has neither shape, so a
fresh install is byte-identical. The shape is created by an operator PUT adding a
host to a built-in category (operator role, an ordinary administrative action) or
by legacy raw-feed residue already persisted in `cat.json`. Not remotely
triggerable; the risk is a policy that quietly stops enforcing.

**Notable.** The signed feed's own producer gate
(`internal/urlcatfeed/readiness.go`) already rejects exactly these two dataset
shapes (`multi_category`, `suffix_conflict`). The same invariant was simply never
applied to the `catStore`-derived embedded baseline that every node runs today.

**Suggested fix (unchanged from the previous report).** Apply the producer gate's
invariant to the `catStore`-derived baseline in `embeddedBaselineEntries()`, and
on any detected conflict fall back — **loudly** (log + metric + operator-contract
row) — to the pre-F3b-4 full-store `catStore.MatchesHost` path rather than
serving a silently narrowed view.

**CWE / OWASP.** CWE-863 (Incorrect Authorization) · OWASP A01:2021 Broken Access
Control. **Regression risk of the fix:** low — the fallback restores the exact
pre-F3b-4 behavior.

---

### F-1 — LOW (new): unvalidated registry override written into the maintenance-agent image allowlist (validate-after-write)

**Files.** `scripts/install.sh` — `heal_maint_proxy_repo()` (new), and its two
call sites in `install_maint_agent()`.

**What changed.** The window added a self-heal that propagates
`CULVERT_RELEASE_PROXY_REPO` / `CULVERT_PROXY_REPO` into
`/etc/culvert-maint/config.toml`, rewriting **both** `proxy_repo` and its paired
`image_allowlist`. Before this window nothing propagated the override, so the
allowlist stayed at the packaging default. This is therefore a **new write path
to a security control** (the allowlist that bounds which image references the
`culvert-maint` agent will accept).

**The gap.** The replacement regex is built as:

```sh
escaped="$(printf '%s' "$wanted" | sed 's/\./\\./g')"
new_allow_line="image_allowlist = '^${escaped}(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})\$'"
```

Only `.` is escaped. Other ERE metacharacters present in `$wanted` — `*`, `+`,
`?`, `[`, `]`, `(`, `)`, `{`, `}` — pass through with their regex meaning intact.
The value is also interpolated into a TOML **basic** string
(`proxy_repo = "$wanted"`) with no quote validation.

The function deliberately (and correctly) refuses to touch an operator-edited
config: it rewrites only when both lines are byte-identical to the packaging
default (`grep -qxF`). The defect is not *when* it writes but *what* it writes.

**Attack scenario.** An operator sets
`CULVERT_PROXY_REPO='registry.example.com/[a-z]*'` (or any value carrying a
bracket expression or quantifier). The installer writes
`image_allowlist = '^registry\.example\.com/[a-z]*(:…|@sha256:…)$'`, widening the
allowlist from one repository to every lowercase path under that host. A value
containing `"` breaks the TOML line outright.

**Why LOW, not higher.** No privilege boundary is crossed — the operator already
runs the installer under `sudo`, and the value is their own env var. The sudoers
`docker pull`/`docker tag` entries bind `{proxy_repo}` as a **rendered literal**,
so a widened allowlist alone does not grant extra pull capability at the sudo
boundary; it only relaxes the agent-side check. `reject_unsafe` in
`packaging/culvert-maint/install.sh:76` already blocks whitespace, quotes, pipe
and control characters — which removes alternation (`|`) and shell/TOML quoting
as vectors, and would `die` on a quote. That last point is itself the secondary
defect: **validation runs only after the privileged file has been rewritten**, so
a rejected value leaves `/etc/culvert-maint/config.toml` carrying a broken
`proxy_repo`, the sudoers un-rerendered, and the installer merely `warn`s and
returns 0.

**Suggested fix (safe implementation).**

1. Validate `$wanted` **before** any write, with the same strictness the
   packaging installer applies afterwards — a bare repository reference only:
   `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?(/[a-z0-9._-]+)+$`. Refuse to heal
   (and `warn`) on a non-match, leaving the default config intact.
2. Escape **all** ERE metacharacters when building the allowlist literal, not
   just `.` — e.g. `sed 's/[][^$.*+?(){}|\\]/\\&/g'`. Keep the existing
   plain-bash/`printf` construction (the comment correctly explains why `awk -v`
   must not be used here).
3. Write to a temp file, run the validation, and only then `install` over the
   real config — so a rejected value can never leave a broken privileged config
   behind.

**Required tests.**
- *Positive:* a valid custom repo heals both lines; the rewritten allowlist
  matches `repo:tag` and `repo@sha256:<64hex>`.
- *Negative:* `registry.example.com/[a-z]*`, `reg.io/culv*`, `reg.io/x(y)` are
  each **refused** and the config is left byte-identical to the default.
- *Boundary:* a repo with a registry port (`127.0.0.1:5000/culvert`) still heals.
- *Malformed:* a value containing `"` or `'` is refused before any write; assert
  the config file's mtime and contents are unchanged.
- *Regression:* the escaped dots stay literal (the existing assertion) **and** a
  `*` in the repo cannot become a quantifier.
- *Idempotence:* a second run against an already-healed config is a no-op.

**CWE / OWASP.** CWE-20 (Improper Input Validation) · CWE-625 (Permissive Regular
Expression) · OWASP A05:2021 Security Misconfiguration.
**Regression risk of the fix:** low — it only *narrows* what is accepted.

---

### F-2 — LOW (new): the QUAL-3 qualification archive is plaintext while its source spool is encrypted

**Files.** `mcp_telemetry.go` — `qualArchiveExporter.Export`, `archiveBatch`,
`newQualArchiveExporter`, `buildMCPTelemetry`.

**What changed.** QUAL-3 composes an encrypted, capability-isolated event spool
(KEK from a model-B `secret.FileProvider`, never in YAML/CLI/env — a good
design) and then adds a **node-local archive exporter** that writes the same
events to `<export.directory>/<capability>/<partition>/<batch_id>.json` as
**plaintext JSON** (`json.Marshal(archiveBatch{… Events: batch})`).

**The delta.** The spool is encrypted because these envelopes are considered
sensitive at rest. `evmodel.Event` embeds `IdentityEvidence`, whose fields
include `Tenant`, `PrincipalID` (the token subject id), `ClientID`, `AgentID`,
`ToolName`, `ResourceRef` and the identity `Chain`. The archive removes that
at-rest protection for the same data on the same host.

**Current exposure is limited.** In the shipped QUAL-3 posture Policy is not
composed, so `commitDecisionAllow` is unreachable and only the **denial lane**
commits on live requests. `routeDenial` (`internal/mcp/runtime/events.go:150`)
populates only `Tenant` and a **token digest** as the principal, plus a stable
reason code and a listener-scoped source bucket — no raw subject id. The
disabled-by-default gate means an unconfigured node writes nothing at all.

**Forward-looking exposure is the real point.** The exporter is generic. The
moment Policy is composed (an explicitly planned later slice), `decisionFacts`
begins committing raw `PrincipalID`, `Tenant`, `ToolName`, `ToolFingerprint`,
`ClientID` and `AgentID` — and the *same* exporter will archive all of it in
plaintext with no further review gate.

**Secondary issue.** `buildMCPTelemetry` calls
`os.MkdirAll(exportDir, telemDirPerm /* 0700 */)`. `MkdirAll` does **not**
tighten an existing directory, so an export root pre-created at `0755` (or a
mounted collection volume — which is the archive's whole purpose) keeps the
looser mode while the code reads as if `0700` were guaranteed. Individual batch
files are correctly `0600` via `fileutil.AtomicWrite`.

**Attack scenario.** Any local principal that can read the export directory (a
sidecar collector, a backup agent, another container sharing the volume, a
misconfigured `0755` root) obtains the identity metadata that the KEK-encrypted
spool exists to protect — without needing the KEK.

**Suggested fix.**
1. Verify (and, where the process owns it, `os.Chmod`) the export root to `0700`
   after `MkdirAll`, and refuse activation with a bounded classification code
   (`export_directory_permissive`) if the resolved mode is group- or
   world-readable. Fail closed, consistent with the rest of the activation path.
2. Document the plaintext-at-rest property explicitly on the
   `qualification_telemetry.export` config block and in the operator docs, so it
   is a stated posture rather than an implicit one.
3. Before Policy is composed, decide the archive's identity policy deliberately:
   either pseudonymize `PrincipalID`/`Tenant` on the archive path (the codebase
   already has a pooled, generation-bound pseudonym HMAC for exactly this), or
   encrypt the archive with the same KEK. Do not let the decision land by
   default.

**Required tests.**
- *Positive:* an archived batch round-trips and contains only safe envelope
  fields; no raw spool frame, encrypted segment or request/response body appears.
- *Negative:* activation is refused when the export root resolves to `0755`.
- *Boundary:* the `max_bytes` cap saturates without dropping (spool retained,
  cursor unadvanced) — already covered; keep it.
- *Authorization:* the archive directory and every batch file are `0700`/`0600`
  after a full export cycle.
- *Regression:* with telemetry disabled, no directory is created and no file is
  written.

**CWE / OWASP.** CWE-311 (Missing Encryption of Sensitive Data) · CWE-732
(Incorrect Permission Assignment) · OWASP A02:2021 Cryptographic Failures.
**Regression risk of the fix:** low; the permission gate is additive and
fail-closed on an explicitly-enabled subsystem.

---

### F-3 — LOW (new): contained background-worker panics are metered and audited, but never alerted

**Files.** `internal/obs/guard.go`, `crashguard.go` (`runGuarded`,
`recordCrash`), and the 22 guarded loop bodies — notably
`internal/threatfeed/threatfeed.go:159,168`,
`internal/blocklistfeed/blocklistfeed.go:163,169`,
`internal/feedsync/feedsync.go:178,187`, `internal/saasfeed/saasfeed.go:213,221`.

**What changed.** CHAOS-24 contains a panic in a long-lived background worker
instead of letting it terminate the process. The containment design is right —
guard the **round**, never the goroutine, so a transient fault costs one interval
and self-heals rather than becoming a silent permanent stall. The two dangerous
cases (the reqlog drain, which owns a blocking queue, and the fencing-lease
keepalive) are handled explicitly and correctly.

**The detectability gap.** `recordCrash` increments
`culvert_crash_records_total{component}`, writes a system-actor
`panic_recovered` audit entry, stores a bounded redacted record, and logs one
ERROR line — **but it dispatches no alert.** The previous behavior (process
death) was loud by construction: every orchestrator, health probe and restart
monitor notices immediately.

**Attack scenario.** The feed workers parse **third-party data** the operator
does not control (URLhaus, OpenPhish, blocklist feeds, the SaaS category feed).
An input that deterministically panics the parser now produces: the loop stays
alive, the round fails every interval, throttling suppresses all but the first
log line per component per interval, and the gateway runs on **indefinitely
stale threat intelligence** while every dashboard stays green. An operator not
scraping and alerting on `culvert_crash_records_total` will not notice.

**Preconditions.** A parser bug reachable from feed content. **Likelihood:** low.
**Impact:** stale threat intel / stale blocklists — a detection gap, not a
policy bypass (the policy engine still default-denies).

**Suggested fix.** Fire a rate-limited alert from `recordCrash` on the first
crash per component per throttle interval — reusing the existing `fireAlert`
plumbing and the existing per-component throttle, so no new flood surface is
created. Gate it on `HasSubscriber` per the project's per-producer alert-gate
convention. Add a `panic_recovered` (or `worker_crash_loop`) event name and an
operator-contract row that reports a component whose crash count is still
increasing. **Do not** revert the containment.

**Required tests.**
- *Positive:* a panicking guarded round emits exactly one alert per component per
  throttle interval.
- *Negative:* a healthy loop emits none; the `HasSubscriber` gate keeps the
  no-webhook path allocation-free.
- *Concurrency:* concurrent panics across several components do not exceed the
  throttle budget or evict the audit ring.
- *Regression:* the existing guarantee that the loop survives and self-heals is
  unchanged.

**CWE / OWASP.** CWE-778 (Insufficient Logging) · CWE-390 (Detection of Error
Condition Without Action) · OWASP A09:2021 Security Logging and Monitoring
Failures. **Regression risk of the fix:** low — additive observability only.

---

### F-4 — LOW (new): audit boundary-repair state is published outside the writer's mutex

**Files.** `internal/audit/audit.go` — `persistEntry`, `Add`;
`internal/fileutil/rotating.go:40` — `RotatingFile.Write`.

**What changed.** The window added a line-boundary repair so that a partial
write (a fragment with no terminating newline) is closed off with a leading
newline before the next record, rather than having the next record concatenated
onto it into one unparseable line. The repair itself is correct, and the flag is
honestly re-derived from the bytes actually written. **The publication of that
flag is not serialized with the write it describes.**

**The race.** `Add` deliberately calls `persistEntry` *outside* the package
mutex (`mu` is released before the persist call, so a failing disk cannot block
admin callers), so two `Add`s can be inside `persistEntry` concurrently.
`RotatingFile.Write` serializes the *file* writes under its own mutex — but it
releases that mutex on return, and `needsBoundaryRepair.Store(true)` happens
*after* `f.Write` returns:

```
A: CAS(true→false) = false  →  no repair prefix
A: f.Write(b) → n < len(b)  →  FRAGMENT on disk, RotatingFile mutex RELEASED
                            ←── window ──→
B: CAS(true→false) = false  →  no repair prefix   (A has not stored yet)
B: f.Write(b) → n == len(b) →  complete record appended ONTO A's fragment
B: noteWriteSuccess(path)   →  counted as a SUCCESS
A: needsBoundaryRepair.Store(true)   (too late — B already wrote)
```

**Impact.** The file now contains one unparseable line holding A's fragment plus
B's whole record. A is charged to `WriteErrors()` (short write). **B is not** —
it is reported as a successful durable write and additionally clears the
storage-health degraded state via `noteWriteSuccess`. So an entry is lost from
the durable compliance record while the counter says nothing was lost: exactly
the under-reporting the ST-8 work exists to eliminate, surviving in the
concurrent case.

**Preconditions / exploitability.** Requires (a) a partial write — i.e. the
failing-volume condition the feature targets, where writes fail repeatedly and
the window recurs — and (b) a second `Add` landing inside the window. Audit
writes come from the admin plane, where concurrency is genuinely low, but not
zero: `recordCrash` writes a system-actor entry from arbitrary goroutines, and
the DP push path and API handlers can overlap. Not remotely triggerable on its
own; it degrades the integrity guarantee of the anti-forensics fix under load.

**Suggested fix (safe implementation).** Serialize the *decision and the write*
as one critical section, rather than serializing only the write. A dedicated
persist mutex in `internal/audit` held across `CAS → f.Write → re-derive` is the
minimal change; it must **not** be the existing `mu` (that would put a failing
disk back in front of the ring and the admin callers, which the current design
deliberately avoids). Reusing the writer's own mutex is not sufficient, because
the flag update has to be inside the same critical section as the write.

**Required tests.**
- *Concurrency:* N goroutines calling `Add` against an `io.Writer` seam that
  returns a short write on a chosen call; assert every entry is either present
  and parseable in the file **or** charged to `WriteErrors()` — never neither.
  This is the regression test the current implementation fails.
- *Positive:* single-writer partial write followed by a normal write still yields
  a standalone (already-charged) fragment line plus an intact record.
- *Negative:* a zero-byte write hands the repair back (existing behavior).
- *Boundary:* repair applied exactly once when several writers observe the flag.

**CWE / OWASP.** CWE-362 (Race Condition) · CWE-778 (Insufficient Logging) ·
OWASP A09:2021. **Regression risk of the fix:** low, provided the new mutex is
distinct from `mu` so persistence stays off the caller-blocking path.

---

### F-5 — LOW (new): `logsink.Writer.Write` reports success for lines dropped after shutdown

**Files.** `internal/logsink/logsink.go` — `Write`, `drainLoop`, `Close`.

**What changed.** The process log became asynchronous, with an explicit contract:
the queue is a shock absorber and **not** a load shedder — a full queue blocks
the caller and *no line is ever dropped*. That holds while the sink is running.
It does not hold across shutdown, and the API does not tell the caller so.

**Two paths lose a line while returning `(len(p), nil)`:**

1. **Fast path after the drain goroutine has exited.** `Write`'s first
   `select` sends on the buffered channel and returns success; it never checks
   `stop`. Once `Close` has closed `stop` and `drainLoop` has taken its final
   `drainPending` and returned, a line enqueued afterwards sits in the channel
   forever, unwritten — reported as written.
2. **Queue-full path.** The second `select` has an explicit `case <-w.stop`
   arm that abandons the send (correctly — waiting would hang the caller
   forever) and then falls through to `return len(p), nil`.

Neither path increments `WriteErrors()`, so the loss is invisible on
`culvert_logsink_backpressure_total` and on the write-error surface alike. The
same gap widens if `Close` hits its 5s timeout and abandons a wedged drain
goroutine: every subsequent line is silently dropped for the remainder of the
process's life.

**Impact.** Correctly ordered shutdown is mostly safe — `logCloser` runs last in
the shutdown sequence, so hooks that log before it are drained. The exposure is
anything that logs *after* that point: still-winding-down guarded background
workers, the crash sink recording a panic during shutdown, and detached tunnel
goroutines. Losing a `PANIC_RECOVERED` line or a final hook error during a
shutdown that is itself being investigated is the case that matters.

**Correction to this report and to `CLAUDE.md`.** The "no loss" claim should read
*no loss while the sink is running*; the residual is not only SIGKILL/OOM
(recorded as I-3) but also any line logged after the sink stops draining.

**Suggested fix.** Have `Write` observe `stop` on both paths and charge an
abandoned line to `WriteErrors()` (or a dedicated `Dropped()` counter) so a
post-shutdown drop is counted rather than silent. Keep returning a nil error —
`log.Logger` discards Write errors and a short write would make it retry — so the
counter, not the return value, is the honest signal. Optionally have the drain
goroutine perform one final non-blocking sweep after observing `stop`, narrowing
(though not closing) the window.

**Required tests.**
- *Concurrency:* writers racing `Close`; assert every line is either written or
  counted — never silently absent.
- *Negative:* a line written after `Close` returns is counted as dropped.
- *Boundary:* a wedged sink that trips the `closeTimeout` counts subsequent
  writes rather than reporting success.
- *Regression:* the steady-state no-loss, FIFO and blocking-backpressure
  guarantees are unchanged.

**CWE / OWASP.** CWE-778 (Insufficient Logging) · CWE-392 (Missing Report of
Error Condition) · OWASP A09:2021. **Regression risk of the fix:** low —
counter-only; no change to the steady-state path.

---

### I-1 — INFO: `initCDR` uses stdlib `log.Fatalf`

`main.go` — the new `-cdr-fail-mode` CLI validation calls `log.Fatalf`, while the
rest of the window converted every `logger.Fatalf` to the new `logFatalf` helper
(which flushes the async log sink before `os.Exit`). The stdlib logger writes to
`os.Stderr`, so nothing is lost — but the line does not reach the configured log
file or SIEM, and it deviates from the project's "never `log.Printf`/`log.Fatalf`"
convention. **Fix:** use `logFatalf`. The validation itself is a genuine
fail-open fix and should stay.

### I-2 — INFO: `syslog.Writer.Panics()` is surfaced nowhere

`internal/syslog/syslog.go` added a `Panics()` counter so a recurring formatting
bug is distinguishable from ordinary collector-down drops — but no caller reads
it. It appears on no `/metrics` series, no `/api/stats` field and no diagnostics
row. **Fix:** expose it alongside the existing `Drops()` surface.

### I-3 — INFO (accepted, documented): in-flight process-log loss on abrupt death

`internal/logsink` decouples the process log from the request goroutine. The
contract is explicitly a shock absorber and **not** a load shedder — a full queue
blocks the caller (exactly the pre-change behavior, never worse) and no line is
ever dropped; ordering stays strictly FIFO under a single drain goroutine;
`Close` flushes and `logFatalf` calls `Sync` before `os.Exit`. The residual is
that SIGKILL/OOM can lose the in-flight batch. This is documented in the package
header and in `CLAUDE.md`, and is the correct trade for removing a
process-wide throughput ceiling. Recorded, not a finding.

---

## Regression Analysis

### Verified safe, with the reasoning recorded

**DPI content scanner (`internal/scanner/scanner.go`) — enforcement path, every
inspected body.** The per-pattern ReDoS budget is preserved exactly. The parent
arms one timer for the whole scan but, on fire, charges elapsed time only against
the pattern *currently running* (`budgetRemaining`) and re-arms for the remainder
if that pattern still has budget — arithmetically equivalent to one timer per
pattern. The `startedAt`/`current` publication race is conservative in the safe
direction (a stale `startedAt` inflates elapsed time, i.e. errs toward failing
closed). Timeout still returns `(pattern, true)` — fail closed per S17 — even
when the pattern index is out of range. The worker's own completion check closes
a genuine pre-existing gap: a descheduled parent could previously re-arm against
the *next* pattern's stamp and forget a completed overrun, admitting suspicious
input. The `patternSet` is now immutable and published atomically, removing the
real race between an abandoned worker and `Add`/`Remove` (which used to shift the
shared backing array in place). Goroutine count per scan dropped from P to 1;
the abandoned worker stops between patterns via the `abandoned` flag. `done` is
buffered (cap 1) and written exactly once on every path, so no worker can leak.

**HA fencing-lease keepalive (`ha_lease.go`).** `leaseRenewRound` treats a
panicking round as a round that did **not** confirm the lease — the same
epistemic state as a transport failure — and `fenceIfLeaseWindowElapsed` mirrors
the transport-failure branch including the `haLeaseWriteMargin` safety margin,
using `time.Since` over the monotonic clock so a wall-clock rollback cannot
extend write authority. Containment therefore never extends this node's write
authority by even one tick. This is the correct answer to the split-brain hazard
the guard could otherwise have created.

**Request-log drain (`internal/reqlog/persist.go`).** The guard is on the round,
not the goroutine — correct, because this goroutine owns a *blocking* queue and
an exited drain would wedge every request goroutine in `Add` with no crash and no
alert. `batch.discard()` is load-bearing: `bufio.Writer.Flush` clears its buffer
only after the underlying `Write` returns, so a panicking write leaves the batch
buffered and would replay the poisoned bytes forever. Discarding + charging the
loss bounds it to one batch and makes it visible. The `stop` branch still
converges after a panic because `takePending` has already consumed the entries.

**Audit persistence (`internal/audit/audit.go`).** Every loss path *on the
writing goroutine* is charged — write error, **short write with a nil error**
(the truncated-line case an `io.Writer` seam can produce), and the defensive
marshal branch. The line-boundary repair closes a fragment with a leading newline
so the next record lands intact rather than concatenating into one unparseable
line, and the repair flag is honestly re-derived from bytes actually written (a
zero-byte write hands the repair back). **This holds for a single writer only —
see F-4**: the flag is published after `RotatingFile.Write` has released its
mutex, so a concurrent `Add` can slip between the fragment and the repair and be
counted as a success. Observers are re-entrancy-guarded and panic-contained, and the
documented "observer must not call `Add`" contract is satisfied by the production
observer (`noteStorageWriteFailure` writes no audit entry and dispatches an
audit-free alert). The success observer is correctly wired too — without it, a
node whose only durable writes are audit entries would pin degraded forever after
one transient blip.

**Async process log (`internal/logsink`, `logger.go`).** While the sink is
running: no loss, no reorder, blocking backpressure with a counter. `Close` and
`Sync` are both bounded so a wedged volume degrades the exit path instead of
hanging it — but that bound is also where the guarantee ends, and **the "no loss"
contract does not extend across shutdown (see F-5)**: `Write`'s fast path never
observes `stop`, so a line enqueued after the drain goroutine exits is reported
as written and never is. The JSON-mode record
boundary is correct: `jsonLogWriter` encodes **before** the sink, so the sink only
ever transports complete `{...}\n` lines whose concatenation is valid NDJSON —
had the wrapping been the other way around, batching would have folded several
records into one object with embedded newlines. `json.Marshal` escapes the
message value, so log injection into the JSON structure is not possible.
`setupLogger` has exactly one call site, so the published `logSink` pointer is
never orphaned.

**Config-version integrity (`internal/configver`).** The full-history scan is a
genuine DoS fix: it previously ran per `/api/diagnostics` call, letting any
*viewer* force `max × snapshot-size` of disk+CPU per request. The cache is
invalidated on every write/prune, the lock order is documented and consistent
(`mu → integrityMu`, never the reverse, with `dirSnapshot` releasing `mu` first),
and a valid-JSON-but-zero-version envelope is now correctly excluded from the
rollback list rather than presented as a usable target.

**MCP Gateway Observe activation (`mcp_observe_startup*.go`).** Fail-closed
defaults resolve blank values to the strongest posture. `NewProtectedResourceMetadata`
rejects a non-absolute or non-https canonical resource, and every published value
is precomputed from operator config — the runtime parses no URL and trusts no
request `Host` header, so host-header confusion cannot influence the advertised
resource, the metadata URL or the `WWW-Authenticate` challenge. The RFC 9728
document is served on an exact escaped-path match, is genuinely public (it is
precisely what a token-less client reads), never runs the request pipeline, opens
no stream and touches no session. `mcpLoadTrustedKeys` counts a key only when it
registers under at least one **non-empty** issuer, so a `trusted_issuers` list of
empty strings yields zero keys and trips the `no_trusted_keys` gate rather than
reporting ready with keys that can validate nothing. `readFileClean` rejects
traversal. `assembleGatewayConfig` composes no executor, upstream client,
credential broker, policy or inspection — a bound listener structurally cannot
execute an upstream tool call. Every activation failure closes the opened
telemetry spool (`closeMCPTelemetryOnStartupFailure`) so a fail-closed startup
leaks nothing. `mcpRuntime` is written in `initMCPRuntime`, which runs before
`startAdminUI` on the same goroutine — no data race with the admin readers.

**MCP telemetry durability (`mcp_telemetry.go`).** Path traversal is rejected by
path *segment* (`hasDotDotSegment`), not substring, so legitimate names
containing `..` are accepted while real traversal is not. Every tunable is
clamped. The export cursor is monotonic and advances **only** after a durable
archive acceptance; a cursor-persist failure deliberately leaves it unadvanced,
accepting duplicates (dedupable via unique `EventDigest`) rather than a false
advance. Batch identity is a content-range hash so an identical retry is
idempotent while a conflicting batch under the same identity is rejected. Error
text is reduced to a bounded reason class before it reaches metrics or health.
All Prometheus labels are fixed closed enums (capability ∈ {gateway}, partition ∈
{crit,ord,den}, result ∈ {ok,fail}) — no cardinality-explosion vector.

**MCP qualification inventory (`mcp_inventory.go`).** Bounded read (1 MiB via
`io.LimitReader`), strict decode (`DisallowUnknownFields`, so a typo or injected
field fails closed), id-charset validation, duplicate detection, and a
present-but-invalid file fails activation closed without partially seeding.

**MCP admin surface (`ui_mcp.go`, `internal/mcp/adminapi`).** No new
`mux.HandleFunc` was added, so no route/metadata drift is possible — confirmed by
C1 forward/reverse parity passing on the head commit. Management policy
publication is now rejected at **both** the handler boundary and the service
layer (defense in depth, case- and whitespace-insensitive), preserving the
ADR-0024 D-13 "Management is non-mutating in V1" invariant. New status fields on
`apiMCPOverview` are counts and closed-enum state strings only.

**MCP policy conditions (`internal/mcp/policy/condition.go`).** Rejecting an
empty scalar/set condition value at compile time closes a real fail-open
asymmetry (`prefix ""` is vacuously true for every present value) and aligns the
scalar family with `one_of` and `glob`. Backward compatibility is in the safe
direction: an existing policy carrying an empty value now fails to compile rather
than silently matching everything.

**Cluster bootstrap (`bootstrap.go`).** The added length check fixes an
unauthenticated panic on `/api/cluster/bootstrap/compose`. The prefix/suffix
overlap on the separating slash meant the bare path satisfied both tests while
`len(path) < len(prefix)+len(suffix)`, slicing past the end. This route is
reachable without session auth (its own token is the auth), so the fix removes a
remote crash primitive. No change to the token check itself.

**Release management (`release_api.go`, `release_wiring.go`).** The
`rm.svc == nil` split is safe: the new warning-only manager path returns before
any `rm.svc` dereference, and every other release handler (`refresh`, `current`,
`dispatch`, `resume`) independently gates on `rm == nil || rm.svc == nil` and
returns 503. `sigstore_warn` is a fixed operator-facing string, not attacker
input. **No trust material, verify-mode default, pinned identity or baked root
changed in this window** — the enforce-by-default posture is intact.

**Admin UI (`static/index.html`, +1,689 lines).** Only two new `innerHTML`
assignments across the whole diff, both interpolating exclusively
`escHtml()`-wrapped values into a static SVG-icon wrapper. No
`insertAdjacentHTML`, `outerHTML`, `document.write`, `srcdoc`, `eval`,
`new Function`, or concatenated `href` was added. The new MCP panels build DOM
nodes and use `textContent`.

**Everything else.** `clusterCA.Info()` now surfaces `lastRotationError` — an
internal `crypto/x509` error string, never user input, admin-surface only, and it
closes a silent-failure gap where a stuck rotation was invisible until the CA
expired. `apiAlertsDeliveryHist` adds three integer counters (no secrets).
`checkSyslogFeed` correctly distinguishes "not configured" from "configured but
silently down" by comparing recorded intent against the target actually
connected — a nil-check alone would have reported OK while pointing at a stale
collector. `internal/syslog`'s `deliverGuarded` releases `s.mu` through a defer,
so unwinding never leaves the mutex held.

### Explicitly checked and NOT present in this window

Authentication bypass · authorization bypass · default-allow · missing deny ·
policy-precedence change · session-validation or cookie-security change · CSRF
scope change · new XSS sink · new SSRF egress · open redirect · header injection ·
host-header attack · request smuggling / response splitting / HTTP desync ·
directory traversal · symlink attack · unsafe temp file · privilege escalation ·
weak crypto or downgraded TLS · missing signature validation · certificate-validation
change · new MITM opportunity · replay window change · command injection · SQL
injection · unsafe deserialization · secret exposure in logs, metrics or API
responses · broken RBAC · missing route metadata · config-surface drift.

---

## Attack Scenarios Considered

| Scenario | Outcome |
|---|---|
| Craft a response body that blows the DPI ReDoS budget to slip past content inspection | **Blocked.** Fail-closed on timeout is preserved, and the worker-side check closes the "completed overrun forgotten by a descheduled parent" window that could previously have admitted the body. |
| Race a DPI pattern edit against an in-flight scan to corrupt the pattern list | **Blocked.** The pattern set is immutable and copy-on-write; the pre-change in-place `append`-shift was the actual race and is gone. |
| Fill the disk to silently disable the durable audit trail, then act unrecorded | **Blocked.** Every lost entry is counted and surfaced on `/api/stats`, `/metrics`, `/healthz` and the dashboard; a partial write no longer corrupts the following record. |
| Panic a background worker (via feed content) to take down the gateway | **Blocked** (contained, metered, audited) — but see **F-3**: no alert fires, so the resulting stale threat intel is quiet. |
| Panic the fencing-lease keepalive to keep write authority without renewing (split brain) | **Blocked.** A panicking round is charged against the last confirmed validity window and self-fences. |
| Panic the request-log drain to silently wedge the proxy (every request goroutine parked in `Add`) | **Blocked.** Per-round guard keeps the consumer alive; the poisoned batch is discarded and charged. |
| Crash the gateway with `GET /api/cluster/bootstrap/compose` (no session auth needed) | **Blocked.** Length check added. |
| Reach the MCP Gateway listener on a default install | **Not reachable.** `mcp.gateway.enabled` is false by default; no listener binds, no socket opens, no goroutine starts. |
| Enable the MCP listener with a partially-valid security config and get a weaker-but-live listener | **Blocked.** Every prerequisite failure yields an empty runtime config — nothing binds. Blank values resolve to the strongest posture, not the weakest. |
| Use the `Host` header to redirect the MCP RFC 9728 metadata document or `WWW-Authenticate` challenge at an attacker-controlled authorization server | **Blocked.** Both are precomputed from operator config at startup; the runtime parses no URL and reads no request `Host`. |
| Ship a JWKS containing private key material, or issuers that are all empty strings, to get a listener that reports ready but validates nothing | **Blocked.** `jose.ParsePublicJWK` rejects private material; a key is counted only when registered under a non-empty issuer, so the `no_trusted_keys` gate fires. |
| Force expensive full-history config-version parsing on every `/api/diagnostics` as a viewer | **Blocked.** The scan is cached and invalidated only on write/prune. |
| Read MCP identity metadata from disk without the KEK | **Possible** for a local principal with read access to the export directory — see **F-2**. |
| Widen the maintenance agent's image allowlist via the registry override | **Possible** for a local operator — see **F-1**; the sudoers literal binding still bounds the actual pull capability. |
| Reach a policy rule keyed on a built-in URL category that has silently stopped matching | **Possible** — see **C-1** (carried forward, unremediated). |

---

## Files Reviewed

**Enforcement / always-on:** `internal/scanner/scanner.go`,
`internal/logsink/logsink.go`, `logger.go`, `internal/audit/audit.go`,
`internal/reqlog/persist.go`, `internal/configver/configver.go`,
`internal/obs/guard.go`, `crashguard.go`, `ha_lease.go`, `ha.go`,
`storage_health.go`, `internal/syslog/syslog.go`, `internal/alerts/store.go`,
`internal/upstream/upstream.go`, `internal/threatfeed/threatfeed.go`,
`internal/blocklistfeed/blocklistfeed.go`, `internal/feedsync/feedsync.go`,
`internal/saasfeed/saasfeed.go`, `logstore.go`, `metrics.go`, `connlimit_startup.go`,
`cdr_health.go`, `ca.go`, `enrollment.go`, `dp_enrollment.go`, `bootstrap.go`,
`socks5.go`, `main.go`, `main_shutdown.go`, `cluster_startup.go`,
`observability_startup.go`, `config.go`, `diagnostics.go`, `store.go`, `events.go`,
`admin_settings.go`, `policy.go` (C-1 re-verification), `internal/urlcat/urlcat.go`,
`saas_feed_view.go`.

**New MCP surface:** `mcp_observe_startup_config.go`, `mcp_observe_startup.go`,
`mcp_observe_health.go`, `mcp_runtime.go`, `mcp_inventory.go`, `mcp_telemetry.go`,
`mcp_telemetry_health.go`, `mcp_telemetry_metrics.go`, `mcp_evidence_readmodel.go`,
`internal/mcp/runtime/{oauth_meta,listener,config,events,pipeline}.go`,
`internal/mcp/policy/condition.go`, `internal/mcp/adminapi/{publication,health}.go`,
`internal/mcp/events/{denial,model/model}.go`, `ui_mcp.go`, `ui_mcp_rollout.go`.

**Admin/API/UI:** `ui_config.go`, `ui_security.go`, `ui_policy.go`,
`ui_routes_meta.go`, `ui.go`, `release_api.go`, `release_wiring.go`,
`static/index.html`.

**Privileged host tooling:** `scripts/install.sh`, `docker-compose.yml`, and
`packaging/culvert-maint/install.sh` (read for the downstream validation it
applies to F-1's output).

**Evidence gathered:** `go build ./...` clean; `go test` green for
`internal/{scanner,logsink,audit,reqlog,configver,obs,syslog}`; root-package
`TestC1*`/`TestC2*`/`TestD0*`/`TestConfigSurface*`/`TestSnapshot*`/
`TestUIRoutes*`/`TestStartupSliceContract*`/`TestBenchGate_DPIScan*` all pass at
`6a2960e`.

---

## Residual Risk

1. **C-1 remains open and is the highest-severity item on the register.** A
   silent fail-open narrowing of URL-category policy matching, live by default on
   every node, in an enforcement path. It has now survived two review windows.
   Recommend it be scheduled rather than carried a third time.
2. **F-2 is a decision that has not been made yet, not just a bug.** The archive
   is safe *today* only because Policy is not composed. The exposure changes
   materially the moment the execution/policy slice lands, and nothing in the
   current code forces that decision to be revisited. The permission gate is the
   cheap half; the identity-policy decision is the important half.
3. **F-3 is a detectability trade, and it is the right trade** — but it is only
   complete once the crash counter is alerted on. Until then, operators who do
   not scrape `culvert_crash_records_total` have strictly *less* signal than the
   pre-CHAOS-24 behavior (process death) gave them for free.
4. **The MCP Observe listener is now genuinely activatable.** Its inertness when
   unconfigured was verified structurally, and its activation path is fail-closed
   — but the live request pipeline behind it (authn, sender-constraint, session,
   protocol parsing) now has a production on-ramp. Its crypto and admission
   kernels were reviewed in the previous window; the *composition* was reviewed
   here. A dedicated review of the live pipeline under an enabled listener is
   warranted before any customer is directed to enable it.
5. **F-1's blast radius is bounded by the sudoers literal binding**, which is the
   control doing the real work. The allowlist is the second layer, and the fix is
   small; it should land with the next installer change rather than as an urgent
   patch.
6. **Abrupt-death process-log loss (I-3)** is accepted and documented. It is the
   correct trade for removing a process-wide throughput ceiling, but it does mean
   a SIGKILL during an incident can cost the last in-flight batch of
   POLICY_* lines. Operators relying on the process log for forensics should
   prefer the request log (blocking, no loss) or the SIEM feed.
7. **F-4 and F-5 share a shape worth naming**, because it is likely to recur as
   more of the codebase moves to counted, asynchronous durability: the guarantee
   is established on the happy path and at the single-writer boundary, and the
   *counter* — not the return value — is where a loss is supposed to become
   visible. In both cases the edge case returns success and increments nothing,
   so the loss is invisible on precisely the surface built to reveal it. When
   auditing the next durability change, the question to ask first is not "is a
   loss counted?" but "can any path return success without either writing or
   counting?" Both fixes are small; neither is urgent; both should land before
   the durability contracts in `CLAUDE.md` are cited as guarantees elsewhere.

---

*Reviewed at `6a2960e`. Previous report:
`docs/security-reviews/2026-08-04-mcp-gateway-signed-feed-category-resolution-window.md`.*
