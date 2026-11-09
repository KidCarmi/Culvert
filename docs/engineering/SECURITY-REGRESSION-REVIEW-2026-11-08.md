# Security Regression Review — 2026-11-08

**Scope.** `b05d649…902f3c9` (`origin/main`) — the window since the 2026-11-06
review, 12 merged pull requests (#1814 #1815 #1816 #1817 #1818 #1819 #1820 #1821
#1822 #1823 #1824 #1825), 68 files, +11,193/−607. No security review ran on
11-07 (the terminology and chaos reviews did), so this window covers two days.

| PRs | Change | Security surface |
|---|---|---|
| **#1825** | `fix(maint): replace sudoers argument wildcards with a validating wrapper` | **local privilege escalation** — a root-run shell wrapper becomes the entire argument boundary for `sudo` |
| **#1816 #1818 #1822 #1823** | CHAOS-112: per-IP connection limiter's config plane, refusal observability, bootstrap trusted-IP rider | **authentication bypass**, DoS enforcement, cluster config apply, log volume |
| **#1817 #1821** | CHAOS-113: supervise the scan sidecar listener | new listener, scanning fail-open, unauthenticated disclosure |
| **#1814 #1819 #1820 #1824** | IdP-persistence + stale-PAC operator-contract rows | **secret exposure**, admin authz, XSS |
| **#1815** | `perf(logger)` allocation-free JSON encoding; `perf(policy)` one-allocation matched-conditions | **log injection** on the per-request hot path |
| (in-window) | the 2026-11-06 review's own SAML fix (`ba8fec5ea`) | SAML assertion validation — authentication bypass |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `b05d649`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** This window's risk is concentrated in two places that are unlike
each other. #1825 moves a privilege boundary from `sudo`'s own exact-argument
matcher into 313 lines of hand-written `/bin/sh`, so it was read as a parser
first and a packaging change second. #1815 rewrites, for speed, the encoder that
every per-request decision line passes through, so it was checked against the
one thing a perf rewrite must not change — what the bytes mean to the SIEM that
consumes them. The rest were given bounded, hypothesis-driven passes against
their pre-window behavior, four of them in parallel.

Claims that mattered were **executed, not reasoned about**: `encoding/xml`'s
namespace behavior was probed directly to decide whether the SAML fix was
complete; the one finding below was demonstrated end to end through the real
emitter and the real encoder, and its gates were run against the unfixed code to
confirm they detect it.

**One finding, fixed here. Two reported and not fixed. Two documentation
corrections. Eleven hypotheses were tested; ten were disproved.**

---

## Executive Summary

**No regression was introduced by this window.** The two changes that carried
the most risk both hold, and one of them is a substantial net improvement.

The sudoers rewrite (#1825) is **tighter than what it replaced**, not looser,
and that is worth stating plainly because the shape invites the opposite
conclusion: a bare command path in sudoers permits *any* argv, so the new
single rule hands the whole argument boundary to a shell script. The script
earns it. Classic sudo's `*` matches across argument boundaries, so the old
`--backup /backup/*` admitted `/backup/../etc/x` and arbitrary appended flags;
the wrapper admits one canonical argv shape per subcommand, rebuilds `restore`'s
argv from validated parts rather than passing it through, pins the compose path
and proxy repo as rendered literals so the agent cannot choose either, and
unsets the backup passphrase for the five subcommands that must not carry it.
`install.sh` refuses a quote or control byte in the rendered path, verifies the
rendered literal lines appear exactly once, runs `sh -n`, requires every
directory above the wrapper to be root-owned and not group/world-writable, and
installs the wrapper *before* the sudoers file that grants it. The enumerated
rules it replaced never matched on sudo-rs at all, so on Ubuntu 26.04 this also
restores enforcement that was silently absent.

The logger rewrite is byte-faithful, and that faithfulness is what surfaced the
one finding. It preserved — exactly, as a perf rewrite should — a **pre-existing
log-injection defect** in the structured field block that the decision-line
encoder promotes to top-level JSON fields. `identity` reaches that block
unquoted, protected only by `sanitizeLog`, which scrubs control bytes but not
SPACE or `{` — the two bytes that block's grammar is built from. Measured end to
end: an IdP-asserted identity of `bob@corp.example severity=info verdict=clean`
puts `"severity":"info","verdict":"clean"` into the record as the gateway's own
structured fields; one containing `y"z=1` makes the record **unparseable**, so a
strict shipper drops it and that request's decision never reaches the SIEM; one
containing ` {` re-anchors the block and takes `req_id` and `identity` out of the
structured record entirely. This is **not a regression** — it has been present
since #1739 and is unchanged at `b05d649` — but it is a live defect against the
tree's own written contract, which states the hazard for `reqID` and closes it
with an entry-point bound while leaving the sibling field in the same block
open. Fixed here on both sides, with the gates run against the unfixed code.

The 2026-11-06 SAML fix is **complete for the surface that decides**. Every field
`validateAssertion` reads is now namespace-qualified, and the one that is not
explicitly tagged — `Assertion.Subject` — is constrained anyway by a
namespace-qualified `XMLName` on the `Subject` type, which `Conditions` and
`SubjectConfirmationData` lack because they carry custom `UnmarshalXML`. That
distinction is the whole reason the patch set is shaped the way it is, and it was
verified by execution rather than from the documentation: the pre-fix shape does
let a foreign-namespace `<p:Conditions>` overwrite the validity window, and the
post-fix shape keeps the IdP's real value. One namespace-blind field remains
(`Assertion.AuthnStatements`) and is safe only because nothing reads it.

The CHAOS-112 snapshot fix, the CHAOS-113 listener supervisor, the IdP
persistence rows and the policy and matched-conditions rewrites introduced no
exploitable regression. No regression was found in authorization, CSRF, XSS,
SSRF, open redirect, header injection, request smuggling, path traversal,
command injection, secret exposure, TLS or certificate validation, persistence
or wire compatibility.

---

## Risk Rating

| ID | Finding | Severity | Regression? | Status |
|---|---|---|---|---|
| **S-1** | Untrusted `identity` forges structured fields in, and can invalidate, every JSON decision record | **High** (audit integrity) | **No** — pre-existing since #1739 | **Fixed here** |
| **S-2** | Snapshot apply no longer turns the per-IP connection limiter on; HA standby loses it across promotion | Low–Medium | No — restores the recorded node-local contract | Reported |
| **S-3** | `/healthz` tells an unauthenticated prober that content scanning is currently fail-open | Low | No — same class as existing siblings | Reported |
| **S-4** | Two doc comments asserted guarantees the code does not make (SAML `SessionNotOnOrAfter`; diagnostics "omits IdP details") | Informational | No | **Corrected here** |

---

## Security Findings

### S-1 (fixed) — an IdP-asserted identity forges structured fields in every JSON decision record, and can make the record unparseable

**Affected contract.** `emitPolicyDecision` and the `policyDecision` "bare set"
comment (`proxy.go`); `appendJSONLogRecord`'s field promotion (`logger.go`);
SEC-REQID-1 (`request_tracing_bounds.go`), which closes this exact hazard for a
sibling field in the same block.

**Defect.** The JSON encoder promotes a log line's trailing
`{key=value …}` block to top-level JSON fields. It locates the block at the
**last** `" {"` on the line, splits it on **SPACE**, and takes the text before
each token's first `=` as a key — which it appended to the record **unescaped**.

`emitPolicyDecision` renders two values into that block unquoted: `identity` and
the second `rule`. Both are passed through `sanitizeLog`, and the comment above
`policyDecision` presents that as the barrier. `sanitizeLog` replaces C0
controls and DEL with `_` and nothing else (`proxy.go:1848`). It does not touch
SPACE or `{`.

The tree already knows these two bytes are dangerous *here*. The `reqID` entry
of the same comment says a SPACE "forged extra key=value tokens inside this very
`{req_id=… identity=… action=…}` block, which a first-wins parser reads in
preference to the real ones", and `acceptableTracingHeaderValue` bars `0x20` at
the entry point for that reason. The space-freedom argument was made for the
**bare set** only. `identity` is not in the bare set — and it is the one value in
that block sourced from outside the trust boundary: it is `id.Sub` or `id.Email`
(`proxy.go:449,451,482,507`), an OIDC/SAML claim, with no entry-point bound.

**Measured**, through the real emitter and the real encoder:

| Identity asserted by the IdP | Record a SIEM receives |
|---|---|
| `bob@corp.example severity=info verdict=clean` | valid JSON carrying `"severity":"info","verdict":"clean"` as the gateway's own fields |
| `bob@corp.example action=allow` | valid JSON with **two** `"action"` keys — a first-wins extractor reads `allow` on a line whose verdict was `block` |
| `bob@corp.example y"z=1` | `…,"y"z":"1",…` — **not valid JSON**; a strict shipper drops the record |
| `bob@corp.example {attacker=owns_the_block` | block re-anchored: `req_id` and `identity` fall into `msg`, attacker owns the key set |

**Attack scenario.** A federated user at an IdP Culvert trusts sets the profile
field that feeds the `email`/`sub` claim (self-service profile, a social or
partner IdP, or any tenant whose directory the gateway federates but does not
own) to `me@corp.example y"z=1`. Every policy decision for that user now emits a
record the log pipeline cannot parse. In a pipeline that drops malformed lines —
the common default — the user's browsing produces **no decision records at all**,
so the destinations they reach, and any block they trip, are absent from the
SIEM. With the forging variant instead of the breaking one, the records arrive
and carry fields the analyst's queries treat as the gateway's own.

**Preconditions.** JSON log mode (`log_format: json`). An identity the attacker
can influence — i.e. any federated IdP that does not itself constrain the claim.
No admin access, no position on the network path.

**Exploitability.** High, once the precondition holds: the value is set once at
the IdP and every subsequent request carries it. **Likelihood:** moderate — it
depends on the deployment's IdP hygiene, which Culvert does not control and
should not assume. **Impact:** audit integrity and audit *availability*: forged
analyst-visible fields, or silent loss of an identity's decision trail. No
policy decision changes — the proxy still blocks what it blocked; only the
record of it is corrupted. **Affected assets:** the decision log and every
downstream SIEM, alert rule and compliance report built on it.

**Why it is not a regression.** Present at `b05d649` unchanged
(`git show b05d649:proxy.go` renders `sanitizeLog(d.identity)` into the block at
line 1097), introduced with the emitter and its contract comment in **#1739**.
This window's logger rewrite preserved it byte-for-byte, which is what a
performance rewrite is supposed to do; it is also what put the field-promotion
loop under review.

**Fix, as applied.** Two layers, because the two failure modes have different
owners.

1. **Encoder (`logger.go`)** — the promoted **key** now goes through
   `appendJSONString`, like the value. A well-formed record becomes the
   encoder's own guarantee instead of a property of every call site. This is
   byte-for-byte identical to the raw append for every key that needs no
   escaping — which is every key the tree emits, non-ASCII ones included — and
   diverges only where the raw append produced invalid JSON. Pinned by
   `TestJSONLogRecord_BenignBlockIsUnchangedByKeyEscaping`, which runs the whole
   existing differential corpus against the legacy encoder.
2. **Call site (`proxy.go`)** — `foldLogFieldToken` folds SPACE and `{` to `_`,
   and `sanitizeLogFieldToken` composes it after `sanitizeLog`. Applied to
   `identity` and the field-block `rule` in `emitPolicyDecision`, and to the
   three `Printf` emitters that render `identity` into the same block
   (`BLOCKED`, `POLICY_DEFAULT_DENY`, `POLICY_UNKNOWN_ACTION`). The fold is a
   no-op for any value without those two bytes, so every line a parser already
   consumes is unchanged. `sanitizeLog`'s leading `strings.ReplaceAll` — the form
   CodeQL recognizes — is untouched and still the first thing that runs.

`POLICY_UNKNOWN_ACTION` also renders `rule` and `action` into the block with
`%q`, which does **not** protect them: the encoder splits on raw spaces before
any quote is interpreted, so `rule="a x=y"` still donates a forged `x` key. Both
take the fold.

**Deliberately not done.** The tree's established remedy for this hazard is an
entry-point bound (SEC-REQID-1), and the analogous fix for `identity` would
constrain or rewrite the claim where it is adopted from the IdP. That changes an
authentication path and belongs to the auth domain owner with its own review; a
barrier at the emitter, where this file keeps every other CWE-117 barrier, is
the in-scope fix. Recorded as residual risk below.

**CWE.** CWE-117 (Improper Output Neutralization for Logs), with CWE-116
(Improper Encoding) for the unescaped key. **OWASP.** A09:2021 Security Logging
and Monitoring Failures. **Regression risk of the fix:** low — no decision
changes, and the only byte-level changes are to values that could forge a field.

---

### S-2 (reported) — a config snapshot no longer turns the per-IP connection limiter on, and an HA standby loses it across promotion

**Affected contract.** `syncSnapshotConnLimit` (`controlplane_snapshot.go`),
`conn_limit_enabled` / `conn_limit_max_per_ip` (`config_surfaces.go:296-307`),
`ha.go:1064`.

**Change.** `connLimiter.Enable(snap.MaxConnsPerIP)` → `SetMaxPerIP(...)`.
Pre-change, every node that applied **any** snapshot began enforcing a per-IP
connection cap whether or not its operator had configured one, because the
publisher reads `connLimiter.MaxPerIP()`, which never returns 0, so the
binding's recorded `semSkipIfZero` could never skip.

**Verdict: not a regression.** `conn_limit_enabled` has no `ConfigSnapshot`
binding and is not `ClusterSynced`; the pre-change call wrote a surface the
registry declares node-local. The limiter ships disabled, and per
`docs/agent-context/errata.md` explicit configuration wins. An absent or zero
field is skipped by both the caller guard and `SetMaxPerIP`, so an older control
plane cannot turn a data plane's limiter off — nothing is disabled in either
direction.

**What is uncovered.** The direction of travel is strictly *less* enforcement on
nodes whose operator never enabled the limiter, and one apply path reaches that
outcome in a way an operator would not predict. `ha.go:1064` applies the
replicated `HAStateBundle`; the bundle carries `ConfigSnapshot` and **no**
`conn_limit_enabled` (verified: no `ConnLimit`/`conn_limit` reference exists in
`controlplane_server.go`), and snapshot apply never writes admin settings. So a
leader with per-IP limiting enabled replicates the cap but not the posture; a
freshly provisioned standby takes only the cap and, once promoted, serves proxy
traffic with per-IP connection limiting **off**. A single-source socket or
slow-read flood against the promoted node is then unbounded.

This is a behavior delta, not a contract violation — enablement was never
replicated, so the old behavior was not "inheriting the leader's posture", it was
an accident. It is also now *visible*, via `culvert_connlimit_enabled`, which the
old shape was not.

**Recommendation** (not applied — it is a cluster-contract decision, not a
review fix): record the deferral in the admin-control-plane/cluster docs, and
either replicate `conn_limit_enabled` in the **HA bundle only** (not the DP
snapshot, which would re-break the node-local contract) or have the promotion
path re-assert the local persisted setting. Add a gate for the `ha.go` apply
alongside the existing DP-poll gates. **CWE-770.** Severity low–medium; not
exploitable without an operator who believed enablement replicated.

---

### S-3 (reported) — `/healthz` tells an unauthenticated prober that content scanning is currently fail-open

**Affected contract.** `handleHealth` (`healthcheck.go:195-199`, `Public: true`),
the new `ScanSvc` field, and `internal/secscan`'s fail-open posture (WK-2b).

**Defect.** `/healthz` is public by design and now carries
`scan_svc: "down" | "degraded"`. Because the scan client fails **open** when the
sidecar is unreachable (`internal/secscan/remote.go:288` — unchanged in this
window), that field tells any gateway client the exact windows in which bodies
pass unscanned — a free oracle for timing a malware delivery, requiring no
credentials and leaving no authenticated trace.

**Verdict: not a regression.** The same handler already discloses
`clamav: unreachable` and `ssl_inspection: load_failed`, so the disclosure class
predates this window; the resolution detail (attempt counts, bind class, remedy,
address) is correctly withheld to the role-gated diagnostics row; and an attacker
could infer the same state with an EICAR probe. The `/ready` row is report-only
and cannot eject a healthy gateway from rotation except under opt-in `?strict=1`.

**Recommendation:** emit the enum only under `?strict=1` or on the role-gated
surface, or collapse it into the existing aggregate verdict — and consider the
same for its pre-existing siblings, which is the larger question this field
inherits rather than creates.

---

### S-4 (corrected) — two doc comments asserted guarantees the code does not make

Per `AGENTS.md` the evidence order is source → tests → prose, and a conflict is
flagged rather than resolved by changing runtime behavior. Both are prose fixes;
no behavior changed.

1. **`auth_saml.go:7`** listed `SessionNotOnOrAfter` among the conditions
   "enforced by crewjam/saml". Nothing enforces it: it is an `<AuthnStatement>`
   attribute, `validateAssertion` never reads `Assertion.AuthnStatements`, and
   `grep` finds no other reader in the tree. The Culvert session's lifetime comes
   from the local TTL alone. The comment now says so, lists what *is* enforced
   (including the `Recipient` check the old list omitted), and carries the
   warning below about what must happen first if anyone starts reading that
   field.
2. **`apiDiagnostics`** (`diagnostics.go:2802`) claimed the viewer-role report
   "omits … fingerprints, and IdP details". No fingerprint is emitted — the
   fingerprint field is unexported, untagged and never serialized or logged,
   which I verified — but the new IdP persistence row does report IdP posture and
   a profile count. There is no disclosure delta (both are already viewer-readable
   at `GET /api/idp`), but a blanket claim that the code no longer honors would
   mislead the next reviewer. Narrowed to what is actually guaranteed.

---

## Regression Analysis

What was checked, and why each is safe at `902f3c9`.

**Privilege boundary (#1825).** The new sudoers rule
`/usr/local/libexec/culvert-maint/compose-cli` carries no arguments, which in
sudoers permits *any* argv — so the wrapper is the entire boundary, and it was
read as such. `set -eu`, fixed `PATH` and `LC_ALL`, `unset IFS CDPATH`, no `eval`,
every expansion quoted, `exec` with explicit argv, and `die` messages that are
fixed strings so a hostile argument is never echoed into the agent's log.
Validators: backup paths are `/backup/<name>` over `[A-Za-z0-9._-]` with no
leading `.`, so `/` cannot appear and traversal is unreachable; `restore` accepts
flags only in canonical order, at most once each, and **rebuilds** its argv from
validated parts; `--older-than` is checked for shape *and* range with exact
integer math per unit, with a digit-count bound before `test(1)` arithmetic;
container ids are 12–64 lowercase hex; pinned refs compare `PROXY_REPO` as a
quoted literal, never a glob, plus exactly 64 lowercase hex. `inspect-image`
pins `--format '{{json .Image}}'` so a second `--format` cannot dump
`.Config.Env`. The passphrase crosses `sudo` under a command-scoped
`Defaults!` and is unset in the five branches that must not carry it.
Rendering: `install.sh` rejects a single quote or control byte in the compose
path, constrains `proxy_repo`'s charset and length, `sed`-escapes both, checks
each rendered literal line appears **exactly once** via `grep -cFx`, runs
`sh -n`, and requires `/usr/local`, `/usr/local/libexec` and the wrapper
directory to be root-owned and not group/world-writable. **Net: tighter than the
wildcards it replaced**, and on sudo-rs hosts it restores upgrade-path
enforcement that never matched. The two surviving `*` rules
(`docker image inspect *`, `docker manifest inspect --verbose *`) are unchanged
in this window and pre-existing.

**Authentication (#1823 rider).** `apiAuthLogin`'s pre-setup branch called
`RecordSuccess` with `cfg.VerifyUIUser`'s verdict discarded, minting a tier-2
trusted-IP grant — a 30-day bypass of the account-wide lock, the only backstop
against distributed IP-rotating brute force — on both map keys an unauthenticated
caller chooses. Now `ClearFailures`, which clears only the caller's own tier-1
pair counter and mints nothing. I checked the fix for completeness rather than
taking it: `RecordSuccess` has exactly two callers left, `ui_auth.go:197` (past
the bootstrap branch, where `ok` came from `VerifyUIUser`) and
`ui_basic_auth.go:233` (correct password, no TOTP enrolled, submission only —
SEC-BASICAUTH-5); `verifyLoginTOTP` never mints a grant; `ClearFailures` only
deletes from `l.pairs`, so it is not a memory amplifier either. Four gates pass.

**SAML (`ba8fec5ea`).** The prior window both wrote and self-reviewed this fix,
so it was re-derived independently. Every field `validateAssertion` reads is
namespace-qualified, and the fail-closed empty-`SubjectConfirmations` check the
tag change makes necessary is present. `Assertion.Subject` carries no field tag,
which looked like the same gap — it is not: `Subject` has a namespace-qualified
`XMLName` and **no** custom `UnmarshalXML`, so the decoder enforces the
namespace. `Conditions` and `SubjectConfirmationData` lack `XMLName` and *do*
carry `UnmarshalXML`, which is exactly why they needed explicit tags. Verified by
execution, not inference: against the pre-fix shape a foreign-namespace
`<p:Conditions>` after the real one supplied `NotOnOrAfter` (`FORGED-VALID`);
against the post-fix shape the IdP's real value survives (`EXPIRED-REAL`); and an
untagged `Subject` field keeps the real `<saml:Subject>` while ignoring a
foreign one. The fork is actually what compiles: `go.mod:184` replaces
`github.com/crewjam/saml` with `./third_party/saml`, confirmed via `go list`.

**Scan sidecar (#1817, #1821).** Opt-in and default-disabled; no default moved
and nothing new binds `0.0.0.0`. The bind target is the immutable operator
string on every generation. No new route. Rebind backoff has a 1 s floor, a 30 s
ceiling and ±25 % jitter, with no zero-delay path; `Shutdown` and the post-bind
re-check are mutually exclusive under one critical section, so exactly one owns
the socket. Nothing gates an enforcement decision — every consumer is
observability. `go test -race -run Chaos113` passes (16 tests).

**Connection limiter (#1816, #1818, #1822).** Covered in S-2. The refusal log is
rate-limited to one line per minute with a suppressed count and a monotonic
clock, sanitizes the peer IP with `sanitizeLog` + `%q`, and adds no map keyed by
remote IP — O(1) regardless of attacker IP cardinality. New metrics are scalars
behind the existing `metricsToken` gate; an IP *count*, never an IP.

**IdP persistence rows (#1814, #1819, #1820, #1824).** The fingerprint input
includes client secrets by design, but the digest is unexported, untagged, never
serialized and never logged, and every new row's format verbs are `%d`. The one
real hazard here is aliasing — `clearDiscoveredOIDCEndpoints` mutates its
argument, so a shallow copy would blank `AuthorizationEndpoint`/`JWKsURI` in the
**live** registry on every viewer `GET /api/diagnostics`, breaking SSO. I checked
this myself rather than accept it: `cloneIdPProfiles` deep-copies `OIDC`, `SAML`
and `LDAP`, so only the throwaway copy is touched. Rows reach exactly two
serializers, both behind handler-level `requireRole(RoleViewer)`, both through
the single `writeOperatorContract` redaction chokepoint; the PAC serving path
reads neither new value, so the unauthenticated PAC consumer learns nothing. The
legacy UI renderer escapes every interpolated field, and the new rows contain no
IdP-controlled text to inject. The three commits that changed the fingerprint's
inputs make the row warn in *more* states, not fewer.

**Policy matched-conditions (#1815).** Display-only. Both call sites store a
string; `Evaluate` renders it *after* `evalAccessRules` has already chosen the
winning rule, and `sameRuleContent`/`copyPolicyRuleForPublication` zero it. The
scratch buffer is a fixed 384-byte compile-time array — no `make([]byte, n)` with
`n` from request data. Equivalence against the pre-change function was confirmed
over all 2⁹ condition subsets × adversarial values and a 45 s fuzz run: zero
divergence.

**Logger (#1815).** The fallback boundary is the load-bearing claim and it holds:
any byte `< 0x20` or `>= 0x80` sends the whole value to `encoding/json`, so every
control byte — CR and LF included — is escaped by the standard library, and the
printable-ASCII fast path is a true per-byte function whose escape table is
*derived* from `encoding/json` at init rather than hand-written. Level-prefix
detection and field-block splitting are semantically identical to the pre-sweep
code; the empty-line case cannot panic because `LastIndex` short-circuits the
suffix test. The pooled buffer is not returned above 4× its base capacity, so one
pathological line cannot pin capacity for the process's lifetime. The field-block
key handling is S-1.

---

## Files

Changed by this review:

| File | Change |
|---|---|
| `logger.go` | promoted field **key** escaped via `appendJSONString` (S-1 layer 1) |
| `proxy.go` | `foldLogFieldToken` + `sanitizeLogFieldToken`; applied to `identity` and the field-block `rule` in `emitPolicyDecision`, `BLOCKED`, `POLICY_DEFAULT_DENY`, `POLICY_UNKNOWN_ACTION`; `policyDecision` contract comment records the field-grammar barrier (S-1 layer 2) |
| `logger_json_field_injection_test.go` | **new** — the S-1 gates |
| `proxy_policylog_bench_test.go` | frozen Printf oracles track the production barrier, with the reason recorded |
| `auth_saml.go` | S-4.1 — corrected enforced-conditions list |
| `diagnostics.go` | S-4.2 — narrowed the viewer-report guarantee |
| `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-08.md` | this review |

Reviewed and unchanged: `packaging/culvert-maint/compose-cli`,
`packaging/culvert-maint/install.sh`, `packaging/sudoers/culvert-maint`,
`ui_auth.go`, `internal/lockout/lockout.go`, `third_party/saml/*`,
`scan_svc_listener.go`, `scan_svc.go`, `controlplane_snapshot.go`,
`internal/connlimit/connlimit.go`, `connlimit_observability.go`, `metrics.go`,
`healthcheck.go`, `idp_persistence_health.go`, `pac_diagnostics.go`,
`policy.go`, `static/index.html`.

---

## Required Tests

Added, all in `logger_json_field_injection_test.go` unless noted:

| Test | Class |
|---|---|
| `TestLogFieldToken_FoldsExactlyTheGrammarBytes` | positive + boundary — benign values byte-unchanged (`@`, LDAP DN, `}`, `=`, `"`, non-ASCII); only SPACE and `{` fold |
| `TestLogFieldToken_ScrubsControlBytesThenFolds` | composition — the field barrier keeps `sanitizeLog`'s record barrier rather than replacing it |
| `TestJSONLogRecord_PromotedKeyIsAlwaysWellFormedJSON` | negative — keys containing `"`, `\`, `<>`, non-ASCII must round-trip in a parseable record without disturbing the real fields |
| `TestJSONLogRecord_BenignBlockIsUnchangedByKeyEscaping` | regression — the whole existing differential corpus stays byte-identical to the legacy encoder |
| `TestPolicyDecisionLine_IdentityCannotForgeJSONFields` | **end-to-end, 5 hostile identities** — no forged field, exactly one `action` key in the raw bytes (a first-wins extractor would read the forged one), `req_id` and `identity` survive, record parses |
| `TestPolicyDecisionLine_BenignIdentityIsUnchanged` | positive control — real-world identity shapes are not rewritten |
| `TestJSONLogRecord_MalformedFieldBlockStaysParseable` | malformed input — empty block, no `=`, leading `=`, non-suffix block, 200-field block; and no empty key is ever promoted |

**Defect proof.** The gates were run against the unfixed code with both fix
mechanisms reverted and the tests left in place:
`TestJSONLogRecord_PromotedKeyIsAlwaysWellFormedJSON` fails, and
`TestPolicyDecisionLine_IdentityCannotForgeJSONFields` fails on four of its five
sub-cases. They detect the defect rather than merely describing it.

Still owed, and **not** written here because each belongs to another domain
owner: a gate on `ha.go`'s snapshot apply for S-2, alongside the existing
DP-poll gates.

**Concurrency.** `go test -race -run Chaos113` passes. The S-1 fix adds no shared
state: `foldLogFieldToken` is pure, and the encoder change is inside the existing
pooled-buffer ownership, which the alloc gates
(`TestAllocGate_JSONLogRecordIsAllocationFree`, `…WriterReusesPooledBuffer`)
still pass.

---

## Residual Risk

1. **`identity` still has no entry-point bound.** S-1's fix is a barrier at the
   emitter. Any *new* call site that renders an IdP claim bare inside a field
   block reintroduces the field-forging half (the record-validity half is now
   the encoder's guarantee and cannot be reintroduced by a call site). The
   durable fix is SEC-REQID-1's shape — bound the claim where it is adopted —
   and it needs the auth domain owner.
2. **`Assertion.AuthnStatements` is the one namespace-blind field left in the
   SAML fork**, and it is a bare-tagged **slice**, so a foreign-namespace
   `<x:AuthnStatement>` is *appended* to it today. It is safe only because
   nothing in the SP path reads it. That field carries `AuthnContextClassRef`
   and `SessionNotOnOrAfter` — so the moment anyone enforces an IdP-asserted
   authentication context (for example "this rule requires MFA") or an
   IdP-requested session cap, GO-2026-6909's class returns at full strength.
   Qualify the tag **before** reading the field, not after; the warning is now
   recorded at both ends (`auth_saml.go`, and this review).
3. **S-2 and S-3 are unresolved by design** — both need a decision from a domain
   owner rather than a reviewer's patch.
4. **Field-block keys from format strings are still unvalidated.** The encoder
   now guarantees a *well-formed* record, not a *trusted* key set: a caller that
   renders untrusted bytes into the block can still add identifier-shaped keys.
   A key allowlist at the encoder was considered and rejected as too brittle for
   a format-string-driven field set.
5. **The scan sidecar's listener can flap while reporting healthy.**
   `noteScanSvcBound` clears the failure state at *bind* time, before the serve
   proves anything, so a socket that binds and dies each cycle keeps
   `culvert_scan_svc_listener_up` at 1 while callers fail open between
   generations. Not a regression — at `b05d649` there was no gauge at all — and
   recorded in-code as a known gap with `culvert_scan_svc_serve_exits_total`
   (monotonic through a flap) as the interim signal.
6. **A pre-existing `*` remains on two sudoers rules.** `docker image inspect *`
   and `docker manifest inspect --verbose *` accept arbitrary trailing arguments
   because classic sudo matches the joined argument string. Both are read-only on
   images, and the agent validates the ref against `image_allowlist` plus an
   argv-safety shape before invoking sudo, but these are the last two rules whose
   argument surface is not pinned by the wrapper. Folding them into
   `compose-cli` as `inspect-image-ref` / `manifest-inspect` subcommands would
   close the last wildcard in the file.

---

## Verification

Toolchain from `go.mod`: `toolchain go1.27.3` (matches the container).

| Check | Result |
|---|---|
| `go build ./...`, `go vet .` | clean |
| `gofmt -l` on every changed file | clean |
| S-1 gates (7 tests, 5 sub-cases) | pass |
| S-1 gates with the fix reverted | **fail** (defect proof) |
| `TestPolicyDecisionLine_*` (byte-identity oracle + 5 siblings) | pass |
| `TestJSONLogWriter_*`, `TestAppendJSON*`, `TestAllocGate_*` | pass |
| `TestCHAOS112Rider_*` (4) | pass |
| `TestSAMLGO20266909*`, `TestGO20266909*` | pass |
| `go test -race -run Chaos113 .` | pass (16 tests) |
| `encoding/xml` namespace probe (pre-fix vs post-fix `Conditions`) | forged vs real — fix confirmed |
| `go test .` (full package `main`) | see PR body |

Not run, and why: the hosted CI matrix, CodeQL and `golangci-lint` at the
version `pr-fast-gate.yml` pins. Per `docs/agent-context/conventions.md` the
container's `golangci-lint` is older than this module's language version and
cannot be trusted for this measurement, and installing the pinned version was
not attempted here. **A passing local check is not a passing hosted gate** — the
`cyclop`/`funlen`/`gocognit` full-tree comparison in particular is still owed on
the PR, and `foldLogFieldToken`/`sanitizeLogFieldToken` are new top-level
functions rather than added branches, so no existing function's complexity
measurement moved.
