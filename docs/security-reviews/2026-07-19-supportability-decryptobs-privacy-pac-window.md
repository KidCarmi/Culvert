# Security Regression Review — TAC supportability appliance + decryption observability/privacy + PAC enterprise steering + OIDC identity hardening (window d5585d5 → 6349722)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-19
> **Baseline:** `d5585d5` — end of the previous review's window
> (`docs/security-reviews/2026-07-16-maint-journal-policy-draft-import-id-window.md`)
> **Head:** `6349722` (`origin/main`)
> **Scope reviewed:** every code-bearing change in the window — 78 first-parent
> commits (PRs ~#699–#870), reviewed as one orchestrator deep pass over the
> newest nine merges plus four parallel domain deep passes, all verified
> against the working tree at `6349722`.
>
> The window is dominated by: the **TAC supportability appliance M1–M4**
> (`internal/support`, support bundles, sealed export, recipient registry,
> the `diagnose` verb family — #788, #792–#845), the **ADR-0011 decryption
> observability program P1–P3** (dec.\* projection, failure feed, health API,
> trend, panel — #758–#846), **PR3 Option B traffic-log destination privacy**
> (keyed-HMAC pseudonymization — #860/#868/#870), **PR2 autoexclude
> security-generation fencing** (#862), **PAC enterprise steering**
> (profiles/pools/governance — #799/#821/#825), **OIDC identity + policy
> hardening** (#738), **expired-node re-enrollment recovery** (#737),
> **CHAOS-09 `/ready` DP dependency health** (#767), the **M5 diagnose-etcd
> probe + HA failover ring + recovery-bundle pins** (#857/#858/#859), and the
> **prior-review remediation commit** (#736).

---

## Executive summary

**Verdict: no CRITICAL or HIGH security regressions.** The window is
net-strengthening: the OIDC change closes a real identity-spoofing gap
(caller-chosen Basic username can no longer label bearer-token traffic), the
autoexclude security-generation fence strictly *narrows* the decryption-bypass
boundary, the new destination-privacy posture is fail-closed with correct key
containment, the supportability appliance ships with a four-layer fail-closed
redaction pipeline and a pinned no-egress wall, and the prior review's
import-ID confused-deputy (F1, import half) and `/ready` path-leak (F3)
findings were fixed.

Six LOW findings are recorded (none attacker-triggerable without either a
filesystem fault, an already-compromised control plane, or an admin-issued
credential), plus one prior finding whose *class* was re-introduced on a new
row one commit after being fixed:

- **F1 — LOW** (info disclosure, regression of a just-fixed class): the new
  unauthenticated `/ready` row `node_cert` embeds the **raw cert-renewal
  error** (a wrapped gRPC/transport error that can carry the internal CP
  address/port, TLS detail, or file paths). The same window's #736 scrubbed
  exactly this class from the `state_file_*` rows.
- **F2 — LOW** (fail-closed gate inversion on fault): a partial
  `os.RemoveAll` during support-bundle delete/eviction that unlinks
  `state.json` but leaves the artifact behind flips a PENDING bundle to
  READY (absence is grandfathered), making it downloadable without the
  admin approval the mandatory-preview gate requires.
- **F3 — LOW** (audit completeness): the sealed-export audit event records
  the format but **not the recipient** (name or key fingerprint) — the audit
  trail cannot answer "sealed to whom" for the actual exfil event.
- **F4 — LOW** (client-triggerable log amplification): every failed inspect
  handshake now writes an unconditional HIGH-priority `DECRYPT_FAILED` feed
  row (ring + JSONL + history + syslog), deliberately bypassing the per-rule
  quiet flag — a client matched to an inspect rule can mint rows at
  connection rate.
- **F5 — LOW** (defense-in-depth gap): the tolerant PAC profile-compile path
  emits a pool endpoint host into the `PROXY` directive **raw** when
  normalization fails, and the DP snapshot-apply installs profiles/pools with
  only count caps — a `"; DIRECT"`-bearing host reaching the store would
  semantically add a fallback directive. Requires a compromised CP or direct
  disk write (every normal write path is strictly validated).
- **F6 — LOW** (accepted trade-off, recorded): expired-node re-enrollment
  lets any holder of a fresh admin-issued enrollment token claim an
  **existing expired node's identity** and silently inherit its
  admin-assigned labels (hence node-group membership and group-scoped
  config). Token gate, CRL of the superseded serial, audit + alert all
  verified intact.

Prior-review findings: **F1(2026-07-16) import half FIXED / rollback half
OPEN; F2 OPEN (accepted); F3 FIXED (but see F1 above); F4 OPEN (accepted,
packaging untouched); F5 OPEN (unreachable — outer validators still enforce
the floor).**

---

## Security findings

### F1 — LOW: unauthenticated `/ready` row `node_cert` emits the raw renewal error (re-introduces the scrubbed F3 class)

- **Files:** `readyz_dp_health.go:123-131` (Detail embeds `lastErr`);
  producer `dp_enrollment.go:406` (`recordDPCertRenewalFailure(days, renewErr)`),
  `dp_enrollment.go:466` (`fmt.Errorf("RenewCert RPC: %w", err)`); surface
  `pac.go:126-127` (unauthenticated proxy-listener dispatch).
- **Attack scenario:** any client that can reach the proxy port of a DP node
  whose cert renewal is failing reads the CP's internal endpoint/port from
  the gRPC dial error ("dial tcp 10.x.x.x:9443: connection refused"), TLS
  failure detail, or cert-file write paths — and can fingerprint a node
  sliding toward cert-expiry (an opportune target). The same window's #736
  (`healthcheck.go:119-126`) deliberately replaced `state_file_*` details
  with fixed non-path text for exactly this reason; #767 added this row with
  a raw error string the same day. The `cp_poll` row is correctly fixed-text.
- **Preconditions:** DP mode + an active renewal failure (fault-gated).
- **Exploitability/likelihood:** low; **Impact:** internal-topology and
  node-weakness disclosure to unauthenticated clients.
- **Fix:** mirror the #736 pattern — fixed detail
  (`node certificate renewal failing, expires in N day(s) — see server logs`)
  with days-left only; keep `lastErr` in logs/alerts/authenticated
  diagnostics.
- **Tests:** positive (failing renewal ⇒ row present, detail == fixed
  string, no substring of the injected error), negative (healthy ⇒ ok row),
  regression pin alongside the existing `state_file_*` scrub test.
- **CWE-209** (error message information exposure); OWASP A01/A05.
  **Regression risk of fix:** nil.

### F2 — LOW: partial bundle delete/eviction can flip PENDING → READY (approval-gate grandfather hazard)

- **Files:** `ui_support.go:588-601` (`readBundleState`: absent `state.json`
  ⇒ `ready`, deliberate for pre-gate bundles), `ui_support.go:692` (DELETE),
  `ui_support.go:887` (`evictBundleDir`) — both `os.RemoveAll`;
  gate consumers `ui_support.go:666`, `support_export.go:58,182`.
- **Attack scenario:** not directly attacker-triggerable — a mid-removal
  I/O/permission fault that unlinks `state.json` but leaves
  `manifest.json` + `bundle.csb.tgz` yields a listable bundle reported READY,
  downloadable by an operator **without** the admin approval the
  mandatory-preview gate requires. A fail-closed gate inverts to fail-open on
  a filesystem fault.
- **Preconditions:** filesystem fault during delete/eviction.
- **Fix:** remove `bundle.csb.tgz` **first** (before `state.json`) in the
  delete/eviction paths, so a partial removal can never leave an approvable
  artifact; or require an explicit `ready` marker for post-gate bundles.
  (Creation already writes state-first — `ui_support.go:790-797` — which is
  the correct half.)
- **Tests:** simulate partial removal (delete `state.json` only) ⇒ download
  must 403/404; ordered-delete unit test; concurrency test delete-vs-download.
- **CWE-696** (incorrect behavior order) / CWE-636 (fail open); OWASP A04.

### F3 — LOW: sealed-export audit does not record the recipient

- **Files:** `support_export.go:214` (audits `support.bundle.download_sealed`
  with format only); contrast `support_recipients.go:242,290` (registration/
  rotation are fingerprint-audited); `support_exports_audit.go` (history view
  can therefore never answer "sealed to whom").
- **Attack scenario:** an operator seals a bundle to a raw per-request
  X25519 key (`support_export.go:121-133` allows it); the audit trail records
  that a sealed export happened but not the destination key. Combined with
  the (accepted) raw-key posture, exfil attribution is incomplete.
- **Fix:** include `recipient_name` or `recipientFingerprint(pub)` (public
  material, safe to log) in the audit detail for both registry and raw-key
  seals.
- **Tests:** audit-content assertions per the repo's discriminator pattern
  (TEST-NET-2 actor + action + fingerprint substring).
- **CWE-778** (insufficient logging); OWASP A09.

### F4 — LOW: client-triggerable ERROR-row amplification via unconditional `DECRYPT_FAILED` feed rows

- **Files:** `decryption_metrics.go:235-249` (`recordDecryptFailureEntry`,
  quiet-flag bypass documented at `:231-234`); call sites
  `proxy_tunnel.go:626-628,717-718,809-812`, `proxy_tunnel_h2.go:166-171,186-189`.
- **Attack scenario:** any proxy client matched to an inspect rule CONNECTs
  repeatedly to an unreachable port / handshake-incompatible origin; each
  attempt writes a persistent HIGH-priority row to ring + JSONL + history
  store + syslog (previously: one logger line) — retention pressure and SIEM
  noise at connection rate.
- **Preconditions:** proxy access + an inspect-matched destination.
  **Mitigations already present:** per-IP connlimit, bounded ring, rotating
  JSONL, drop-on-full async syslog, history retention caps, parity with the
  pre-existing unconditional block rows — hence LOW.
- **Fix (optional hardening):** per-(clientIP, host) token bucket on the
  *feed write* only (metrics stay unconditional), mirroring
  `crashThrottleAllow`.
- **Tests:** flood test asserting bounded feed growth + unchanged metric
  counts; boundary test at the bucket rate.
- **CWE-400/779**; OWASP A09.

### F5 — LOW: tolerant PAC profile-compile emits unvalidated pool hosts into `PROXY` directives (defense-in-depth)

- **Files:** `internal/pac/compile_profiles.go:24-30` (`PoolDirectives`),
  `internal/pac/compile.go:112-117` (`emitProxyHost` raw fallback),
  `controlplane_snapshot.go:778-781` (DP snapshot-apply installs
  `PACProfiles`/`PACPools` with count caps only, no per-entry
  `ValidateProfilesConfig`).
- **Attack scenario:** all emission is `%q`-quoted so **JS injection is
  impossible**, but PAC clients parse `;`-separated fallbacks *inside* the
  directive string: a pool host of `proxy.corp; DIRECT` (or
  `;PROXY attacker:80`) reaching the store adds a semantic DIRECT/attacker
  fallback for every steered client. Every normal write path (admin API,
  import pre-validation, rollback of canonically-persisted config) is
  strictly validated — reaching the store requires a compromised CP or a
  direct disk write, i.e. an attacker who already controls fleet policy.
- **Fix:** in `PoolDirectives`/`profileTerminal`, skip-with-warning any
  endpoint host failing `hostutil.NormalizeHostStrict` +
  `validHostnameLabels` instead of emitting the raw value (matches the
  compiler's drop-junk-with-warnings philosophy).
- **Tests:** malformed-host pool entry ⇒ endpoint skipped + warning; snapshot
  apply with a hostile pool ⇒ compiled PAC carries no `;` inside directives.
- **CWE-20/74**; OWASP A03.

### F6 — LOW (accepted trade-off, recorded): expired-node re-enrollment allows identity takeover with a valid token

- **Files:** `controlplane_server.go:363-369` (expired node exempted from
  the blanket duplicate-ID denial), `:292-305` (new registration inherits
  `priorNode.Labels` + draining status).
- **Verified intact:** the enrollment token gate is unchanged
  (`ValidateAndConsumeToken`, single-use, unconsumed on the deny path); the
  gate opens only when `CertExpiry` is past per the CP clock (zero expiry
  fails closed); the superseded serial is CRL'd; serial pinning + the mTLS
  handshake exclude the old cert; the swap is logged, audited
  (`cluster.node.reenroll-expired`) and alerted. **No token bypass exists.**
- **Residual delta:** a fresh-token holder can now claim an *existing*
  expired node's NodeID and silently inherit its admin-assigned labels —
  hence node-group membership and group-scoped bandwidth/config targeting —
  where before they could only create a new node. Minor: two concurrent
  enrolls for the same expired NodeID can both pass the `GetNode` check and
  burn two tokens (last `RegisterNode` wins) — admin-gated, negligible.
- **Recommendation:** include the inherited labels in the audit detail.
- **CWE-284**; OWASP A01.

---

## Informational notes (no action required unless noted)

- **I1:** `apiDecryptionExclusions` GET (Viewer, `ui_policy.go:791-833`)
  lists learned exclusion hosts in **plaintext** while the PR3 redaction
  posture pseudonymizes the feed — the two Viewer surfaces disagree on
  destination visibility when redaction is ON. Consider documenting or
  operator-gating the exclusion list under redaction.
- **I2:** the unauthenticated PAC surface widened **by design**:
  `/pac/{id}.pac` (+ auth-allowlist prefix, `ui_middleware.go:237-238`)
  exposes per-group steering topology (pool hostnames/ports, failover
  chains, exclusions) to anyone who can guess a profile ID. Handler is
  tight (regex-pinned IDs, disabled ⇒ 404, host-fallback artifacts uncached,
  `r.Host` character-whitelisted + `%q`). Unguessable profile IDs are the
  operational mitigation.
- **I3:** operators may seal a support bundle to a **raw per-request
  public key**, bypassing the admin-curated recipient registry
  (`support_export.go:121-133`). Not a privilege regression (the same role
  can plain-download the plaintext) — the registry is a safety rail, not an
  exfil-destination control. Reviewed and accepted; F3 (recipient in audit)
  is the compensating control worth adding.
- **I4:** `/api/diagnose/etcd`'s route note says "endpoints never echoed",
  but the bounded `error` field can embed the etcd endpoint address from
  transport error text. Operator-only + operator-configured infra —
  informational; consider stripping addresses for note accuracy.
- **I5:** HA `failover_events` (incl. self-fence reasons that may embed
  lease/keepalive error text, bounded to 256 chars) surface at RoleViewer on
  `GET /api/cluster/ha`. Viewer already sees lease holder/epoch/health there;
  incremental. Consider operator-gating reasons if etcd endpoints appear.
- **I6:** `decryption_failure_feed_test.go:121-124`'s comment claims the
  top-level feed `Host` "stays plaintext" under redaction — true only
  because the test drives the dec-block `redact` param without flipping the
  global posture; in production both derive from `decRedactHosts()` and the
  top-level Host **is** redacted at the `persistLogEntry` chokepoint. Stale
  comment; suggest cleanup to avoid future contract confusion.
- **I7:** plaintext destination hosts persist on surfaces *outside* the
  declared PR3 scope (autoexclude promotion audit events, blocklist store,
  threat-feed hits, `/api/pac/analyze` observed destinations — the last
  aligned with the existing `/api/top-hosts` viewer disclosure). Not a
  violation of the declared contract (`host`/`uri`/`dec.*`/`top_hosts`);
  worth one line in `docs/operator` privacy docs.

---

## Prior-finding status (2026-07-16 report)

| # | Finding | Status | Evidence |
|---|---|---|---|
| F1 | import/rollback persist object-ref IDs verbatim (confused deputy) | **PARTIALLY FIXED** | Import half fixed by #736: `importPolicyRules` calls `stampObjectRefIDs` on replace (`ui_config.go:864-870`) and merge (`:876`); pinned by `TestImport_ReDerivesObjectRefIDs`. **Rollback half OPEN:** `applyConfigBackup` (`configversion.go:365-373`) still installs `b.PolicyRules[i]` verbatim. Mitigated by the new dangling-ID delete guard (`policy_refs.go:136-176`). Recommended: add `stampObjectRefIDs` to the rollback rule loop. |
| F2 | merge-mode import upserts name-colliding live rules | **OPEN (accepted)** | `matchForImport` name-fallback upsert unchanged (`ui_config.go:874-888`); dry-run preview still counts-only. |
| F3 | `/ready` leaks state-file path/parse-error | **FIXED** — but the *class* re-introduced on a new row (this report's F1) | `appendStateFileChecks` now fixed-text (`healthcheck.go:119-126`, #736). |
| F4 | maint systemd sandbox options dropped | **OPEN (accepted, corrective)** | `git diff d5585d5..6349722 -- packaging/` is empty — no packaging change this window. |
| F5 | autoexclude engine doesn't clamp `confirmN ≥ 2` internally | **OPEN (unreachable)** | Engine still floors at `<=0` only (`internal/autoexclude/autoexclude.go:194-196,472-475`); both outer validators enforce `≥2` (`autoexclude_tunables.go:43,102`; `admin_settings.go:430`). PR2's fencing did not touch this. |

---

## Regression analysis — surfaces verified safe

**PR3 Option B destination privacy (#860/#868/#870).** Fail-closed
(posture ON + missing key ⇒ constant sentinel, never plaintext); key is
32-byte `crypto/rand`, minted transactionally before persist, rolled back
(flag AND key) on persist failure; load accepts only exact-32-byte keys
(corrupt ⇒ sentinel, not weak-key HMAC); legacy-B0 upgrade mints from the
*loaded* posture (correct ordering). Key containment: 0600
`admin_settings.json` + the pre-existing backup channel only; no API returns
it (`key_provisioned` bool only); registered `Sensitive` + AdminDurable-only
in `configSurfaces` (off export/import/rollback/CP→DP), wall-enforced. All
request-log writers funnel through the single `persistLogEntry` chokepoint
(Host + URI redacted before entry construction; ring/JSONL/history/syslog
consume the redacted entry); `dec.host`/`dec.sni` use the same keyed helper;
`topHosts` and `fireAlert` payloads redacted in `recordStats`. URI scrub is
whole-host, case-insensitive, boundary-aware, no regex (no ReDoS), covers
host:port and portless forms, sentinels on unparseable+unknown; the
differently-bracketed IPv6 path echo is a documented residual. GET viewer /
PUT admin + CSRF + audit verified; `rotate_key` deliberately preserves the
posture (prevents the omitted-field-decodes-false silent-disable trap).

**PR2 autoexclude security-generation fencing (#862).** Strict narrowing:
`Contains` treats gen mismatch as a miss; `Observe` scopes pending evidence
by gen (no cross-posture confirmation merging); promotion overwrites
stale-gen entries. `computeSecurityGen` covers exactly the
security-effective fields, versioned, 0x00-delimited over a closed ASCII
vocabulary, precomputed at store-write (hot path never hashes), pure
function of synced fields (identical on every node). Rule-level inherited
fields deliberately out of scope with a sound safety argument (cert-verify
failures never learn; inspection-mode axis TTL-bounded). No broadening path
found.

**TAC supportability appliance (#788, #792–#845).** Every
`/api/support*`/`/api/diagnose*` route's metadata matches handler
`requireRole` exactly; all mutating/exfil routes audited. Bundle content
maps into `redact:`-tagged structs — secrets appear only as presence
booleans; four fail-closed redaction layers (untagged ⇒ Sensitive default;
SECRET dropped / SENSITIVE HMAC-masked with a per-bundle never-exported
salt; RE2 scrubber with fail-closed overflow; runtime raw-struct hard-gate +
per-section MaxClass ceiling). Sealed export: NaCl anonymous box
(X25519+XSalsa20-Poly1305) with low-order-point rejection at seal,
registration, and registry read; passphrase envelope PBKDF2-SHA256(600k) →
AES-256-GCM, AAD-bound header, min-iteration floor on decrypt. Path safety:
every `{id}` regex-pinned (`^csb_[a-z2-7]{26}$`) before filesystem use;
recipient names pinned; evictions re-validate. No-egress wall intact with
exact-count seam pins; `diagnose dns/tls` SSRF-guarded twice (resolve-time
private-IP fail-closed block + `ssrfControl` at dial). Retention/DoS caps
serialized, typed `confirm_evict`, TTL-bounded debug elevation.

**Decryption observability (#758–#846).** The load-bearing record-only
invariant CONFIRMED: `resolveSSLDecision` byte-identical in action
computation; every outcome builder is a pure value constructor; every
failure site keeps its prior terminal action (recording is additive). #844
rescue attribution rides the unchanged `clientCertRescueDecision` gate;
`handleTunnelBypass` keeps its inline `isPrivateHost`+`ssrfControl` re-dial.
#846 excludes client-aborts/SSRF only from *metrics*. Metric labels pass
compile-time closed enums (≤144/≤70 series; scope labels fold to
`_other_`); trend ring ≤360; raw error strings never escape the classifiers;
new log lines `sanitizeLog`+`%q`. Log filter is exact-match on
role-visible fields. Panel JS escapes all attacker-influenced values.

**PAC enterprise steering (#799/#821/#825).** Compiler: every host/pattern
strictly normalized or `%q`-escaped; wildcard tolerant path rejects `"` and
`\`; profile-ID comments regex-pinned; scheme allowlist http|https; 1 MiB
caps. CRUD: admin + DP-write refusal + strict validation + `auditEventDiff`
+ `saveConfigVersion`; the typed-DIRECT confirmation guard covers CRUD,
publish, AND rollback under one mutex (no laundering, TOCTOU-safe). Export
carries no credentials; import pre-validates the exact merged candidate and
never wipes on absent fields.

**OIDC/policy hardening (#738) — strengthening only.** Identity now bound
exclusively to introspection claims: non-empty `sub`/`username` required
(fail closed), Basic username can no longer become the authenticated
identity, `sub = username` client-input fallback removed
(`auth_oidc_flow.go:677-679`); `exp` fails closed (null/string/fraction/
out-of-range rejected; flow path now enforces expiry where it previously
ignored it); strict JSON decoding; cache keyed by token only; positive cache
entries must carry an identity. Check ordering verified — no path skips a
previously-enforced check. Policy half: default-deny untouched; immutable
revision publication, ULID rule-ID validation, edit cannot rewrite a stable
ID.

**Maintenance agent (#759/#787).** Journal digest capture only (#759);
#787's `validateReconcileRefs` requires every present ref to pass the same
repo-bound exact-digest gate as the sudoers pattern, zero validatable refs ⇒
not actionable ⇒ fail; `!RefValid` ⇒ loud-stop. The destructive reconciler
remains **unwired** (no non-test callers). `packaging/` untouched this
window.

**M5 slice (#857/#858/#859) + misc.** `diagnose etcd`: operator+, audited,
5s-bounded, `Provider.Read` verified read-only (Get + TimeToLive only),
no-egress wall extended with an exact-count pin; probe target is
startup-scoped operator config (non-SSRF, deliberate). HA failover ring:
bounded (64), mutex-guarded, `boundedErr`-capped reasons, `escHtml`-rendered.
bcrypt 72-byte cap: strictly better (400 instead of bcrypt 500; Go bcrypt
errors rather than truncates, so no silent-truncation hazard). GeoIP #731
gates only the stats tracker; policy-side fail-closed matching untouched.
Syslog drop counter atomic + admin-gated. Static read wall #839 is
test-only (no new file-serving handler; no traversal surface).
`/api/health/explain` viewer-gated posture rows, no secret values.
Admin-settings load observability quarantines corrupt files without
exposing values. CP `GetConfig` secret redaction preserved after the
version-conditional short-circuit. `/api/dpi` aliases keep identical
roles + audit. IdP login shows the admin display name, HTML-escaped; the
machine key is a profile ID, not key material.

**Tests run at head:** `go build` OK; `go test ./internal/autoexclude
./internal/decryptprofile` OK; targeted root-package suite covering
traffic redaction, decryption redaction, secgen fencing, failover ring,
diagnose etcd, decrypt-failure feed, memory backstop, password complexity,
and recovery pins — OK.

---

## Residual risk

- The five documented-and-accepted postures: node-local pseudonym key rides
  the (sensitive) backup channel; 48-bit truncated HMAC tokens
  (pseudonymization, not encryption); PAC topology readable by
  unauthenticated clients holding a profile ID; raw-key sealed export at
  operator role; expired-node identity inheritance behind a valid token.
- The bounded-LWW window on HA partition (≤TTL) and the rule-level
  inherited-field gap in PR2's fingerprint remain the recorded, analyzed
  deferrals from their respective design docs.
- Prior findings F1-rollback-half, F2, F4, F5 remain open as itemized above;
  none is newly exposed by this window.

**Recommended next actions (smallest first):** (1) scrub `lastErr` from the
`/ready` `node_cert` detail (F1); (2) reorder support-bundle deletion to
remove the artifact before `state.json` (F2); (3) add the recipient
fingerprint to the sealed-export audit (F3); (4) `stampObjectRefIDs` in
`applyConfigBackup`'s rule loop (prior F1 rollback half); (5) fail-closed
host validation in `PoolDirectives` (F5).
