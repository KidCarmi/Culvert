# Decryption Profile — PAN-OS-style GUI-managed inspection profile

> **Superseded note (production hardening, issue #716):** the deferred
> `CertVerification=permissive` value referenced below was **retired**, not shipped.
> Its documented allow-on-failure enforcement was never implemented (it verified
> like `strict`), so keeping it in the schema was a misleading operator contract.
> `certVerification` now accepts only `strict` and `skip` (plus inherit); a legacy
> `permissive` is fail-closed-migrated to `strict` on load/sync. A genuine
> allow-on-failure posture needs a separate approved design. See
> `docs/operator/decryption-profiles.md`.

**Status:** PLAN (v1, pre-implementation). To be validated by three independent
reviewers (PAN-OS decryption/product, config-architecture/anti-drift, UI/API +
security) before any code — same gate that preceded the native-H2 program and PR3d.

**Why now.** The native-H2 inspection fix (PR #667/#669/#680/#685) is stranded: the
only switch that turns it on — `PolicyRule.StripALPN *bool` — has **no GUI control**
(reachable only by hand-editing rule JSON), violating CLAUDE.md's GUI-parity rule
("CLI-only features are not acceptable"). Culvert already has the "what to match"
half of decryption (policy rules + `sslbypass`); this adds the missing "how to
decrypt" half as a first-class, GUI-managed **Decryption Profile** object, and folds
the H2 toggle + its safety knobs into it. This is the PAN-OS "Decryption Profile"
model.

**Scope discipline (carried from PR3d).** Correctness first; ONE inspection pipeline
(`runInspectExchange`) — no second enforcement path; preserve every H1 + native-H2 +
PR3d invariant; no unrelated refactors. This PR series is **config resolution + a UI
panel feeding existing engine behavior** — it introduces no new protocol code.

---

## 1. Object model

A `DecryptionProfile` is a **named** object (mirrors CategoryGroups precedent),
referenced by policy rules, managed via admin API + SPA UI, synced CP→DP, and covered
by config-version rollback + export/import.

```go
// internal/decryptprofile — engine; aliased into package main as DecryptionProfile.
type DecryptionProfile struct {
	ID            string `json:"id"`                       // stable ULID, backfilled on load
	Name          string `json:"name"`                     // unique identity; the rule reference
	InspectHTTP2  *bool  `json:"inspectHttp2,omitempty"`   // nil = inherit default (strip/H1); true = native H2; false = force strip/H1
	StallTimeoutSecs int `json:"stallTimeoutSecs,omitempty"` // per-stream inactivity bound; 0 = engine default (sslInspectBodyStallTimeout)
	MinTLSVersion string `json:"minTlsVersion,omitempty"`  // "" = engine default (1.2); "1.2" | "1.3"
	// Slice 5 (deferred): OnUnsupported "fail-close"|"fail-open" TLS posture.
}
```

Design notes on the field set (each defended below in §3):
- `InspectHTTP2 *bool` carries the H2 toggle in **operator-positive** terms
  ("Inspect as HTTP/2 = on") rather than the engine-internal `StripALPN` double
  negative. The resolver maps it back to strip semantics.
- `StallTimeoutSecs` promotes the per-stream watchdog bound (`h2StreamStallTimeout`,
  today `= sslInspectBodyStallTimeout`) to a per-profile value. This is a per-STREAM
  var threaded into `h2InspectStream`, so per-profile is trivial and does NOT touch
  the PR3d shared server.
- `MinTLSVersion` sets the floor on the **upstream inspect** handshake
  (`upstreamInspectTLSConfig`) and the forged-leaf client config.
- **`MaxConcurrentStreams` is deliberately NOT a profile field** — see §3.1 (it is a
  server-wide SETTINGS value on the ONE shared PR3d `http2.Server`; per-profile would
  break graceful drain). It stays global; §5 optionally promotes the constant to a
  single admin-tunable global.

---

## 2. Per-rule binding + back-compat with the shipped `StripALPN`

Add one reference field to `PolicyRule` (policy.go:91), mirroring
`DestCategoryGroup`/`FileProfile`:

```go
DecryptionProfile string `json:"decryptionProfile,omitempty"` // name of a DecryptionProfile; empty = none
```

**Back-compat is the load-bearing constraint** — the inline `StripALPN *bool` is
already shipped and in customers' rule JSON. It STAYS. Resolution precedence
(`resolveStripALPN`, proxy.go:624, made profile-aware):

1. If `rule.DecryptionProfile` names a real profile whose `InspectHTTP2 != nil` →
   use it (`InspectHTTP2==true` ⇒ strip=false / native H2).
2. Else if `rule.StripALPN != nil` → use the inline field (today's behavior).
3. Else → strip (true) — the pre-feature default; an upgrade never silently
   switches an existing rule to H2.

A **dangling** `DecryptionProfile` reference (profile deleted / never existed)
resolves as "no profile" and falls through to step 2/3 — **fail-safe to today's
strip/H1**, never fail-open to no-inspection. This mirrors the category-group /
file-profile dangling-ref posture (fail-closed at match time; references are NOT
existence-validated at rule write time — `validatePolicyRule` deliberately doesn't,
per the precedent map).

New resolvers, same pattern:
- `resolveH2StallTimeout(match) time.Duration` — profile `StallTimeoutSecs` → else
  `sslInspectBodyStallTimeout`. Threaded into `h2InspectStream` (replaces the read of
  the global `h2StreamStallTimeout` var **on the inspected path**; the global stays as
  the default source).
- `resolveMinTLS(match) uint16` — profile `MinTLSVersion` → else TLS 1.2. Applied in
  `handshakeUpstreamALPN`/`upstreamInspectTLSConfig` and `newMITMClientConfigForALPN`.

---

## 3. Key design decisions (for reviewers to confirm)

### 3.1 MaxConcurrentStreams stays GLOBAL, not per-profile — OPEN DECISION A
PR3d serves every inspected-H2 tunnel on ONE shared `http2.Server`
(`h2InspectSrv`, ConfigureServer'd for graceful GOAWAY). `MaxConcurrentStreams` is a
**server-wide** SETTINGS value on that server; it cannot vary per-tunnel without
either (a) abandoning the shared-server graceful drain, or (b) a pool of servers
keyed by distinct MaxConcurrentStreams values (each ConfigureServer'd + drained) —
both a large step backward in complexity for a knob that is a **system resource /
DoS bound**, not a per-destination decryption choice. PAN-OS models concurrent-stream
limits as a system setting, not a per-profile field. **Recommendation: keep it
global** (§5 may promote the constant to one admin-tunable global). Reviewers:
confirm, or argue the keyed-pool is worth it.

### 3.2 Keep the inline `StripALPN` field (don't migrate it away) — OPEN DECISION B
Migrating `StripALPN` out of `PolicyRule` into an auto-created profile would touch the
already-shipped field, the snapshot, and every customer's rule JSON. **Recommendation:
keep both**, with the precedence in §2 (profile wins when set; inline is the
fallback/advanced path). The UI leads with the profile dropdown. Reviewers: confirm
vs. a migration.

### 3.3 fail-open/fail-close posture is SLICE 5 (deferred) — OPEN DECISION C
`MinTLSVersion` (a floor) ships in slice 1–2 (cheap: a `MinVersion` on two configs).
A `fail-open` posture (bypass inspection — raw-relay — when the origin's TLS is
unsupported) is materially riskier: it silently drops a flow OUT of inspection, and
must interact correctly with the CONNECT relay path. **Recommendation: ship the
profile field set WITHOUT fail-open first; add `OnUnsupported` in slice 5** with its
own review. Reviewers: confirm the field is deferred (not the whole profile).

### 3.4 No built-in seed profiles initially — OPEN DECISION D
FileProfile seeds built-ins; CategoryGroups does not. **Recommendation: no seed** —
empty profile set ⇒ rules fall back to inline `StripALPN`/default (§2), so nothing
changes on upgrade. A convenience "recommended-h2" profile can be added later.
Reviewers: confirm.

---

## 4. Slices (each a mergeable PR; 3-reviewer gate per meaningful milestone)

**Slice 1 — Engine + persistence (dormant object).**
`internal/decryptprofile` (struct + `Store`: List/GetByName/GetByID/Add/Update/
Delete/ReplaceAll/Names, ULID backfill) mirroring `internal/catgroup`; package-main
shim + `globalDecryptionProfiles` singleton (per `categorygroup.go`); JSON at
`<dataDir>/decryption_profiles.json` (path in a `*_startup_config.go`, `Load` in a
`*_startup.go`). No behavior wired yet. Tests: engine unit + startup-slice contract.

**Slice 2 — Binding + resolvers (behavior).**
`PolicyRule.DecryptionProfile` field; `resolveStripALPN` profile-aware (§2 precedence);
`resolveH2StallTimeout` + thread into `h2InspectStream`; `resolveMinTLS` + apply in the
inspect handshakes. Add `decryption-profile` to `objectRefTypes` (policy_refs.go:40) +
a `ruleReferencesObject` case (:96) so **delete-block + Where-Used** cover the field.
Fail-closed dangling-ref handling (§2) — verified by test, no change to
`validatePolicyRule`. Regression tests: precedence table (profile vs inline vs
default), dangling ref → strip, stall/min-TLS resolution.

**Slice 3 — Admin API + SPA UI (closes the GUI-parity gap).**
`apiDecryptionProfiles` (GET viewer / POST·PUT·DELETE operator, Mutating,
AuditExpected) registered in `registerPolicyRoutes`; `uiRoutes` metadata row;
`saveConfigVersion(actor, action)` after each mutating `auditEvent`. SPA: nav-item +
`#view-decryption-profiles` + viewMeta + switchView dispatch + fetch/render JS (per the
`catgroups` view); a **"Decryption Profile" dropdown in the policy-rule editor**
(mirrors `loadFileProfileDropdown`) — this is the operator on-switch for native H2.
D0/C1/C1.5/C2 route-parity tests updated (canonical route count + metadata).

**Slice 4 — Config-surface parity (cluster + rollback + export/import).**
`ConfigSnapshot.DecryptionProfiles` (+ `maxSnapDecryptionProfiles` cap +
`validateConfigSnapshot` row) captured in `CurrentConfigSnapshot`, applied nil-skip in
the `applySnapshot*` family **ordered BEFORE policy_rules** (rules reference profiles);
`configBackup.DecryptionProfiles` (no `omitempty`) + capture/apply(leaf-first, before
PolicyRules)/diff in `configversion.go`; export in `apiConfigExport` "all" branch +
import (before policy rules, merge = upsert-by-name, **never wipes**) in
`apiConfigImport`; ONE new `configSurfaces` row (Export/Import/Rollback/Diffed/
DiffNilGuarded/ClusterSynced, `Apply: semNilSkipEmptyWipe`). `config_surfaces_test.go`
enumerates anything left unwired — it is the completeness gate for this slice.

**Slice 5 — (deferred) fail-open/fail-close posture + optional global
MaxConcurrentStreams admin knob.** Its own plan + review.

Slices 1–4 are the release. Slice 2 may fold into 1 if small; 4 is atomic (the parity
test forces it complete once the DTO fields exist).

---

## 5. Invariants preserved

1. **One pipeline (C5):** untouched. The profile resolves upstream of the existing
   ALPN-intersection dispatch and the H2 server; `runInspectExchange` / `h2CopyBody` /
   the watchdog are unchanged.
2. **PR3d graceful drain:** untouched — MaxConcurrentStreams stays on the ONE shared
   server (§3.1); the profile only changes the per-stream stall bound (already a var)
   and the H2-vs-strip dispatch decision (already per-rule).
3. **Back-compat:** absent profile ⇒ byte-identical to today (inline `StripALPN` /
   strip default). Upgrade changes nothing until an operator creates + binds a profile.
4. **Default-deny / policy semantics:** unchanged — the profile is a decryption
   *modifier*, not an allow/deny decision; a dangling ref fails safe to strip/H1.
5. **Config anti-drift (Finding 10.3 / DEBT-004/006/009):** the new object is fully
   walled by the `configSurfaces` registry + `config_surfaces_test.go` (reflection
   parity, snapshot-cap parity, diff-nil-guard parity, rollback round-trip).
6. **RBAC / C2 governance:** `apiDecryptionProfiles` follows `requireRole` +
   `uiRoutes` metadata (viewer read / operator write), like every admin handler.

---

## 6. Edge cases & risks

- **Rule references a profile that is later deleted.** Delete is 409-blocked while
  referenced (`deleteBlockedByReferences` once `decryption-profile` is registered), so
  an operator can't orphan a rule silently; a force/racing delete still fails safe to
  strip/H1 at match time.
- **Snapshot/rollback ordering.** Profiles MUST apply before policy_rules on both the
  DP apply path and rollback (rules bind by name) — mirrors category_groups; pinned by
  the parity tests.
- **Import never wipes** (merge = upsert-by-name), matching the taxonomy objects — an
  import that omits profiles must not delete existing ones; only rollback wipes.
- **Stall-timeout as a footgun.** A very large `StallTimeoutSecs` lets a slow-loris
  stream pin a handler + scan buffer longer. Bound it (min/max clamp) in validation;
  document the interaction with the global memory ceiling
  (`maxScanBufferBytes × MaxConcurrentStreams`).
- **min-TLS raising the floor can break a rule** whose origin only speaks < the floor
  (the inspect handshake fails → tunnel drops). This is the intended posture (a floor),
  but the UI must make it clear and it is per-profile so blast radius is scoped.

---

## 7. Testing

- Engine unit tests (CRUD, name-uniqueness, ULID backfill).
- Resolver precedence table (profile-set / inline-only / neither / dangling) →
  strip decision; stall + min-TLS resolution.
- Delete-block + Where-Used for `decryption-profile`.
- Config-surface parity (the registry test suite) — the slice-4 completeness gate.
- Route/metadata parity (D0/C1/C1.5/C2) for the new API.
- Determinism: all new tests pass `-race` and `-count=2 -shuffle=on`; no global-state
  pollution across tests (PR3d lesson — reset any process globals via `t.Cleanup`).
- A native-H2 e2e that drives the profile on-switch end to end (rule → profile → H2
  negotiated), reusing the `nativeH2ClientConn` harness.

---

## 8. Validation gates
`gofmt` · `go vet ./...` · `go build ./...` · diff-scoped `golangci-lint` · `-race`
on the touched surface · `-count=2 -shuffle=on` determinism · full-package test.
Keep the required **Fast PR Gate** and **Deep PR Gate** green.

---

## 9. Rollout / rollback
Low risk, additive: the object is dormant until an operator creates + binds a profile;
absent-profile behavior is byte-identical to today. Rollback = revert the slice(s);
no schema migration (a persisted `decryption_profiles.json` is simply ignored if the
code is reverted, and rules keep working via inline `StripALPN`/default).

---

## 10. Explicit questions for reviewers
- **Q1 (product/PAN-OS):** Is this the right first field set for a Decryption Profile
  (Inspect-as-HTTP/2, stall timeout, min-TLS), and is deferring fail-open (§3.3) to
  slice 5 correct? What PAN-OS profile field is most conspicuously missing that should
  be in v1?
- **Q2 (architecture):** OPEN DECISION A — MaxConcurrentStreams global vs per-profile
  keyed-pool (§3.1). Confirm global is right given the PR3d shared server.
- **Q3 (architecture):** OPEN DECISION B — keep the inline `StripALPN` with the §2
  precedence vs. migrate it into the profile. Confirm keep-both.
- **Q4 (config-arch):** Is mirroring CategoryGroups (full surface: snapshot + rollback
  + export/import, leaf-first-before-rules, never-wipe-on-import) the correct model,
  and is the single `configSurfaces` row + parity test sufficient to keep it honest?
- **Q5 (UI/security):** Is the dangling-ref fail-closed-to-strip posture right (vs.
  existence-validating the reference at rule write time)? Any RBAC/CSRF/validation gap
  in the API/SPA plan? Should the policy editor hide the legacy inline `StripALPN`
  once a profile is bound?
- **Q6 (scope):** Is 4 slices the right cut, and should slice 2 fold into slice 1?

---

## 11. Review consolidation (v2) — four reviewers

Four independent reviewers: **PAN-OS product** (APPROVE-WITH-AMENDMENTS),
**config-architecture/anti-drift** (APPROVE-WITH-AMENDMENTS), **UI/API+security**
(APPROVE-WITH-AMENDMENTS), and **customer/field voice-of-customer**
(HELPS-WITH-CAVEATS). The architecture is validated; two themes reshape v1:
**(A) the field set is too thin to honestly be a "Decryption Profile,"** and
**(B) the feature ships sharp knobs without the operability guardrails that make
them safe to touch — and its value must be positioned honestly.**

### 11.1 Field set — REVISED (PAN-OS product MAJOR-1/2/3 + customer)
The v1 set {InspectHTTP2, StallTimeoutSecs, MinTLSVersion} is an H2-tuning object,
not a PAN-OS Decryption Profile — whose *defining* content is cert-verification +
failure posture. Deferring those forces a **second migration of every walled config
surface** later (config-arch agrees this is the churn the anti-drift wall exists to
avoid). **Decision: define the fuller field set NOW (migrate surfaces once); split
enforce-vs-defer:**

```go
type DecryptionProfile struct {
	ID   string; Name string
	InspectHTTP2     *bool  // H2 toggle (back-compat fallback: rule.StripALPN → strip default)
	CertVerification string // "" inherit | "strict" | "skip"  (folds per-rule TLSSkipVerify; "permissive" retired — see superseded note)
	OnUnsupported    string // "" inherit | "fail-close" | "fail-open"  (unsupported TLS version/cipher)
	MinTLSVersion    string // "" | "1.2" | "1.3"
	MaxTLSVersion    string // "" | "1.2" | "1.3"   (PAN-OS parity: floor AND cap — NIT-1)
	StallTimeoutSecs int    // 0 = default; Advanced UI section; clamped [5s, tunnel-idle ceiling]
}
```
- **Enforced in v1:** `InspectHTTP2`; `MinTLSVersion`/`MaxTLSVersion`;
  `StallTimeoutSecs`; `CertVerification` limited to `strict` (= today's verify) and
  `skip` (= today's `TLSSkipVerify=true`) — both already exist in the upstream
  handshake, so this just re-homes them onto the profile as the expected PAN-OS
  field; `OnUnsupported=fail-close` (= today's emergent behavior when a handshake
  can't proceed — now *declared* and operator-visible).
- **Deferred to slice 5 (field present, not yet enforced / greyed in UI):**
  `CertVerification=permissive` (verify-but-allow+log) and `OnUnsupported=fail-open`
  (raw-relay bypass out of inspection) — both are "relax safety" behaviors that touch
  the CONNECT relay path and need their own review.
- **Back-compat, same precedence as StripALPN:** `CertVerification==""` inherits the
  rule's existing `TLSSkipVerify` (skip if true, else strict); an absent/dangling
  profile is byte-identical to today. Fold, don't migrate.

### 11.2 Fail-open/close DEFAULT — the one reviewer conflict, resolved
PAN-OS product said "declare `OnUnsupported`, default fail-close"; customer said "a
fail-*close* default black-holes pinned/critical apps (Scenario D — M365)". They are
about **different axes** and both are right: `OnUnsupported` (unsupported TLS
version/cipher) legitimately defaults **fail-close** because that IS today's behavior
(unmet floor → handshake fails → tunnel drops) and making it explicit is honest. The
customer's black-hole fear is the future **cert-verification fail-close** and the
**fail-open ACTION** — so: **`OnUnsupported` default = fail-close (honest, = today);
the deferred fail-open ACTION, when it lands (slice 5), defaults OFF/opt-in; and
`CertVerification` defaults to inherit (= today), never a new stricter default that
would silently start blocking previously-allowed certs.** No default changes existing
behavior on upgrade.

### 11.3 Operability guardrails — NEW v1 requirements (customer)
The plan under-invested in operability; these determine whether the knob helps in the
field. Added to scope:
- **Honest positioning IN THE PRODUCT (not just docs).** UI copy + the profile panel
  must state: *"Inspect-as-HTTP/2 removes the HTTP/1.1-downgrade anti-bot signal. It
  does NOT change the TLS fingerprint (Culvert re-originates TLS with Go's stack), so
  Google-class destinations that fingerprint the ClientHello (JA3/JA4) or key on
  egress-IP reputation may still challenge — those need a bypass rule or warmed
  dedicated egress."* This is decisive: the origin reCAPTCHA customer will otherwise
  file the same ticket twice. (Rewrites Q1's framing.)
- **Warn-on-binding guardrails (slice 3 UI + a validation warning):** (1) binding a
  profile to a `SSLAction:Bypass` (non-Inspect) rule is a silent no-op — the editor
  must warn/gray-out (also PAN-OS MINOR-2); (2) binding to a broad/category rule that
  fans out H2 across many origins risks an H1-only/gRPC/WebSocket origin — surface a
  caution + the "protocols observed" signal below.
- **Success-delta + failure observability (metrics):** land the investigation's
  per-destination ALPN metric so an operator can SEE the knob worked —
  `culvert_inspect_upstream_alpn_total{protocol}` (H2-vs-H1 negotiated) plus
  `culvert_decrypt_profile_mintls_reject_total{profile}` (min-TLS silent-drop made
  visible) and reuse the PR3d `stall`-reset signal per profile. Without a before/after
  number the customer can't tell it helped.
- **Guardrailed default:** ship a **documented, NON-auto-bound** `recommended-h2` seed
  profile as a safe on-ramp (revises OPEN DECISION D — a non-bound seed is safe and
  is an on-ramp, unlike auto-binding).

The heavier guardrails — the **"test this profile against a destination" preview
tool** (customer's #1: probe a host, report negotiated ALPN/TLS + the honest
fingerprint verdict) and a **24h dry-run/shadow mode** — are high value but are their
own subsystems; scoped as a dedicated **operability slice (post-core, pre-GA)**, not
gating the core object.

### 11.4 Correctness amendments — config-architecture (all verified vs code)
- **(MAJOR)** The `RollbackRoundTrip` parity test passes **vacuously** unless the
  three hand-maintained helpers `csrIsolateRollbackStores` / `csrSeedStateA` /
  `csrMutateStateB` (config_surfaces_test.go) are extended so State B **diverges the
  profile store** — otherwise a capture-without-apply half-migration ships green (the
  RateLimitExempt class). Slice 4 MUST name these three edits; do NOT rely on "the
  parity test enumerates everything" for apply-wiring. Also add `globalDecryptionProfiles`
  to the isolation helper or the round-trip leaks global state across tests.
- **(MINOR)** ULID stability: `ReplaceAll` must preserve incoming IDs (backfill only
  when empty), OR add `decryption_profiles` to the `csrCanon` `stripID` set (mirror
  `rewrite_rules`) — else the round-trip mismatches on `id`.
- **(MINOR)** Opposite JSON tags: `configBackup.DecryptionProfiles` **no** `omitempty`
  (rollback `[]`-wipe must survive), `ConfigSnapshot.DecryptionProfiles` **with**
  `omitempty` (SnapshotWireWipe requires it for a non-WireWipeCapable field). Both
  test-enforced; call out the asymmetry.
- **(MINOR)** Snapshot cap wiring is three items, not two: `maxSnapDecryptionProfiles`
  (=1000, like siblings), a `validateConfigSnapshot` row, AND bump `capped 19→20` in
  `SnapshotCapParity`. Capture via a direct receiver call (`snap.DecryptionProfiles =
  globalDecryptionProfiles.List()`) for `SnapshotCaptureOwner`; apply nil-skip in
  `applySnapshotExtendedState` for `SnapshotApplyParity`.
- **(MINOR)** Downgrade the apply-ordering claim: the DP snapshot path is
  CLOSED-BY-ANALYSIS (no load-bearing order; `resolveStripALPN` reads the store at
  eval time, fail-safe to strip in a transient window). Keep profiles-before-rules for
  rollback/import (cheap, mirrors category_groups) but it is belt-and-suspenders on
  the DP, not a correctness requirement. **The real invariant is fail-safe-at-eval.**

### 11.5 Correctness amendments — UI/API + security (all verified vs code)
- **(MAJOR)** Slice 3's DELETE branch must **explicitly call**
  `deleteBlockedByReferences(w, r, "decryption-profile", name, …)` — registering the
  ref type only powers the read endpoint, not the 409-on-delete.
- **(MAJOR)** Field validation (name uniqueness/charset, `StallTimeoutSecs` clamp,
  `MinTLSVersion`/`MaxTLSVersion` enum, `CertVerification`/`OnUnsupported` enum) MUST
  live in the engine `Store.Add/Update`, not just the handler — config-import and
  CP→DP snapshot-apply are other write paths that bypass a handler-only check.
- **(MINOR)** Concrete `StallTimeoutSecs` bound: `[5s, sslInspectBodyStallTimeout /
  tunnel-idle ceiling]`, hard-reject out of range (not silent clamp).
- **(MINOR)** Every interpolation of `Name`/`MinTLSVersion`/etc. into the render list,
  policy-editor dropdown, and Where-Used view MUST use `escHtml()` (house pattern is
  innerHTML+escHtml — following it is sufficient; the "no innerHTML" framing was an
  overstatement).
- **(MINOR)** GET branch calls `requireRole(RoleViewer)` explicitly (keeps C1.5 AST
  parity clean, no metadata `Note` exception).
- **(NIT)** D0 count is `136` (d0_helpers_test.go), not 141 — adding
  `/api/decryption-profiles` → `137`; bump the constant + append a count-history line.

### 11.6 Resolved OPEN DECISIONS
- **A (MaxConcurrentStreams global):** CONFIRMED global by product + config-arch (no
  PAN-OS gap; per-profile would break PR3d graceful drain).
- **B (keep inline StripALPN):** CONFIRMED keep-both with the §2 precedence; UI
  **disables** the inline `StripALPN` (and `TLSSkipVerify`) control when a profile is
  bound, showing the profile-derived effective value read-only.
- **C (fail-open deferral):** REVISED — declare `OnUnsupported` in v1 (fail-close
  enforced), defer only the fail-open ACTION (§11.2).
- **D (no seed):** REVISED — ship a documented, non-auto-bound `recommended-h2` seed
  as a safe on-ramp (§11.3).

### 11.7 Verdict on the core promise (customer — must be baked into the product)
Native-H2-via-profile **reduces but does not eliminate** reCAPTCHA, and for **Google
specifically likely does not stop it** (JA3/JA4 + egress-IP reputation survive). It is
a clean win for the *middle tier* — H2 SaaS with self-tuned bot defense that must stay
under inspection (Scenario B) — and closes the real GUI-parity gap. It is NOT the
Google cure; that stays bypass + warmed egress. §11.3's positioning requirement makes
this honest in-product, not just in this roadmap.

### 11.8 Re-cut slices (v2)
1. **Engine + persistence** (dormant): `internal/decryptprofile` (full struct §11.1) +
   shim + `globalDecryptionProfiles` + JSON + startup slice. Engine-side validation
   (§11.5 MAJOR-2). ULID-preserving `ReplaceAll` (§11.4).
2. **Binding + resolvers** (behavior): `PolicyRule.DecryptionProfile`; profile-aware
   `resolveStripALPN`, `resolveH2StallTimeout`, `resolveMinTLS`/`resolveMaxTLS`,
   `resolveCertVerification` (strict/skip enforced); fail-safe-at-eval; objectRefTypes
   + ruleReferencesObject. Positioning-honest inline doc.
3. **Admin API + SPA** (closes GUI gap): `apiDecryptionProfiles` (+ explicit
   `deleteBlockedByReferences`, GET `requireRole`), `uiRoutes` row, `saveConfigVersion`,
   D0 137; SPA panel + policy-editor dropdown + **disable-inline-when-bound** +
   **warn-on-Bypass/broad-binding** + **positioning copy** + `escHtml` everywhere.
4. **Config-surface parity** (cluster+rollback+export/import): the CategoryGroups
   mirror + the §11.4 test-helper edits (isolate/seed/mutate), cap wiring, tag
   asymmetry — `config_surfaces_test.go` green.
5. **Observability + guardrailed default:** the §11.3 metrics + the non-auto-bound
   `recommended-h2` seed.
6. **(deferred, own review)** fail-open action + `CertVerification=permissive`; and the
   **operability preview tool + dry-run/shadow** subsystem (customer #1 guardrail).

Slices 1–5 are the release; 6 is fast-follow. This is the honest, PAN-OS-credible,
field-safe shape.
