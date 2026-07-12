# Culvert Supportability Framework — Test Strategy & CI Gates

- **Status:** Proposed (design).
- **Depends on:** all `docs/support/*` specs; mirrors the repo's existing parity-wall discipline (`config_surfaces_test.go`, C1/C1.5/C2, D0).
- **Principle:** every security and reliability claim in these docs has an enforcement mechanism *and* a test. Untested claims are not shippable.

---

## 1. Test layers

| Layer | Scope | Pattern reused |
|---|---|---|
| **Unit — per collector** | each `Collector` in isolation | `internal/*` whitebox tests |
| **Golden schema** | frozen JSON schema per bundle section + manifest | golden-file (like release-catalog determinism) |
| **Parity walls** | registries can't drift | `config_surfaces_test.go` reflection parity |
| **Redaction / secret-leak** | no secret in any output | planted-secret fixtures |
| **Failure injection** | degraded appliance behavior | chaos-style, injected faults |
| **Integration** | full bundle lifecycle | end-to-end in-process |
| **Cross-version** | old bundles still validate | frozen corpus |
| **Security** | threat-model controls | one test per threat (THREAT-MODEL §2) |

---

## 2. Mandatory tests (mapped to the prompt's required list)

| Required test | Concrete test(s) | Gate |
|---|---|---|
| Unit tests per collector | `Test<ID>_*` suite (COLLECTOR-CONTRACT §8), one per collector | Fast PR Gate |
| Golden schema tests | `TestBundleManifestSchema`, `Test<ID>_Schema` per section | Fast PR Gate |
| Redaction tests | `TestUnclassifiedFieldIsMasked`, `TestProfileMonotonic`, `TestFreeFormScrubberCatchesLiveSecrets` | Fast PR Gate |
| Secret-leakage tests | `TestNoSecretInBundle` (all-collectors, planted every class), `TestRawStateFilesExcluded`, `TestNeverExportUnreachable` | **Blocking** (Security gate) |
| Failure-injection tests | `TestPartialBundle_OneCollectorPanics`, `TestBundleUnderDegradation` (DB down/disk full/GUI down/CP down) | Deep PR Gate |
| Collector timeout tests | `Test<ID>_Timeout`, `TestRunnerCancelsOnDeadline` | Fast PR Gate |
| Partial bundle tests | `TestPartialBundleErrorsVisible`, `TestMandatorySectionMissingInvalid` | Fast PR Gate |
| Disk-pressure tests | `TestBundleRefusesLowDisk`, `TestRetentionJanitor`, `TestPreflightHeadroom` | Deep PR Gate |
| Permission tests | `TestBundlePermissions0600`, `TestCollectOpReadOnly`, sudoers-diff | Security gate |
| RBAC tests | `TestSupportRBAC` (C1.5), `TestSupportRoutesHaveMetadata` (C1) | Fast PR Gate |
| Upgrade-compatibility tests | `TestBundleBackwardCompat` (frozen corpus per `collector_version`) | Deep PR Gate |
| Corrupted-bundle tests | `TestValidateRejectsCorrupt`, `TestBundleTamperDetected` | Fast PR Gate |
| Backward-compatibility tests | `TestManifestForwardCompat` (newer bundle opens degraded) | Deep PR Gate |
| Load tests | `TestBundleUnderLoad` (collection doesn't starve hot path); benchgate on collectors | Nightly |
| Chaos tests | fault-injected collectors, agent-unreachable, partial cluster | Nightly |
| Security tests | one per THREAT-MODEL threat (§2) | Security gate |
| Air-gapped tests | `TestAirGappedBundle`, `TestOfflineBundleAirGapped` | Deep PR Gate |
| HA tests | `TestClusterFanOutCorrelation`, `TestSplitBrainDetectedInBundle`, `TestFanOutRedactsPeerSecrets` | Deep PR Gate |
| Appliance-recovery tests | `TestRecoveryBundleNoServer` (one-shot with server down), `TestDebugRevertsOnRestart` | Deep PR Gate |

---

## 3. The load-bearing CI gate (the prompt's core requirement)

> "CI gates that prevent new configuration fields, secrets, or components from being added without corresponding diagnostic and redaction coverage."

Three parity walls, each a reflection/AST test that fails the build on drift:

1. **`data_surfaces_test.go` (redaction parity).** Every field of every struct a collector serializes MUST be claimed by exactly one `DataClassRegistry` row with an explicit `DataClass`. Adding a field to a collected struct without classifying it → **compile-adjacent test failure** naming the field. (Mirrors `config_surfaces_test.go` exactly.)
2. **`support_registry_test.go` (collector parity).** Every registered collector has a unique `ID`/`Path`, a golden schema file, a `MaxClass ≤ INTERNAL` if in the shareable set, and a `_test.go` with the mandatory `Test<ID>_*` set. Adding a collector without coverage → failure.
3. **`config_surface_diagnostic_coverage_test.go` (config→bundle coverage).** Every `config_surfaces.go` row of `Kind: kindConfig` is either (a) present in the redacted config collector's output, or (b) explicitly listed as excluded with a reason. A **new config field added to `config_surfaces` that is neither collected nor explicitly excluded → failure.** This is the direct "new config field can't be added without diagnostic coverage" wall.

Additionally, a **secret-introduction guard**: any new struct field whose name matches the gosec G117 secret pattern, or any new `config_surfaces` row with `Sensitive:true`, must map to a `DataClass ≥ SECRET` and be proven absent from bundles by `TestNoSecretInBundle` — enforced by extending the existing `config_surfaces_test.go` Sensitive-invariant checks into the redaction registry.

---

## 4. Golden secret-leak test (the crown-jewel test)

`TestNoSecretInBundle` is the single most important test:
- Boots a fully-configured node with **planted canary secrets of every class** in every store (a unique sentinel string per secret: CA passphrase, session HMAC, OIDC client secret, webhook secret, metrics token, OTLP header, upstream cred, user password/TOTP, KEK).
- Generates a bundle at **every debug level and every incident scope**.
- Asserts **none of the canary sentinels appears anywhere** in the decompressed bundle (all sections, manifest, summary, error file, timeline, host section) — byte-scan, not field-scan.
- Runs under `-count=2 -shuffle=on` and in the determinism gate.
- A failure blocks merge unconditionally (Security gate), no override.

---

## 5. Determinism & the audit-ring pitfall

- **Determinism:** bundle sections are byte-identical over frozen state with an injected clock; `TestBundleDeterministic` runs in the existing `QA · Determinism` lane. Collectors must take `Clock` from input (COLLECTOR-CONTRACT §2) — `TestCollectorNoWallClock` greps for `time.Now()` in `internal/support` collectors (allowed only via the injected clock).
- **Audit-ring saturation (existing repo pitfall):** support tests MUST NOT assert on `len(auditGet())` deltas — the ring saturates at 500 under shuffle. Assert on entry **content** (unique discriminator: a TEST-NET-2 actor IP + `support.*` action + a pre-call baseline TS), per the canonical pattern in `security_feedsync_audit_test.go`.

---

## 6. CI lane placement (respecting `roadmap/CI-REDESIGN.md`)

| Lane | Support tests |
|---|---|
| **Fast PR Gate** (required) | unit collectors, golden schema, redaction, RBAC/parity (C1/C1.5), timeout, partial, corrupted-bundle, the three parity walls, benchgate on collector hot paths |
| **Deep PR Gate** (required-if-triggered) | failure-injection, disk-pressure, air-gapped, HA fan-out, recovery, cross-version corpus, forward-compat |
| **Security gate** (main/tags/weekly) | `TestNoSecretInBundle`, permission tests, sudoers-diff, one-per-threat suite, `TestNeverExportUnreachable` |
| **Nightly** | load (hot-path non-starvation), chaos (agent-unreachable, partial cluster, disk-full), fuzz the manifest parser + free-form scrubber |
| **CodeQL** | `internal/support`, `internal/redaction`, `/api/support` handlers, `/v1/collect` — added to the proxy/security surface trigger set |

---

## 7. Fuzzing targets

Coverage-guided fuzz (Mon/Wed/Fri, existing `fuzz-nightly.yml`):
- **Manifest parser** — malformed/oversized/hostile manifests never crash the consumer.
- **Free-form scrubber** — random text with embedded secret shapes; assert secrets always masked, no ReDoS (bounded-time regexes only).
- **Bundle reader** — malformed tar/gzip/AEAD; fails closed, no traversal, no OOM (T-BOMB/T-TRAVERSE).

---

## 8. Acceptance bar per milestone

A milestone is "done" only when: its collectors each have the full `Test<ID>_*` set; the three parity walls pass; `TestNoSecretInBundle` covers its new sections at all levels/scopes; its threat-model rows have passing tests; and the determinism + audit-content patterns are honored. No milestone ships on a red Security gate.
