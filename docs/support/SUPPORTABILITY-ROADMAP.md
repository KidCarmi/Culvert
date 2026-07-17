# Culvert Supportability Framework — Implementation Roadmap

- **Status:** Appliance track **M0–M5 implemented and shipped**; cloud track
  (M6 secure upload, M7 proactive/telemetry) remains proposed (design). See
  `docs/operator/support-bundles-and-diagnostics.md` for the live operator
  runbook covering everything M0–M5 shipped. Milestones M0–M7 below. First
  slices deliberately small enough to review safely.
- **Depends on:** all `docs/support/*` specs + ADRs 0008–0018.
- **Sequencing principle:** ship the redaction wall and a minimal bundle before breadth. Never add a collector before its classification + tests exist. Each milestone is independently valuable and independently revertible.

> **REVISION 2 (2026-07-13) — two tracks (cloud-first, ADR-0012).** The milestones below are now split across two independently-deliverable tracks. **Appliance track (Tier 1/2):** M0–M2, M4-appliance (encrypt + outbound upload + queue/retry + offline export), M5-appliance (emit richer cluster raw facts). **Cloud track (Tier 3):** the analysis previously drafted as appliance work — **timeline construction (was M3), incident correlation, cluster discriminators/split-brain/drift (was M5), known-issue matching, AI diagnosis, TAC workflow — is re-homed to the TAC Cloud** (`TAC-CLOUD-ARCHITECTURE.md`). The appliance keeps only: lightweight health (M1), collector execution + scope/window selection + debug-level *capture* control (M3-appliance), and the upload/export pipeline (M4/M6). Remote support stays deferred. The appliance track can ship end-to-end (produce → encrypt → export/upload) before the cloud track is built; a customer with only the appliance track gets redacted bundles they can hand to TAC manually.

---

## Milestone summary

| M | Theme | Ships | Gates it must pass |
|---|---|---|---|
| M0 | Discovery & contracts | this doc set + ADRs + parity-wall scaffolding | design review |
| M1 | Health model + standard bundle | CHR, `internal/redaction`, `internal/support`, standard CSB, `/api/support` read surface, SPA panel, recovery one-shot | secret-leak, RBAC, determinism |
| M2 | Plugin collectors + centralized redaction | full collector registry, `data_surfaces_test.go` wall, free-form scrubber, `redaction-report` preview | three parity walls, `TestNoSecretInBundle` |
| M3 | Targeted diagnostics + incident scopes | `diagnose *` verbs, `IncidentScope` catalog, debug levels L0–L4 + watchdog, timeline | debug-revert, timeline-redaction |
| M4 | Encrypted export + case workflow | offline download, passphrase + recipient-key crypto, bundle lifecycle FSM, history, `case_id` | air-gapped, tamper-detect |
| M5 | HA & recovery diagnostics | cluster fan-out, 3 CP/DP instrumentation additions, failover ring, recovery bundle | HA fan-out, split-brain-in-bundle |
| M6 | Secure upload | opt-in resumable upload, SSRF-guarded, tenant-scoped, receipt | no-auto-upload, upload-SSRF |
| M7 | Proactive support + opt-in telemetry | scheduled health self-checks, alert-linked scopes, separately-consented telemetry subset | consent-separation |

---

## M0 — Current-state discovery & contracts ✅ (this deliverable)

- **Scope:** the gap analysis, architecture, all contracts (bundle/collector/redaction/command/health/upload), threat model, test strategy, ADRs, and the empty parity-wall test scaffolding (`data_surfaces_test.go`, `support_registry_test.go` asserting an empty-but-valid registry).
- **Non-goals:** any collector, any endpoint, any bundle byte.
- **Dependencies:** none.
- **Risks:** contracts drift from reality → mitigated by file:line-grounded gap analysis and by shipping the parity scaffolding now.
- **Security gate:** design review vs the 20 architectural rules.
- **Testing gate:** the scaffolding tests compile and pass over an empty registry.
- **Migration impact:** none (docs + test scaffolding only).
- **Operator experience:** none yet.
- **Acceptance:** all 12 docs internally consistent (shared vocabulary, no contradictions); scaffolding merged.
- **Rollback:** delete docs/tests; zero runtime impact.

---

## M1 — Local health model & standard support bundle ✅ shipped

- **Scope:**
  - `internal/redaction` v1: `DataClass`, `Redactor.Struct`, registry backed by `config_surfaces.go` + a minimal `dataFileClasses`; fail-closed default.
  - `internal/support` v1: `Collector` iface, registry, runner (isolation/timeout/budget/panic-recovery), manifest builder, tar/gzip via reused `backup.go` machinery, section SHA-256.
  - CHR model + aggregator extending `buildOperatorContract`; `/api/support/status`, `/api/health/explain`, `GET /api/support/bundles/{id}`, `POST /api/support/bundles` (standard scope only), download.
  - The **five mandatory collectors** (`product`, `health`, `readiness`, `diagnostics`, `collection-errors`) + `config`, `policy`, `audit`, `metrics`, `logs/system` — all reusing existing safe accessors.
  - `data-view="support"` SPA panel (status + collect + download + health-explain) with `uiRoutes` metadata.
  - **Recovery one-shot** `culvert --support-bundle <out>` (minimal collector set, no server).
  - Top-level **panic-recovery middleware** emitting a redacted crash record + metric (fills T-CRASH and seeds the crash timeline).
- **Non-goals:** host/cluster/runtime collectors, incident scopes, debug levels, encryption, upload, timeline.
- **Dependencies:** M0 contracts.
- **Risks:** redaction correctness (highest) → mitigated by shipping `TestNoSecretInBundle` in this milestone even before all collectors exist; reusing already-redacting accessors first.
- **Security gate:** `TestNoSecretInBundle`, `TestBundlePermissions0600`, RBAC parity.
- **Testing gate:** per-collector suites, golden schema, determinism, partial-bundle, recovery-no-server.
- **Migration impact:** additive; new package + routes + panel + one dir under `/data/support`. No config migration.
- **Operator experience:** an admin can, from GUI or CLI, produce and download a redacted standard bundle and read an explained health verdict — the first tangible TAC win, and the endorsed GAP-MON-01 deliverable.
- **Acceptance:** a standard bundle validates, contains the mandatory sections, leaks no planted secret at any point, and works with the GUI down.
- **Rollback:** feature-flag the route family + panel off; the package is inert if unregistered; delete `/data/support`. No data migration to unwind.

---

## M2 — Plugin collectors & centralized redaction ✅ shipped

- **Scope:** complete the collector registry (tls, config-versions, timeline-stub, request-logs with masking, governance, upstream/CDR/scan posture); harden `internal/redaction` with the free-form scrubber + masking semantics + profiles + custom exclusions; `redaction-report.json` + mandatory preview; land all three parity walls as **blocking**.
- **Non-goals:** host/cluster collectors, debug levels beyond L1, upload.
- **Dependencies:** M1.
- **Risks:** free-form scrubber ReDoS / false-negatives → bounded-time regexes + fuzz + live-secret seeding; parity walls flagging legitimate churn → clear failure messages naming the field.
- **Security gate:** the three parity walls blocking; `TestNoSecretInBundle` across all collectors; fuzz the scrubber.
- **Testing gate:** redaction suite, profile monotonicity, preview-before-export.
- **Migration impact:** additive; existing bundles remain valid (additive sections).
- **Operator experience:** richer bundles with a visible redaction report and a mandatory preview; strict/paranoid profiles.
- **Acceptance:** a new collected struct field cannot merge without a `DataClass`; preview blocks export until confirmed.
- **Rollback:** individual collectors are independently unregisterable; the redaction hardening is backward-safe (only tightens).

---

## M3 — Targeted diagnostics & incident scopes ✅ shipped

- **Scope:** `diagnose dns|tls|upstream|storage|policy`; `IncidentScope` catalog + `--scope` selection; debug levels L0–L4 with mandatory TTL + restart-surviving watchdog + auto-stop; the operational timeline (taps on config-version/failover/CA/alert/restart/crash) with improved (dated/compressed) retention.
- **Non-goals:** cluster diagnostics (M5), upload.
- **Dependencies:** M2 (redaction), M1 (bundle).
- **Risks:** debug level left on / perf impact → watchdog + resource-refusal + perf-bounded tracing, all tested; timeline cardinality → operational-events-only, bounded ring.
- **Security gate:** `TestDebugSetRequiresTTL`, `TestDebugLevelAutoRevert`, `TestDebugRevertsOnRestart`, timeline redaction.
- **Testing gate:** diagnose-args validation, incident-scope collector-set correctness, timeline "last N before T" query.
- **Migration impact:** additive; new persisted `{level,expires_at}` + timeline JSONL under `/data/support`.
- **Operator experience:** "collect for *this* incident," a live debug countdown, "what changed before the incident" in the summary.
- **Acceptance:** any raised level reverts within its TTL even across restart; each scope collects only its declared set.
- **Rollback:** scopes/verbs are additive; debug controller defaults to L0 if the package is disabled.

---

## M4 — Encrypted export & support-case workflow ✅ shipped

- **Scope:** bundle lifecycle FSM (persisted, crash-safe); offline download with optional passphrase (`backupcrypt`) or recipient-key (age/X25519) encryption; `culvert support validate/inspect/history`; `case_id` binding; retention janitor.
- **Non-goals:** online upload (M6), remote support.
- **Dependencies:** M1–M3.
- **Risks:** key handling / recipient-key trust → public-key-only, pinned like catalog roots; retention deleting a needed bundle → oldest-first + audit + configurable.
- **Security gate:** air-gapped, tamper-detect, recipient-only-decrypts.
- **Testing gate:** lifecycle-FSM transitions audited, validate-rejects-corrupt, retention janitor.
- **Migration impact:** additive; retention config field (governed by `config_surfaces` + admin_settings durability).
- **Operator experience:** encrypt-to-TAC without sharing a secret; verify integrity offline; case-bound history.
- **Rollback:** encryption is opt-in; unencrypted download path unchanged; FSM is internal.

---

## M5 — HA & recovery diagnostics ✅ shipped

- **Scope:** the three CP/DP instrumentation additions (per-DP applied version in `MetricsReport`; populate `EnrolledNode.Version`; failover/self-fence ring on `/api/cluster/ha`); cluster fan-out collector + `diagnose cluster` with local-vs-cluster discriminators; etcd-endpoint reachability probe; recovery-mode hardening (bundle under DB/CP down).
- **Non-goals:** upload, telemetry.
- **Dependencies:** M1–M3; touches control-plane code (highest blast radius) → gated behind additive, backward-compatible wire fields (old binaries ignore unknown keys, per existing snapshot discipline).
- **Risks:** control-plane wire changes → strictly additive `MetricsReport` fields, `config_surfaces`/snapshot-parity tests extended; fan-out trusting rogue peers → enrolled-mTLS only, peer input redacted+labeled.
- **Security gate:** `TestFanOutRedactsPeerSecrets`, `TestFanOutUntrustedPeerInput`, split-brain-in-bundle.
- **Testing gate:** cluster fan-out correlation, per-DP lag table, HA under partition.
- **Migration impact:** additive wire fields; a mixed-version cluster degrades gracefully (missing fields → `unknown`, not error).
- **Operator experience:** a cluster bundle that says *which node* and whether the fault is local or cluster-wide.
- **Rollback:** instrumentation fields are additive and ignorable; fan-out is a separate collector.

---

## M6 — Optional secure upload

- **Scope:** opt-in, explicit, per-bundle, case-bound, admin-gated, SSRF-guarded, resumable upload to a TAC portal; signed receipt; tenant-scoped credential; recipient-key E2E encryption reused from M4.
- **Non-goals:** automatic/background upload (out of scope, would need its own ADR); remote support.
- **Dependencies:** M4 (recipient encryption), portal availability.
- **Risks:** accidental data egress → no auto path, explicit per-upload action, preview reused; malicious portal → E2E encryption + pinned trust + SSRF guard.
- **Security gate:** `TestNoAutoUpload`, `TestUploadSSRFGuarded`, `TestUploadTenantScoped`, `TestUploadReceiptHashMatch`.
- **Testing gate:** resumable-under-flaky-link, upload requires case+admin.
- **Migration impact:** additive; upload disabled by default (`not_enabled` until configured).
- **Operator experience:** one-click send-to-case with a receipt; nothing leaves without the click.
- **Rollback:** flag off → verbs return `not_enabled`; offline path is unaffected.

---

## M7 — Proactive support & opt-in telemetry

- **Scope:** scheduled health self-checks that pre-stage an incident-scoped bundle on threshold crossings (local only, no auto-send); alert→scope linkage (a fired alert suggests the matching incident scope); **separately-consented** opt-in telemetry that phones home a strict subset of bundle-eligible aggregate metrics (no bundle contents, no identities).
- **Non-goals:** any telemetry-on-by-default; conflating telemetry with support.
- **Dependencies:** M1–M6; the metric `{in_bundle, local_only, telemetry_eligible}` registry (HEALTH-AND-EVENT §7).
- **Risks:** consent conflation → four independent switches + four audit trails, `TestConsentSeparation`; proactive collection resource cost → bounded, off by default.
- **Security gate:** consent-separation; telemetry payload is a proven strict subset of bundle-eligible metrics.
- **Testing gate:** proactive-bundle stays local, telemetry subset enforcement.
- **Migration impact:** additive; telemetry opt-in defaults off.
- **Operator experience:** "we noticed X degrading — here's a pre-staged bundle"; optional, transparent telemetry with a clear payload preview.
- **Rollback:** telemetry + proactive are independent flags, both default-off.

---

## Cross-milestone invariants (hold at every step)

1. No milestone ships on a red Security gate (esp. `TestNoSecretInBundle`).
2. No collector merges without its full `Test<ID>_*` set + a `DataClass` for every field.
3. Every new route has `uiRoutes` metadata + a UI affordance (GUI parity).
4. Every new persisted state lives under `<dataDir>/support` and is covered by preflight/retention/disk-safety.
5. Additive-only wire/format changes within a major; breaking changes bump the version axis + ADR.

---

## First recommended implementation slice (smallest safe review)

**Slice 1 (subset of M1):** `internal/redaction` skeleton (DataClass enum + `Redactor.Struct` reading `config_surfaces` + fail-closed default) **plus** the `data_surfaces_test.go` parity wall over the config surfaces **plus** a single `diagnostics` collector and a `product` collector wired into a minimal `internal/support` runner that emits a 2-section, unencrypted `csb/1` bundle behind `GET /api/support/bundles/{id}` + `POST /api/support/bundles` (admin), with `TestNoSecretInBundle` seeded for those two sections. No SPA, no CLI, no lifecycle — just prove the redaction wall + bundle skeleton + secret-leak test end-to-end on the two thinnest collectors. Everything else in M1 stacks on a proven spine. See the parent task's "First recommended implementation slice" for the exact file list.
