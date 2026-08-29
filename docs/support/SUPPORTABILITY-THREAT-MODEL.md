# Culvert Supportability Framework — Threat Model

- **Status:** Proposed (design). Every meaningful threat has a control and at least one validation test.
- **Depends on:** all `docs/support/*` specs.
- **Method:** STRIDE-adjacent, scoped to the supportability attack surface. Trust boundaries: (B1) admin API / CLI caller, (B2) proxy ↔ maintenance agent UDS, (B3) collector ↔ in-proc stores, (B4) bundle-at-rest / in-transit, (B5) TAC / upload portal, (B6) CP ↔ DP fan-out.

---

## 1. Assets

| Asset | Boundary | Worst-case loss |
|---|---|---|
| Secret/key material (KEK, CA keys, HMAC, IdP secrets, tokens) | B3/B4 | full compromise of MITM trust + admin auth + cluster |
| Customer identities & traffic metadata | B4 | privacy breach, regulatory exposure |
| Host root (via agent) | B2 | appliance takeover |
| Bundle integrity / provenance | B4/B5 | poisoned diagnosis, tampered evidence |
| Availability of the proxy hot path | B1/B2 | DoS of the customer's egress |
| Cross-tenant isolation | B5/B6 | one customer sees another's data |

---

## 2. Threat catalog (threat → control → test)

| # | Threat | Boundary | Control(s) | Validation test |
|---|---|---|---|---|
| **T-EXFIL** | Bundle exfiltration by an unauthorized actor | B1/B4 | Admin RBAC + C2 gate on all `/api/support/*`; bundles stored `0600` under `<dataDir>/support`; download is authenticated + audited; recipient-key encryption for sensitive bundles | `TestSupportRBAC`, `TestBundlePermissions0600`, `TestDownloadAudited` |
| **T-LEAK** | Sensitive-data leakage into a bundle | B3/B4 | Source-side redaction (ADR-0029); fail-closed default `SENSITIVE`; `SECRET`/`NEVER_EXPORT` dropped; `internal/secret` unreachability; assembled-bundle re-scan; `redaction-report` preview | `TestNoSecretInBundle` (golden, planted secrets), `TestUnclassifiedFieldIsMasked`, `TestRawStateFilesExcluded` |
| **T-PRIV** | Privilege escalation via the collect path | B2 | Agent UDS `0660` + `SO_PEERCRED` allowlist; read-only `/v1/collect`; fixed argv template registry (no operator input); no `sh -c`; closed env allowlist; no write/state-changing verb added | `TestCollectOpReadOnly`, `TestNoShellInCollectors`, sudoers-diff CI check |
| **T-INJECT** | Command injection through a diagnostic argument | B1/B2 | Typed `ArgSpec` validation; hostnames parsed + `isPrivateHost`; no arg concatenated into a command line/path; agent argv built from templates only | `TestDiagnoseArgsValidated`, `TestNoShellInCommands` |
| **T-TRAVERSE** | Path traversal / symlink attack in bundle read or restore-of-bundle | B4 | Reuse `backup.go` `..`-reject + symlink-skip; bundle paths are engine-controlled (never operator strings); op-log paths joined under StateDir + ULID-validated (existing agent pattern) | `TestBundleNoTraversal`, `TestSymlinkSkipped` |
| **T-BOMB** | Zip bomb / decompression DoS on the consumer or the appliance | B4 | Per-section + total bundle byte budgets on write (never expand); documented bounded decompression on read; deterministic sizes in manifest | `TestBundleSizeBudget`, `TestDecompressBounded` |
| **T-DISK** | Disk exhaustion by repeated/oversized bundle generation | B1 | Preflight headroom check; single-flight per node; retention janitor (oldest-first); rate limit per actor; refuse when headroom < budget | `TestBundleRefusesLowDisk`, `TestBundleSingleFlight`, `TestRetentionJanitor` |
| **T-CPU** | CPU exhaustion via debug tracing or collection storm | B1 | Debug L3/L4 rate-limited + refused when node resource-critical; per-collector timeout/budget; per-actor rate limit; hot path never blocked | `TestDebugLevelPerfBounded`, `TestCollectorTimeout` |
| **T-MALSRV** | Malicious upload portal (or MITM) | B5 | TLS 1.3 + pinned portal trust root; recipient-key E2E encryption (portal can't read even if MITM'd); SSRF guard; signed receipt verified | `TestUploadSSRFGuarded`, `TestRecipientEncryptOnlyTACDecrypts` |
| **T-REPLAY** | Replay of a captured bundle/upload | B5 | Deterministic unique `bundle_id` (node|created_at|nonce); upload includes case binding + per-appliance credential; portal dedups by `bundle_id`+hash | `TestBundleIDUnique`, `TestUploadReplayRejected` (portal-side contract) |
| **T-TAMPER** | Bundle tampering (evidence poisoning) | B4/B5 | Per-section SHA-256 + `bundle_sha256` in manifest; AEAD tag when encrypted; `validate` fails closed on mismatch | `TestBundleTamperDetected`, `TestValidateRejectsCorrupt` |
| **T-POISON** | Poisoned diagnostic output feeding a wrong conclusion | B3 | Collectors read only safe accessors; free-form scrubber; `confidence` field prevents overstatement; collection-errors surfaced, never hidden | `TestCollectorRedactsAtSource`, `TestPartialBundleErrorsVisible` |
| **T-XTENANT** | Cross-tenant data exposure in cluster fan-out or upload | B5/B6 | Cluster fan-out uses enrolled-node mTLS + `GetConfig` secret-scrub for unenrolled callers; upload tenant-scoped credential; peer data redacted before inclusion | `TestFanOutRedactsPeerSecrets`, `TestUploadTenantScoped` |
| **T-DEBUG** | Unauthorized or forgotten debug activation | B1 | L2+ admin-only + audited; mandatory TTL + watchdog auto-revert (persisted across restart); no "until disabled" state | `TestDebugSetRequiresTTL`, `TestDebugLevelAutoRevert`, `TestDebugRevertsOnRestart` |
| **T-CRASH** | Crash-data collection itself becomes an exposure/DoS | B3 | Top-level panic recovery emits a bounded, redacted crash record (no raw request bodies); goroutine/heap dumps are admin+level-gated and bounded | `TestPanicRecoveryRedacted`, `TestHeapDumpGated` |
| **T-REMOTE** | Remote-support abuse (if ever enabled) | B1/B5 | Not enabled in MVP; when enabled: per-session approval + TTL + per-command allowlist + mutual auth + immutable recording + instant revoke; no shell | `TestRemoteSupportNotEnabled` (MVP), remote ADR tests (future) |
| **T-SUPPLY** | Supply-chain risk in diagnostic tooling | build | No new external diagnostic binaries; host collection uses the already-signed image's `docker`/coreutils via enumerated sudoers; agent binary cosign-verified (existing); go-licenses/govulncheck/gitleaks gates apply to `internal/support` | existing CI gates + `TestNoNewExternalDeps` |
| **T-CONSENT** | Support consent conflated with telemetry | B1 | Four independent switches, four audit trails; enabling one never enables another | `TestConsentSeparation` |
| **T-DP-VERSION** | A malicious/rogue DP forges health in cluster fan-out | B6 | Fan-out trusts only enrolled-node mTLS identities; peer input treated as untrusted, redacted, and labeled by source; discriminators cross-check (version vs epoch vs fingerprint) | `TestFanOutUntrustedPeerInput` |

---

## 3. Residual risks (accepted, documented)

| Risk | Why accepted | Mitigation posture |
|---|---|---|
| `docker_group_lab` privilege mode is root-equivalent | Lab-only, warns; strict sudoers mode is the supported path | Framework never requires lab mode; `privilege_warning` surfaced in bundle |
| Host root via agent remains a high-value target | Inherent to any host-ops capability; contained by UDS+peercred+argv-registry | No new state-changing verbs; read-only collect; security review of every sudoers change |
| A determined admin can still exfiltrate data they're authorized to see | RBAC is the boundary; support tooling doesn't widen it | All access audited; recipient encryption limits onward exposure |
| Bundle redaction masks but a skilled analyst may re-identify from co-occurrence | Diagnostic value requires some structure | `strict`/`paranoid` profiles; per-bundle salt; section opt-out |
| etcd quorum not directly observable by Culvert | Delegated to etcd by design (ADR-0005) | Independent endpoint probe in cluster bundle; documented |

---

## 4. Attack-surface budget (the framework must not grow the proxy's surface)

- **No new listening port.** `/api/support/*` rides the existing admin UI listener; the agent adds no TCP.
- **No new privileged process.** Host collection extends the existing agent; no second daemon.
- **No new external network origin enabled by default.** Upload origin is opt-in + SSRF-guarded; catalog-style trust pinning.
- **No new secret at rest.** The recipient TAC key is public; the per-bundle salt is ephemeral (`NEVER_EXPORT`, never written).
- **No new shell, exec, or dynamic code path.** Commands and collectors are fixed in-binary registries.

Each bullet is a CI-enforced invariant (route-count D0 test, sudoers-diff, `TestNoNewExternalDeps`, `TestNoShellInCommands`).

---

## 5. Cloud boundary threats (Tier 2/3 — cloud-first, ADR-0012/0014/0016/0018)

The cloud-first model adds a tier boundary. The controlling invariant is **outbound-only**: the cloud can never initiate into Culvert, so a fully compromised cloud cannot reach, command, reconfigure, or exfiltrate from an appliance. Additional threats and controls:

| # | Threat | Boundary | Control(s) | Validation test |
|---|---|---|---|---|
| **T-INBOUND** | Cloud (or attacker posing as it) initiates a connection/command into Culvert | B5 | No inbound listener/route for TAC; all connections outbound; "please send" is an appliance-polled policy gated by local consent | `TestNoInboundTACSurface`, D0 route-count wall |
| **T-CLOUDDOWN** | Cloud outage degrades the product | B1 | Cloud is optional; enforcement/config/health run locally; bundle queues + retries; offline export | `TestOperationWithoutCloud`, `TestHealthWithoutCloud` |
| **T-RAWSTORE** | Raw evidence exposed in the cloud | B4/B5 | Separate encrypted raw plane; per-case data key; sandbox-only reads; no standing access; short retention; audited break-glass (ADR-0016) | cloud contract: `TestRawPlaneNoStandingAccess` |
| **T-SANDBOX** | Malicious bundle escapes the extract worker | B5 | Ephemeral, network-isolated, single-use sandbox; no customer-net route; bounded decompression (≤500 MB); traversal/symlink reject; AV on raw | `TestSandboxIsolated`, `TestExtractBounded` |
| **T-PROMPT** | Prompt injection via bundle-derived text | B5 | AI gets **normalized findings + approved excerpts by default**, not raw (ADR-0036); untrusted-data delimiting; fixed system policy; TAC-approval gate; no appliance action path (outbound-only) | `TestAIInputNormalizedOnly` |
| **T-EXCEPT** | Abuse of exceptional (break-glass) raw access | B5 | Dual-control, fully audited, time-bound; never via the AI path | `TestBreakGlassDualControlAudited` |
| **T-XTENANT2** | Cross-tenant leakage in the cloud | B5/B6 | Case + tenant scoping end-to-end; per-case keys; entitlement at the gateway | `TestUploadTenantScoped`, cloud `TestFindingsTenantScoped` |
| **T-POLICY-COERCE** | Cloud "send bundle" policy used to exfiltrate without consent | B2 | Poll-only; local consent/policy gates collection AND send; redaction still fail-closed | `TestCloudPolicyRequiresLocalConsent` |

**Non-goal reinforced:** no code path lets the cloud read appliance keys/credentials, request arbitrary files, alter config, or bypass redaction — these are structurally impossible under outbound-only + source-side redaction, not merely policy-forbidden.
