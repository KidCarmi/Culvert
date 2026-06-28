# Culvert Technical Risk Register

> **Owner:** Chief Engineering Advisor · **Status:** Living · **Last review:** 2026-06-28
>
> Risks are things that can go wrong in production or in the supply chain. Structural shortcuts
> live in the [Technical Debt Register](./TECHNICAL-DEBT-REGISTER.md). Some items appear in both
> when a structural shortcut also carries runtime risk; the cross-reference is noted.
>
> **Severity:** BLOCKER (must fix before the relevant production claim) · HIGH · MEDIUM · LOW.
> **Status:** OPEN · MITIGATING · ACCEPTED (with rationale) · CLOSED.
> Every row carries repository evidence. `HV` = hand-verified by the Advisor on the review date.

| ID | Sev | Status | Title | Evidence |
|---|---|---|---|---|
| RISK-001 | BLOCKER | OPEN | Multi-CP HA split-brain (no quorum/fencing) | `ha.go` (no `demote`/`stepDown`/quorum symbol, 570 LOC) **HV** |
| RISK-002 | HIGH | OPEN | OIDC introspection path missing SSRF dial guard | `auth_oidc.go:94` vs `auth_oidc_flow.go:300` **HV** |
| RISK-003 | HIGH | OPEN | Webhook HMAC secret persisted cleartext on disk | `alerts.go:169` |
| RISK-006 | HIGH | OPEN | Security gate fetches scanners `@latest`; CodeQL non-blocking | `security-release-gate.yml:52,110,252`; `ci.yml:72` |
| RISK-005 | MEDIUM | OPEN | Interrupted restore can leave `/data` absent | `restore.go:876-894` |
| RISK-008 | MEDIUM | OPEN | Username timing oracle enables user enumeration | `store.go:1670` |
| RISK-009 | MEDIUM | OPEN | `InsecureSkipVerify` admin toggle silent on auth hot path | `auth_oidc.go:95`, `auth_ldap.go:122` |
| RISK-010 | MEDIUM | OPEN | Self-update has no in-binary image signature/digest check | `update.go:496-608` |
| RISK-011 | MEDIUM | OPEN | Cluster rolling-update auto-rollback unverified | `update_cluster.go:804-852` |
| RISK-012 | LOW | OPEN | Account lockout is username-keyed (lockout-as-DoS) | `lockout.go:36,60` |
| RISK-013 | LOW | OPEN | `normalizeHost` IDNA failure is fail-open | `security.go:34-37` |

---

## RISK-001 — Multi-CP HA split-brain · BLOCKER · OPEN
- **Current state:** Standby self-promotes after 3 missed 5s polls (~15s); a restarted leader
  unconditionally re-asserts `leader` from `ha_config.json`; both then report `"leader":true`
  from `/healthz`. No consensus, fencing, or failback reconciliation exists. **Hand-verified:**
  `ha.go` contains `EnableAsLeader`/`StartAsStandby` but no `demote`/`stepDown`/`quorum`/`fenc*`.
  Behavior is *pinned* in `ha_split_brain_failover_evidence_test.go` — it is known, not accidental.
- **Business impact:** "Enterprise HA" is a headline claim; on any >15s CP-to-CP network blip the
  cluster splits into two divergent leaders. Admin mutations (enrollment, tokens, CA) diverge
  permanently and require manual recovery.
- **Engineering/operational impact:** No safe automated failover for multi-CP; single-CP is fine.
- **Recommendation:**
  - *Now (Complexity S):* gate write paths behind a fencing token; refuse leader-on-restart without
    a re-handshake; **document HA as active/passive with manual failover** and write the
    split-brain recovery runbook (`docs/operator/`).
  - *Roadmap (Complexity L):* real consensus (Raft or single-writer lease with fencing).
- **Until then:** ACCEPTED-only for single-CP deployments. Multi-CP on flaky networks is unsafe.
- **Owner:** unassigned · **Target:** mitigation this month.

## RISK-002 — OIDC introspection missing SSRF guard · HIGH · OPEN
- **Current state (HV):** `auth_oidc.go:94` clones the transport with **no**
  `transport.DialContext = ssrfSafeDialContext`; the sibling `auth_oidc_flow.go:300` sets it. The
  admin-configured `IntrospectURL` is reached on every token-validating request.
- **Impact:** A misconfigured/malicious introspection URL can reach `169.254.169.254`/loopback —
  a per-request SSRF that violates the project's own SSRF-everywhere convention on exactly one path.
- **Recommendation:** Add the one line mirroring the flow variant. **Complexity XS.**
- **Owner:** unassigned · **Target:** this week.

## RISK-003 — Webhook HMAC secret cleartext at rest · HIGH · OPEN
- **Current state:** `alerts.go:169` marshals `AlertWebhook.Secret` to `0600` JSON and it
  round-trips through config export/import. The CA bundle is AES-GCM encrypted; this secret is not.
- **Impact:** File read or an exported config bundle lets an attacker forge signed alert payloads.
- **Recommendation:** Encrypt at rest with the existing CA-bundle scheme (or a derived key); redact
  on export. **Complexity S.**
- **Owner:** unassigned · **Target:** this week.

## RISK-006 — CI security gate supply-chain soft spots · HIGH · OPEN
- **Current state:** The mandatory gate installs its own scanners from `@latest`
  (`security-release-gate.yml:52` gosec, `:110` govulncheck, `:252` go-licenses) and runs
  `KidCarmi/Dependency-Obituary@main` (`ci.yml:72`). CodeQL is in no gate's `needs:` (advisory only).
- **Impact:** The gate meant to catch supply-chain risk is itself unpinned and non-reproducible;
  deep SAST findings never block a merge.
- **Recommendation:** Pin scanner versions (or vendor), SHA-pin the `@main` action, add CodeQL to
  the blocking set. **Complexity S.**
- **Owner:** unassigned · **Target:** this week.

## RISK-005 — Interrupted restore leaves `/data` absent · MEDIUM · OPEN
- **Current state:** `restore.go:876-894` does move-aside (`rename /data → /data.bak.<ts>`) then
  swap; a kill between the two renames leaves `/data` missing and the binary cannot boot. The error
  names the recovery command but there is no auto-recovery and no test for the mid-kill path.
- **Impact:** Operator must manually `mv /data.bak.<ts> /data`. Mitigated by the offline-restore
  contract (`compose down` first).
- **Recommendation:** Document the recovery in a runbook; consider a boot-time check that detects an
  orphaned `/data.bak.*` and surfaces it. **Complexity S.**

## RISK-008 — Username timing oracle · MEDIUM · OPEN
- **Current state:** `store.go:1670` returns before the bcrypt compare when the username is unknown,
  so a valid username triggers ~100ms bcrypt and an invalid one returns near-instantly.
- **Impact:** Remotely measurable user-enumeration oracle.
- **Recommendation:** Compare against a fixed dummy hash on miss. **Complexity XS.**

## RISK-009 — `InsecureSkipVerify` toggle is silent · MEDIUM · OPEN
- **Current state:** `auth_oidc.go:95`, `auth_oidc_flow.go:302`, `auth_ldap.go:122` honor an admin
  `TLSSkipVerify` flag that fully disables cert validation on the credential-bearing channel, with
  no warning logged at the auth hot path.
- **Impact:** A MITM on the LDAP/OIDC path can harvest credentials when the toggle is on.
- **Recommendation:** Log loudly (WARN) on every auth init when the toggle is enabled. **Complexity XS.**

## RISK-010 — Self-update has no in-binary image verification · MEDIUM · OPEN
- **Current state:** `apiUpdateApply` (`update.go:496-608`) delegates pull/restart to the external
  updater sidecar; the proxy never verifies the pulled image's signature or digest. The Sigstore
  machinery verifies *catalogs*, not the image the updater pulls.
- **Impact:** A compromised/misconfigured updater can run an arbitrary image with no proxy-side defense.
- **Recommendation:** Verify a pinned digest/signature in-binary before accepting an applied update.
  **Complexity M.**

## RISK-011 — Rolling-update auto-rollback unverified · MEDIUM · OPEN
- **Current state:** `triggerAutoRollback` (`update_cluster.go:804-852`) re-pushes the previous tag
  but never confirms the node reverted; it can mark `rollback_failed` while the node still runs the
  broken version. No failure-path tests.
- **Impact:** "Auto-rollback" cannot be trusted to restore service; mid-rollout failure can strand a
  mixed-version cluster.
- **Recommendation:** Post-rollback health verification + failure-path tests. **Complexity M.**

## RISK-012 — Username-keyed lockout (DoS) · LOW · OPEN
- `lockout.go:36,60`: an attacker who knows an admin username can deliberately lock it out; restart
  clears all lockouts (also the informal break-glass). Consider IP+user keying. **Complexity S.**

## RISK-013 — `normalizeHost` IDNA fail-open · LOW · OPEN
- `security.go:34-37`: on IDNA error the original host is returned, potentially letting a malformed/
  homograph host evade an FQDN rule. Narrow but a fail-open in a security-relevant normalization step.

---

### Review log
- **2026-06-28** — Register created from the baseline audit. RISK-001/002 hand-verified; remainder
  on sub-reviewer evidence. No items closed yet.
