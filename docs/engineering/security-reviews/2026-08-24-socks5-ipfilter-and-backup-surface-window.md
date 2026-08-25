# Security Regression Review — SOCKS5 Listener Health (CHAOS-54), IP-Filter Read View, Backup-Surface Expansion

- **Date:** 2026-08-24
- **Reviewer role:** Security Regression Engineer (standing charter, `docs/engineering/ENGINEERING-CONSTITUTION.md`)
- **Baseline:** `daf66d9` (tip of the 2026-08-23 review)
- **Tip under review:** `9b1ba86`
- **Window:** 27 commits / 59 files / ~3.6k insertions. The security-relevant
  mass is PR #1207 (the lock-free IP-filter read view + `AddAll` bulk load),
  PR #1208 (CHAOS-54 SOCKS5 accept-loop hardening and its health plane), the
  nightly-QA backup-surface expansion (`4117bca`), the interactive-login-state
  diagnostics row (`d711e7e`/`4ea9bcc`), the lint/e2e follow-ups to the previous
  window's pre-auth TLS-fallback redaction, and four dependency/action bumps.

## Executive Summary

**One security regression found and fixed.** It is not a defect in any single
line of the window's diff — it is a *feature interaction*. A backup-completeness
fix added `alert_webhooks.json` to the archive; the alert store has long
responded to an undecryptable signing secret by blanking it and delivering
**unsigned**. Joining those two facts makes "restore a backup onto a fresh
volume" — a supported, documented operator workflow — a routine way to end up
with webhooks that the admin UI shows as healthy and signed while their
deliveries carry no `X-Culvert-Signature` at all. The same interaction also
*destroys* the still-recoverable ciphertext on the next unrelated admin edit.

Everything else in the window is either byte-faithful to the baseline or
strictly tighter. The IP-filter rewrite was re-verified independently (not just
against its own tests) with a differential fuzz against a verbatim copy of the
pre-change algorithm: **no divergence**. The CHAOS-54 work closes a real
availability/log-destruction defect and fails closed on a dead socket.

| ID | Finding | Severity | Class | Status |
|----|---------|----------|-------|--------|
| SEC-WHSIGN-1 | A restored `alert_webhooks.json` whose node-local signing key is absent silently disables webhook HMAC signing — the redacted list renders it identically to a webhook that never had a secret — and the next save of *any* webhook overwrites the recoverable ciphertext with `""`, destroying it permanently. | **Medium** | CWE-325 (Missing Required Cryptographic Step) · CWE-778 (Insufficient Logging) · CWE-212 (Improper Removal of Sensitive Information Before Storage) · OWASP A02 (Cryptographic Failures) / A09 (Logging & Monitoring Failures) | Fixed |
| SEC-BKP-2 | The archive gained a file whose secrets are ciphertext next to the key that unwraps them, with no packer-level rule keeping the two apart (only the named allowlist), and the operator doc's enumeration of what an *unencrypted* backup exposes did not mention webhook endpoint URLs — bearer credentials for most receivers. | **Low** | CWE-522 (Insufficiently Protected Credentials) · CWE-311 · OWASP A02 | Fixed |

---

## SEC-WHSIGN-1 — Restored webhooks deliver unsigned, and the secret is then destroyed

**Files:** `internal/alerts/store.go` (`Init`, `save`, `List`, `Update`, `Add`),
`backup.go` (`defaultBackupArtifacts`)
**Introduced by:** `4117bca` — "add decryption/alert-webhook/fileblock/SaaS-override
stores to the D1.5 backup surface" (this window), interacting with the RISK-003
at-rest encryption behaviour that predates it.

### What changed

`defaultBackupArtifacts` gained four entries; one of them is
`alert_webhooks.json`. Webhook HMAC signing secrets in that file are AES-GCM
ciphertext (RISK-003), encrypted under `<dataDir>/.alert_webhook_key` — a
**node-local** key that is deliberately *not* in the archive, on the same
principle that excludes `.kek` files: a key must never share a tarball with the
material it unwraps.

That is the correct exclusion. The problem is what the alert store does when it
finds a secret it cannot unwrap. Pre-fix:

```go
pt, err := decryptWebhookSecret(as.hooks[i].Secret, dir)
if err != nil {
    obs.Printf("AlertStore: webhook %q secret decrypt failed, disabling signing: %v", …)
    as.hooks[i].Secret = ""   // ← in memory
    continue
}
```

Three consequences, each verified by reproduction against the pre-fix tree:

1. **Signing is off, silently.** `deliverAttempt` sets `X-Culvert-Signature`
   only `if h.Secret != ""`. Every subsequent delivery is unsigned.
2. **The UI cannot show it.** `List()` blanks `Secret` (correctly), so
   *"no signing secret was ever configured"* and *"the configured secret is
   unusable and deliveries are now unsigned"* serialise to byte-identical JSON.
   The only signal was one `obs.Printf` at boot. The alerting plane cannot page
   about its own signing being broken.
3. **The ciphertext is destroyed.** `save()` rewrites the *whole* list, so the
   next add/edit/delete/toggle of **any** webhook re-encrypted the blanked
   cleartext — persisting `""` over a blob that restoring the key file would
   have recovered. The code comment claimed "we do not auto-resave (no data
   loss on a transient key-read failure)"; that intent was not actually upheld,
   because an unrelated mutation resaves.

### Attack scenario

*Preconditions:* a webhook configured with a signing secret; the appliance is
rebuilt/migrated from a backup (§ 5–6 of the backup runbook) onto a volume
without the original `.alert_webhook_key`, **or** the key file is transiently
unreadable when the store loads (permissions, or the descriptor-exhaustion
window CHAOS-54 in this very window documents — `os.ReadFile` fails with EMFILE
like anything else).

*Scenario A — monitoring blind spot (the realistic one).* The SIEM/receiver
verifies `X-Culvert-Signature` and drops anything unsigned. After the restore,
every `threat_detected` / `policy_block` / `cert_expiry` alert this gateway
emits is discarded by the receiver. The admin console shows the webhooks as
Active; delivery history shows 2xx (many receivers accept and then drop at the
validation layer, and a rejecting one looks like an unrelated endpoint fault).
The operator has no reason to suspect the signing key. Security alerting is
dark, and *quiet looks exactly like healthy* — the failure mode security
monitoring exists to avoid.

*Scenario B — forged alerts.* A receiver that accepts unsigned payloads (the
common posture once signature checks start failing) will now accept anything
posted to that endpoint. The endpoint URL is not secret-by-design and — see
SEC-BKP-2 — travels in the archive in cleartext. Whoever can post to it can
inject false "threat cleared"/noise events, or bury a real one.

*Scenario C — irreversible loss.* Any admin edit after the restore (adding a
second webhook, toggling one off) permanently discards the original ciphertext,
so an operator who later locates the node's old key file cannot recover.

*Exploitability:* low as a direct attack (an attacker does not choose when you
restore a backup), but the *reachability* is what changed: from "essentially
never" to "every rebuild-from-backup". Scenario A needs no attacker at all.
*Likelihood:* Medium. *Impact:* Medium — loss of authenticity on the security
alerting channel plus destruction of key material. *Affected assets:* webhook
HMAC signing secrets; the integrity of the outbound alert/SIEM channel.

### Fix (landed)

Security-first and minimal — no delivery behaviour was widened, and nothing was
made more permissive:

1. **The ciphertext survives.** `Webhook.sealedSecret` (unexported) holds the
   value that failed to decrypt; `save()` writes it back verbatim instead of
   re-encrypting the blanked cleartext. In-memory `Secret` stays empty — we
   still never sign with a value we could not verify — but the failure is now
   *recoverable* instead of destructive. `Update` carries it across a
   secret-less edit; supplying a new secret replaces it and clears the state.
2. **The state is visible.** `List()` reports a derived, read-only
   `SigningDegraded` (`signing_degraded` on the wire) — the one bit an operator
   needs, carrying no key material. It is **derived, never accepted**: `Add`,
   `Update` and the on-disk document cannot assert it (pinned by test), and it
   is never persisted.
3. **It reaches the operator contract.** New `alert_webhook_signing`
   diagnostics row (OK / warn) with a remedy, counts only — no name, URL or
   ciphertext on that viewer-role surface — plus an amber
   *"Unsigned — secret unusable"* badge in Security → Alert Webhooks.

Deliberately **not** done: refusing delivery outright when the secret is
unusable. That trades a visible authenticity failure for total alert silence,
which is worse against Scenario A; the posture chosen is "keep delivering, make
the degradation impossible to miss". Recorded as an owner decision.

---

## SEC-BKP-2 — Node-local webhook key had no packer-level exclusion; doc understated the archive

**Files:** `backup.go` (`isNodeLocalKeyArtifactPath`, `packOne`),
`docs/operator/docker-compose-backup-restore.md`

`packOne` refused `*.kek` as defense-in-depth "for the config_versions/ walk and
any future dataDir glob". With `alert_webhooks.json` now archived, the
`.alert_webhook_key` beside it is exactly the same class of file and had no such
rule — only the named allowlist kept it out. A future artifact entry with
`IsDir: true` over `dataDir`, or a glob, would have packed the key together with
every secret it unwraps, making the at-rest encryption of all webhook secrets
decorative for anyone holding the tarball.

`isNodeLocalKeyArtifactPath` now covers both classes and is what `packOne`
calls; `isKEKArtifactPath` is unchanged so its own test stays meaningful. The
operator doc's "what an unencrypted backup contains" list now names webhook
endpoint URLs (bearer credentials for Slack/Teams/most receivers), and a new
§ 9.5 documents that signing secrets are not portable, what the operator will
see, and how to recover.

---

## Regression analysis — what was reviewed and found safe

### IP filter: lock-free read view + `AddAll` (`security.go`, PR #1207)

`IPFilter.Allowed` is the first gate on every proxied request, so this is the
highest-consequence change in the window. It was re-verified **independently**
of its own suite: a throwaway differential harness re-implemented the pre-change
algorithm (`net.ParseIP` + `String()`-keyed exact set + linear
`net.IPNet.Contains` scan) and compared verdicts across hand-picked divergence
shapes (`0.0.0.0/0`, `::/0`, `::ffff:10.0.0.0/104`, `::ffff:0.0.0.0/96`,
4-in-6 probes, zoned addresses, `/32`, `/128`, malformed and non-IP probes) and
400 randomised taxonomies × 60 probes each. **No divergence.** Specifically
confirmed:

- The v4-mapped normalisation mirrors `net.networkNumberAndMask`, so
  `::ffff:10.0.0.0/104` still behaves like `10.0.0.0/8` — the fail-open
  direction a naive "16 bytes means IPv6" reading would produce for a blocklist.
- Zoned probes still match nothing (`net.ParseIP` rejected them; the new path
  rejects them explicitly rather than by accident).
- The corrupt-mode `default: return false` fail-closed arm is intact and now
  reads mode and entries from **one** immutable view, removing the previous
  half-applied-mutation window.
- Every mutator (`SetMode`, `Add`, `AddAll`, `Remove`, `ClearAll`) publishes
  before releasing the lock; the two `IPFilter` composite literals in the tree
  (`security.go`, `controlplane_snapshot.go`) start empty, so the
  `emptyIPFilterView` fallback is mode `""` — the pre-change verdict for a fresh
  filter.
- `configversion.go` swapping a `List()`+`Remove` loop for `ClearAll` is
  equivalent (the loop removed everything) and shortens, not lengthens, the
  transient window in which a `block`-mode list is empty.
- Bulk callers moved to `AddAll`; invalid entries are still skipped, and the two
  callers that logged them still log them (outside the lock).

### SOCKS5 accept loop + health plane (CHAOS-54, PR #1208)

No per-connection control is bypassed — `handleSOCKS5` (IP filter, rate limit,
auth negotiation) is unchanged and still reached only via a successful
`Accept`. A dead listening socket now **closes the port** (fail closed:
connection-refused rather than a bound black hole) and reports DOWN; an
unrecognised errno is deliberately non-fatal but never silent. `net.ErrClosed`
is not treated as a shutdown unless `Stop` actually ran, closing a
green-probe-on-a-dead-listener hole. Disclosure was checked on each new surface:
`/health` and `/readyz` are unauthenticated on the proxy port and carry a fixed
enum / fixed detail string, while the error count, reason class and cause text
stay on the role-gated diagnostics row, the alert and the log. The alert Detail
is a bounded reason class (correct for `Dispatch`'s `event + ":" + Detail`
dedup), the producer is `HasSubscriber`-gated, degraded and down carry separate
fire-once latches, and metrics are omitted entirely when SOCKS5 is unconfigured
so `up == 0` keeps meaning what the paging rule says.

### Pre-auth TLS-fallback redaction (follow-ups to the previous window)

Server-side redaction is intact: `ui_tls_fallback_reason` appears only on the
viewer-gated `GET /api/settings/network`; the wall test's diff is cosmetic
(`nil` → `http.NoBody` for lint). The **shipped** `frontend/dist` bundle was
checked directly, not just the source: the "Server detail:" rendering is gone
and the pointer-to-Settings copy is present. Decoding the reason as optional is
a decoder relaxation only — the `ui_tls_fallback` *flag* stays required, so a
malformed response is still a `DecodeError`.

### Other

- `checkInteractiveLoginState` (diagnostics): counts only, no client IPs, both
  stores are non-nil package globals — no new disclosure, no nil-deref.
- `/healthz` + `/metrics` SOCKS5 additions: bounded, gauges omitted when
  unconfigured.
- `internal/redaction`, `support_upload.go`, `support_telemetry_config.go`:
  ADR-number corrections in comments only; no logic.
- PAC "Bypass Exclusions" → "PAC Exclusions (DIRECT Bypass)": label text only,
  and a clarification in the safe direction.
- Dependency/action bumps (`etree` 1.7.0→1.7.1, `kin-openapi`, `grpc`,
  `golang:1.27-alpine`, `setup-buildx-action` v4.3.0): all forward, the action
  is still pinned by full commit SHA.
- Restore path unchanged: the `..`-component rejection, absolute-path rejection,
  `guardWithinDir` and symlink refusal all still stand between the new nested
  `data/saas_feed/overrides.json` entry and the filesystem.

## Required tests (all landed)

| Kind | Test |
|------|------|
| Regression (fails pre-fix) | `TestSigningDegraded_UndecryptableCiphertextSurvivesUnrelatedSave`, `…_DeleteOfAnotherHookDoesNotDestroyTheCiphertext`, `…_UpdateWithoutSecretPreservesCiphertext` |
| Positive | `TestSigningDegraded_HealthyStoreIsNotDegraded`, `TestDiagnostics_AlertWebhookSigningRow_OKWhenHealthy` |
| Negative / visibility | `TestSigningDegraded_ListReportsItWithoutLeaking`, `TestDiagnostics_AlertWebhookSigningRow_WarnsWhenDegraded`, `TestAlertWebhookList_ExposesSigningDegradedWithoutSecrets` |
| Recovery | `TestSigningDegraded_ReEnteringTheSecretRecovers`, `TestSigningDegraded_RestoringTheKeyFileRecoversSigning` |
| Boundary / malformed input | `TestSigningDegraded_MalformedStoredSecret` (non-base64, empty, truncated), empty-secret round-trip in `…_HealthyStoreIsNotDegraded` |
| Authorization / trust boundary | `TestSigningDegraded_StatusIsNeverAcceptedFromACaller` (create, update, and a hand-edited store file) |
| Concurrency (`-race`) | `TestSigningDegraded_ConcurrentReadersAndWriters` |
| Secret containment | `TestBackup_NeverPacksTheWebhookSigningKey`, `TestIsNodeLocalKeyArtifactPath` |
| Contract | `alert_webhook_signing` added to the required-row set in `diagnostics_test.go`; `TestDiagnostics_AlertWebhookSigningRow_InDefaultReport` |

## Residual risk

1. **A config *import* still discards the sealed ciphertext.** `apiConfigImport`
   deletes every webhook and re-adds the exported (secret-less) list, so the
   preserved blob goes with it. Pre-existing and consistent with "secrets are
   not exported"; now documented in § 9.5 of the backup runbook. Not changed
   here — import semantics are a wider surface than this fix.
2. **Unencrypted backups remain sensitive by construction.** Webhook URLs are
   cleartext in the archive, as are `ui_users.json` hashes and TOTP secrets. The
   doc says dev/lab only and now enumerates the URLs; the encrypted flow is the
   production default.
3. **Legacy cleartext webhook secrets** (a store written before RISK-003 and
   never re-saved since) are archived as cleartext. One mutation migrates them.
   Unchanged by this window; recorded.
4. **`ipf` is a plain package global reassigned by the DP snapshot apply**
   (`applySnapshotTrafficExceptBlocklist`) while request goroutines read it —
   an unsynchronised pointer swap, pre-existing, and the same shape as the other
   snapshot-applied globals. Worst case is a request evaluated against the
   immediately-previous filter. Recorded, not changed in a security-review PR.
5. **The `X-Culvert-Signature` posture on a degraded webhook stays fail-open**
   (deliver unsigned, loudly) rather than fail-closed (refuse to deliver). Owner
   decision, argued above; revisit if a customer requires signed-or-nothing.
6. **The at-rest envelope still carries no key identity.** `enc:v1:` records
   nonce+ciphertext and nothing about which key sealed it, so a store *can*
   hold blobs from two key generations — restore-preserved ones under the old
   key, anything written since under the current one — and nothing but the
   operator's memory distinguishes them. Raised by Codex review on PR #1222.
   Two thirds of the hazard are closed here: a failed decrypt no longer mints a
   key (so a degraded node has *no* key until the operator acts, which makes
   the key-restore path clean), and both operator surfaces state the remedy in
   order. What remains — a mixed store if the operator re-enters secrets and
   *then* restores the old key — is now a visible, badged state rather than a
   silent one, but the durable fix is a key-identified envelope (`enc:v2:
   <key-id>:…`) with rewrap-on-load. That is an on-disk format change with
   downgrade implications, deliberately out of scope for a security-review PR.
