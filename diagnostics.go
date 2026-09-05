package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/session"
)

// OperatorContract is the aggregated, operator-visible health verdict for
// the running node. It is a side-effect-free read of process state via the
// safe accessors that already exist on each subsystem; the handler does no
// disk writes, no network probes, and triggers no fresh ClamAV/health pings.
// One bounded read of the latest config-version envelope is performed per
// call (see configVersionSummary) so the rollback-readiness checks reflect
// the current on-disk state — that read is read-only and never modifies
// /data/config_versions.
//
// The shape is intentionally extensible: future PRs add checks by appending
// to the Checks slice. Field names are stable JSON keys so the SPA and
// downstream tooling can rely on them.
type OperatorContract struct {
	Verdict     string                  `json:"verdict" redact:"internal"` // "ok" | "warn" | "fail"
	GeneratedAt string                  `json:"generated_at" redact:"public"`
	Checks      []OperatorContractCheck `json:"checks" redact:"internal"`
}

// OperatorContractCheck is one row in the diagnostics report.
//
// Code is a stable identifier (snake_case) used by automation and the SPA.
// Status is one of "ok", "warn", "fail". Message is a short human summary.
// OperatorAction tells the operator what (if anything) to do — required when
// Status is "warn" or "fail" so the GUI can render an actionable hint.
type OperatorContractCheck struct {
	Code           string `json:"code" redact:"public"`
	Status         string `json:"status" redact:"public"`
	Message        string `json:"message" redact:"internal"`
	OperatorAction string `json:"operator_action,omitempty" redact:"internal"`
}

const (
	diagOK   = "ok"
	diagWarn = "warn"
	diagFail = "fail"
)

// storageWritability cached states. The probe runs once at startup
// (probeStorageWritability) and never re-runs — so the diagnostics
// handler stays side-effect-free.
const (
	storageStateUnknown    = "unknown"
	storageStateWritable   = "writable"
	storageStateUnwritable = "unwritable"
)

// storageWritableState holds the result of the one-shot startup probe.
// atomic.Value gives us race-free reads from the diagnostics handler
// without locking; it stores a plain string from the storageState* set.
var storageWritableState atomic.Value

// probeStorageWritability runs ONCE at startup against the configured
// dataDir. It creates a temp file, writes a few bytes, closes, and
// removes it. The outcome is cached in storageWritableState; the
// diagnostics handler reads the cached value and never re-probes.
//
// Contract:
//   - never retries
//   - never blocks startup (cleanup failure is logged but does not
//     downgrade the verdict — the write itself proved writability)
//   - safe to call multiple times (last write wins) but expected to
//     run exactly once from initPersistentAdminState
func probeStorageWritability() {
	if dataDir == "" {
		storageWritableState.Store(storageStateUnknown)
		return
	}
	f, err := os.CreateTemp(dataDir, ".culvert-writability-probe-*")
	if err != nil {
		storageWritableState.Store(storageStateUnwritable)
		return
	}
	name := f.Name()
	if _, werr := f.WriteString("ok"); werr != nil {
		_ = f.Close()
		_ = os.Remove(name)
		storageWritableState.Store(storageStateUnwritable)
		return
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(name)
		storageWritableState.Store(storageStateUnwritable)
		return
	}
	if rerr := os.Remove(name); rerr != nil {
		// The write itself succeeded — operator intent (durable write)
		// is satisfied. Log the cleanup miss but do not downgrade the
		// verdict; otherwise a transient unlink failure would
		// permanently mark the node unwritable for the rest of this
		// process lifetime.
		logger.Printf("Storage: writability probe cleanup failed: %v", rerr)
	}
	storageWritableState.Store(storageStateWritable)
}

// storageWritability returns the cached probe result, or
// storageStateUnknown if the probe has not yet run.
func storageWritability() string {
	if v := storageWritableState.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return storageStateUnknown
}

// sessionSecretSet reports whether the admin session HMAC key has been
// initialised. Boolean only — the secret value is never returned or logged.
func sessionSecretSet() bool {
	return len(session.SigningKey()) >= 32
}

// buildOperatorContract assembles the full diagnostics report.
//
// Side-effect contract:
//   - reads cached / atomic / RLock-protected state only
//   - never opens files, sockets, or pings external daemons
//   - safe to call concurrently from the admin API
func buildOperatorContract() OperatorContract {
	// One read per call: scan configVersionsDir, parse the latest
	// envelope, run validateConfigBackup on it. Shared across the
	// three config-version checks so they don't each re-read the file.
	cv := summarizeLatestConfigVersion()
	checks := []OperatorContractCheck{
		checkStorage(),
		checkPolicyLoaded(),
		checkRootCA(),
		checkSessionSecret(),
		checkCDR(),
		checkClusterPosture(),
		checkDPLastGoodConfigSnapshot(),
		checkConfigSnapshotApply(),
		checkSAMLStatePosture(),
		checkSAMLBaseURLPosture(),
		checkDefaultAuthOpen(),
		checkYARAEnginePosture(),
		checkConfigSourcePrecedence(),
		checkConfigSnapshotValidator(),
		checkConfigVersionsPresent(cv),
		checkConfigVersionsReadable(cv),
		checkConfigVersionsIntegrity(),
		checkConfigRollbackValidation(cv),
		checkKeyAtRest(),
		checkPlaintextKeyBackups(),
		checkAuditPersistence(),
		checkCategoryFeedDB(),
		checkSOCKS5Listener(),
		checkRequestLogPersistence(),
		checkIdentityBackend(),
		checkInteractiveLoginState(),
		checkAlertWebhookSigning(),
		checkOIDCJWKSTrust(),
		checkSyslogFeed(),
		checkMemoryBackstop(),
	}
	// Cluster (enrollment) CA — CHAOS-50. Contributes nothing on a node with no
	// cluster CA, so it never adds a row to a single-node appliance's report.
	checks = append(checks, checkClusterCA()...)
	// Auth Exempt risk diagnostics (Slice 8): WARN-only rows for risky Stage-1
	// exemption postures. Contributes nothing when no exempt rules exist.
	checks = append(checks, authExemptDiagnostics(policyStore.List(), policyActionFromDefault())...)
	checks = append(checks, authCredentialRequiredDiagnostics(policyStore.List(), hasCredentialCapableProvider())...)
	// LDAP profile hygiene diagnostics (ADR-0027). Report-only; contribute
	// nothing when no LDAP profiles exist.
	checks = append(checks, authLDAPProfileDiagnostics()...)
	// SSORequired risk diagnostics + auth-rule shadow/overlap diagnostics (Phase 3
	// Slice 5). Report-only; contribute nothing when no SSO/auth rules apply.
	checks = append(checks, authSSORequiredDiagnostics(policyStore.List())...)
	checks = append(checks, authRuleShadowDiagnostics(policyStore.List())...)
	// Slice 3 (S2): scoped CR/SSO rules now ENFORCE under defaultAuthOutcome=Exempt
	// (they were dead under the legacy UnauthMode). Surface that migration risk.
	checks = append(checks, authDefaultExemptMigrationDiagnostics(policyStore.List(),
		cfg != nil && cfg.DefaultAuthOutcome() == OutcomeExempt)...)
	return OperatorContract{
		Verdict:     rollUpVerdict(checks),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Checks:      checks,
	}
}

func checkDPLastGoodConfigSnapshot() OperatorContractCheck {
	if !audit.DPMode() {
		return OperatorContractCheck{
			Code:    "dp_last_known_good_config",
			Status:  diagOK,
			Message: "not running as a data plane",
		}
	}
	if activeDPClient.Load() == nil {
		return OperatorContractCheck{
			Code:           "dp_last_known_good_config",
			Status:         diagWarn,
			Message:        "data plane client is not active",
			OperatorAction: "Check data plane startup logs and enrollment configuration.",
		}
	}
	st, _ := dpLastGoodConfigSnapshotState.Load().(dpLastGoodConfigSnapshotStatus)
	if !dpControlPlanePollFailing.Load() {
		if st.SaveError != "" {
			return OperatorContractCheck{
				Code:           "dp_last_known_good_config",
				Status:         diagWarn,
				Message:        "control plane reachable, but last-known-good snapshot persistence failed",
				OperatorAction: "Fix data directory permissions so this DP can preserve its last successfully applied config for CP outages.",
			}
		}
		return OperatorContractCheck{
			Code:    "dp_last_known_good_config",
			Status:  diagOK,
			Message: "control plane polling healthy",
		}
	}
	if st.Loaded || st.SavedVersion > 0 {
		return OperatorContractCheck{
			Code:           "dp_last_known_good_config",
			Status:         diagWarn,
			Message:        "control plane unreachable; serving last-known-good local config",
			OperatorAction: "Restore control plane connectivity. This DP can continue serving with its cached config, but new policy/auth changes will not arrive until CP polling recovers.",
		}
	}
	return OperatorContractCheck{
		Code:           "dp_last_known_good_config",
		Status:         diagFail,
		Message:        "control plane unreachable and no last-known-good local config is available",
		OperatorAction: "Restore control plane connectivity or re-enroll/restart this DP after it has successfully received a config snapshot.",
	}
}

// checkConfigSnapshotApply covers a failure mode dp_last_known_good_config
// does not: the CONTENT of the last snapshot/delta received from the
// control plane was rejected (malformed payload, over-cap validation
// failure, IdP-profile sync failure, or an
// applyConfigSnapshot/applyBlocklistDeltaSnapshot rejection — see
// configsnapshot_apply_health.go), even though CP polling itself is
// succeeding. Without this check that state reads as a plain "control plane
// polling healthy" ok, even though this node is silently stuck on stale
// policy/auth config. Deliberately silent on CP reachability — that is
// dp_last_known_good_config's claim to make (via dpControlPlanePollFailing),
// and configSnapshotApplyFailing can still be latched from a rejection that
// happened before a later, unrelated poll outage.
func checkConfigSnapshotApply() OperatorContractCheck {
	if !audit.DPMode() {
		return OperatorContractCheck{
			Code:    "dp_config_snapshot_apply",
			Status:  diagOK,
			Message: "not running as a data plane",
		}
	}
	if !lastConfigSnapshotApplyOK() {
		return OperatorContractCheck{
			Code:           "dp_config_snapshot_apply",
			Status:         diagFail,
			Message:        "the last config snapshot/delta received from the control plane was rejected — this node is not applying new policy/auth config",
			OperatorAction: "Check data plane logs for the most recent \"DataPlane: parse config error\", \"DataPlane: rejecting config snapshot\", \"DataPlane: config snapshot ... apply incomplete\", \"DataPlane: config snapshot ... apply rejected\", \"DataPlane: parse delta remainder\", \"DataPlane: rejecting delta remainder\", or \"DataPlane: delta ... apply failed\" line and fix the control-plane-side config that keeps failing validation.",
		}
	}
	return OperatorContractCheck{
		Code:    "dp_config_snapshot_apply",
		Status:  diagOK,
		Message: "last config snapshot/delta applied successfully",
	}
}

// rollUpVerdict folds the per-check statuses into a single top-level verdict.
// Any "fail" → "fail"; otherwise any "warn" → "warn"; else "ok".
func rollUpVerdict(checks []OperatorContractCheck) string {
	verdict := diagOK
	for i := range checks {
		switch checks[i].Status {
		case diagFail:
			return diagFail
		case diagWarn:
			verdict = diagWarn
		}
	}
	return verdict
}

// ── individual checks ───────────────────────────────────────────────────────
//
// Each returns a fully populated OperatorContractCheck. Checks may NOT
// perform disk I/O, network probes, or any operation that mutates state.

func checkStorage() OperatorContractCheck {
	// CHAOS-45: runtime durable-write failures outrank the boot probe. The
	// probe runs ONCE and its verdict is cached forever, so a data directory
	// that goes read-only or full after boot would otherwise keep reporting
	// "writable (verified once at startup)" while every save silently failed.
	// Observed failures are authoritative evidence that persistence is broken
	// NOW; the probe is only evidence about the state at boot.
	// Recovery is reported ONLY on evidence — a successful durable write
	// observed after the last failure. Elapsed silence is not recovery: a
	// filesystem that is still read-only or still full looks identical to a
	// healthy one when nothing tries to write.
	if s := storageWriteFailures(); s.Total > 0 {
		last := s.Last.UTC().Format(time.RFC3339)
		if !storageRecoveryObserved() {
			return OperatorContractCheck{
				Code:   "storage_path",
				Status: diagFail,
				Message: fmt.Sprintf("%d durable write(s) to the data directory failed and NO successful write has been observed since — persisted state is being LOST (last: %s at %s: %s)",
					s.Total, s.Path, last, s.Err),
				OperatorAction: "The data directory has become unwritable or full since startup. Check free space and inode count, confirm the volume is still mounted read-write, then re-apply any configuration changed since the first failure — admin-API changes made during this window are live in memory but did NOT reach disk and will be lost on restart.",
			}
		}
		return OperatorContractCheck{
			Code:   "storage_path",
			Status: diagWarn,
			Message: fmt.Sprintf("%d durable write(s) failed earlier in this process; writes have since been observed to succeed (last failure: %s at %s)",
				s.Total, s.Path, last),
			OperatorAction: "Writes are landing again — a later write was observed to succeed. Configuration changed during the failure window may still not have reached disk: re-save anything edited around that time, and check the host for the transient full-disk / read-only-remount event.",
		}
	}

	// No runtime failures observed — report the cached result of the one-shot
	// writability probe that ran at startup (probeStorageWritability). The
	// handler itself does NO disk I/O — repeated calls are free.
	switch storageWritability() {
	case storageStateWritable:
		return OperatorContractCheck{
			Code:    "storage_path",
			Status:  diagOK,
			Message: "data directory writable (verified once at startup)",
		}
	case storageStateUnwritable:
		return OperatorContractCheck{
			Code:           "storage_path",
			Status:         diagFail,
			Message:        "data directory not writable at startup — persistence is broken",
			OperatorAction: "Fix mount/permissions on the data directory (chown to the proxy UID, ensure the volume is mounted read-write), then restart the proxy.",
		}
	default:
		// storageStateUnknown — either dataDir is empty or the startup
		// probe never ran (e.g. unit-test path that bypasses
		// initPersistentAdminState).
		return OperatorContractCheck{
			Code:           "storage_path",
			Status:         diagWarn,
			Message:        "data directory writability unknown — startup probe did not run or path not configured",
			OperatorAction: "Set --data-dir or the data_dir config field and restart the proxy so the startup probe can verify writability.",
		}
	}
}

func checkPolicyLoaded() OperatorContractCheck {
	version, updatedAt := policyStore.policyVersion()
	if updatedAt == "" && version == 0 {
		// Default-deny is already applied when no rules exist; this is a
		// warn (operational hint), not a failure — empty policy is a
		// valid Zero-Trust posture for a brand-new install.
		return OperatorContractCheck{
			Code:           "policy_loaded",
			Status:         diagWarn,
			Message:        "policy ruleset is empty (default-deny in effect)",
			OperatorAction: "Author at least one allow rule under Policy, or confirm default-deny is intended.",
		}
	}
	return OperatorContractCheck{
		Code:    "policy_loaded",
		Status:  diagOK,
		Message: "policy ruleset loaded",
	}
}

func checkRootCA() OperatorContractCheck {
	if certMgr == nil || !certMgr.Ready() {
		return OperatorContractCheck{
			Code:           "root_ca",
			Status:         diagWarn,
			Message:        "root CA not initialised — SSL inspection unavailable",
			OperatorAction: "Provide CULVERT_CA_PASSPHRASE and a -ca-bundle path to enable SSL inspection, or ignore if SSL inspection is not used.",
		}
	}
	// CHAOS-28: "initialised" is not the same as "usable". A Root CA outside its
	// own validity window is initialised, signs nothing a client will accept,
	// and used to report diagOK through a total inspected-HTTPS outage. The
	// message carries the impact and a count, never the raw cause — this row is
	// a VIEWER-role surface with a standing no-sensitive-values guardrail, and
	// the cause names the appliance's exact certificate state. Full detail stays
	// in the logs, the alert, and the admin-role CA API.
	if certMgr.Usable() != nil {
		return OperatorContractCheck{
			Code:   "root_ca",
			Status: diagFail,
			Message: fmt.Sprintf("root CA outside its validity window — SSL inspection is BLOCKED (%d connections refused since boot)",
				caUsabilityFailures().Blocks),
			OperatorAction: "Rotate the Root CA (CA Management → Force Rotation) and redistribute the new CA certificate to clients.",
		}
	}
	// Keyed on the CURRENT persistence state, not the cumulative counter: an
	// operator who restores the volume and force-rotates has fixed this, and a
	// row latched on the counter would keep contradicting them until restart.
	if caRotationPersistDegraded() {
		return OperatorContractCheck{
			Code:           "root_ca",
			Status:         diagWarn,
			Message:        "root CA rotated but could not be saved — the replacement exists in memory only and will be lost on restart",
			OperatorAction: "Restore write access to the data directory, then force a Root CA rotation so the new CA is persisted.",
		}
	}
	return OperatorContractCheck{
		Code:    "root_ca",
		Status:  diagOK,
		Message: "root CA initialised",
	}
}

// checkClusterCA is the cluster (enrollment) CA's operator-contract row —
// CHAOS-50, register row CA-13.
//
// The cluster CA had no row at all, which is why its failure was silent: an
// operator running the diagnostics report on a control plane whose CA had gone
// unrotatable, or expired, got a clean bill of health for the trust root every
// DP in the fleet authenticates with.
//
// Contributes NOTHING when no cluster CA is loaded — the ordinary single-node
// appliance must not carry a permanently-degraded row for a feature it does not
// use.
//
// Like root_ca, the message carries impact and counts, never the raw cause: this
// is a VIEWER-role surface under the standing no-sensitive-values guardrail, and
// the cause names the appliance's exact certificate state. Full detail stays in
// the logs, the alert, and the admin-role GET /api/cluster/ca.
func checkClusterCA() []OperatorContractCheck {
	if globalClusterCA.Expiry().IsZero() {
		return nil
	}
	snap := clusterCAFailures()
	if globalClusterCA.Usable() != nil {
		return []OperatorContractCheck{{
			Code:   "cluster_ca",
			Status: diagFail,
			Message: fmt.Sprintf("cluster CA outside its validity window — node enrollment and certificate renewal are REFUSED "+
				"and enrolled nodes cannot complete mTLS (%d issuances refused since boot)", snap.SignRefusals),
			OperatorAction: "Import a replacement cluster CA (Cluster → Cluster CA → Import Custom Cluster CA). Nodes renew automatically once trust is restored.",
		}}
	}
	// Keyed on the CURRENT rotation state, not the cumulative counter: an
	// operator who restores write access and imports a new CA has fixed this,
	// and a row latched on the counter would keep contradicting them until
	// restart.
	if snap.RotationDegraded {
		return []OperatorContractCheck{{
			Code:   "cluster_ca",
			Status: diagFail,
			Message: fmt.Sprintf("cluster CA auto-rotation is failing (%d failures since boot) — the CA will not be replaced "+
				"and every enrolled node loses mTLS trust at its expiry", snap.RotationFailures),
			OperatorAction: "Restore write access to the cluster CA directory, or import a replacement cluster CA under Cluster → Cluster CA.",
		}}
	}
	// Clamped issuances mean the CA is inside its own final window and has not
	// been replaced — the warning shoulder in front of the two failures above.
	if snap.ClampedIssuances > 0 {
		return []OperatorContractCheck{{
			Code:   "cluster_ca",
			Status: diagWarn,
			Message: fmt.Sprintf("cluster CA is inside its final validity window and has not rotated — %d node certificate(s) "+
				"clamped to the CA's own expiry, and affected nodes will renew repeatedly until it is replaced", snap.ClampedIssuances),
			OperatorAction: "Check the Cluster CA panel for a rotation error, or import a replacement cluster CA.",
		}}
	}
	return []OperatorContractCheck{{
		Code:    "cluster_ca",
		Status:  diagOK,
		Message: "cluster CA initialised and within its validity window",
	}}
}

func checkSessionSecret() OperatorContractCheck {
	if !sessionSecretSet() {
		return OperatorContractCheck{
			Code:           "session_secret",
			Status:         diagFail,
			Message:        "admin session HMAC key not initialised",
			OperatorAction: "Restart the proxy; if the problem persists, set CULVERT_SESSION_SECRET to a 64-hex-char value.",
		}
	}
	return OperatorContractCheck{
		Code:    "session_secret",
		Status:  diagOK,
		Message: "admin session HMAC key initialised",
	}
}

// checkAuditPersistence reports whether the operator-configured audit log file
// (audit_log_file / -audit-log) is actually persisting entries to disk. A
// silent failure here (bad path, permissions, unmounted volume) degrades the
// compliance audit trail to the volatile 500-entry in-memory ring with only a
// startup log line as signal. GET /api/stats already exposes the configured
// path (auditLogConfiguredPath) as a raw field; this surfaces it as an explicit
// operator-contract VERDICT (fail + remediation) alongside the other health
// rows. auditLogConfiguredPath records operator intent regardless of Init's
// outcome, so it distinguishes "not configured" from "configured but degraded".
func checkAuditPersistence() OperatorContractCheck {
	if auditLogConfiguredPath == "" {
		return OperatorContractCheck{
			Code:    "audit_log_persistence",
			Status:  diagOK,
			Message: "not configured — audit trail is in-memory only (last 500 events, lost on restart)",
		}
	}
	if !audit.PersistActive() {
		return OperatorContractCheck{
			Code:           "audit_log_persistence",
			Status:         diagFail,
			Message:        "configured but failed to open — audit trail has silently fallen back to the in-memory ring (last 500 events, lost on restart)",
			OperatorAction: "Fix permissions/mount on the configured audit log path, then restart the proxy to restore durable audit persistence.",
		}
	}
	return OperatorContractCheck{
		Code:    "audit_log_persistence",
		Status:  diagOK,
		Message: "audit trail is persisting to the configured log file",
	}
}

// checkRequestLogPersistence reports whether the operator-configured request
// log file (request_log_file / -request-log) is actually persisting entries
// to disk. A silent failure here (bad path, permissions, unmounted volume)
// degrades the traffic log — frequently the artifact pulled for incident
// investigation — to the volatile in-memory ring with only a startup log
// line as signal. GET /api/stats already exposes the configured path
// (requestLogConfiguredPath) as a raw field; this surfaces it as an explicit
// operator-contract VERDICT (fail + remediation) alongside the other health
// rows. requestLogConfiguredPath records operator intent regardless of
// initRequestLog's outcome, so it distinguishes "not configured" from
// "configured but degraded". Mirrors checkAuditPersistence.
func checkRequestLogPersistence() OperatorContractCheck {
	if requestLogConfiguredPath == "" {
		return OperatorContractCheck{
			Code:    "request_log_persistence",
			Status:  diagOK,
			Message: "not configured — request log is in-memory only, lost on restart",
		}
	}
	if !requestLogPersistActive() {
		return OperatorContractCheck{
			Code:           "request_log_persistence",
			Status:         diagFail,
			Message:        "configured but failed to open — request log has silently fallen back to the in-memory ring, lost on restart",
			OperatorAction: "Fix permissions/mount on the configured request log path, then restart the proxy to restore durable request-log persistence.",
		}
	}
	return OperatorContractCheck{
		Code:    "request_log_persistence",
		Status:  diagOK,
		Message: "request log is persisting to the configured log file",
	}
}

// checkIdentityBackend reports external identity-backend (LDAP / OIDC)
// reachability (CHAOS-47).
//
// This row exists because the only prior signal for "the directory is down"
// was a rise in authentication failures — indistinguishable from a
// brute-force spike, and the response to those two situations is opposite.
// Like the storage row, recovery is reported on EVIDENCE only: the degraded
// state clears when a backend is observed to answer, never on elapsed time.
// Memory-only read; no probe is issued from the diagnostics path. The cause
// text is deliberately NOT reproduced here: it names the configured endpoint
// (an LDAP URL, an OIDC introspection host), and this contract is a VIEWER-role surface with a
// standing no-sensitive-values guardrail. The cause goes to the admin-scoped
// sinks — the log line and the identity_backend_unreachable alert.
func checkIdentityBackend() OperatorContractCheck {
	s := authBackendHealthStatus()
	if s.Unavailable == 0 {
		return OperatorContractCheck{
			Code:    "identity_backend",
			Status:  diagOK,
			Message: "no external identity-backend outage observed since startup",
		}
	}
	last := s.Last.UTC().Format(time.RFC3339)
	if s.Degraded {
		return OperatorContractCheck{
			Code:   "identity_backend",
			Status: diagFail,
			Message: fmt.Sprintf("identity backend %q is UNREACHABLE — proxy authentication is failing closed (%d outage(s) since boot, %d request(s) denied without reaching it; last at %s)",
				s.Backend, s.Unavailable, s.GatedDenials, last),
			OperatorAction: "Users cannot authenticate until the directory/IdP answers again. Check reachability from this node (DNS, route, firewall, TLS) and the service account's credentials. No operator action is needed here once it recovers: the denials are not cached, so authentication resumes on the first successful reach.",
		}
	}
	return OperatorContractCheck{
		Code:   "identity_backend",
		Status: diagWarn,
		Message: fmt.Sprintf("identity backend %q was unreachable earlier in this process and has since answered (%d outage(s), %d request(s) denied during them; last at %s)",
			s.Backend, s.Unavailable, s.GatedDenials, last),
		OperatorAction: "Authentication has recovered. Users who authenticated during the window saw 407s; investigate the transient directory/IdP outage on the host or the identity service itself.",
	}
}

// checkInteractiveLoginState reports whether the OIDC PKCE / SAML AuthnRequest
// callback-state stores (internal/authstate) have evicted any in-flight login
// before it could be redeemed.
//
// Both stores are populated by UNAUTHENTICATED requests — every captive/SSO
// portal resolution mints an entry — so a non-zero eviction count is the
// operator's ONLY signal that some in-flight logins were displaced before
// their browser could redeem them: either the fixed 1000-entry cap is
// undersized for real login volume, or an anonymous client is flooding the
// login path. An evicted entry does not prove a user actually hit "invalid or
// expired state" — that requires the browser to attempt the callback after
// its state was dropped, which this store does not observe — so the message
// says "may have", not "did".
//
// Evictions() is cumulative for the process lifetime; Len()/Clients() are a
// snapshot of right now. They can describe different points in time: a burst
// that has long since drained (every entry redeemed or expired) still shows a
// non-zero eviction count next to a near-empty, low-client store, which looks
// identical to a resolved incident and MUST NOT be read as "one small active
// flooding source" from this snapshot alone. Distinguishing an active flood
// from a historical one needs a trend (is the counter still climbing?), which
// the operator_action below asks for explicitly instead of inferring it here.
//
// Prior to this check the only place these counters were visible was the raw
// /metrics text (culvert_login_state_*) — an operator had no reason to look
// there for the cause of a wave of "please try logging in again" tickets.
// Memory-only read; no probe is issued from the diagnostics path.
func checkInteractiveLoginState() OperatorContractCheck {
	pkceEvictions := globalPKCEStore.Evictions()
	samlEvictions := globalSAMLStateStore.Evictions()
	if pkceEvictions == 0 && samlEvictions == 0 {
		return OperatorContractCheck{
			Code:   "interactive_login_state",
			Status: diagOK,
			Message: fmt.Sprintf("no interactive-login (OIDC PKCE / SAML) callback state has been evicted since boot (%d OIDC PKCE, %d SAML entr(ies) currently in flight)",
				globalPKCEStore.Len(), globalSAMLStateStore.Len()),
		}
	}
	return OperatorContractCheck{
		Code:   "interactive_login_state",
		Status: diagWarn,
		Message: fmt.Sprintf("interactive-login callback state has been evicted at the cap since boot — some evicted logins may have failed their SSO callback with \"invalid or expired state\" (OIDC PKCE: %d evicted since boot, %d currently in flight across %d client(s) right now; SAML: %d evicted since boot, %d currently in flight across %d client(s) right now)",
			pkceEvictions, globalPKCEStore.Len(), globalPKCEStore.Clients(),
			samlEvictions, globalSAMLStateStore.Len(), globalSAMLStateStore.Clients()),
		OperatorAction: "The eviction count is cumulative since boot while the in-flight/client counts are a snapshot of right now, so a store that has since drained can show this warning long after the cause resolved — do not read the current client count as the size of the event that caused the evictions. Re-check this endpoint (or culvert_login_state_evictions_total on /metrics) over time: if the eviction count is still climbing alongside a small, steady set of clients, that is an active flooding source hitting the captive-portal/SSO-portal resolution path worth rate-limiting or blocking; if it has stopped climbing, the store already recovered and no action is needed.",
	}
}

// checkAlertWebhookSigning reports webhooks whose configured HMAC signing
// secret could not be decrypted at load, so their deliveries go out UNSIGNED
// (SEC-WHSIGN-1, internal/alerts).
//
// Webhook secrets are encrypted at rest (RISK-003) under a NODE-LOCAL key file
// that is deliberately never archived — putting it in the same tarball as the
// ciphertext it unwraps would defeat encryption at rest, the same rule that
// excludes .kek files. alert_webhooks.json IS archived, so the reachable way to
// land here is restoring a backup onto a fresh volume; an unreadable key file
// (permissions, a descriptor exhaustion window at boot) gets there too.
//
// It needs a row of its own because the failure is INVISIBLE everywhere else an
// operator looks: GET /api/alerts/webhooks redacts the secret, so a webhook
// whose signing is dead renders exactly like one that never had a secret, and
// the alerting plane cannot page about its own signing being off. A receiver
// that verifies X-Culvert-Signature silently stops accepting this node's
// security alerts — a monitoring blind spot that looks like quiet.
//
// Counts only; no webhook name, URL or secret material reaches this VIEWER-role
// surface.
func checkAlertWebhookSigning() OperatorContractCheck {
	degraded := globalAlertStore.SigningDegradedCount()
	if degraded == 0 {
		return OperatorContractCheck{
			Code:    "alert_webhook_signing",
			Status:  diagOK,
			Message: "no alert webhook has an unusable signing secret",
		}
	}
	return OperatorContractCheck{
		Code:   "alert_webhook_signing",
		Status: diagWarn,
		Message: fmt.Sprintf("%d alert webhook(s) were configured with an HMAC signing secret this node cannot decrypt — their deliveries are going out UNSIGNED",
			degraded),
		OperatorAction: "Two remedies, and the ORDER matters. If you still have this node's original .alert_webhook_key (never included in a backup, by design), restore it and restart FIRST — the stored ciphertext is preserved, so every affected webhook recovers with no re-entry. Only if that key is gone, re-enter each affected signing secret in Security → Alert Webhooks. Do not restore the key file AFTER re-entering secrets: the re-entered ones are sealed under this node's new key and putting the old key back would make them unusable in turn. Until one remedy is applied, a receiver that verifies X-Culvert-Signature will reject this node's alerts.",
	}
}

// checkOIDCJWKSTrust reports whether any live OIDC provider's JWKS key set is
// past the stale-trust ceiling (SEC-JWKS-1, auth_oidc_flow.go). The engine
// keeps authenticating with a stale-but-still-trusted key set for up to
// jwksStaleMaxAge while the IdP's JWKS endpoint stays unreachable — a
// deliberate availability trade — but past that ceiling ID-token validation
// starts failing CLOSED for that provider, and the only prior signal was a
// rate-limited log line: "the transition from degraded but working to
// authentication is failing must not be silent" (see logStaleRefusal).
// Memory-only read; issues no fetch. Contributes nothing when no configured
// OIDC provider has ever breached the ceiling.
func checkOIDCJWKSTrust() OperatorContractCheck {
	stale := jwksStaleProviders()
	if len(stale) == 0 {
		return OperatorContractCheck{
			Code:    "oidc_jwks_trust",
			Status:  diagOK,
			Message: "no OIDC provider's JWKS key set is past the stale-trust ceiling",
		}
	}
	return OperatorContractCheck{
		Code:   "oidc_jwks_trust",
		Status: diagFail,
		Message: fmt.Sprintf("OIDC provider(s) %s cannot refresh their JWKS key set and are past the stale-trust ceiling — ID-token validation is FAILING CLOSED for them (a signing key withdrawn at the IdP would otherwise keep authenticating indefinitely)",
			strings.Join(stale, ", ")),
		OperatorAction: "Restore reachability to the provider's JWKS endpoint (DNS, route, firewall, TLS). Logins via this provider will keep failing until one refresh succeeds; no operator action is needed once it does — recovery is automatic on the next successful fetch.",
	}
}

// checkSyslogFeed reports whether the operator-configured syslog/SIEM feed is
// actually delivering. A silent connect failure at startup (unreachable
// collector, bad host/port, TCP refused) leaves globalSyslog nil while the
// /api/syslog readback reports the feed as "not configured" — indistinguishable
// from an intentional no-op — so a compliance/SIEM feed can be down with only a
// single startup log line ("Syslog: connect failed …") as signal. This surfaces
// that state as an explicit operator-contract verdict. syslogConfiguredAddr
// records operator intent regardless of InitSyslog's outcome, so it
// distinguishes "not configured" from "configured but silently down". Mirrors
// checkAuditPersistence. Side-effect-free: reads process state only, never
// dials the collector (use POST /api/syslog/test for an active probe).
func checkSyslogFeed() OperatorContractCheck {
	if syslogConfiguredAddr == "" {
		return OperatorContractCheck{
			Code:    "syslog_feed",
			Status:  diagOK,
			Message: "not configured — no remote syslog/SIEM forwarding",
		}
	}
	// Healthy only when the target we actually connected to (syslogConfigured,
	// set SOLELY on a successful InitSyslog) matches the operator's current
	// intent (syslogConfiguredAddr, recorded regardless of outcome). A bare
	// globalSyslog != nil check is not enough: observability inits from
	// YAML/flags BEFORE admin settings apply a persisted override, so if the
	// first target connects and a later re-init to a new target fails,
	// globalSyslog stays non-nil pointing at the PREVIOUS collector while intent
	// has moved on — the persisted SIEM target is silently down but a nil-check
	// would still report OK.
	if globalSyslog == nil || syslogConfigured != syslogConfiguredAddr {
		return OperatorContractCheck{
			Code:           "syslog_feed",
			Status:         diagFail,
			Message:        "configured but failed to connect — remote syslog/SIEM forwarding is silently down, events are not reaching the collector",
			OperatorAction: "Verify the collector host/port and network path, then re-save the syslog target (POST /api/syslog) or restart the proxy; use POST /api/syslog/test to confirm connectivity.",
		}
	}
	return OperatorContractCheck{
		Code:    "syslog_feed",
		Status:  diagOK,
		Message: "remote syslog/SIEM forwarding is active",
	}
}

// checkCDR summarises Content-Disarm-and-Reconstruction state without
// pinging the Sluice service or the ClamAV daemon. We use only the cached
// config snapshot (cdrActiveConfig — RLock-protected) and the live pool
// length (cdrPool.Len — RLock-protected).
func checkCDR() OperatorContractCheck {
	cfg := cdrActiveConfig()
	if !cfg.Enabled {
		return OperatorContractCheck{
			Code:    "cdr",
			Status:  diagOK,
			Message: "disabled",
		}
	}
	poolSize := cdrPool.Len()
	switch {
	case poolSize == 0:
		return OperatorContractCheck{
			Code:           "cdr",
			Status:         diagFail,
			Message:        "enabled-broken: CDR is enabled but no Sluice instance is connected",
			OperatorAction: "Enrol at least one Sluice instance under CDR, or disable CDR if not in use.",
		}
	case cfg.FailMode == "" || cfg.DefaultProfile == "":
		return OperatorContractCheck{
			Code:           "cdr",
			Status:         diagWarn,
			Message:        "enabled-degraded: CDR is connected but missing fail-mode or default profile",
			OperatorAction: "Set a fail-mode and default profile under CDR → Configuration.",
		}
	default:
		return OperatorContractCheck{
			Code:    "cdr",
			Status:  diagOK,
			Message: "enabled-healthy",
		}
	}
}

// checkClusterPosture reports the cluster TLS posture. clusterInsecure=true
// is intentionally a WARN, not a FAIL — operators are explicitly allowed to
// run insecure clusters for development. The warning surfaces the risk.
func checkClusterPosture() OperatorContractCheck {
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()

	switch role {
	case "", "standalone":
		return OperatorContractCheck{
			Code:    "cluster_posture",
			Status:  diagOK,
			Message: "standalone (clustering disabled)",
		}
	}
	if clusterInsecure {
		return OperatorContractCheck{
			Code:           "cluster_posture",
			Status:         diagWarn,
			Message:        "cluster running in explicitly-insecure mode — gRPC traffic is not encrypted",
			OperatorAction: "Provide TLS certificates via -cp-grpc-cert/-cp-grpc-key/-cp-grpc-ca (Control Plane) and -dp-cert/-dp-key/-dp-ca (Data Plane), then remove --cluster-insecure to harden the cluster.",
		}
	}
	return OperatorContractCheck{
		Code:    "cluster_posture",
		Status:  diagOK,
		Message: "cluster running with mTLS",
	}
}

func checkSAMLStatePosture() OperatorContractCheck {
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role == "" || role == "standalone" || !hasLiveSAMLProvider() {
		return OperatorContractCheck{
			Code:    "saml_state_posture",
			Status:  diagOK,
			Message: "SAML callback state is local to this node (no clustered SAML IdP warning)",
		}
	}
	return OperatorContractCheck{
		Code:           "saml_state_posture",
		Status:         diagWarn,
		Message:        "SAML callback state is node-local while clustering is enabled",
		OperatorAction: "Configure load-balancer affinity for SAML browser flows, especially /auth/saml/callback, so each response returns to the node that created the AuthnRequest.",
	}
}

func hasLiveSAMLProvider() bool {
	for _, prov := range idpRegistry.EnabledProviders() {
		if _, ok := prov.(*SAMLProvider); ok {
			return true
		}
	}
	return false
}

func checkSAMLBaseURLPosture() OperatorContractCheck {
	if !hasEnabledSAMLProfile() {
		return OperatorContractCheck{
			Code:    "saml_base_url",
			Status:  diagOK,
			Message: "no enabled SAML IdP requires SP callback base URL validation",
		}
	}
	baseURL := ""
	if cfg != nil {
		baseURL = strings.TrimSpace(cfg.ProxyBaseURL())
	}
	if baseURL == "" {
		return OperatorContractCheck{
			Code:           "saml_base_url",
			Status:         diagWarn,
			Message:        "SAML IdP enabled but proxy.base_url is unset",
			OperatorAction: "Set proxy.base_url to the externally reachable UI origin, configure the IdP SP Entity ID to that exact value, and configure ACS as proxy.base_url + /auth/saml/callback. trust_forwarded_headers is not a substitute for SAML SP metadata built at startup.",
		}
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return OperatorContractCheck{
			Code:           "saml_base_url",
			Status:         diagFail,
			Message:        "SAML IdP enabled but proxy.base_url is not a valid absolute URL",
			OperatorAction: "Set proxy.base_url to a full external URL such as https://proxy.example.com or https://proxy.example.com/culvert, then update the IdP Entity ID and ACS URL to match.",
		}
	}
	// proxy.base_url must be a clean base origin (+optional path prefix) only.
	// OIDC callbacks are built by string concatenation and SAML metadata/ACS
	// construction drops RawQuery/Fragment, so a query, fragment, or userinfo
	// component would silently produce wrong/inconsistent Entity ID and ACS
	// values. Reject them as malformed rather than reporting a clean bill.
	if hasNonBaseURLComponents(u) {
		return OperatorContractCheck{
			Code:           "saml_base_url",
			Status:         diagFail,
			Message:        "SAML IdP enabled but proxy.base_url contains query, fragment, or userinfo components",
			OperatorAction: "Set proxy.base_url to a bare external origin (optionally with a path prefix) such as https://proxy.example.com or https://proxy.example.com/culvert. Remove any \"?query\", \"#fragment\", or \"user:pass@\" parts, then update the IdP Entity ID and ACS URL to match.",
		}
	}
	if isLocalhostBaseURL(u) {
		return OperatorContractCheck{
			Code:           "saml_base_url",
			Status:         diagWarn,
			Message:        "SAML IdP enabled but proxy.base_url points at localhost",
			OperatorAction: "Use the externally reachable DNS name that browsers and the IdP can reach. Localhost is only safe for single-node local development.",
		}
	}
	if u.Scheme != "https" {
		return OperatorContractCheck{
			Code:           "saml_base_url",
			Status:         diagWarn,
			Message:        "SAML IdP enabled but proxy.base_url is not HTTPS",
			OperatorAction: "Use an HTTPS external URL for production SAML. Most IdPs require HTTPS ACS URLs, and browser SSO cookies are safest behind TLS.",
		}
	}
	return OperatorContractCheck{
		Code:    "saml_base_url",
		Status:  diagOK,
		Message: "SAML SP Entity ID, metadata URL, and ACS URL have an explicit external base URL",
	}
}

func hasEnabledSAMLProfile() bool {
	if idpRegistry == nil {
		return false
	}
	for _, p := range idpRegistry.All() {
		if p != nil && p.Enabled && p.Type == IdPTypeSAML {
			return true
		}
	}
	return false
}

func isLocalhostBaseURL(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// hasNonBaseURLComponents reports whether u carries any component that a usable
// SAML/OIDC base URL must not have: a query string, a fragment, or userinfo.
// These are dropped or string-concatenated downstream, so their presence makes
// the registered callback/EntityID values wrong or inconsistent.
func hasNonBaseURLComponents(u *url.URL) bool {
	return u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil
}

// checkDefaultAuthOpen is a visible WARN when the global default authentication
// is Open unmatched traffic (defaultAuthOutcome=Exempt). Report-only — we never
// remove the operator's freedom to run this way.
func checkDefaultAuthOpen() OperatorContractCheck {
	if cfg != nil && cfg.DefaultAuthOutcome() == OutcomeExempt {
		return OperatorContractCheck{
			Code:           "default_auth_open",
			Status:         diagWarn,
			Message:        "default authentication is Open unmatched traffic — traffic that matches no auth rule is admitted without credentials (not Allow; Stage-2 policy still governs)",
			OperatorAction: "Set default authentication to Require under Settings if unmatched traffic should authenticate; otherwise rely on policy rules to gate access.",
		}
	}
	return OperatorContractCheck{
		Code:    "default_auth_open",
		Status:  diagOK,
		Message: "default authentication requires credentials for unmatched traffic (or no IdP configured)",
	}
}

// checkYARAEnginePosture warns when either on_timeout or on_saturation is set
// to fail_open_with_alert, or when YARA scanning has been disabled by admin
// override. Both are valid operator choices, but require explicit visibility.
func checkYARAEnginePosture() OperatorContractCheck {
	if !yaraGetEnabled() {
		return OperatorContractCheck{
			Code:           "yara_engine_posture",
			Status:         diagWarn,
			Message:        "YARA scanning is disabled by admin override",
			OperatorAction: "Re-enable YARA under Security Scanning → YARA Engine Settings if content scanning is required.",
		}
	}
	timeout := yaraGetOnTimeout()
	sat := yaraGetOnSaturation()
	if timeout == yaraFailOpenWithAlert || sat == yaraFailOpenWithAlert {
		parts := []string{}
		if timeout == yaraFailOpenWithAlert {
			parts = append(parts, "on_timeout=fail_open_with_alert")
		}
		if sat == yaraFailOpenWithAlert {
			parts = append(parts, "on_saturation=fail_open_with_alert")
		}
		return OperatorContractCheck{
			Code:           "yara_engine_posture",
			Status:         diagWarn,
			Message:        "YARA engine posture: " + strings.Join(parts, ", ") + " — unscanned content may pass through on engine stress",
			OperatorAction: "Review YARA Engine Settings under Security Scanning; set both policies to fail_closed to restore Zero Trust posture.",
		}
	}
	return OperatorContractCheck{
		Code:    "yara_engine_posture",
		Status:  diagOK,
		Message: "YARA engine posture: fail-closed on timeout and saturation",
	}
}

// checkConfigSourcePrecedence surfaces the DEBT-009 residual gap: config.yaml
// and CLI flags for a specific group of settings (log retention, log-store
// enable, trusted-proxy CIDRs, blocklist feeds, upstream proxy pool, YARA
// engine settings, decryption auto-exclusion tunables, support-bundle
// retention) are silently superseded the moment ANY admin GUI/API mutation
// is saved — saveAdminSettingsWithOverrides always snapshots the full set
// together, so an operator who only meant to change an unrelated setting
// (e.g. the session timeout) unknowingly pins all of these to their current
// values, and a later config.yaml edit for any of them has no effect after
// restart. This is intended persistence behavior, not a fault, so it always
// reports "ok" — the point is visibility, not a warning.
func checkConfigSourcePrecedence() OperatorContractCheck {
	overridden := AdminSettingsOverriddenSurfaces()
	if len(overridden) == 0 {
		return OperatorContractCheck{
			Code:   "config_source_precedence",
			Status: diagOK,
			Message: "No admin settings saved yet — log retention, log-store enable, trusted-proxy CIDRs, " +
				"blocklist feeds, upstream proxy pool, YARA engine settings, decryption auto-exclusion tunables, " +
				"and support-bundle retention are all sourced from config.yaml/CLI flags.",
		}
	}
	// Per-sentinel, not all-or-nothing: an admin_settings.json written by an
	// older build carries only the sentinels that existed then, and any
	// surface without its sentinel still follows config.yaml/CLI.
	return OperatorContractCheck{
		Code:   "config_source_precedence",
		Status: diagOK,
		Message: "Durable admin overrides are active for: " + strings.Join(overridden, ", ") + ". " +
			"config.yaml/CLI edits for these settings are ignored on restart; any sentinel-gated " +
			"setting not listed still follows config.yaml/CLI.",
		OperatorAction: "Manage the listed settings from the admin GUI or REST API. To return one to " +
			"config.yaml/CLI ownership, stop the node and remove its *_saved sentinel (or the whole " +
			"admin_settings.json) from the data directory — GUI/API edits always re-save the sentinel, " +
			"so YAML never silently regains precedence.",
	}
}

// checkConfigSnapshotValidator confirms the validator function is wired and
// returns nil on the empty snapshot (its baseline contract). Pure function;
// no I/O.
func checkConfigSnapshotValidator() OperatorContractCheck {
	if err := validateConfigSnapshot(ConfigSnapshot{}); err != nil {
		return OperatorContractCheck{
			Code:           "config_snapshot_validator",
			Status:         diagFail,
			Message:        "config snapshot validator rejected the empty baseline",
			OperatorAction: "File a bug — this should never happen; restart the proxy and review startup logs.",
		}
	}
	return OperatorContractCheck{
		Code:    "config_snapshot_validator",
		Status:  diagOK,
		Message: "config snapshot validator available",
	}
}

// ── config-version checks ────────────────────────────────────────────────
//
// These three checks expose the existing config-versioning subsystem
// (configversion.go) as diagnostics. They reuse the canonical numeric
// version-selection logic and the existing validateConfigBackup helper —
// no new backup/restore primitives are introduced here.

// configVersionSummary aggregates one read of the latest config version
// envelope. Built once per /api/diagnostics call so the three
// config-version checks share I/O. Read-only — no files are created,
// modified, or removed by populating this struct.
type configVersionSummary struct {
	Count         int           // count of v{N}.json files on disk
	LatestVersion int           // highest numeric N found; 0 when none
	Found         bool          // true when at least one valid v{N}.json exists
	DirAccessible bool          // true when configVersionsDir could be opened
	LoadErr       error         // non-nil when the latest envelope failed to read or parse
	BadShape      bool          // envelope parsed but meta is missing or has zero version
	Backup        *configBackup // parsed config (only when LoadErr/BadShape are nil)
	Warnings      []string      // validateConfigBackup result on Backup
}

// summarizeLatestConfigVersion is the production entry point used by
// the diagnostics handler. It scans configVersionsDir.
func summarizeLatestConfigVersion() configVersionSummary {
	return summarizeLatestConfigVersionAt(configVersions.Dir())
}

// summarizeLatestConfigVersionAt is the dir-parameterised inner form.
// Tests pass a tempdir to exercise present / readable / validation
// paths without touching the production path constant.
//
// Latest version is selected strictly by numeric version parsed from
// the v{N}.json filename — never by file modified time. This matches
// the semantics of initConfigVersioning, pruneConfigVersions, and
// listConfigVersions.
func summarizeLatestConfigVersionAt(dir string) configVersionSummary {
	var sum configVersionSummary
	entries, err := os.ReadDir(dir)
	if err != nil {
		return sum
	}
	sum.DirAccessible = true
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "v") || !strings.HasSuffix(name, ".json") {
			continue
		}
		numStr := strings.TrimSuffix(strings.TrimPrefix(name, "v"), ".json")
		n, perr := strconv.Atoi(numStr)
		if perr != nil || n <= 0 {
			continue
		}
		sum.Count++
		if !sum.Found || n > sum.LatestVersion {
			sum.LatestVersion = n
			sum.Found = true
		}
	}
	if !sum.Found {
		return sum
	}
	// loadConfigVersion intentionally ignores meta, so we cannot reuse
	// it for envelope-shape checks. Read the file and parse both halves
	// here. This is the only read this function performs — and it is
	// strictly read-only.
	path := filepath.Join(dir, fmt.Sprintf("v%d.json", sum.LatestVersion))
	data, rerr := os.ReadFile(path) // #nosec G304 -- path built from dir + validated v{N}.json
	if rerr != nil {
		sum.LoadErr = rerr
		return sum
	}
	var env struct {
		Meta   ConfigVersion `json:"meta"`
		Config configBackup  `json:"config"`
	}
	if uerr := json.Unmarshal(data, &env); uerr != nil {
		sum.LoadErr = uerr
		return sum
	}
	// Confirm envelope structure: a valid envelope has a populated meta
	// block with a positive version number. A missing or zeroed meta
	// means the file is not a usable rollback target.
	if env.Meta.Version <= 0 {
		sum.BadShape = true
		return sum
	}
	sum.Backup = &env.Config
	sum.Warnings = validateConfigBackup(&env.Config)
	return sum
}

func checkConfigVersionsPresent(s configVersionSummary) OperatorContractCheck {
	if s.Found {
		return OperatorContractCheck{
			Code:    "config_versions_present",
			Status:  diagOK,
			Message: fmt.Sprintf("%d config version(s) on disk; latest is v%d", s.Count, s.LatestVersion),
		}
	}
	return OperatorContractCheck{
		Code:           "config_versions_present",
		Status:         diagWarn,
		Message:        "no config versions found — automatic rollback is unavailable until a config change is made",
		OperatorAction: "Make any config change in the admin UI to seed an initial v1 snapshot, or restore the config_versions directory from a /data backup.",
	}
}

func checkConfigVersionsReadable(s configVersionSummary) OperatorContractCheck {
	if !s.Found {
		// No version on disk: the previous check already flags this.
		// This row stays informational so a single root cause does not
		// cascade into multiple operator alerts.
		return OperatorContractCheck{
			Code:    "config_versions_readable",
			Status:  diagOK,
			Message: "no version file to read",
		}
	}
	if s.LoadErr != nil {
		return OperatorContractCheck{
			Code:           "config_versions_readable",
			Status:         diagFail,
			Message:        fmt.Sprintf("latest config version v%d is unreadable or corrupt", s.LatestVersion),
			OperatorAction: "Inspect the latest v{N}.json under the config versions directory; if it is truncated or invalid JSON, remove it (a prior intact version remains usable) or restore the directory from a /data backup, then restart the proxy.",
		}
	}
	if s.BadShape {
		return OperatorContractCheck{
			Code:           "config_versions_readable",
			Status:         diagFail,
			Message:        fmt.Sprintf("latest config version v%d has a malformed envelope (missing meta block)", s.LatestVersion),
			OperatorAction: "The file does not match the {meta, config} envelope shape Culvert writes. Remove it (a prior intact version remains usable) or restore the directory from a /data backup, then restart the proxy.",
		}
	}
	return OperatorContractCheck{
		Code:    "config_versions_readable",
		Status:  diagOK,
		Message: fmt.Sprintf("latest config version v%d parses cleanly", s.LatestVersion),
	}
}

// checkConfigVersionsIntegrity scans the FULL version history, not just the
// latest snapshot: checkConfigVersionsReadable only inspects the most recent
// v{N}.json, so a corrupt file anywhere else in the retained window (disk
// fault, external tampering, an older-build bug) is silently dropped by
// List/ListMeta and never appears in this check — the rollback list just
// looks shorter, indistinguishable from normal retention pruning.
func checkConfigVersionsIntegrity() OperatorContractCheck {
	present, readable := configVersions.Integrity()
	if present == 0 {
		return OperatorContractCheck{
			Code:    "config_versions_integrity",
			Status:  diagOK,
			Message: "no version history to check",
		}
	}
	if readable < present {
		return OperatorContractCheck{
			Code:           "config_versions_integrity",
			Status:         diagWarn,
			Message:        fmt.Sprintf("%d of %d config version file(s) on disk are corrupt or unreadable and are hidden from the rollback list", present-readable, present),
			OperatorAction: "Inspect the config versions directory for truncated or invalid v{N}.json files; remove any that are unusable (other intact versions remain usable) or restore the directory from a /data backup.",
		}
	}
	return OperatorContractCheck{
		Code:    "config_versions_integrity",
		Status:  diagOK,
		Message: fmt.Sprintf("all %d config version file(s) on disk parse cleanly", present),
	}
}

func checkConfigRollbackValidation(s configVersionSummary) OperatorContractCheck {
	if !s.Found {
		return OperatorContractCheck{
			Code:    "config_rollback_validation",
			Status:  diagOK,
			Message: "no version to validate",
		}
	}
	// Per spec: fail only when parse/load failed.
	if s.LoadErr != nil || s.BadShape {
		return OperatorContractCheck{
			Code:           "config_rollback_validation",
			Status:         diagFail,
			Message:        fmt.Sprintf("cannot validate latest config version v%d — file failed to parse", s.LatestVersion),
			OperatorAction: "Resolve the parse error reported by config_versions_readable, then re-check diagnostics.",
		}
	}
	if n := len(s.Warnings); n > 0 {
		// We deliberately do NOT echo the raw validateConfigBackup
		// warning strings here — they include actual config field
		// values from the backup. Operators can pull the specifics via
		// POST /api/config/versions { "version": N, "dry_run": true }
		// which is the existing, role-gated path.
		return OperatorContractCheck{
			Code:           "config_rollback_validation",
			Status:         diagWarn,
			Message:        fmt.Sprintf("latest config version v%d would roll back with %d validation warning(s)", s.LatestVersion, n),
			OperatorAction: "Run a dry-run rollback via POST /api/config/versions {\"version\":N,\"dry_run\":true} to inspect the warnings, then either roll back to an earlier version or accept the warnings.",
		}
	}
	return OperatorContractCheck{
		Code:    "config_rollback_validation",
		Status:  diagOK,
		Message: fmt.Sprintf("latest config version v%d passes pre-flight validation", s.LatestVersion),
	}
}

// ── Auth Exempt risk diagnostics (Phase 1 Slice 6; wired in Slice 8) ─────────
//
// authExemptDiagnostics inspects auth/exempt (Stage-1) rules for risky postures
// and returns WARN checks. It NEVER mutates, enables, or disables a rule — it
// only reports. Pure over an explicit ruleset + default action, so it is testable
// without globals. Served via the operator contract (buildOperatorContract →
// /api/diagnostics) since Slice 8.

// policyActionFromDefault maps the runtime default policy action string
// ("allow"/"deny") to a PolicyAction for the auth-exempt diagnostics; only
// Allow is significant there.
func policyActionFromDefault() PolicyAction {
	if defaultPolicyAction() == "allow" {
		return ActionAllow
	}
	return ActionDrop
}
func authExemptDiagnostics(rules []PolicyRule, defaultAction PolicyAction) []OperatorContractCheck {
	var exempt []*PolicyRule
	for i := range rules {
		r := &rules[i]
		if ruleTypeOf(r) == ruleTypeAuth && r.Auth != nil && r.Auth.Outcome == OutcomeExempt {
			exempt = append(exempt, r)
		}
	}
	if len(exempt) == 0 {
		return nil
	}

	b := classifyExemptRisks(exempt)

	var checks []OperatorContractCheck
	warn := func(code, msg, action string, names []string) {
		if len(names) == 0 {
			return
		}
		checks = append(checks, OperatorContractCheck{
			Code:           code,
			Status:         diagWarn,
			Message:        msg + ": " + strings.Join(names, ", "),
			OperatorAction: action,
		})
	}
	warn("auth_exempt_broad_exemption",
		"exempt rules waive authentication for ALL destinations (broadExemption=true)",
		"Scope each rule to a destination (destFQDN/category/group) unless a blanket waiver is truly required.",
		b.broadExempt)
	warn("auth_exempt_any_source",
		"exempt rules match ALL source addresses (0.0.0.0/0 or ::/0)",
		"Restrict subjectMatch to the specific client CIDRs that need the exemption.",
		b.anySource)
	warn("auth_exempt_wide_source",
		"exempt rules use a source prefix broader than /24",
		"Tighten the subjectMatch CIDR to the smallest range that covers the exempt clients.",
		b.wideSource)
	warn("auth_exempt_no_expiry",
		"exempt rules have no expiry and will never auto-retire",
		"Set an expiresAt (RFC3339) so each exemption is reviewed and removed on schedule.",
		b.noExpiry)
	warn("auth_exempt_broad_destination",
		"exempt rules match all destinations (no destFQDN/category/group, or destCategory=Any)",
		"Add a destination selector so the exemption is least-privilege.",
		b.broadDest)
	warn("auth_exempt_expired",
		"exempt rules are already expired (they will not match, but remain configured)",
		"Remove the expired exempt rules to keep the ruleset clean.",
		b.expired)

	if defaultAction == ActionAllow {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_exempt_default_allow",
			Status:         diagWarn,
			Message:        fmt.Sprintf("default policy action is Allow while %d exempt rule(s) exist — exemptions add little over an allow-all default", len(exempt)),
			OperatorAction: "Set the default policy action to deny (Zero Trust) so exempt rules are meaningful and unmatched traffic is not allowed by default.",
		})
	}
	return checks
}

// authCredentialRequiredDiagnostics reports operator risks for CredentialRequired
// (CR) Stage-1 rules. It NEVER mutates rules — report only. Pure over an explicit
// ruleset plus the two environmental facts it needs, so it is testable without
// globals (buildOperatorContract supplies the live values):
//
//   - hasCredProvider: whether any credential-capable validator is configured. CR
//     rules with no such validator would challenge (407) covered requests forever
//     → FAIL. SAML alone does NOT count (it cannot validate a presented in-band
//     credential — see hasCredentialCapableProvider).
//
// Slice 3 (S2): the legacy "dead under UnauthMode" WARN is removed — CR rules now
// ENFORCE under defaultAuthOutcome=Exempt. The migration risk is surfaced by
// authDefaultExemptMigrationDiagnostics instead.
func authCredentialRequiredDiagnostics(rules []PolicyRule, hasCredProvider bool) []OperatorContractCheck {
	var names []string
	for i := range rules {
		r := &rules[i]
		if ruleTypeOf(r) != ruleTypeAuth || r.Auth == nil || r.Auth.Outcome != OutcomeCredentialRequired {
			continue
		}
		// Disabled or already-expired rules cannot fire (authRuleMatches checks
		// ruleIsEnabled + authRuleNotExpired), so they must not produce findings —
		// otherwise an inert rule could falsely FAIL the operator contract.
		if !ruleIsEnabled(r) || !authRuleNotExpired(r.Auth) {
			continue
		}
		names = append(names, r.Name)
	}
	if len(names) == 0 {
		return nil
	}
	var checks []OperatorContractCheck
	if !hasCredProvider {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_cr_no_credential_provider",
			Status:         diagFail,
			Message:        "CredentialRequired rules exist but no credential-capable validator is configured — covered requests would be challenged (407) indefinitely: " + strings.Join(names, ", "),
			OperatorAction: "Configure a local account, a legacy auth provider, or an OIDC IdP (SAML alone cannot validate presented credentials), or remove the CredentialRequired rules.",
		})
	}
	return checks
}

// authDefaultExemptMigrationDiagnostics warns that scoped CredentialRequired /
// SSORequired rules — which were DEAD under the legacy UnauthMode — now ENFORCE
// for matching traffic under defaultAuthOutcome=Exempt (Slice 3 / S2). Report-
// only; fires only when the global default is Exempt and ≥1 enabled, non-expired
// CR/SSO rule exists. Pure over an explicit ruleset + the one environmental fact.
func authDefaultExemptMigrationDiagnostics(rules []PolicyRule, defaultExempt bool) []OperatorContractCheck {
	if !defaultExempt {
		return nil
	}
	var names []string
	for i := range rules {
		r := &rules[i]
		if ruleTypeOf(r) != ruleTypeAuth || r.Auth == nil {
			continue
		}
		if r.Auth.Outcome != OutcomeCredentialRequired && r.Auth.Outcome != OutcomeSSORequired {
			continue
		}
		// Disabled / expired rules cannot fire — never surface them.
		if !ruleIsEnabled(r) || !authRuleNotExpired(r.Auth) {
			continue
		}
		names = append(names, r.Name)
	}
	if len(names) == 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:           "auth_default_exempt_rules_now_enforce",
		Status:         diagWarn,
		Message:        "The global default authentication is Open unmatched traffic (defaultAuthOutcome=Exempt). Scoped CredentialRequired/SSORequired rules still ENFORCE for matching traffic — auth rules evaluate first; the global default applies only on no-match: " + strings.Join(names, ", "),
		OperatorAction: "Confirm these rules should enforce. To restore fully-open behavior remove them; to require authentication globally, set the default authentication to Required.",
	}}
}

// hasCredentialCapableProvider reports whether any validator that can verify a
// PRESENTED in-band credential is configured: a local bcrypt account, the legacy
// auth provider, or an enabled OIDC IdP profile. SAML profiles are excluded —
// SAMLProvider.Verify always returns false (interactive browser SSO only), so a
// SAML-only deployment cannot satisfy a CredentialRequired rule.
func hasCredentialCapableProvider() bool {
	if cfg != nil {
		if cfg.GetUser() != "" || cfg.ProviderEnabled() {
			return true
		}
	}
	// HasEnabledCredentialProvider reads the profiles in place (OIDC or LDAP —
	// the CREDENTIAL-capable types, ADR-0027). This probe runs on EVERY
	// proxied request (resolveRequestAuth's credCapable), and the previous
	// idpRegistry.All() loop deep-cloned every profile per call just to
	// answer this boolean — pure per-request allocation on the hot path.
	return idpRegistry != nil && idpRegistry.HasEnabledCredentialProvider()
}

// exemptRiskBuckets collects offending exempt-rule names per risk category.
type exemptRiskBuckets struct {
	broadExempt, anySource, wideSource, noExpiry, broadDest, expired []string
}

// classifyExemptRisks buckets each exempt rule into the risk categories it
// triggers. Pure; never mutates the rules.
func classifyExemptRisks(exempt []*PolicyRule) exemptRiskBuckets {
	var b exemptRiskBuckets
	for _, r := range exempt {
		if r.Auth.BroadExemption {
			b.broadExempt = append(b.broadExempt, r.Name)
		}
		if anySrc, wide := subjectSourceBreadth(r.SubjectMatch); anySrc || wide {
			if anySrc {
				b.anySource = append(b.anySource, r.Name)
			}
			if wide {
				b.wideSource = append(b.wideSource, r.Name)
			}
		}
		if r.Auth.ExpiresAt == "" {
			b.noExpiry = append(b.noExpiry, r.Name)
		}
		if !authRuleHasDestination(*r) {
			b.broadDest = append(b.broadDest, r.Name)
		}
		if authExemptExpired(r.Auth) {
			b.expired = append(b.expired, r.Name)
		}
	}
	return b
}

// apiDiagnostics serves the operator contract as JSON.
//
// Auth: viewer role is sufficient — the report intentionally omits secrets,
// raw URLs, file paths, fingerprints, and IdP details. Any field added in
// the future that could leak sensitive data must be redacted to admin-only
// at the API layer before being returned here.
func apiDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, buildOperatorContract())
}

// registerObservabilityRoutes wires the operator-facing observability
// endpoints. /healthz is intentionally unauthenticated (LB probe);
// uiAuthMiddleware does NOT gate it because it is on the public-route
// allowlist by absolute path. /api/diagnostics requires viewer role.
// The apiHealthz handler lives in ha.go; the apiDiagnostics handler
// lives in this file.
func registerObservabilityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/diagnostics", apiDiagnostics) // GET — aggregated operator contract (viewer)
	mux.HandleFunc("/healthz", apiHealthz)             // GET unauthenticated health check (LB probe)
}
