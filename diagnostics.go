package main

import (
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// OperatorContract is the aggregated, operator-visible health verdict for
// the running node. It is a side-effect-free read of process state via the
// safe accessors that already exist on each subsystem; the handler does no
// disk I/O, no network probes, and triggers no fresh ClamAV/health pings.
//
// The shape is intentionally extensible: future PRs add checks by appending
// to the Checks slice. Field names are stable JSON keys so the SPA and
// downstream tooling can rely on them.
type OperatorContract struct {
	Verdict     string                  `json:"verdict"` // "ok" | "warn" | "fail"
	GeneratedAt string                  `json:"generated_at"`
	Checks      []OperatorContractCheck `json:"checks"`
}

// OperatorContractCheck is one row in the diagnostics report.
//
// Code is a stable identifier (snake_case) used by automation and the SPA.
// Status is one of "ok", "warn", "fail". Message is a short human summary.
// OperatorAction tells the operator what (if anything) to do — required when
// Status is "warn" or "fail" so the GUI can render an actionable hint.
type OperatorContractCheck struct {
	Code           string `json:"code"`
	Status         string `json:"status"`
	Message        string `json:"message"`
	OperatorAction string `json:"operator_action,omitempty"`
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
	return len(sessionSecret) >= 32
}

// buildOperatorContract assembles the full diagnostics report.
//
// Side-effect contract:
//   - reads cached / atomic / RLock-protected state only
//   - never opens files, sockets, or pings external daemons
//   - safe to call concurrently from the admin API
func buildOperatorContract() OperatorContract {
	checks := []OperatorContractCheck{
		checkStorage(),
		checkPolicyLoaded(),
		checkRootCA(),
		checkSessionSecret(),
		checkCDR(),
		checkClusterPosture(),
		checkUnauthMode(),
		checkUpdaterURL(),
		checkConfigSnapshotValidator(),
	}
	return OperatorContract{
		Verdict:     rollUpVerdict(checks),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Checks:      checks,
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
	// This check reports the cached result of the one-shot writability
	// probe that ran at startup (probeStorageWritability). The handler
	// itself does NO disk I/O — repeated calls are free.
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
	return OperatorContractCheck{
		Code:    "root_ca",
		Status:  diagOK,
		Message: "root CA initialised",
	}
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
			OperatorAction: "Provide TLS certificates via --cluster-grpc-cert/--cluster-grpc-key/--cluster-grpc-ca and remove --cluster-insecure to harden the control plane.",
		}
	}
	return OperatorContractCheck{
		Code:    "cluster_posture",
		Status:  diagOK,
		Message: "cluster running with mTLS",
	}
}

// checkUnauthMode is a visible WARN when the proxy is in unauthenticated
// pass-through mode. Per scope, we surface the risk — we never remove the
// operator's freedom to run this way.
func checkUnauthMode() OperatorContractCheck {
	if cfg != nil && cfg.UnauthMode() {
		return OperatorContractCheck{
			Code:           "unauth_mode",
			Status:         diagWarn,
			Message:        "proxy is running in unauthenticated mode — no client credentials required",
			OperatorAction: "If clients should authenticate, disable Unauth Mode under Settings; otherwise rely on policy rules to gate access.",
		}
	}
	return OperatorContractCheck{
		Code:    "unauth_mode",
		Status:  diagOK,
		Message: "client authentication enforced (or no IdP configured)",
	}
}

// checkUpdaterURL re-runs the same pure validateUpdaterURL the startup path
// uses. It does not contact the updater. The handler returns only a coarse
// verdict — never the URL itself — so the field stays admin-safe at viewer
// role.
func checkUpdaterURL() OperatorContractCheck {
	if err := validateUpdaterURL(updaterURL); err != nil {
		return OperatorContractCheck{
			Code:           "updater_url",
			Status:         diagFail,
			Message:        "configured updater URL is rejected by the SSRF/allowlist guard",
			OperatorAction: "Set --updater-url-allowlist (or the YAML equivalent) to include the configured updater URL, or revert to the default sidecar.",
		}
	}
	return OperatorContractCheck{
		Code:    "updater_url",
		Status:  diagOK,
		Message: "updater URL passes SSRF / allowlist validation",
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
