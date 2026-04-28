package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
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
		checkUnauthMode(),
		checkYARAEnginePosture(),
		checkUpdaterURL(),
		checkConfigSnapshotValidator(),
		checkConfigVersionsPresent(cv),
		checkConfigVersionsReadable(cv),
		checkConfigRollbackValidation(cv),
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
	return summarizeLatestConfigVersionAt(configVersionsDir)
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
