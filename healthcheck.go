package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip"
)

// healthReport is the liveness + posture snapshot served by /healthz and
// collected into sections/health.json. Status/version/uptime are PUBLIC; the
// subsystem-posture fields are INTERNAL (operationally revealing, not secret).
type healthReport struct {
	Status            string `json:"status" redact:"public"`
	Uptime            string `json:"uptime" redact:"public"`
	Version           string `json:"version" redact:"public"`
	ClamAV            string `json:"clamav" redact:"internal"`
	CAExpiresDays     int    `json:"ca_expires_days" redact:"internal"`
	SSLInspection     string `json:"ssl_inspection" redact:"internal"`
	ThreatFeedEntries int64  `json:"threat_feed_entries" redact:"internal"`
}

// computeHealth builds the liveness/posture snapshot from side-effect-free reads.
// Shared by handleHealth and the health support collector.
func computeHealth() healthReport {
	// CA cert expiry
	caExpiresDays := caExpiryDaysRemaining()

	// Threat feed entry count
	tfEntries, _, _ := globalThreatFeed.Stats()

	// ClamAV connectivity
	clamStatus := "disabled"
	if globalSecScanner != nil {
		clamStatus = globalSecScanner.ClamAVStatus()
	}

	// SSL inspection state (CHAOS-06): a CA that was configured but failed to
	// load leaves the gateway serving TLS as tunnel-only bypass — that
	// degradation must be visible to monitoring, not just a startup log line.
	//
	// The recorded load failure is consulted BEFORE Ready(): LoadOrInitCA calls
	// InitCA() (which flips Ready() true) before SaveCA(), so a SaveCA failure
	// (missing/unwritable parent dir) leaves initInspectionCA having recorded a
	// failure while Ready() stays true. Reporting "ready" there would hide a CA
	// bundle that never persisted — the configured inspection material is not
	// actually usable across a restart.
	// CHAOS-28: an installed-but-expired (or not-yet-valid) CA is reported as
	// "expired", NOT "ready". Ready() only asks whether a CA is loaded, so
	// before this the probe stayed green through a total inspected-HTTPS outage
	// — the single least-visible failure in the appliance. Checked after the
	// load failure (which is the more specific fault) and before Ready().
	sslInspection := "ready"
	switch {
	case sslInspectionLoadFailure() != "":
		sslInspection = "load_failed"
	case !certMgr.Ready():
		sslInspection = "unavailable"
	case certMgr.Usable() != nil:
		sslInspection = "expired"
	}

	return healthReport{
		Status:            "ok",
		Uptime:            uptime(),
		Version:           version,
		ClamAV:            clamStatus,
		CAExpiresDays:     caExpiresDays,
		SSLInspection:     sslInspection,
		ThreatFeedEntries: tfEntries,
	}
}

// handleHealth returns liveness + readiness details for monitoring tools.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(computeHealth()); err != nil {
		logger.Printf("handleHealth encode: %v", err)
	}
}

// readinessCheck is one row of the readiness probe.
type readinessCheck struct {
	Status string `json:"status" redact:"public"` // "ok" or "fail"
	Detail string `json:"detail,omitempty" redact:"public"`
}

// readinessReport is the /readyz snapshot, also collected into
// sections/readiness.json (PUBLIC — no identities or secrets).
type readinessReport struct {
	Status  string                     `json:"status" redact:"public"`
	Uptime  string                     `json:"uptime" redact:"public"`
	Version string                     `json:"version" redact:"public"`
	Checks  map[string]*readinessCheck `json:"checks" redact:"public"`
}

// configSnapshotValidatorOK reports whether the config-snapshot validator accepts
// the empty baseline (its identity contract). Defined as a package-level variable
// so tests can swap in a stub that simulates a broken validator without mutating
// the per-slice caps in configversion / controlplane.
var configSnapshotValidatorOK = func() bool {
	return validateConfigSnapshot(ConfigSnapshot{}) == nil
}

// appendStateFileChecks adds the report-only CHAOS-05/07 rows
// (state_file_ui_users / state_file_cluster): a quarantined state file
// means the node is serving with an empty roster/cluster store —
// survivable (env fallback creds / re-enrollment) but it must stay
// visible to probes beyond the startup log line and the alert.
//
// /ready is served UNAUTHENTICATED on the proxy port (main.go), so the row
// carries only a FIXED, non-path detail — the verbose text
// (absolute state-file path, raw parse error, quarantine filename, the
// "running with an EMPTY store" note) would fingerprint a security-degraded
// node and disclose internal filesystem layout to any client that can reach
// the proxy port. The full detail remains in the server logs, the
// state_file_corrupt alert, and the authenticated diagnostics. The row KEY
// (state_file_<kind>) still says which file, so the operator signal is intact.
func appendStateFileChecks(checks map[string]*readinessCheck) {
	for kind := range stateCorruptionSnapshot() {
		checks["state_file_"+kind] = &readinessCheck{
			Status: "fail",
			Detail: "state file quarantined; running with a degraded store — see server logs",
		}
	}
}

// appendCAReadinessCheck adds the report-only `ca` row.
//
// Report status but don't fail readiness — the proxy still works as a plain
// forward proxy if the CA didn't load. A configured-but-failed load is surfaced
// as a failing (non-gating) check so the degradation is visible to probes
// instead of the row silently disappearing (CHAOS-06); posture (report-only)
// mirrors policy_loaded.
//
// The recorded load failure is checked BEFORE Ready(): LoadOrInitCA runs
// InitCA() (Ready() → true) before SaveCA(), so a SaveCA failure leaves a
// recorded failure while Ready() stays true. Reporting "ok" there would hide a
// configured CA bundle that never persisted.
//
// CHAOS-28 adds the unusable-CA branch (loaded, but outside its own validity
// window — so it signs nothing a client accepts). It stays REPORT-ONLY like the
// rest of this check, and that is a deliberate availability choice: an expired
// CA is typically fleet-wide (every node was provisioned from the same bundle
// at the same time), so gating readiness on it would eject the entire fleet
// from the load balancer simultaneously and take plain HTTP and bypassed HTTPS
// — which still work — down with it. An operator who wants those nodes ejected
// opts in via /ready?strict=1.
//
// EVERY detail on this row is a FIXED string. /ready is served unauthenticated
// on the proxy port — the same port every client on the network already dials —
// so anything written here is readable by any user, not just an operator.
//
// That applies to BOTH failing branches, and the load-failure one is why this
// paragraph is stated as a rule rather than a note about the validity branch.
// It used to pass sslInspectionLoadFailure() through verbatim, which is
// "Root CA load/init failed for <bundle path>: <OS error> — SSL inspection
// DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)". That published
// the CA bundle's filesystem path AND an explicit, machine-readable
// announcement that the gateway's inspection controls are off, to anyone who
// can reach the proxy. An attacker or insider polling /ready learns exactly
// when DLP/AV/CDR/DPI are down and can time exfiltration for that window —
// the fingerprint of a security-degraded node this row must not hand out.
//
// The full detail is not lost: it stays in the process log, the
// `ca_load_failed` alert, and the role-gated admin surfaces. Status is
// unchanged ("fail", still report-only), so probe and monitoring behaviour is
// byte-identical — only the operator-only cause is withheld from the
// unauthenticated surface.
//
// The detail also does not state the ENFORCEMENT POSTURE, which is the part
// that actually arms an attacker. "ca: fail" alone says a named subsystem is
// degraded; it does not say which way it fails, and the two directions are
// opposite. A load failure degrades to tunnel-only BYPASS — traffic flows
// UNINSPECTED — so spelling that out hands an unauthenticated observer the
// exfiltration window directly. (The validity branch below fails CLOSED, i.e.
// refuses traffic, which is why naming its posture is not the same hazard.)
// Withholding it costs the operator nothing: they are being pointed at the log,
// which carries the cause and the consequence in full.
func appendCAReadinessCheck(checks map[string]*readinessCheck) {
	switch {
	case sslInspectionLoadFailure() != "":
		checks["ca"] = &readinessCheck{
			Status: "fail",
			Detail: "configured root CA is unavailable — see server logs",
		}
	case !certMgr.Ready():
		// Not configured yet — no row at all (pre-CHAOS-06 baseline behavior).
	case certMgr.Usable() != nil:
		checks["ca"] = &readinessCheck{
			Status: "fail",
			Detail: "root CA outside its validity window; SSL inspection is blocked — see server logs",
		}
	default:
		checks["ca"] = &readinessCheck{Status: "ok"}
	}
}

// appendClusterCAReadinessCheck adds the CHAOS-50 cluster-CA row. Report-only,
// exactly like the `ca` row above: an expired cluster CA does not stop this node
// serving proxy traffic, and gating readiness on it would take a healthy
// gateway out of a load-balancer rotation over a control-plane fault.
//
// No row at all on a node with no cluster CA — a Data Plane, or a proxy that was
// never promoted — so the row's presence is itself the "this node issues node
// certificates" signal.
//
// The detail follows the same rule as the `ca` validity branch: this failure
// fails CLOSED (issuance is refused), so naming it hands an unauthenticated
// observer no exfiltration window. It still carries no path, fingerprint, or
// timestamp — the operator-actionable cause is in the log, the cert_expiry
// alert, and the role-gated /api/cluster/ca surface.
func appendClusterCAReadinessCheck(checks map[string]*readinessCheck) {
	if !globalClusterCA.Ready() {
		return
	}
	if globalClusterCA.Usable() != nil {
		checks["cluster_ca"] = &readinessCheck{
			Status: "fail",
			Detail: "cluster CA outside its validity window; node enrollment and renewal are blocked — see server logs",
		}
		return
	}
	// A failing rotation is NOT a readiness failure: the CA can still issue
	// today, and flipping the row to "fail" would pull a healthy gateway out of
	// a load-balancer rotation over a fault whose deadline is months away. It
	// rides an "ok" row's detail instead, so the status vocabulary stays the
	// ok/fail pair every consumer of this endpoint already handles. The paging
	// signal for it is the cert_expiry alert and
	// culvert_cluster_ca_rotation_failures_total, not this probe.
	if clusterCARotationDegraded() {
		checks["cluster_ca"] = &readinessCheck{
			Status: "ok",
			Detail: "cluster CA is usable but auto-rotation is failing — see server logs",
		}
		return
	}
	checks["cluster_ca"] = &readinessCheck{Status: "ok"}
}

// computeReadiness builds the readiness snapshot and the HTTP status code (200
// when all gating checks pass, 503 otherwise). Shared by handleReady and the
// readiness support collector. The verdict returned here is the DEFAULT
// (non-strict) one — the report-only rows (ca, policy_loaded, state_file_*,
// cp_poll, node_cert) never gate it; the opt-in strict verdict (CHAOS-09,
// /ready?strict=1) is layered on top by handleReady via strictVerdictFails,
// since it depends on the incoming request and the collector has none.
func computeReadiness() (report readinessReport, code int) {
	checks := map[string]*readinessCheck{}
	allOK := true

	// 1. CA — see appendCAReadinessCheck. Report-only: never gates.
	appendCAReadinessCheck(checks)
	// 1b. Cluster CA (CHAOS-50) — see appendClusterCAReadinessCheck.
	// Report-only: never gates.
	appendClusterCAReadinessCheck(checks)

	// 2. ClamAV: if scanner is initialised, verify connectivity.
	//
	// The detail is FIXED for the same reason as the `ca` row above: this
	// endpoint is unauthenticated on the proxy port, and ClamAVStatus()'s
	// non-connected value is a raw dial error ("unreachable: clamav: connect
	// failed: dial tcp 10.0.1.5:3310: connect: connection refused") that
	// publishes the internal address and port of the AV daemon — internal
	// network topology, handed to any client that can reach the proxy, together
	// with the fact that AV scanning is currently down. The gating verdict is
	// unchanged: this row still fails readiness, exactly as before.
	//
	// It points at the ADMIN SURFACE rather than at the log, unlike the `ca` row
	// above, and the difference is not cosmetic. ClamAV's ping error is logged
	// only by Scanner.Init (startup and reconfigure); ClamAVStatus caches it and
	// logs nothing. A daemon that dies at RUNTIME — a restart, an OOM, a crashed
	// container, which is the ordinary case — therefore produces a failing row
	// with no corresponding log line at all, so "see server logs" would send an
	// operator to a source that need not mention the outage. The live cause is
	// always on the role-gated /api/security-scan/status (`clamav_status`),
	// which re-pings on cache miss.
	if globalSecScanner != nil {
		st := globalSecScanner.ClamAVStatus()
		switch st {
		case "disabled":
			// Not configured — skip.
		case "connected":
			checks["clamav"] = &readinessCheck{Status: "ok"}
		default:
			checks["clamav"] = &readinessCheck{
				Status: "fail",
				Detail: "ClamAV unreachable — see Security Scanning status in the admin UI",
			}
			allOK = false
		}
	}

	// 3. GeoIP: if configured, verify DB is loaded.
	if geoip.Enabled() {
		checks["geoip"] = &readinessCheck{Status: "ok"}
	}
	// GeoIP is optional — absence is not a failure.

	// 4. YARA rules: if configured, verify loaded.
	if globalYARA.Enabled() {
		checks["yara"] = &readinessCheck{Status: "ok"}
	}

	// 5. Policy loaded (informational). Empty policy is a valid Zero-Trust posture
	// — default-deny applies — so this row does NOT gate readiness. Surfaces "no
	// rules yet" as a hint without flapping load balancers on a fresh install.
	if ver, _ := policyStore.policyVersion(); ver > 0 {
		checks["policy_loaded"] = &readinessCheck{Status: "ok"}
	} else {
		checks["policy_loaded"] = &readinessCheck{Status: "fail", Detail: "no rules"}
	}

	// 6. Admin session HMAC initialised. Without this, signed cookies cannot be
	// issued or verified — the admin UI is effectively unmanageable. Fail
	// readiness so traffic is held off until the node is restarted with a secret.
	if sessionSecretSet() {
		checks["session_secret"] = &readinessCheck{Status: "ok"}
	} else {
		checks["session_secret"] = &readinessCheck{Status: "fail", Detail: "uninitialised"}
		allOK = false
	}

	// 7. ConfigSnapshot validator. The pure validateConfigSnapshot function must
	// accept the empty baseline (its identity contract). If it ever rejects, the
	// cluster control-plane apply path is broken and we must shed load.
	if configSnapshotValidatorOK() {
		checks["config_snapshot_validator"] = &readinessCheck{Status: "ok"}
	} else {
		checks["config_snapshot_validator"] = &readinessCheck{Status: "fail", Detail: "validator rejected empty baseline"}
		allOK = false
	}

	// 8+9. Quarantined state files (CHAOS-05/07) and DP dependency health
	// (CHAOS-09, cp_poll + node_cert, DP mode only): report-only rows like ca.
	appendStateFileChecks(checks)
	appendDPHealthChecks(checks)

	// 10. Signed SaaS feed (F3b-4) — REPORT-ONLY, never gates readiness. A valid
	// embedded baseline always exists, so the feed never makes readiness
	// internet-dependent: a stuck origin / stale LKG is a non-gating degradation, and
	// corruption/equivocation/authority-loss is a non-gating critical row (probes that
	// want to eject such nodes opt in via /ready?strict=1).
	appendSaaSFeedHealthCheck(checks)

	status, code := "ready", http.StatusOK
	if !allOK {
		status, code = "not_ready", http.StatusServiceUnavailable
	}
	return readinessReport{Status: status, Uptime: uptime(), Version: version, Checks: checks}, code
}

// handleReady is a readiness probe — returns 200 only when all configured
// subsystems are operational. Use for Kubernetes readinessProbe / startup gate.
// Unlike /health (liveness), this returns 503 when dependencies are degraded.
// Supports the opt-in strict verdict (CHAOS-09): /ready?strict=1 treats every
// failing row — including the report-only ones — as gating (see
// strictVerdictFails).
func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	report, code := computeReadiness()
	if strictVerdictFails(r, report.Checks) {
		report.Status = "not_ready"
		code = http.StatusServiceUnavailable
	}
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(report); err != nil {
		logger.Printf("handleReady encode: %v", err)
	}
}

// strictVerdictFails implements the opt-in strict readiness verdict
// (CHAOS-09): /ready?strict=1 (or strict=true) treats EVERY failing row as
// gating, including the report-only rows (ca, policy_loaded, state_file_*,
// cp_poll, node_cert) that never gate the default verdict. The default
// posture is deliberately unchanged: gating on CP-poll failure by default
// would let a CP outage eject the entire DP fleet from the load balancer at
// once. A load balancer that SHOULD eject dependency-degraded nodes points
// its probe at the strict URL instead. Nil-request tolerant (tests).
func strictVerdictFails(r *http.Request, checks map[string]*readinessCheck) bool {
	if r == nil {
		return false
	}
	if s := r.URL.Query().Get("strict"); s != "1" && s != "true" {
		return false
	}
	for _, c := range checks {
		if c.Status == "fail" {
			return true
		}
	}
	return false
}

// caExpiryDaysRemaining returns the number of days until the internal CA
// certificate expires, or -1 when no CA is loaded/ready. Shared by
// computeHealth and the support-telemetry registry's
// support_health_ca_expiry_bucket read (support_telemetry_registry.go) so
// there is exactly one place that reads the CA's notAfter — not a second,
// independently-computed source of truth.
func caExpiryDaysRemaining() int {
	info := certMgr.CACertInfo()
	if info["ready"] != true {
		return -1
	}
	notAfterStr, ok := info["notAfter"].(string)
	if !ok {
		return -1
	}
	t, err := time.Parse("2006-01-02", notAfterStr)
	if err != nil {
		return -1
	}
	return int(time.Until(t).Hours() / 24)
}

// ── Helpers ──────────────────────────────────────────────────────────────────
