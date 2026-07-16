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
	caExpiresDays := -1
	if info := certMgr.CACertInfo(); info["ready"] == true {
		if notAfterStr, ok := info["notAfter"].(string); ok {
			if t, err := time.Parse("2006-01-02", notAfterStr); err == nil {
				caExpiresDays = int(time.Until(t).Hours() / 24)
			}
		}
	}

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
	sslInspection := "ready"
	if sslInspectionLoadFailure() != "" {
		sslInspection = "load_failed"
	} else if !certMgr.Ready() {
		sslInspection = "unavailable"
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

// computeReadiness builds the readiness snapshot and the HTTP status code (200
// when all gating checks pass, 503 otherwise). Shared by handleReady and the
// readiness support collector.
func computeReadiness() (readinessReport, int) {
	checks := map[string]*readinessCheck{}
	allOK := true

	// 1. CA: report status but don't fail readiness — proxy still works as a
	// plain forward proxy if the CA didn't load. A configured-but-failed load is
	// surfaced as a failing (non-gating) check so the degradation is visible to
	// probes instead of the row silently disappearing (CHAOS-06); posture
	// (report-only) mirrors policy_loaded.
	//
	// The recorded load failure is checked BEFORE Ready(): LoadOrInitCA runs
	// InitCA() (Ready() → true) before SaveCA(), so a SaveCA failure leaves a
	// recorded failure while Ready() stays true. Reporting "ok" there would hide
	// a configured CA bundle that never persisted.
	if detail := sslInspectionLoadFailure(); detail != "" {
		checks["ca"] = &readinessCheck{Status: "fail", Detail: detail}
	} else if certMgr.Ready() {
		checks["ca"] = &readinessCheck{Status: "ok"}
	}

	// 2. ClamAV: if scanner is initialised, verify connectivity.
	if globalSecScanner != nil {
		st := globalSecScanner.ClamAVStatus()
		switch st {
		case "disabled":
			// Not configured — skip.
		case "connected":
			checks["clamav"] = &readinessCheck{Status: "ok"}
		default:
			checks["clamav"] = &readinessCheck{Status: "fail", Detail: st}
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

	status, code := "ready", http.StatusOK
	if !allOK {
		status, code = "not_ready", http.StatusServiceUnavailable
	}
	return readinessReport{Status: status, Uptime: uptime(), Version: version, Checks: checks}, code
}

// handleReady is a readiness probe — returns 200 only when all configured
// subsystems are operational. Use for Kubernetes readinessProbe / startup gate.
// Unlike /health (liveness), this returns 503 when dependencies are degraded.
func handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	report, code := computeReadiness()
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(report); err != nil {
		logger.Printf("handleReady encode: %v", err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────
