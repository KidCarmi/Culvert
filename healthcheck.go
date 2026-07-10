package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip"
)

// handleHealth returns liveness + readiness details for monitoring tools.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

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

	type healthResponse struct {
		Status            string `json:"status"`
		Uptime            string `json:"uptime"`
		Version           string `json:"version"`
		ClamAV            string `json:"clamav"`
		CAExpiresDays     int    `json:"ca_expires_days"`
		ThreatFeedEntries int64  `json:"threat_feed_entries"`
	}
	resp := healthResponse{
		Status:            "ok",
		Uptime:            uptime(),
		Version:           version,
		ClamAV:            clamStatus,
		CAExpiresDays:     caExpiresDays,
		ThreatFeedEntries: tfEntries,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Printf("handleHealth encode: %v", err)
	}
}

// handleReady is a readiness probe — returns 200 only when all configured
// subsystems are operational. Use for Kubernetes readinessProbe / startup gate.
// Unlike /health (liveness), this returns 503 when dependencies are degraded.
// configSnapshotValidatorOK reports whether the config-snapshot
// validator accepts the empty baseline (its identity contract). Defined
// as a package-level variable so tests can swap in a stub that simulates
// a broken validator without mutating the per-slice caps in
// configversion / controlplane.
var configSnapshotValidatorOK = func() bool {
	return validateConfigSnapshot(ConfigSnapshot{}) == nil
}

func handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	type checkResult struct {
		Status string `json:"status"` // "ok" or "fail"
		Detail string `json:"detail,omitempty"`
	}
	checks := map[string]*checkResult{}
	allOK := true

	// 1. CA: report status but don't fail readiness — proxy still works
	// as a plain forward proxy if the CA didn't load.
	if certMgr.Ready() {
		checks["ca"] = &checkResult{Status: "ok"}
	}

	// 2. ClamAV: if scanner is initialised, verify connectivity.
	if globalSecScanner != nil {
		st := globalSecScanner.ClamAVStatus()
		switch st {
		case "disabled":
			// Not configured — skip.
		case "connected":
			checks["clamav"] = &checkResult{Status: "ok"}
		default:
			checks["clamav"] = &checkResult{Status: "fail", Detail: st}
			allOK = false
		}
	}

	// 3. GeoIP: if configured, verify DB is loaded.
	if geoip.Enabled() {
		checks["geoip"] = &checkResult{Status: "ok"}
	}
	// GeoIP is optional — absence is not a failure.

	// 4. YARA rules: if configured, verify loaded.
	if globalYARA.Enabled() {
		checks["yara"] = &checkResult{Status: "ok"}
	}

	// 5. Policy loaded (informational). Empty policy is a valid
	// Zero-Trust posture — default-deny applies — so this row does NOT
	// gate readiness. Surfaces "no rules yet" as a hint to operators
	// without flapping load balancers on a fresh install.
	if ver, _ := policyStore.policyVersion(); ver > 0 {
		checks["policy_loaded"] = &checkResult{Status: "ok"}
	} else {
		checks["policy_loaded"] = &checkResult{Status: "fail", Detail: "no rules"}
	}

	// 6. Admin session HMAC initialised. Without this, signed cookies
	// cannot be issued or verified — the admin UI is effectively
	// unmanageable. Fail readiness so traffic is held off until the
	// node is restarted with a valid secret.
	if sessionSecretSet() {
		checks["session_secret"] = &checkResult{Status: "ok"}
	} else {
		checks["session_secret"] = &checkResult{Status: "fail", Detail: "uninitialised"}
		allOK = false
	}

	// 7. ConfigSnapshot validator. The pure validateConfigSnapshot
	// function must accept the empty baseline (its identity contract).
	// If it ever rejects, the cluster control-plane apply path is
	// broken and we must shed load. configSnapshotValidatorOK is a
	// package-level seam so tests can simulate a broken validator
	// without mutating the per-slice caps.
	if configSnapshotValidatorOK() {
		checks["config_snapshot_validator"] = &checkResult{Status: "ok"}
	} else {
		checks["config_snapshot_validator"] = &checkResult{Status: "fail", Detail: "validator rejected empty baseline"}
		allOK = false
	}

	status := "ready"
	code := http.StatusOK
	if !allOK {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}

	resp := struct {
		Status  string                  `json:"status"`
		Uptime  string                  `json:"uptime"`
		Version string                  `json:"version"`
		Checks  map[string]*checkResult `json:"checks"`
	}{
		Status:  status,
		Uptime:  uptime(),
		Version: version,
		Checks:  checks,
	}

	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Printf("handleReady encode: %v", err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────
