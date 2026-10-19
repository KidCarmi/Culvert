package main

// av_unavailable_posture.go — package-main wiring for the scanner's
// av_unavailable posture (internal/secscan/avposture.go owns the decision):
// the boot default from CULVERT_AV_UNAVAILABLE, admin_settings.json
// durability, and the GET/PUT /api/security-scan/av-settings admin surface.
//
// Precedence, mirroring CULVERT_DEFAULT_ACTION:
//
//	1. a posture an admin explicitly SAVED (admin_settings.json,
//	   av_unavailable_saved sentinel) — applied by LoadAdminSettings;
//	2. CULVERT_AV_UNAVAILABLE (open|closed), read once in the initScanning
//	   shim and applied by the scanning loader — the appliance passes closed;
//	3. open — the historical fail-open behaviour, byte-identical.
//
// The sentinel is written ONLY by an explicit save (the PUT, or carrying an
// already-saved value forward). An unrelated omnibus save therefore never
// freezes the env-derived boot posture into the file, so changing
// CULVERT_AV_UNAVAILABLE keeps working until an admin takes ownership.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// avUnavailableEnv is the boot-time posture override consumed by the shim.
const avUnavailableEnv = "CULVERT_AV_UNAVAILABLE"

// avPostureSaved records that the live posture came from an explicit admin
// save (loaded from the settings file or installed by the PUT), so omnibus
// saves keep carrying it. Guarded for writers by adminSettingsMu; atomic so
// the status surfaces can read it lock-free.
var avPostureSaved atomic.Bool

// avUnavailableClosedGauge renders the posture for the 0/1 Prometheus gauge.
func avUnavailableClosedGauge() int64 {
	if secscan.AVUnavailablePosture() == secscan.AVUnavailableClosed {
		return 1
	}
	return 0
}

// applyAVUnavailableBootPosture installs the CULVERT_AV_UNAVAILABLE boot
// posture. Unset keeps open (historical behaviour). An unrecognised value is
// IGNORED with a warning, exactly as CULVERT_DEFAULT_ACTION treats junk — the
// posture stays open, and the warning names the variable so the typo is
// findable. A saved admin choice, applied later by LoadAdminSettings, wins.
func applyAVUnavailableBootPosture(env string) {
	raw := strings.TrimSpace(env)
	if raw == "" {
		return
	}
	posture, ok := secscan.NormalizeAVUnavailable(raw)
	if !ok {
		logger.Printf("SecurityScan: ignoring %s=%q (want open or closed); av_unavailable stays %s",
			avUnavailableEnv, sanitizeLog(raw), secscan.AVUnavailablePosture())
		return
	}
	_ = secscan.SetAVUnavailablePosture(posture) //nolint:errcheck // normalized above, cannot fail
	logger.Printf("SecurityScan: av_unavailable=%s set by %s (boot posture; a saved admin setting still wins)",
		posture, avUnavailableEnv)
}

// applyAdminAVUnavailable restores an explicitly saved posture on load. A
// file without the sentinel leaves the boot posture untouched; a saved but
// unrecognised value is refused (logged) and the boot posture stands.
func applyAdminAVUnavailable(s *AdminSettings) {
	if !s.AVUnavailableSaved {
		return
	}
	if err := secscan.SetAVUnavailablePosture(s.AVUnavailable); err != nil {
		logger.Printf("AdminSettings: refusing saved av_unavailable=%q (%v); keeping %s",
			sanitizeLog(s.AVUnavailable), err, secscan.AVUnavailablePosture())
		return
	}
	avPostureSaved.Store(true)
}

// snapshotAVUnavailable records the posture in an omnibus save. target is the
// PUT's persist-before-apply TARGET (nil for an ordinary save, which carries
// an already-saved posture forward and records nothing otherwise).
func snapshotAVUnavailable(s *AdminSettings, target *string) {
	switch {
	case target != nil:
		s.AVUnavailableSaved = true
		s.AVUnavailable = *target
	case avPostureSaved.Load():
		s.AVUnavailableSaved = true
		s.AVUnavailable = secscan.AVUnavailablePosture()
	}
}

// avSettingsMapOf renders one posture for the GET/PUT response and the audit
// diff.
func avSettingsMapOf(posture string, saved bool) map[string]any {
	source := "boot"
	if saved {
		source = "admin"
	}
	return map[string]any{
		"av_unavailable": posture,
		"source":         source,
		"revision":       avSettingsRevisionOf(posture),
	}
}

// avSettingsRevisionOf is the content-derived stale-writer fence revision
// (the 2E-A ifRevision contract shared with the YARA settings surface).
func avSettingsRevisionOf(posture string) string {
	return contentSecRevision("av-settings", posture)
}

// avSettingsSnapshot reads the posture and its provenance coherently under
// adminSettingsMu, the surface's writer domain.
func avSettingsSnapshot() (posture string, saved bool) {
	adminSettingsMu.Lock()
	defer adminSettingsMu.Unlock()
	return secscan.AVUnavailablePosture(), avPostureSaved.Load()
}

// GET /api/security-scan/av-settings — read the av_unavailable posture.
// PUT /api/security-scan/av-settings — set it ({"av_unavailable":"open|closed"}).
//
// The PUT is persist-before-apply, exactly like the YARA settings surface: the
// settings file records the TARGET posture first and only a successful write
// applies it, so a persist failure is a truthful 500 with the running posture
// untouched. The optional ifRevision fence is evaluated inside the same
// adminSettingsMu critical section.
func apiSecAVSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		posture, saved := avSettingsSnapshot()
		jsonOK(w, avSettingsMapOf(posture, saved))
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiSecAVSettingsPut(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiSecAVSettingsPut is the admin write half of apiSecAVSettings.
func apiSecAVSettingsPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AVUnavailable string `json:"av_unavailable"`
		IfRevision    string `json:"ifRevision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	target, ok := secscan.NormalizeAVUnavailable(body.AVUnavailable)
	if !ok {
		http.Error(w, `av_unavailable must be "open" or "closed"`, http.StatusBadRequest)
		return
	}
	var prev map[string]any
	err := saveAdminSettingsWithOverrides(adminSaveOverrides{
		avUnavailable: &target,
		precondition: func() error {
			cur := secscan.AVUnavailablePosture()
			if body.IfRevision != "" {
				if rev := avSettingsRevisionOf(cur); rev != body.IfRevision {
					return errContentSecRevisionConflict{current: rev, asserted: body.IfRevision}
				}
			}
			prev = avSettingsMapOf(cur, avPostureSaved.Load())
			return nil
		},
		applyOnSuccess: func() {
			_ = secscan.SetAVUnavailablePosture(target) //nolint:errcheck // normalized above, cannot fail
			avPostureSaved.Store(true)
		},
	})
	var conflict errContentSecRevisionConflict
	if errors.As(err, &conflict) {
		writeContentSecRevisionConflict(w, "AV scan posture", conflict.current, conflict.asserted)
		return
	}
	if err != nil {
		logger.Printf("SecurityScan: av_unavailable persist error: %v", err)
		http.Error(w, "AV scan posture could not be persisted; the live posture is unchanged", http.StatusInternalServerError)
		return
	}
	next := avSettingsMapOf(target, true)
	auditEventDiff(r, "security.av_unavailable", "scan_posture", "", prev, next)
	// Intentionally NOT calling saveConfigVersion: like the YARA engine
	// settings, the av_unavailable posture is out of the rollback surface by
	// design — rolling back could silently re-open a scanner posture the admin
	// chose to close (config_surfaces.go row av_unavailable).
	jsonOK(w, next)
}
