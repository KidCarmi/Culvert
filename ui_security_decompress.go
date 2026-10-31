package main

// ui_security_decompress.go — the operator setting for the CHAOS-106
// scan-path decompression ratio (internal/secscan owns the bound, its default
// and its allowed range; this file is the admin/persistence/diagnostics glue).
//
// The setting mirrors the YARA engine settings surface (ui_security.go
// apiSecYARASettings) on every axis, because it is the same kind of thing: a
// node-local scanner-engine posture knob that can relax a fail-closed default.
//
//   - GET viewer / PUT admin, handler-level requireRole on both.
//   - Persist-before-apply through saveAdminSettingsWithOverrides: the durable
//     file records the TARGET first, and only a successful write installs it
//     in the scanner, so a persist failure is a truthful 500 with the running
//     bound untouched.
//   - Optional ifRevision stale-writer fence evaluated inside the same
//     adminSettingsMu critical section (ui_security_fence.go doctrine).
//   - Audited with a before/after diff; NOT versioned, NOT exported, NOT
//     replicated CP→DP — see the handler and config_surfaces.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// scanDecompressAuditAction is the audit Action for a ratio change.
const scanDecompressAuditAction = "security.scan_decompress_ratio"

// scanDecompressRevisionOf derives the surface revision from one ratio value.
// The ratio is a single atomic, so one Load is already a coherent snapshot —
// unlike the six-field YARA posture it needs no writer-domain lock to read.
func scanDecompressRevisionOf(ratio int64) string {
	return contentSecRevision("scan-decompress", strconv.FormatInt(ratio, 10))
}

// scanDecompressSettingsMapOf renders one ratio value for JSON responses and
// audit diffs. The bounds and default travel with it so the GUI never
// hard-codes them.
func scanDecompressSettingsMapOf(ratio int64) map[string]any {
	return map[string]any{
		"ratio_limit":          ratio,
		"default_ratio_limit":  int64(secscan.DefaultDecompressRatioLimit),
		"min_ratio_limit":      int64(secscan.MinDecompressRatioLimit),
		"max_ratio_limit":      int64(secscan.MaxDecompressRatioLimit),
		"relaxed":              ratio > secscan.DefaultDecompressRatioLimit,
		"floor_bytes":          int64(secscan.DecompressFloorBytes),
		"max_decompress_bytes": int64(secscan.MaxDecompressBytes),
	}
}

// scanDecompressAuditDetail names the posture direction in the audit detail,
// so a relaxation is legible in the trail without reading the diff.
func scanDecompressAuditDetail(prev, next int64) string {
	switch {
	case next > secscan.DefaultDecompressRatioLimit:
		return fmt.Sprintf("ratio %d -> %d (RELAXED above the fail-closed default %d)", prev, next, secscan.DefaultDecompressRatioLimit)
	case next < secscan.DefaultDecompressRatioLimit:
		return fmt.Sprintf("ratio %d -> %d (tightened below the default %d)", prev, next, secscan.DefaultDecompressRatioLimit)
	default:
		return fmt.Sprintf("ratio %d -> %d (default)", prev, next)
	}
}

// GET /api/security-scan/decompression — read the scan-path expansion ratio.
// PUT /api/security-scan/decompression — set it ({ratio_limit, ifRevision?}).
func apiSecScanDecompression(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		ratio := secscan.DecompressRatioLimit()
		contentSecGETPause("scan-decompress")
		m := scanDecompressSettingsMapOf(ratio)
		m["revision"] = scanDecompressRevisionOf(ratio)
		jsonOK(w, m)

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		putScanDecompression(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// putScanDecompression is the admin PUT half of apiSecScanDecompression
// (split out to keep the dispatcher under the cyclop threshold). The caller
// has already enforced RoleAdmin.
func putScanDecompression(w http.ResponseWriter, r *http.Request) {
	var body struct {
		// int64, so a fractional or quoted value is a decode error (400), not
		// a silently truncated ratio.
		RatioLimit int64  `json:"ratio_limit"`
		IfRevision string `json:"ifRevision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := secscan.ValidateDecompressRatioLimit(body.RatioLimit); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target := body.RatioLimit
	var prev int64
	err := saveAdminSettingsWithOverrides(adminSaveOverrides{
		scanDecompressRatio: &target,
		precondition: func() error {
			cur := secscan.DecompressRatioLimit()
			if body.IfRevision != "" {
				if rev := scanDecompressRevisionOf(cur); rev != body.IfRevision {
					return errContentSecRevisionConflict{current: rev, asserted: body.IfRevision}
				}
			}
			prev = cur
			return nil
		},
		applyOnSuccess: func() {
			// Validated above, so this cannot fail; SetDecompressRatioLimit
			// re-validates anyway and keeps the current bound on refusal.
			if err := secscan.SetDecompressRatioLimit(target); err != nil {
				logger.Printf("SecurityScan: decompression ratio apply refused after a durable write: %v", err)
			}
		},
	})
	var conflict errContentSecRevisionConflict
	if errors.As(err, &conflict) {
		writeContentSecRevisionConflict(w, "Decompression ratio setting", conflict.current, conflict.asserted)
		return
	}
	if err != nil {
		logger.Printf("SecurityScan: decompression ratio persist error: %v", err)
		http.Error(w, "decompression ratio could not be persisted; the live bound is unchanged", http.StatusInternalServerError)
		return
	}
	auditEventDiff(r, scanDecompressAuditAction, "scan_decompress", scanDecompressAuditDetail(prev, target),
		map[string]any{"ratio_limit": prev}, map[string]any{"ratio_limit": target})
	// Log the bound the scanner now enforces, read back from secscan, rather
	// than the request value: it is what the hot path uses, and it keeps
	// request-derived data out of the application log (CWE-117).
	if live := secscan.DecompressRatioLimit(); live > secscan.DefaultDecompressRatioLimit {
		logger.Printf("SecurityScan: decompression ratio limit RELAXED to %d (default %d) — compressed responses expanding up to %dx their transferred bytes are now admitted",
			live, secscan.DefaultDecompressRatioLimit, live)
	}
	// Intentionally NOT calling saveConfigVersion: like the YARA engine
	// settings (D-sec, CONFIG-VERSIONING-TRIAGE.md §4.2) this is a scanner
	// posture knob that is out of the rollback surface by design — rolling
	// back could silently re-raise a ratio the operator chose to tighten,
	// relaxing the decompression-bomb bound without anyone touching it.
	//
	// The response is the posture THIS PUT installed (coherent by
	// construction, 2E-A-2 §1).
	m := scanDecompressSettingsMapOf(target)
	m["revision"] = scanDecompressRevisionOf(target)
	jsonOK(w, m)
}

// snapshotScanDecompressRatio records the ratio in the settings file: the
// TARGET for a persist-before-apply PUT, else the live value. The default is
// recorded as 0 (absent, omitempty) so a node that never changed the setting
// keeps following the shipped default across upgrades instead of pinning it.
func snapshotScanDecompressRatio(s *AdminSettings, override *int64) {
	ratio := secscan.DecompressRatioLimit()
	if override != nil {
		ratio = *override
	}
	if ratio == secscan.DefaultDecompressRatioLimit {
		ratio = 0
	}
	s.ScanDecompressRatioLimit = ratio
}

// applyAdminScanDecompressRatio installs the persisted ratio on load; the file
// is authoritative, so absent (0) installs the shipped default. A hand-edited
// out-of-range value is REFUSED and the default installed instead (fail
// closed: a corrupt file can never widen the bound), the
// applyAdminSupportRetention pattern.
func applyAdminScanDecompressRatio(s *AdminSettings) {
	ratio := s.ScanDecompressRatioLimit
	if ratio == 0 {
		ratio = secscan.DefaultDecompressRatioLimit
	}
	if err := secscan.SetDecompressRatioLimit(ratio); err != nil {
		logger.Printf("AdminSettings: ignoring invalid persisted decompression ratio limit %d (%v) — using the default %d",
			ratio, err, secscan.DefaultDecompressRatioLimit)
		_ = secscan.SetDecompressRatioLimit(secscan.DefaultDecompressRatioLimit) // the default is in range by construction
	}
}

// checkScanDecompressRatioPosture is the operator-contract row for the
// setting: warn whenever the ratio is above the fail-closed default. A raised
// ratio is a valid operator choice (that is why the setting exists) but it
// lowers the wire bytes an attacker needs per refused expansion, so it gets
// the same explicit visibility as a relaxed YARA posture.
func checkScanDecompressRatioPosture() OperatorContractCheck {
	ratio := secscan.DecompressRatioLimit()
	if ratio > secscan.DefaultDecompressRatioLimit {
		return OperatorContractCheck{
			Code:   "scan_decompress_ratio",
			Status: diagWarn,
			Message: fmt.Sprintf("Decompression ratio limit relaxed to %d:1 (default %d:1) — compressed responses expanding up to %dx their transferred bytes are admitted for scanning, so a maximal scan-path expansion costs an attacker proportionally fewer wire bytes",
				ratio, secscan.DefaultDecompressRatioLimit, ratio),
			OperatorAction: fmt.Sprintf("Keep it raised only while the highly repetitive downloads that needed it are in use; restore %d under Security Scanning → Decompression Bound.", secscan.DefaultDecompressRatioLimit),
		}
	}
	return OperatorContractCheck{
		Code:    "scan_decompress_ratio",
		Status:  diagOK,
		Message: fmt.Sprintf("Decompression ratio limit %d:1 (default %d:1) — responses expanding past it are refused (fail-closed)", ratio, secscan.DefaultDecompressRatioLimit),
	}
}
