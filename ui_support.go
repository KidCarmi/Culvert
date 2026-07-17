package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

// Support-bundle disk-safety bounds (roadmap cross-milestone invariant #4: every
// new persisted state under <dataDir>/support carries preflight + retention). The
// full crash-safe lifecycle FSM + age-based janitor is M4; these are the minimal
// M1 bounds so a bundle build can never fill the /data volume nor accumulate
// without limit.
const (
	supportMinFreeBytes  = 256 << 20 // refuse a new bundle build below this free headroom
	supportRetentionKeep = 10        // keep the newest N persisted bundles, evict oldest-first
)

// errSupportLowDisk is the fail-closed preflight sentinel: the POST handler maps
// it to 507 Insufficient Storage so the operator sees a clear, distinct cause.
var errSupportLowDisk = errors.New("insufficient disk headroom for support bundle")

// Support-bundle admin API (M1 Slice 1). Two routes, registered with plain paths
// and method-dispatched in-handler (repo convention):
//
//	POST /api/support/bundles       — create a redacted csb/1 bundle (admin)
//	GET  /api/support/bundles/{id}   — download a created bundle (operator)
func registerSupportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/support/status", apiSupportStatus)
	mux.HandleFunc("/api/support/bundles", apiSupportBundles)
	mux.HandleFunc("/api/support/bundles/{id}", apiSupportBundleItem)
	mux.HandleFunc("/api/support/bundles/{id}/redaction-report", apiSupportBundleReport)
	mux.HandleFunc("/api/support/bundles/{id}/approve", apiSupportBundleApprove)
	mux.HandleFunc("/api/support/bundles/{id}/validate", apiSupportBundleValidate)
	mux.HandleFunc("/api/support/debug-level", apiSupportDebugLevel)
	mux.HandleFunc("/api/health/explain", apiHealthExplain)
}

// debugLevelView is the read-only status of the capture-level controller.
type debugLevelView struct {
	EffectiveLevel int    `json:"effective_level"` // level a bundle would capture at right now
	BaselineLevel  int    `json:"baseline_level"`  // the un-elevated default
	Elevated       bool   `json:"elevated"`        // an unexpired elevation is in force
	ExpiresAt      string `json:"expires_at,omitempty"`
	RemainingSecs  int64  `json:"remaining_secs,omitempty"`
	SetBy          string `json:"set_by,omitempty"`
	MinTTLSecs     int64  `json:"min_ttl_secs"`
	MaxTTLSecs     int64  `json:"max_ttl_secs"`
}

type debugLevelSetReq struct {
	Level      int   `json:"level"`
	TTLSeconds int64 `json:"ttl_seconds"`
}

// apiSupportDebugLevel is the capture-level controller surface:
//   - GET (viewer): the effective level, elevation state, and remaining TTL.
//   - POST (admin): elevate the default capture depth for a BOUNDED window. A
//     positive, in-range ttl_seconds is MANDATORY (400 otherwise) — an elevation
//     can never be open-ended.
//   - DELETE (operator): revert to baseline immediately.
func apiSupportDebugLevel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		now := time.Now()
		eff := effectiveDebugLevel(now)
		view := debugLevelView{
			EffectiveLevel: int(eff),
			BaselineLevel:  int(debugLevelBaseline),
			Elevated:       eff != debugLevelBaseline,
			MinTTLSecs:     int64(debugLevelMinTTL / time.Second),
			MaxTTLSecs:     int64(debugLevelMaxTTL / time.Second),
		}
		debugLevelMu.Lock()
		st := readDebugLevelStateLocked()
		debugLevelMu.Unlock()
		if st.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, st.ExpiresAt); err == nil && now.Before(exp) {
				view.ExpiresAt = st.ExpiresAt
				view.RemainingSecs = int64(exp.Sub(now).Seconds())
				view.SetBy = st.SetBy
			}
		}
		jsonOK(w, view)

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var req debugLevelSetReq
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Level < 0 || req.Level > 4 {
			http.Error(w, "invalid debug level (0..4)", http.StatusBadRequest)
			return
		}
		// Mandatory TTL: a positive, bounded window is required.
		if req.TTLSeconds <= 0 {
			http.Error(w, "ttl_seconds is required and must be positive", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		exp, err := setDebugLevel(support.DebugLevel(req.Level), ttl, sanitizeLog(auditActor(r)), time.Now())
		if err != nil {
			if errors.Is(err, errDebugTTL) {
				http.Error(w, fmt.Sprintf("ttl_seconds must be between %d and %d",
					int64(debugLevelMinTTL/time.Second), int64(debugLevelMaxTTL/time.Second)), http.StatusBadRequest)
				return
			}
			logger.Printf("support: set debug level failed: %v", err)
			http.Error(w, "could not set debug level", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "support.debug_level.set", "debug-level",
			fmt.Sprintf("L%d until %s", req.Level, exp.Format(time.RFC3339)))
		jsonOK(w, map[string]any{"level": req.Level, "expires_at": exp.Format(time.RFC3339)})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		if err := clearDebugLevel(); err != nil {
			logger.Printf("support: clear debug level failed: %v", err)
			http.Error(w, "could not clear debug level", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "support.debug_level.clear", "debug-level", "reverted to baseline")
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiSupportBundleReport serves a persisted bundle's redaction report — the
// counts-only (never values) per-section masked/dropped/scrubbed + class_max
// summary — so an operator can preview WHAT a bundle redacted without downloading
// and unpacking the whole archive (viewer; the report carries no sensitive data).
func apiSupportBundleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	b, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, support.RedactionReportName))
	if err != nil {
		// A pre-report bundle (created before this feature) simply has no file.
		http.Error(w, "redaction report not found", http.StatusNotFound)
		return
	}
	var rep support.RedactionReport
	if json.Unmarshal(b, &rep) != nil {
		http.Error(w, "redaction report corrupt", http.StatusInternalServerError)
		return
	}
	jsonOK(w, rep)
}

// apiHealthExplain returns the explained operator-contract health verdict —
// per-check status + a plain-language operator_action for each — so an admin can
// read "what is wrong and what to do" from the GUI, not just a liveness bit
// (viewer, read-only; the endorsed GAP-MON-01 explained-health surface).
func apiHealthExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, buildOperatorContract())
}

// supportCollectorInfo is the read-only view of one registered collector.
type supportCollectorInfo struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Owner         string `json:"owner"`
	Mandatory     bool   `json:"mandatory"`
	MinLevel      int    `json:"min_level"`
	MaxClass      string `json:"max_class"`
	SchemaVersion int    `json:"schema_version"`
}

type supportStatus struct {
	BundleFormat          string                 `json:"bundle_format"`
	CollectorEngineVer    int                    `json:"collector_engine_version"`
	RedactionModelVersion int                    `json:"redaction_model_version"`
	Collectors            []supportCollectorInfo `json:"collectors"`
	Scopes                []string               `json:"scopes"` // selectable incident scopes
}

// apiSupportStatus reports the support subsystem's static contract: engine +
// redaction versions and the registered collector inventory (viewer, read-only).
func apiSupportStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	cols := support.Collectors()
	info := make([]supportCollectorInfo, 0, len(cols))
	for _, c := range cols {
		m := c.Meta()
		info = append(info, supportCollectorInfo{
			ID: m.ID, Path: m.Path, Owner: m.Owner, Mandatory: m.Mandatory,
			MinLevel: int(m.MinLevel), MaxClass: m.MaxClass.String(), SchemaVersion: m.SchemaVersion,
		})
	}
	jsonOK(w, supportStatus{
		BundleFormat:          support.BundleFormat,
		CollectorEngineVer:    support.CollectorEngineVer,
		RedactionModelVersion: support.RedactionModelVer,
		Collectors:            info,
		Scopes:                supportScopeNames(),
	})
}

// supportBundleIDRe pins the deterministic bundle-id shape so a path segment can
// never traverse out of the bundles dir.
var supportBundleIDRe = regexp.MustCompile(`^csb_[a-z2-7]{26}$`)

func supportBundlesDir() string { return filepath.Join(dataDir, "support", "bundles") }

// supportBundleSummary is the read-only list view of a persisted bundle.
type supportBundleSummary struct {
	BundleID        string `json:"bundle_id"`
	CreatedAt       string `json:"created_at"`
	Format          string `json:"format"`
	TotalCollectors int    `json:"total_collectors"`
	OK              int    `json:"ok"`
	Failed          int    `json:"failed"`
	SizeBytes       int64  `json:"size_bytes"`
	State           string `json:"state"`             // pending|ready (mandatory-preview lifecycle)
	CaseID          string `json:"case_id,omitempty"` // operator-bound support case (M4)
}

// apiSupportBundles lists (GET, viewer) or creates (POST, admin) support bundles.
// Creating is admin-gated: a standard bundle can contain INTERNAL sections
// (COLLECTOR-CONTRACT §4).
func apiSupportBundles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, listSupportBundles())
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		// Optional ?scope= for an incident-focused bundle (default: standard = all).
		scope := r.URL.Query().Get("scope")
		if _, ok := resolveSupportScope(scope); !ok {
			http.Error(w, "unknown incident scope", http.StatusBadRequest)
			return
		}
		// Optional ?level= (0..4) explicitly overrides the capture depth. When
		// absent, the effective controller level applies — the operator's bounded
		// elevation (if any), else baseline L1.
		var level support.DebugLevel
		if r.URL.Query().Has("level") {
			lv, ok := parseSupportLevel(r.URL.Query().Get("level"))
			if !ok {
				http.Error(w, "invalid debug level (0..4)", http.StatusBadRequest)
				return
			}
			level = lv
		} else {
			level = currentDebugLevel()
		}
		// Optional ?case= binds the bundle to a support case for triage/history.
		// Validate the RAW value (no trimming): the grammar disallows whitespace, so
		// a padded "%20CASE-7%20" or whitespace-only "%20" must 400, not be silently
		// trimmed into a different/empty case. An absent-or-empty param = no case.
		caseID := r.URL.Query().Get("case")
		if caseID != "" && !validSupportCaseID(caseID) {
			http.Error(w, "invalid case id (1..64 of letters/digits/._-, no whitespace)", http.StatusBadRequest)
			return
		}
		res, err := createSupportBundle(r.Context(), scope, level, caseID)
		if err != nil {
			if errors.Is(err, errSupportLowDisk) {
				logger.Printf("support: bundle build refused — insufficient disk headroom")
				http.Error(w, "insufficient disk headroom for bundle", http.StatusInsufficientStorage)
				return
			}
			logger.Printf("support: bundle build failed: %v", err)
			http.Error(w, "bundle build failed", http.StatusInternalServerError)
			return
		}
		if scope == "" {
			scope = "standard"
		}
		detail := fmt.Sprintf("%s L%d", scope, int(level))
		if caseID != "" {
			detail += " case=" + caseID
		}
		auditEvent(r, "support.bundle.create", res.BundleID, detail)
		jsonOK(w, res.Manifest)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listSupportBundles reads persisted bundle manifests newest-first. Malformed or
// partial bundle dirs are skipped (never fatal).
func listSupportBundles() []supportBundleSummary {
	entries, err := os.ReadDir(supportBundlesDir())
	if err != nil {
		return []supportBundleSummary{} // dir absent (no bundle yet) → empty, not an error
	}
	out := make([]supportBundleSummary, 0, len(entries))
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || !supportBundleIDRe.MatchString(id) {
			continue
		}
		manifestBytes, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, "manifest.json"))
		if err != nil {
			continue
		}
		var man support.SupportBundleManifest
		if json.Unmarshal(manifestBytes, &man) != nil {
			continue
		}
		var size int64
		if fi, err := os.Stat(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz")); err == nil {
			size = fi.Size()
		}
		st := readBundleState(id)
		out = append(out, supportBundleSummary{
			BundleID: man.BundleID, CreatedAt: man.CreatedAt, Format: man.Format,
			TotalCollectors: man.Collection.TotalCollectors, OK: man.Collection.OK,
			Failed: man.Collection.Failed, SizeBytes: size, State: st.State, CaseID: st.CaseID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// Bundle lifecycle (M2 PR3 — SUPPORT-BUNDLE-SPEC §6 mandatory preview): a created
// bundle is PENDING until an admin reviews its redaction report and approves it;
// only a READY bundle is downloadable. State lives in a sidecar so the immutable
// tar/manifest are never touched.
const (
	bundleStatePending = "pending"
	bundleStateReady   = "ready"
)

type supportBundleStateFile struct {
	State      string `json:"state"`
	CreatedAt  string `json:"created_at,omitempty"`
	ApprovedAt string `json:"approved_at,omitempty"`
	ApprovedBy string `json:"approved_by,omitempty"`
	CaseID     string `json:"case_id,omitempty"` // operator-bound support case (M4)
}

// supportCaseIDRe pins the safe shape of an operator-supplied support case id:
// 1..64 of letters/digits/dot/hyphen/underscore. Bounded and free of path,
// whitespace, and control characters so it can be echoed in the UI and audit
// without escaping surprises. Empty (no case) is allowed at the call sites.
var supportCaseIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// validSupportCaseID reports whether s is a well-formed case id. The empty string
// is NOT valid here — callers treat "" as "no case" before calling.
func validSupportCaseID(s string) bool { return supportCaseIDRe.MatchString(s) }

func supportBundleStatePath(id string) string {
	return filepath.Join(supportBundlesDir(), id, "state.json")
}

// readBundleState returns the lifecycle state. An ABSENT state file is a pre-gate
// bundle (created before mandatory preview) and is grandfathered READY — the gate
// never retroactively blocks an already-downloadable bundle. A PRESENT-but-corrupt
// file fails closed to PENDING (never grant export on unreadable state).
func readBundleState(id string) supportBundleStateFile {
	b, err := os.ReadFile(supportBundleStatePath(id))
	if os.IsNotExist(err) {
		return supportBundleStateFile{State: bundleStateReady}
	}
	if err != nil {
		return supportBundleStateFile{State: bundleStatePending}
	}
	var st supportBundleStateFile
	if json.Unmarshal(b, &st) != nil || st.State == "" {
		return supportBundleStateFile{State: bundleStatePending}
	}
	return st
}

func writeBundleState(id string, st supportBundleStateFile) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := supportBundleStatePath(id) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, supportBundleStatePath(id))
}

// apiSupportBundleApprove marks a PENDING bundle READY for download after an admin
// has reviewed its redaction report (the mandatory-preview gate). Admin-gated: the
// approval is what authorizes export of a bundle's INTERNAL sections.
func apiSupportBundleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(filepath.Join(supportBundlesDir(), id, "manifest.json")); err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}
	st := readBundleState(id)
	st.State = bundleStateReady
	st.ApprovedAt = time.Now().UTC().Format(time.RFC3339)
	st.ApprovedBy = auditActor(r)
	if err := writeBundleState(id, st); err != nil {
		logger.Printf("support: bundle approve failed: %v", err)
		http.Error(w, "approve failed", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "support.bundle.approve", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// apiSupportBundleItem downloads (GET, operator+) or deletes (DELETE, operator+)
// a created bundle by id. Download is the exfil event for a bundle that may carry
// INTERNAL sections, so it is audited like create is AND gated on approval; DELETE
// is the in-product reclaim path (no host FS access required).
func apiSupportBundleItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// Mandatory-preview gate: a bundle is downloadable only after an admin has
		// reviewed its redaction report and approved it.
		if readBundleState(id).State != bundleStateReady {
			http.Error(w, "bundle pending approval — an admin must review the redaction report and approve before download", http.StatusConflict)
			return
		}
		f, err := os.Open(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"))
		if err != nil {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		// Audit at grant time (access authorized), before streaming: the download
		// is the actual exfiltration event, so it must leave a trace even if the
		// copy is interrupted mid-stream.
		auditEvent(r, "support.bundle.download", id, support.BundleFormat)
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id+".csb.tgz"))
		_, _ = io.Copy(w, f)
	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		dir := filepath.Join(supportBundlesDir(), id)
		if _, err := os.Stat(dir); err != nil {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		if err := os.RemoveAll(dir); err != nil {
			logger.Printf("support: bundle delete failed: %v", err)
			http.Error(w, "bundle delete failed", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "support.bundle.delete", id, "")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// buildSupportBundle runs the engine over the registered collectors at the given
// level. No model or network is in the path; the bundle is redacted at source.
// parseSupportLevel maps an optional "0".."4" query value to a DebugLevel; empty
// defaults to L1 (standard). ok=false for a malformed value.
func parseSupportLevel(s string) (support.DebugLevel, bool) {
	switch s {
	case "":
		return support.L1, true
	case "0":
		return support.L0, true
	case "1":
		return support.L1, true
	case "2":
		return support.L2, true
	case "3":
		return support.L3, true
	case "4":
		return support.L4, true
	}
	return support.L1, false
}

func buildSupportBundle(ctx context.Context, level support.DebugLevel, scope string) (*support.BuildResult, error) {
	include, ok := resolveSupportScope(scope)
	if !ok {
		return nil, fmt.Errorf("unknown incident scope %q", scope)
	}
	if scope == "" {
		scope = "standard"
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return support.NewRunner().Build(ctx, support.BuildOptions{
		Version:   version,
		GoVersion: runtime.Version(),
		Runtime: support.RuntimeInfo{
			NodeID: clusterRole.nodeID, Role: clusterRole.role, Runtime: "unknown",
		},
		Level:             level,
		Profile:           "default",
		IncidentScope:     scope,
		IncludeCollectors: include, // nil for "standard" → every collector runs
		Nonce:             hex.EncodeToString(nonce),
		Clock:             time.Now,
	})
}

// createSupportBundle builds a standard (L1) bundle and persists it under
// <dataDir>/support/bundles/<id>/. It is fail-closed on low disk (preflight),
// crash-safe on the error path (a failed persist never strands a partial dir),
// and bounded (oldest-first retention cap) — roadmap cross-milestone invariant #4.
func createSupportBundle(ctx context.Context, scope string, level support.DebugLevel, caseID string) (res *support.BuildResult, retErr error) {
	// Disk-headroom preflight: never begin a build that could fill /data. A
	// statfs error is non-fatal (fail-open on an unreadable FS is fine here —
	// the write itself still errors and cleans up), a low reading is fail-closed.
	if _, free, _, err := diskUsage(dataDir); err == nil && free < supportMinFreeBytes {
		return nil, errSupportLowDisk
	}
	res, err := buildSupportBundle(ctx, level, scope)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(supportBundlesDir(), res.BundleID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir bundle dir: %w", err)
	}
	// Any failure past this point must not strand a partial bundle dir (SPEC §6
	// P5 no-partial-write): a manifest-less dir is invisible to listSupportBundles
	// yet still occupies disk, so remove the whole dir on any error return.
	defer func() {
		if retErr != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	// Write PENDING state FIRST — before the tgz and the manifest — so no openable
	// or listable artifact can ever exist without a pending state. If we wrote it
	// last, a crash between the manifest commit and the state write would leave a
	// bundle that readBundleState grandfathers to READY (missing state ⇒ ready),
	// i.e. downloadable without approval. State-first closes that bypass window:
	// a missing state file now means only a genuine pre-gate bundle.
	if err := writeBundleState(res.BundleID, supportBundleStateFile{State: bundleStatePending, CreatedAt: res.Manifest.CreatedAt, CaseID: caseID}); err != nil {
		return nil, fmt.Errorf("write state: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.csb.tgz"), res.TarGz, 0o600); err != nil {
		return nil, fmt.Errorf("write bundle: %w", err)
	}
	manifestJSON, err := json.MarshalIndent(res.Manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	// redaction-report.json is persisted alongside the manifest (it also lives
	// inside the tar) so the preview endpoint can serve it without unpacking the
	// whole bundle. Counts-only (REDACTION-MODEL P4/P6) — no values. Written
	// BEFORE the manifest commit so a listable bundle always has its report.
	reportJSON, err := json.MarshalIndent(res.Report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, support.RedactionReportName), reportJSON, 0o600); err != nil {
		return nil, fmt.Errorf("write report: %w", err)
	}
	// manifest.json is the list/commit marker (listSupportBundles keys on it), so
	// write it atomically via tmp+rename — a torn write can never present a
	// half-manifest as a listable bundle.
	tmp := filepath.Join(dir, "manifest.json.tmp")
	if err := os.WriteFile(tmp, manifestJSON, 0o600); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "manifest.json")); err != nil {
		return nil, fmt.Errorf("commit manifest: %w", err)
	}
	pruneSupportBundles(supportRetentionKeep)
	return res, nil
}

// pruneSupportBundles enforces an oldest-first retention cap so persisted bundles
// cannot grow without bound. The full age-based, crash-safe lifecycle janitor is
// M4; this is the minimal M1 disk-safety bound. Each eviction is audited as
// support.bundle.expire (system actor). Best-effort: an eviction failure is
// logged and skipped, never fatal to the build that triggered it.
func pruneSupportBundles(keep int) {
	if keep < 1 {
		return
	}
	sums := listSupportBundles() // newest-first
	if len(sums) <= keep {
		return
	}
	for _, s := range sums[keep:] {
		// Defense-in-depth: BundleID here comes from manifest content, so re-guard
		// against the path-traversal shape before any os.RemoveAll.
		if !supportBundleIDRe.MatchString(s.BundleID) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(supportBundlesDir(), s.BundleID)); err != nil {
			logger.Printf("support: retention evict failed for %q: %v",
				strings.ReplaceAll(s.BundleID, "\n", ""), err)
			continue
		}
		auditSystem("support.bundle.expire", s.BundleID, "retention cap")
	}
}

// runSupportBundleCommand is the `culvert --support-bundle <path>` recovery
// one-shot: it builds a minimal (L0) bundle headless — no server, no admin UI —
// and writes it to outPath. This is the "GUI is down" escape hatch (the endorsed
// GAP-MON-01 recovery path). Prints a short summary to stdout.
func runSupportBundleCommand(outPath string) error {
	res, err := buildSupportBundle(context.Background(), support.L0, "standard")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, res.TarGz, 0o600); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	fmt.Printf("support bundle written: %s\n  bundle_id: %s\n  sections:  %d ok, %d failed, %d skipped\n  sha256:    %s\n",
		outPath, res.BundleID, res.Manifest.Collection.OK,
		res.Manifest.Collection.Failed, res.Manifest.Collection.Skipped, res.BundleSHA256)
	return nil
}
