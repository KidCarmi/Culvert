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
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

// Retention-sweep observability (node-local, since-boot). An operator asking
// "why did my bundle disappear?" can see the total evicted and when the age
// janitor last ran. Atomics: read lock-free from the status handler, written
// from the prune paths / janitor goroutine.
var (
	supportRetentionEvicted   atomic.Int64 // bundles removed by retention (both caps) since boot
	supportRetentionLastSweep atomic.Int64 // unix seconds of the last age-sweep pass (0 = never run)
)

// Support-bundle disk-safety bounds (roadmap cross-milestone invariant #4: every
// new persisted state under <dataDir>/support carries preflight + retention). The
// full crash-safe lifecycle FSM + age-based janitor is M4; these are the minimal
// M1 bounds so a bundle build can never fill the /data volume nor accumulate
// without limit.
const (
	supportMinFreeBytes  = 256 << 20 // refuse a new bundle build below this free headroom
	supportRetentionKeep = 10        // keep the newest N persisted bundles, evict oldest-first

	// supportRetentionMaxAge bounds how long a persisted bundle lives on disk. The
	// count-based prune runs only when a NEW bundle is built, so an idle appliance
	// (one that stopped creating bundles) would otherwise keep stale bundles
	// forever; the background janitor evicts anything older than this.
	supportRetentionMaxAge = 30 * 24 * time.Hour
	// supportRetentionTick is the age-sweep cadence.
	supportRetentionTick = 6 * time.Hour

	// supportMaxStoreBytes is a hard ceiling on the TOTAL on-disk size of the bundle
	// store. The count/age caps can't predict per-bundle size, and the
	// supportMinFreeBytes preflight only REFUSES a new build (507) — it never reclaims
	// — so without this a store of large bundles can wedge the diagnostic path exactly
	// when an operator needs a fresh bundle. This reclaims oldest-first over EVICTABLE
	// bundles until the store is under the ceiling.
	supportMaxStoreBytes = 2 << 30 // 2 GiB
)

// supportPruneMu serializes every retention prune pass (count, age, size). Each pass
// is list-then-RemoveAll with no per-file lock; two concurrent passes (create-path
// prune vs the 6h janitor vs a second concurrent build) would otherwise race —
// os.RemoveAll returns nil for an already-gone path, so the error guard misses it and
// the eviction counter + audit trail double-count a single physical eviction. Prunes
// are infrequent, so full serialization is free.
var supportPruneMu sync.Mutex

// retentionEvidence reports whether a bundle is FORENSIC EVIDENCE that retention must
// never auto-delete: bound to a support case (CaseID). Exempt from ALL caps.
func retentionEvidence(s *supportBundleSummary) bool { return s.CaseID != "" }

// retentionExemptFromCountCap is the count-cap exemption: evidence (case-bound) PLUS
// any bundle still under mandatory review (pending) — a fresh build must not evict a
// bundle an admin is mid-approval on. The age/size caps use retentionEvidence only, so
// a stale never-approved pending bundle can still age out / be reclaimed under pressure.
func retentionExemptFromCountCap(s *supportBundleSummary) bool {
	return retentionEvidence(s) || s.State == bundleStatePending
}

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
	mux.HandleFunc("/api/support/bundles/{id}/download-encrypted", apiSupportBundleExportEncrypted)
	mux.HandleFunc("/api/support/bundles/{id}/download-sealed", apiSupportBundleExportSealed)
	mux.HandleFunc("/api/support/bundles/{id}/exports", apiSupportBundleExports)
	mux.HandleFunc("/api/support/bundles/{id}/manifest", apiSupportBundleManifest)
	mux.HandleFunc("/api/support/recipients", apiSupportRecipients)
	mux.HandleFunc("/api/support/recipients/{name}", apiSupportRecipientItem)
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
		handleSupportDebugLevelGet(w, r)
	case http.MethodPost:
		handleSupportDebugLevelPost(w, r)
	case http.MethodDelete:
		handleSupportDebugLevelDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSupportDebugLevelGet reports the effective capture level, elevation
// state, and remaining TTL (viewer).
func handleSupportDebugLevelGet(w http.ResponseWriter, r *http.Request) {
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
}

// handleSupportDebugLevelPost elevates the default capture depth for a
// BOUNDED window (admin). A positive, in-range ttl_seconds is MANDATORY (400
// otherwise) — an elevation can never be open-ended.
func handleSupportDebugLevelPost(w http.ResponseWriter, r *http.Request) {
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
		logger.Printf("support: set debug level failed: %v", sanitizeLog(err.Error()))
		http.Error(w, "could not set debug level", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "support.debug_level.set", "debug-level",
		fmt.Sprintf("L%d until %s", req.Level, exp.Format(time.RFC3339)))
	jsonOK(w, map[string]any{"level": req.Level, "expires_at": exp.Format(time.RFC3339)})
}

// handleSupportDebugLevelDelete reverts to the baseline capture level
// immediately (operator).
func handleSupportDebugLevelDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleOperator) {
		return
	}
	if err := clearDebugLevel(); err != nil {
		logger.Printf("support: clear debug level failed: %v", sanitizeLog(err.Error()))
		http.Error(w, "could not clear debug level", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "support.debug_level.clear", "debug-level", "reverted to baseline")
	w.WriteHeader(http.StatusNoContent)
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
	// Attach the server-side consent preview (retained INTERNAL free-form values)
	// so the APPROVER sees what the counts-only report cannot show — the whole
	// point of the mandatory-preview gate. Read from redaction-preview.json (never
	// in the bundle); a pre-feature bundle simply has none and the field stays
	// empty.
	//
	// RBAC: the counts-only report is viewer-safe, but the retained free-form
	// values can carry a bare secret the precision-first scrubber cannot catch, so
	// they are the APPROVER's backstop, NOT viewer-safe. Only attach retained_preview
	// for operator+ (the approve/download role — RoleOperator ⊆ RoleAdmin); a viewer
	// still gets a 200 with the counts-only report, just without the preview.
	resp := struct {
		support.RedactionReport
		RetainedPreview []support.RedactionPreviewSection `json:"retained_preview"`
	}{RedactionReport: rep}
	if uiRole(r).HasRole(RoleOperator) {
		if pb, perr := os.ReadFile(filepath.Join(supportBundlesDir(), id, support.RedactionPreviewName)); perr == nil {
			var prev support.RedactionPreview
			if json.Unmarshal(pb, &prev) == nil {
				resp.RetainedPreview = prev.Sections
			}
		}
	}
	jsonOK(w, resp)
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
	Scopes                []string               `json:"scopes"`                         // selectable incident scopes
	RetentionKeep         int                    `json:"retention_keep"`                 // count cap: newest N persisted bundles kept
	RetentionMaxAgeDays   int                    `json:"retention_max_age_days"`         // age cap: idle-appliance background sweep
	RetentionEvicted      int64                  `json:"retention_evicted_total"`        // bundles removed by retention since boot
	RetentionLastSweep    string                 `json:"retention_last_sweep,omitempty"` // RFC3339 of the last age sweep (empty = never)
	RecipientCount        int                    `json:"recipient_count"`                // registered sealing recipients
	RecipientMax          int                    `json:"recipient_max"`                  // registry cap
}

// apiSupportStatus reports the support subsystem's contract + current state: engine
// + redaction versions, the registered collector inventory, selectable scopes, the
// bundle-retention window, and the sealing-recipient registry size (viewer,
// read-only; no secrets — counts and capabilities only).
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
	lastSweep := ""
	if u := supportRetentionLastSweep.Load(); u > 0 {
		lastSweep = time.Unix(u, 0).UTC().Format(time.RFC3339)
	}
	jsonOK(w, supportStatus{
		BundleFormat:          support.BundleFormat,
		CollectorEngineVer:    support.CollectorEngineVer,
		RedactionModelVersion: support.RedactionModelVer,
		Collectors:            info,
		Scopes:                supportScopeNames(),
		RetentionKeep:         supportRetentionKeep,
		RetentionMaxAgeDays:   int(supportRetentionMaxAge / (24 * time.Hour)),
		RetentionEvicted:      supportRetentionEvicted.Load(),
		RetentionLastSweep:    lastSweep,
		RecipientCount:        len(listSupportRecipients()),
		RecipientMax:          maxSupportRecipients,
	})
}

// supportWritePrometheus exposes the support-bundle retention counters for
// scraping — durable, alertable observability that complements the point-in-time
// JSON on /api/support/status (e.g. alert if the last sweep timestamp goes stale,
// or on a sudden eviction-rate spike). Counts + a timestamp only; no secrets.
func supportWritePrometheus(w *strings.Builder) {
	w.WriteString("\n# HELP culvert_support_bundle_retention_evicted_total Support bundles removed by retention (count + age caps) since process start\n")
	w.WriteString("# TYPE culvert_support_bundle_retention_evicted_total counter\n")
	fmt.Fprintf(w, "culvert_support_bundle_retention_evicted_total %d\n", supportRetentionEvicted.Load())
	w.WriteString("# HELP culvert_support_bundle_retention_last_sweep_timestamp_seconds Unix time of the last age-retention sweep (0 = never run)\n")
	w.WriteString("# TYPE culvert_support_bundle_retention_last_sweep_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_support_bundle_retention_last_sweep_timestamp_seconds %d\n", supportRetentionLastSweep.Load())
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

	// dirName is the ON-DISK directory name this summary was scanned from. It is
	// deliberately distinct from BundleID (which is manifest CONTENT): a corrupt
	// or hand-copied manifest can carry a bundle_id that differs from the directory
	// it lives in, so any filesystem eviction MUST target dirName — never BundleID,
	// which could name a different, valid bundle. Unexported ⇒ never serialized.
	dirName string
}

// apiSupportBundles lists (GET, viewer) or creates (POST, admin) support bundles.
// Creating is admin-gated: a standard bundle can contain INTERNAL sections
// (COLLECTOR-CONTRACT §4).
func apiSupportBundles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleSupportBundlesGet(w, r)
	case http.MethodPost:
		handleSupportBundlesPost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSupportBundlesGet lists persisted bundles, optionally filtered to one
// support case (viewer).
func handleSupportBundlesGet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	// Optional ?case= filters the history to one support case. Validate the raw
	// value (same grammar as creation) so a malformed filter 400s rather than
	// silently matching nothing.
	bundles := listSupportBundles()
	if caseFilter := r.URL.Query().Get("case"); caseFilter != "" {
		if !validSupportCaseID(caseFilter) {
			http.Error(w, "invalid case id filter", http.StatusBadRequest)
			return
		}
		bundles = filterBundlesByCase(bundles, caseFilter)
	}
	jsonOK(w, bundles)
}

// resolveSupportBundlesPostParams validates and resolves the POST ?scope=,
// ?level=, and ?case= query params for handleSupportBundlesPost. ok is false
// iff a 400 has already been written to w.
func resolveSupportBundlesPostParams(w http.ResponseWriter, r *http.Request) (scope string, level support.DebugLevel, caseID string, ok bool) {
	// Optional ?scope= for an incident-focused bundle (default: standard = all).
	scope = r.URL.Query().Get("scope")
	if _, valid := resolveSupportScope(scope); !valid {
		http.Error(w, "unknown incident scope", http.StatusBadRequest)
		return "", 0, "", false
	}
	// Optional ?level= (0..4) explicitly overrides the capture depth. When
	// absent, the effective controller level applies — the operator's bounded
	// elevation (if any), else baseline L1.
	if r.URL.Query().Has("level") {
		lv, valid := parseSupportLevel(r.URL.Query().Get("level"))
		if !valid {
			http.Error(w, "invalid debug level (0..4)", http.StatusBadRequest)
			return "", 0, "", false
		}
		level = lv
	} else {
		level = currentDebugLevel()
	}
	// Optional ?case= binds the bundle to a support case for triage/history.
	// Validate the RAW value (no trimming): the grammar disallows whitespace, so
	// a padded "%20CASE-7%20" or whitespace-only "%20" must 400, not be silently
	// trimmed into a different/empty case. An absent-or-empty param = no case.
	caseID = r.URL.Query().Get("case")
	if caseID != "" && !validSupportCaseID(caseID) {
		http.Error(w, "invalid case id (1..64 of letters/digits/._-, no whitespace)", http.StatusBadRequest)
		return "", 0, "", false
	}
	return scope, level, caseID, true
}

// handleSupportBundlesPost creates a redacted csb/1 bundle (admin). A standard
// bundle can contain INTERNAL sections (COLLECTOR-CONTRACT §4).
func handleSupportBundlesPost(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	scope, level, caseID, ok := resolveSupportBundlesPostParams(w, r)
	if !ok {
		return
	}
	res, err := createSupportBundle(r.Context(), scope, level, caseID)
	if err != nil {
		if errors.Is(err, errSupportLowDisk) {
			logger.Printf("support: bundle build refused — insufficient disk headroom")
			http.Error(w, "insufficient disk headroom for bundle", http.StatusInsufficientStorage)
			return
		}
		logger.Printf("support: bundle build failed: %v", sanitizeLog(err.Error()))
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
}

// filterBundlesByCase returns only the bundles bound to caseID (exact match). A
// new slice is returned; the input is not mutated.
func filterBundlesByCase(in []supportBundleSummary, caseID string) []supportBundleSummary {
	out := make([]supportBundleSummary, 0, len(in))
	for i := range in {
		if in[i].CaseID == caseID {
			out = append(out, in[i])
		}
	}
	return out
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
			dirName: id,
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
		logger.Printf("support: bundle approve failed: %v", sanitizeLog(err.Error()))
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
			logger.Printf("support: bundle delete failed: %v", sanitizeLog(err.Error()))
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

func buildSupportBundle(ctx context.Context, level support.DebugLevel, scope, caseID string) (*support.BuildResult, error) {
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
		// case_id binds the persisted manifest + downloaded tar to a TAC support
		// case (offline evidence↔case binding); empty when none was supplied.
		CaseID: caseID,
		Nonce:  hex.EncodeToString(nonce),
		Clock:  time.Now,
	})
}

// createSupportBundle builds a standard (L1) bundle and persists it under
// <dataDir>/support/bundles/<id>/. It is fail-closed on low disk (preflight),
// crash-safe on the error path (a failed persist never strands a partial dir),
// and bounded (oldest-first retention cap) — roadmap cross-milestone invariant #4.
func createSupportBundle(ctx context.Context, scope string, level support.DebugLevel, caseID string) (res *support.BuildResult, retErr error) {
	// Reclaim over-cap OLD bundles BEFORE the low-disk preflight — otherwise a store
	// already at the size ceiling refuses every new build (507) while stale bundles
	// sit un-reclaimed, the exact wedge the size cap exists to prevent. No just-created
	// bundle exists yet, so nothing to exempt.
	pruneSupportBundlesBySize(supportMaxStoreBytes, "")

	// Disk-headroom preflight: never begin a build that could fill /data. A
	// statfs error is non-fatal (fail-open on an unreadable FS is fine here —
	// the write itself still errors and cleans up), a low reading is fail-closed.
	if _, free, _, err := diskUsage(dataDir); err == nil && free < supportMinFreeBytes {
		return nil, errSupportLowDisk
	}
	res, err := buildSupportBundle(ctx, level, scope, caseID)
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
	// redaction-preview.json is the SERVER-SIDE consent preview: a bounded sample
	// of the retained INTERNAL free-form values, surfaced to the approving admin
	// so the mandatory-preview gate is SIGHTED. It is written to the bundle dir
	// but is NEVER inside bundle.csb.tgz and is NEVER downloaded — it exists only
	// to inform approval. 0600, same as the report.
	previewJSON, err := json.MarshalIndent(res.Preview, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal preview: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, support.RedactionPreviewName), previewJSON, 0o600); err != nil {
		return nil, fmt.Errorf("write preview: %w", err)
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
	// Exempt the bundle we just built: a store over-cap from case-bound evidence must
	// not delete the fresh bundle before we return its id (it would be un-approvable).
	pruneSupportBundlesBySize(supportMaxStoreBytes, res.BundleID)
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
	supportPruneMu.Lock()
	defer supportPruneMu.Unlock()

	// Count the cap against EVICTABLE bundles only. Evidence (case-bound) and
	// under-review (pending) bundles are exempt and must NOT consume a keep slot or be
	// evicted — otherwise a fresh build can silently delete a bundle a TAC engineer is
	// mid-download on (the bundle a case is anchored to). listSupportBundles is
	// newest-first, so iterate and evict only the evictable overflow past `keep`.
	sums := listSupportBundles()
	kept := 0
	for i := range sums {
		s := &sums[i]
		if retentionExemptFromCountCap(s) {
			continue // never counts toward the cap, never evicted
		}
		kept++
		if kept <= keep {
			continue
		}
		evictBundleDir(s.dirName, "retention count-cap")
	}
}

// evictBundleDir removes one bundle directory (best-effort, path-guarded) and records
// the eviction. Returns true ONLY on a real removal — the size cap uses this to avoid
// crediting bytes it did not actually reclaim. Caller MUST hold supportPruneMu. dirName
// is the ON-DISK directory, NEVER the manifest BundleID (a corrupt/hand-copied manifest
// can name a different, valid bundle).
func evictBundleDir(dirName, reason string) bool {
	if !supportBundleIDRe.MatchString(dirName) {
		return false // defense-in-depth against a path-traversal shape
	}
	if err := os.RemoveAll(filepath.Join(supportBundlesDir(), dirName)); err != nil {
		logger.Printf("support: %s evict failed for %q: %v",
			reason, strings.ReplaceAll(dirName, "\n", ""), err)
		return false
	}
	supportRetentionEvicted.Add(1)
	auditSystem("support.bundle.expire", dirName, reason)
	return true
}

// pruneSupportBundlesByAge evicts persisted bundles whose manifest CreatedAt is
// older than maxAge. The count-based prune runs ONLY on a new build, so this is
// what protects an IDLE appliance from accumulating stale bundles on disk. now is
// injected for deterministic tests. FAIL-SAFE: a bundle whose CreatedAt is
// absent/unparseable is KEPT (a parse failure must never trigger an eviction).
// Best-effort: an eviction failure is logged and skipped, never fatal.
func pruneSupportBundlesByAge(now time.Time, maxAge time.Duration) {
	if maxAge <= 0 {
		return
	}
	supportPruneMu.Lock()
	defer supportPruneMu.Unlock()

	// Record that a real sweep ran (observability), regardless of how many — if
	// any — bundles it evicts. now is injected, so this is deterministic in tests.
	supportRetentionLastSweep.Store(now.Unix())
	sums := listSupportBundles()
	for i := range sums {
		s := &sums[i]
		if retentionEvidence(s) {
			continue // case-bound evidence never ages out
		}
		created, err := time.Parse(time.RFC3339, s.CreatedAt)
		if err != nil {
			continue // fail-safe: unparseable/absent timestamp ⇒ keep
		}
		if now.Sub(created) <= maxAge {
			continue
		}
		evictBundleDir(s.dirName, "retention max-age")
	}
}

// pruneSupportBundlesBySize reclaims oldest-first over EVICTABLE (non-evidence) bundles
// until the total store is under maxBytes. Backstops the count/age caps, which can't
// bound total size; without it a store of large bundles wedges the diagnostic path
// (the supportMinFreeBytes preflight only refuses new builds, never reclaims). Evidence
// (case-bound) bundles are exempt — if the store is over the ceiling with only evidence,
// nothing is reclaimed (an operator must unbind/delete manually; logged once).
// exceptDir (may be "") is a bundle the caller must never evict — the create path
// passes the bundle it just built so a store already over-cap from case-bound
// evidence can't delete the freshly-created bundle before returning its id.
func pruneSupportBundlesBySize(maxBytes int64, exceptDir string) {
	if maxBytes <= 0 {
		return
	}
	supportPruneMu.Lock()
	defer supportPruneMu.Unlock()

	sums := listSupportBundles() // newest-first
	var total int64
	for i := range sums {
		total += sums[i].SizeBytes
	}
	if total <= maxBytes {
		return
	}
	// Evict oldest-first (walk from the tail) over evictable bundles until under cap.
	for i := len(sums) - 1; i >= 0 && total > maxBytes; i-- {
		s := &sums[i]
		if retentionEvidence(s) || s.dirName == exceptDir {
			continue // evidence (and the just-created bundle) are never size-reclaimed
		}
		// Only credit the reclaim if the removal actually succeeded — otherwise the
		// loop could stop under the cap while the files are still on disk.
		if evictBundleDir(s.dirName, "retention size-cap") {
			total -= s.SizeBytes
		}
	}
	if total > maxBytes {
		logger.Printf("support: store still over size cap (%d > %d bytes) after reclaiming all evictable bundles — remaining are case-bound evidence; manual cleanup required", total, maxBytes)
	}
}

// startSupportRetentionJanitor runs the age-based sweep once at boot and then on a
// fixed cadence, so an idle appliance still evicts stale bundles. Parented to ctx;
// it exits on shutdown.
func startSupportRetentionJanitor(ctx context.Context) {
	sweep := func() {
		pruneSupportBundlesByAge(time.Now(), supportRetentionMaxAge)
		pruneSupportBundlesBySize(supportMaxStoreBytes, "")
	}
	sweep()
	t := time.NewTicker(supportRetentionTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}

// runSupportBundleCommand is the `culvert --support-bundle <path>` recovery
// one-shot: it builds a minimal (L0) bundle headless — no server, no admin UI —
// and writes it to outPath. This is the "GUI is down" escape hatch (the endorsed
// GAP-MON-01 recovery path). Prints a short summary to stdout.
func runSupportBundleCommand(outPath string) error {
	res, err := buildSupportBundle(context.Background(), support.L0, "standard", "")
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
