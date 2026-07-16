package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

// Support-bundle admin API (M1 Slice 1). Two routes, registered with plain paths
// and method-dispatched in-handler (repo convention):
//
//	POST /api/support/bundles       — create a redacted csb/1 bundle (admin)
//	GET  /api/support/bundles/{id}   — download a created bundle (operator)
func registerSupportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/support/status", apiSupportStatus)
	mux.HandleFunc("/api/support/bundles", apiSupportBundles)
	mux.HandleFunc("/api/support/bundles/{id}", apiSupportBundleItem)
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
	})
}

// supportBundleIDRe pins the deterministic bundle-id shape so a path segment can
// never traverse out of the bundles dir.
var supportBundleIDRe = regexp.MustCompile(`^csb_[a-z2-7]{26}$`)

func supportBundlesDir() string { return filepath.Join(dataDir, "support", "bundles") }

// apiSupportBundles creates a bundle. Requesting a bundle is admin-gated: a
// standard bundle can contain INTERNAL sections (COLLECTOR-CONTRACT §4).
func apiSupportBundles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	res, err := createSupportBundle(r.Context())
	if err != nil {
		logger.Printf("support: bundle build failed: %v", err)
		http.Error(w, "bundle build failed", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "support.bundle.create", res.BundleID, support.BundleFormat)
	jsonOK(w, res.Manifest)
}

// apiSupportBundleItem downloads a created bundle by id (operator+).
func apiSupportBundleItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	f, err := os.Open(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"))
	if err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id+".csb.tgz"))
	_, _ = io.Copy(w, f)
}

// buildSupportBundle runs the engine over the registered collectors at the given
// level. No model or network is in the path; the bundle is redacted at source.
func buildSupportBundle(ctx context.Context, level support.DebugLevel) (*support.BuildResult, error) {
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
		Level:         level,
		Profile:       "default",
		IncidentScope: "standard",
		Nonce:         hex.EncodeToString(nonce),
		Clock:         time.Now,
	})
}

// createSupportBundle builds a standard (L1) bundle and persists it under
// <dataDir>/support/bundles/<id>/.
func createSupportBundle(ctx context.Context) (*support.BuildResult, error) {
	res, err := buildSupportBundle(ctx, support.L1)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(supportBundlesDir(), res.BundleID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir bundle dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.csb.tgz"), res.TarGz, 0o600); err != nil {
		return nil, fmt.Errorf("write bundle: %w", err)
	}
	manifestJSON, err := json.MarshalIndent(res.Manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestJSON, 0o600); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	return res, nil
}

// runSupportBundleCommand is the `culvert --support-bundle <path>` recovery
// one-shot: it builds a minimal (L0) bundle headless — no server, no admin UI —
// and writes it to outPath. This is the "GUI is down" escape hatch (the endorsed
// GAP-MON-01 recovery path). Prints a short summary to stdout.
func runSupportBundleCommand(outPath string) error {
	res, err := buildSupportBundle(context.Background(), support.L0)
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
