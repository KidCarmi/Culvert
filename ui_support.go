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
	mux.HandleFunc("/api/support/bundles", apiSupportBundles)
	mux.HandleFunc("/api/support/bundles/{id}", apiSupportBundleItem)
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

// createSupportBundle runs the engine over the registered collectors and persists
// the bundle under <dataDir>/support/bundles/<id>/. No model or network is in the
// path; the bundle is redacted at source by the engine.
func createSupportBundle(ctx context.Context) (*support.BuildResult, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	opts := support.BuildOptions{
		Version:   version,
		GoVersion: runtime.Version(),
		Runtime: support.RuntimeInfo{
			NodeID: clusterRole.nodeID, Role: clusterRole.role, Runtime: "unknown",
		},
		Level:         support.L1,
		Profile:       "default",
		IncidentScope: "standard",
		Nonce:         hex.EncodeToString(nonce),
		Clock:         time.Now,
	}
	res, err := support.NewRunner().Build(ctx, opts)
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
