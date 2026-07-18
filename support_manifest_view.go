package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/support"
)

// Bundle manifest view (M5). apiSupportBundleManifest returns a bundle's manifest
// metadata (GET, viewer) so an operator/TAC can inspect the section inventory,
// sizes, data classes, collection outcome, and integrity anchor WITHOUT
// downloading the tarball — distinct from the counts-only redaction report and
// from validate (which re-derives hashes). The manifest is secret-free by
// construction (metadata + counts + hashes, never values); this reads it verbatim
// from disk.
func apiSupportBundleManifest(w http.ResponseWriter, r *http.Request) {
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
	b, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, "manifest.json"))
	if err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}
	var man support.SupportBundleManifest
	if err := json.Unmarshal(b, &man); err != nil {
		http.Error(w, "manifest unreadable", http.StatusInternalServerError)
		return
	}
	jsonOK(w, man)
}
