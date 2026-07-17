package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/support"
)

// TestSupportBundleReport_RetainedPreviewGatedToApprover pins the Codex #788 P1
// fix: the retained free-form preview can carry a bare secret the precision-first
// scrubber cannot catch, so it is the APPROVER's backstop — a read-only viewer
// must get the counts-only report WITHOUT the retained values; only operator+
// (the approve/download role) receives retained_preview.
func TestSupportBundleReport_RetainedPreviewGatedToApprover(t *testing.T) {
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prevDir })

	res, err := createSupportBundle(context.Background(), "standard", support.L1, "")
	if err != nil {
		t.Fatalf("createSupportBundle: %v", err)
	}
	// Plant a retained free-form value in the SERVER-SIDE preview file (as if the
	// scrubber could not catch a bare secret typed into an INTERNAL field).
	secret := "bare-secret-Xy9qKp2mLw7zReview"
	pv := support.RedactionPreview{ModelVersion: 1, Sections: []support.RedactionPreviewSection{
		{ID: "cfg", RetainedFreeForm: []string{secret}},
	}}
	pb, _ := json.Marshal(pv)
	if err := os.WriteFile(filepath.Join(supportBundlesDir(), res.BundleID, support.RedactionPreviewName), pb, 0o600); err != nil {
		t.Fatalf("plant preview: %v", err)
	}

	// Viewer: 200 with the counts-only report, but NEVER the retained value.
	vreq, vrec := supportRoleReq(http.MethodGet, res.BundleID, RoleViewer)
	apiSupportBundleReport(vrec, vreq)
	if vrec.Code != http.StatusOK {
		t.Fatalf("viewer report code=%d, want 200", vrec.Code)
	}
	if strings.Contains(vrec.Body.String(), secret) {
		t.Fatalf("VIEWER received a retained free-form value (privilege escalation): %s", vrec.Body.String())
	}

	// Operator (the approver role): 200 WITH the retained value so the approval is sighted.
	oreq, orec := supportRoleReq(http.MethodGet, res.BundleID, RoleOperator)
	apiSupportBundleReport(orec, oreq)
	if orec.Code != http.StatusOK || !strings.Contains(orec.Body.String(), secret) {
		t.Fatalf("operator must receive retained_preview; code=%d body=%q", orec.Code, orec.Body.String())
	}
}

// TestSupportBundle_CaseIDInManifest pins the Codex #788 P2 fix: a case ID
// supplied at create time must be threaded into the runner so the PERSISTED
// manifest (and the downloaded tar) bind the evidence to the TAC case — not just
// the sidecar state. Empty when none was supplied.
func TestSupportBundle_CaseIDInManifest(t *testing.T) {
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prevDir })

	const caseID = "CASE-4242"
	res, err := createSupportBundle(context.Background(), "standard", support.L1, caseID)
	if err != nil {
		t.Fatalf("createSupportBundle: %v", err)
	}
	if res.Manifest.CaseID != caseID {
		t.Errorf("BuildResult manifest case_id = %q, want %q", res.Manifest.CaseID, caseID)
	}
	// And it is persisted in manifest.json (the offline/TAC binding).
	mb, err := os.ReadFile(filepath.Join(supportBundlesDir(), res.BundleID, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var man support.SupportBundleManifest
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if man.CaseID != caseID {
		t.Errorf("persisted manifest case_id = %q, want %q", man.CaseID, caseID)
	}

	// No case ID → empty (omitempty), not a stray binding.
	res2, err := createSupportBundle(context.Background(), "standard", support.L1, "")
	if err != nil {
		t.Fatalf("createSupportBundle (no case): %v", err)
	}
	if res2.Manifest.CaseID != "" {
		t.Errorf("no-case bundle manifest case_id = %q, want empty", res2.Manifest.CaseID)
	}
}
