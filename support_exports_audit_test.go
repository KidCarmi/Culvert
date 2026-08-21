package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

// exportTestSeq gives each test invocation a UNIQUE bundle id, so a rerun in the
// same process (e.g. the determinism gate's `-count=2`) does not accumulate the
// prior run's seeded events in the global audit ring (the CLAUDE.md audit-ring
// pitfall — never assert on a fixed id's cumulative count).
var exportTestSeq atomic.Int64

func uniqueExportBundleID(prefix string) string {
	return "csb_" + prefix + strconv.FormatInt(exportTestSeq.Add(1), 10)
}

// TestBundleExportEvents seeds export audit events for a UNIQUE bundle id and
// confirms the scan surfaces exactly those (actor/action), ignoring non-export
// actions and other bundles.
func TestBundleExportEvents(t *testing.T) {
	id := uniqueExportBundleID("exportaudit")
	other := uniqueExportBundleID("otherbundle")

	seed := func(action, object string) {
		r := roleReq(RoleOperator, http.MethodPost, "/seed", nil)
		r.RemoteAddr = "198.51.100.9:5555" // TEST-NET-2 discriminator
		auditEvent(r, action, object, "csb/1")
	}
	seed("support.bundle.download", id)
	seed("support.bundle.download_sealed", id)
	seed("support.bundle.delete", id)      // must be ignored (not an export)
	seed("support.bundle.download", other) // different bundle

	ev := bundleExportEvents(id)
	if len(ev) != 2 {
		t.Fatalf("got %d export events for %q, want 2: %+v", len(ev), id, ev)
	}
	for _, e := range ev {
		if e.Action != "support.bundle.download" && e.Action != "support.bundle.download_sealed" {
			t.Fatalf("unexpected action surfaced: %q", e.Action)
		}
		if e.Actor == "" || e.Time == "" {
			t.Fatalf("event missing actor/time: %+v", e)
		}
	}
}

// TestApiSupportBundleExports covers method/RBAC/id validation on the endpoint.
func TestApiSupportBundleExports(t *testing.T) {
	id := "csb_apiexports234567abcdefghij" // csb_ + 26 chars [a-z2-7]

	// POST → 405.
	pRec := httptest.NewRecorder()
	pr := roleReq(RoleViewer, http.MethodPost, "/api/support/bundles/"+id+"/exports", nil)
	pr.SetPathValue("id", id)
	apiSupportBundleExports(pRec, pr)
	if pRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code=%d want 405", pRec.Code)
	}
	// Bad id → 400.
	bRec := httptest.NewRecorder()
	br := roleReq(RoleViewer, http.MethodGet, "/api/support/bundles/bad/exports", nil)
	br.SetPathValue("id", "bad")
	apiSupportBundleExports(bRec, br)
	if bRec.Code != http.StatusBadRequest {
		t.Fatalf("bad id code=%d want 400", bRec.Code)
	}
	// Viewer GET → 200 with the expected envelope.
	gRec := httptest.NewRecorder()
	gr := roleReq(RoleViewer, http.MethodGet, "/api/support/bundles/"+id+"/exports", nil)
	gr.SetPathValue("id", id)
	apiSupportBundleExports(gRec, gr)
	if gRec.Code != http.StatusOK {
		t.Fatalf("viewer GET code=%d want 200 (body=%q)", gRec.Code, gRec.Body.String())
	}
	var body struct {
		BundleID string              `json:"bundle_id"`
		Exports  []bundleExportEvent `json:"exports"`
	}
	if err := json.Unmarshal(gRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.BundleID != id {
		t.Fatalf("bundle_id=%q want %q", body.BundleID, id)
	}
}
