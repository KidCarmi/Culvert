package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/sealbox"
)

// TestApiSupportStatus_State asserts the status endpoint surfaces the subsystem's
// current state (retention window + recipient-registry size) alongside the static
// collector/scope inventory, and stays viewer-gated.
func TestApiSupportStatus_State(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// Register one recipient so recipient_count is exercised.
	pub, _, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := addSupportRecipient("tac", base64.StdEncoding.EncodeToString(pub[:]), ""); err != nil {
		t.Fatalf("add recipient: %v", err)
	}

	// POST → 405.
	pRec := httptest.NewRecorder()
	apiSupportStatus(pRec, roleReq(RoleViewer, http.MethodPost, "/api/support/status", nil))
	if pRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code=%d want 405", pRec.Code)
	}

	// Viewer GET → 200 with the enriched state.
	gRec := httptest.NewRecorder()
	apiSupportStatus(gRec, roleReq(RoleViewer, http.MethodGet, "/api/support/status", nil))
	if gRec.Code != http.StatusOK {
		t.Fatalf("viewer GET code=%d want 200 (body=%q)", gRec.Code, gRec.Body.String())
	}
	var st supportStatus
	if err := json.Unmarshal(gRec.Body.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if st.RetentionKeep != supportRetentionKeepVal() {
		t.Fatalf("retention_keep=%d want %d", st.RetentionKeep, supportRetentionKeepVal())
	}
	if st.RecipientMax != maxSupportRecipients {
		t.Fatalf("recipient_max=%d want %d", st.RecipientMax, maxSupportRecipients)
	}
	if st.RecipientCount != 1 {
		t.Fatalf("recipient_count=%d want 1", st.RecipientCount)
	}
	if len(st.Collectors) == 0 || len(st.Scopes) == 0 {
		t.Fatal("status should still carry the collector + scope inventory")
	}
}
