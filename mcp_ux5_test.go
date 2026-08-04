package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp/publication"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// PR-UX-5 backend contracts for the truthful rollout / scope / fleet read models.
// These pin: the acknowledgement read model (truthful counts + rows, never
// fabricated), the not-configured (disabled-default) posture, the enriched scope
// summary, and the read-only candidate-scope validation + diff preview - all
// capability-scoped and never mutating.

func mcpAck(node, hash string, state cpdp.AckState, rejectReason string) cpdp.Acknowledgement {
	return cpdp.Acknowledgement{
		AckID: "ack-" + node, NodeID: node, Capability: cpdp.CapabilityGateway,
		ContentHash: hash, State: state, ActiveHash: hash, Health: "healthy",
		RejectReason: rejectReason, TimeUnixNano: 1,
	}
}

// TestMCPUX5_AckDTO_NotConfigured proves the honest disabled-default: with no
// acknowledgement source wired, the model is Configured=false, Counts=nil,
// distribution_state=local_only, and no rows - never a benign zero-as-healthy.
func TestMCPUX5_AckDTO_NotConfigured(t *testing.T) {
	dto := buildMCPAckDTO("gateway", nil, nil, "sha256:abc", 42)
	if dto.Configured {
		t.Fatal("nil ack source must report configured=false")
	}
	if dto.Counts != nil {
		t.Fatalf("not-configured must have nil counts (never fabricated zeros), got %+v", dto.Counts)
	}
	if dto.DistributionState != string(publication.StateLocalOnly) {
		t.Fatalf("distribution_state = %q, want local_only", dto.DistributionState)
	}
	if len(dto.Rows) != 0 || dto.Intended != 0 {
		t.Fatalf("not-configured must have no rows / intended=0, got rows=%d intended=%d", len(dto.Rows), dto.Intended)
	}
	if dto.AsOfUnixNano != 42 || dto.ContentHash != "sha256:abc" {
		t.Fatalf("as_of / content_hash not echoed truthfully: %+v", dto)
	}
}

// TestMCPUX5_AckDTO_RealTracker proves the counts and per-DP rows are derived from
// REAL acknowledgements: applied / rejected(incompatible) / rolled_back, and an
// intended node with NO ack renders "unavailable" (never a benign default).
func TestMCPUX5_AckDTO_RealTracker(t *testing.T) {
	hash := "sha256:deadbeef"
	tr := publication.NewAckTracker(cpdp.CapabilityGateway, cpdp.DefaultLimits())
	tr.MarkKnown(hash)
	incompatible := mcperr.ReasonSnapshotMinVersionUnmet.Code()
	must := func(err error) {
		if err != nil {
			t.Fatalf("record ack: %v", err)
		}
	}
	must(tr.Record("n1", mcpAck("n1", hash, cpdp.AckApplied, "")))
	must(tr.Record("n2", mcpAck("n2", hash, cpdp.AckRejected, incompatible)))
	must(tr.Record("n3", mcpAck("n3", hash, cpdp.AckRolledBack, "")))
	// n4 is intended but never acknowledged this hash ⇒ unavailable.
	intended := []string{"n1", "n2", "n3", "n4"}

	dto := buildMCPAckDTO("gateway", tr, intended, hash, 7)
	if !dto.Configured || dto.Counts == nil {
		t.Fatal("real tracker must report configured=true with counts")
	}
	c := *dto.Counts
	if c.Intended != 4 || c.Applied != 1 || c.Rejected != 1 || c.Incompatible != 1 || c.RolledBack != 1 || c.Unavailable != 1 {
		t.Fatalf("counts wrong: %+v", c)
	}
	if dto.DistributionState != string(publication.StateDistributionDegraded) {
		t.Fatalf("distribution_state = %q, want distribution_degraded", dto.DistributionState)
	}
	byNode := map[string]mcpAckRow{}
	for _, row := range dto.Rows {
		byNode[row.NodeID] = row
	}
	if byNode["n1"].State != "applied" {
		t.Fatalf("n1 row state = %q, want applied", byNode["n1"].State)
	}
	if byNode["n2"].State != "rejected" || !byNode["n2"].Incompatible {
		t.Fatalf("n2 row = %+v, want rejected+incompatible", byNode["n2"])
	}
	if byNode["n3"].State != "rolled_back" {
		t.Fatalf("n3 row state = %q, want rolled_back", byNode["n3"].State)
	}
	if byNode["n4"].State != "unavailable" {
		t.Fatalf("n4 (no ack) row state = %q, want unavailable", byNode["n4"].State)
	}
}

// TestMCPUX5_AckHandler proves the endpoint is viewer-readable, GET-only, and
// returns the truthful not-configured model in the shipped disabled-default.
func TestMCPUX5_AckHandler(t *testing.T) {
	rec := mcpReq(http.MethodGet, "/api/mcp/distribution/acks?capability=gateway", RoleViewer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET acks = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"configured":false`, `"distribution_state":"local_only"`, `"counts":null`, `"capability":"gateway"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("acks body missing %q: %s", want, body)
		}
	}
	if got := mcpReq(http.MethodPost, "/api/mcp/distribution/acks", RoleAdmin, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST acks = %d, want 405", got)
	}
	// Management capability is read-only visible and isolated.
	m := mcpReq(http.MethodGet, "/api/mcp/distribution/acks?capability=management", RoleViewer, "").Body.String()
	if !strings.Contains(m, `"capability":"management"`) {
		t.Fatalf("management acks not capability-bound: %s", m)
	}
}

// TestMCPUX5_ScopeGetEnriched proves the scope GET now returns the structured
// summary (kind / enumerable / counts / spec), not just a hash.
func TestMCPUX5_ScopeGetEnriched(t *testing.T) {
	rec := mcpReq(http.MethodGet, "/api/mcp/rollout/scope?capability=gateway", RoleViewer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET scope = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Disabled-default scope is empty ⇒ matches-nothing, not enumerable.
	for _, want := range []string{`"kind":"matches-nothing"`, `"matches_nothing":true`, `"enumerable":false`, `"selector_counts"`, `"exclusion_counts"`, `"spec"`, `"scope_hash"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("enriched scope body missing %q: %s", want, body)
		}
	}
}

// TestMCPUX5_ScopeValidate proves the candidate-scope preview: valid candidate ⇒
// valid:true + diff; an invalid candidate ⇒ valid:false + a classified error code;
// viewer-readable, POST-only, and capability-bound (never mutating).
func TestMCPUX5_ScopeValidate(t *testing.T) {
	// Valid candidate: a concrete inclusion selector (read-only, enumerable).
	rec := mcpReq(http.MethodPost, "/api/mcp/rollout/scope/validate?capability=gateway", RoleViewer, `{"scope":{"servers":["srv-1","srv-2"]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer POST validate = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"valid":true`, `"diff"`, `"candidate"`, `"current"`, `"capability":"gateway"`, `"enumerable":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("validate(valid) body missing %q: %s", want, body)
		}
	}
	// Invalid candidate: a write operation (RiskWrite=2) without high_risk ⇒ the
	// pure Compile rejects it with a classified code.
	inv := mcpReq(http.MethodPost, "/api/mcp/rollout/scope/validate?capability=gateway", RoleViewer, `{"scope":{"operations":[2]}}`).Body.String()
	if !strings.Contains(inv, `"valid":false`) || !strings.Contains(inv, `"error_code"`) {
		t.Fatalf("validate(invalid) must report valid:false + error_code: %s", inv)
	}
	// GET is not allowed.
	if got := mcpReq(http.MethodGet, "/api/mcp/rollout/scope/validate", RoleViewer, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET validate = %d, want 405", got)
	}
	// Capability binding: a management request validates as management regardless
	// of any capability embedded in the candidate body.
	mgmt := mcpReq(http.MethodPost, "/api/mcp/rollout/scope/validate?capability=management", RoleViewer, `{"scope":{"servers":["s"]}}`).Body.String()
	if !strings.Contains(mgmt, `"capability":"management"`) {
		t.Fatalf("validate must bind capability to management: %s", mgmt)
	}
}
