package adminapi

import (
	"encoding/json"
	"strings"
	"testing"

	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// fakeReader serves committed events per (capability, partition).
type fakeReader struct {
	byPart map[string][]evmodel.Event
}

func (f *fakeReader) CommittedEvents(_, partition string, afterSeq uint64, max int) ([]evmodel.Event, []uint64, uint64, error) {
	all := f.byPart[partition]
	var (
		evs  []evmodel.Event
		seqs []uint64
	)
	next := afterSeq
	for i := range all {
		seq := uint64(i + 1)
		if seq <= afterSeq {
			continue
		}
		if len(evs) >= max {
			break
		}
		evs = append(evs, all[i])
		seqs = append(seqs, seq)
		next = seq
	}
	return evs, seqs, next, nil
}

func decEvent(tenant, id, action, reason, rule string) evmodel.Event {
	return evmodel.Event{
		SchemaVersion: evmodel.SchemaVersion, EventID: id, Phase: evmodel.PhaseDecision,
		Capability: evmodel.CapGateway, TimeUnixNano: 100,
		Identity: evmodel.IdentityEvidence{Tenant: tenant, PrincipalID: "u", PrincipalType: "human", ServerID: "s1", ToolName: "t1"},
		Decision: evmodel.DecisionEvidence{Action: action, ReasonCode: reason, MatchedRuleID: rule, PolicyRevision: 4, CatalogRevision: 2},
	}
}

func decSvc() *DecisionService {
	r := &fakeReader{byPart: map[string][]evmodel.Event{
		partitionCrit: {
			decEvent("acme", "evt-1", "DENY", "MCP.POLICY.RESOURCE_SCOPE", "R-block"),
			decEvent("globex", "evt-2", "ALLOW", "MCP.POLICY.OK", "R-allow"),
		},
		partitionOrd: {
			decEvent("acme", "evt-3", "MONITOR", "MCP.POLICY.OK", "R-mon"),
		},
	}}
	return NewDecisionService(r, DefaultLimits())
}

func TestDecisions_ExplainHistoricalFromEvidence(t *testing.T) {
	s := decSvc()
	ex, err := s.Explain("gateway", "acme", "evt-1")
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	// Comes straight from the committed event, not a re-evaluation.
	if ex.Source != "historical" {
		t.Fatalf("explanation must be historical, got %q", ex.Source)
	}
	if ex.Action != "DENY" || ex.ReasonCode != "MCP.POLICY.RESOURCE_SCOPE" || ex.MatchedRuleID != "R-block" {
		t.Fatalf("explanation did not reflect persisted evidence: %+v", ex)
	}
	if ex.PolicyRevision != 4 || ex.CatalogRevision != 2 {
		t.Fatalf("historical revisions not preserved: %+v", ex)
	}
}

func TestDecisions_ExplainCrossTenantNotFound(t *testing.T) {
	s := decSvc()
	if _, err := s.Explain("gateway", "acme", "evt-2"); mcperr.ReasonOf(err) != mcperr.ReasonAdminNotFound {
		t.Fatalf("cross-tenant explain must be not_found, got %v", err)
	}
}

func TestDecisions_SearchTenantIsolation(t *testing.T) {
	s := decSvc()
	res, err := s.Search("gateway", "acme", "", 100, DecisionFilter{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Decisions) != 2 {
		t.Fatalf("acme should see its 2 events, got %d", len(res.Decisions))
	}
	for _, d := range res.Decisions {
		if d.Tenant != "acme" {
			t.Fatalf("cross-tenant event leaked: %s", d.EventID)
		}
	}
}

func TestDecisions_SearchFilter(t *testing.T) {
	s := decSvc()
	res, _ := s.Search("gateway", "acme", "", 100, DecisionFilter{Action: "DENY"})
	if len(res.Decisions) != 1 || res.Decisions[0].EventID != "evt-1" {
		t.Fatalf("action filter wrong: %+v", res.Decisions)
	}
}

func TestDecisions_SearchCursorPagination(t *testing.T) {
	s := decSvc()
	p1, err := s.Search("gateway", "acme", "", 1, DecisionFilter{})
	if err != nil {
		t.Fatalf("Search p1: %v", err)
	}
	if len(p1.Decisions) != 1 || p1.NextCursor == "" {
		t.Fatalf("first page should have 1 + a cursor: %+v", p1)
	}
	p2, err := s.Search("gateway", "acme", p1.NextCursor, 100, DecisionFilter{})
	if err != nil {
		t.Fatalf("Search p2: %v", err)
	}
	if len(p2.Decisions) != 1 || p2.Decisions[0].EventID == p1.Decisions[0].EventID {
		t.Fatalf("second page should continue past the first: %+v", p2)
	}
}

func TestDecisions_RangeValidation(t *testing.T) {
	s := decSvc()
	f := DecisionFilter{StartUnixNano: 1000, EndUnixNano: 10}
	if _, err := s.Search("gateway", "acme", "", 10, f); mcperr.ReasonOf(err) != mcperr.ReasonAdminRequestInvalid {
		t.Fatalf("end-before-start must be rejected, got %v", err)
	}
}

func TestDecisions_TenantRequired(t *testing.T) {
	s := decSvc()
	if _, err := s.Search("gateway", "", "", 10, DecisionFilter{}); mcperr.ReasonOf(err) != mcperr.ReasonAdminTenantScope {
		t.Fatalf("empty tenant must be rejected, got %v", err)
	}
}

// TestDecisions_NoSecretFields proves the serialized explanation carries no
// argument/output/secret/token key, by construction.
func TestDecisions_NoSecretFields(t *testing.T) {
	s := decSvc()
	ex, _ := s.Explain("gateway", "acme", "evt-1")
	b, _ := json.Marshal(ex)
	blob := strings.ToLower(string(b))
	for _, banned := range []string{"argument", "\"output\"", "secret", "token", "password", "private_key", "query_string", "provider_error"} {
		if strings.Contains(blob, banned) {
			t.Fatalf("explanation JSON contains forbidden key %q: %s", banned, blob)
		}
	}
}
