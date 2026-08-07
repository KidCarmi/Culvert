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

func (f *fakeReader) CommittedEvents(_, partition string, afterSeq uint64, maxN int) (events []evmodel.Event, seqs []uint64, next uint64, err error) {
	all := f.byPart[partition]
	next = afterSeq
	var seq uint64 // 1-based sequence; a counter avoids an int->uint64 conversion (gosec G115)
	for i := range all {
		seq++
		if seq <= afterSeq {
			continue
		}
		if len(events) >= maxN {
			break
		}
		events = append(events, all[i])
		seqs = append(seqs, seq)
		next = seq
	}
	return events, seqs, next, nil
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

// decEventRich builds an event that also populates the fields the PR-UX-3
// additive filters match against (client, fingerprint, execution state, snapshot
// hash, credential profile). These are real persisted event fields - the same
// ones ExplanationView projects - so an exact-match filter over them is truthful.
func decEventRich(tenant, id string, mut func(*evmodel.Event)) evmodel.Event {
	e := decEvent(tenant, id, "DENY", "MCP.POLICY.RESOURCE_SCOPE", "R-block")
	e.Identity.ClientID = "app-desktop"
	e.Identity.ToolFingerprint = "fp-aaaa"
	e.Decision.ExecutionState = "shadow_recorded"
	e.Decision.PolicySnapshotHash = "sha256:deadbeef"
	e.Credential.ProfileID = "cp-github-rw"
	if mut != nil {
		mut(&e)
	}
	return e
}

func decSvcRich() *DecisionService {
	r := &fakeReader{byPart: map[string][]evmodel.Event{
		partitionCrit: {
			decEventRich("acme", "evt-a", nil),
			decEventRich("acme", "evt-b", func(e *evmodel.Event) {
				e.Identity.ClientID = "app-mobile"
				e.Identity.ToolFingerprint = "fp-bbbb"
				e.Decision.ExecutionState = "executed"
				e.Decision.PolicySnapshotHash = "sha256:feedface"
				e.Credential.ProfileID = "cp-readonly"
			}),
		},
	}}
	return NewDecisionService(r, DefaultLimits())
}

// TestDecisions_SearchNewFilters proves every PR-UX-3 additive filter matches by
// exact equality against the persisted event and never widens the result set.
func TestDecisions_SearchNewFilters(t *testing.T) {
	s := decSvcRich()
	cases := []struct {
		name string
		f    DecisionFilter
		want string // sole expected event id
	}{
		{"client_id", DecisionFilter{ClientID: "app-desktop"}, "evt-a"},
		{"tool_fingerprint", DecisionFilter{ToolFingerprint: "fp-bbbb"}, "evt-b"},
		{"execution_state", DecisionFilter{ExecutionState: "executed"}, "evt-b"},
		{"policy_snapshot_hash", DecisionFilter{PolicySnapshotHash: "sha256:deadbeef"}, "evt-a"},
		{"credential_profile_ref", DecisionFilter{CredentialProfileRef: "cp-readonly"}, "evt-b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := s.Search("gateway", "acme", "", 100, c.f)
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			if len(res.Decisions) != 1 || res.Decisions[0].EventID != c.want {
				t.Fatalf("%s filter: want sole %s, got %+v", c.name, c.want, res.Decisions)
			}
		})
	}
}

// TestDecisions_SearchFilterCombination proves filters are AND-ed: a combination
// that no single event satisfies returns nothing (no widening).
func TestDecisions_SearchFilterCombination(t *testing.T) {
	s := decSvcRich()
	// evt-a has client app-desktop but execution shadow_recorded; asking for
	// app-desktop AND executed matches neither event.
	res, err := s.Search("gateway", "acme", "", 100, DecisionFilter{ClientID: "app-desktop", ExecutionState: "executed"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Decisions) != 0 {
		t.Fatalf("AND of non-co-occurring filters must be empty, got %+v", res.Decisions)
	}
	// The consistent pair on evt-b matches exactly one.
	res, _ = s.Search("gateway", "acme", "", 100, DecisionFilter{ClientID: "app-mobile", ExecutionState: "executed"})
	if len(res.Decisions) != 1 || res.Decisions[0].EventID != "evt-b" {
		t.Fatalf("consistent AND should match evt-b, got %+v", res.Decisions)
	}
}

// TestDecisions_SearchFilterEmptyResult proves a well-formed filter that matches
// nothing returns an empty page and no error (not a 400).
func TestDecisions_SearchFilterEmptyResult(t *testing.T) {
	s := decSvcRich()
	res, err := s.Search("gateway", "acme", "", 100, DecisionFilter{ClientID: "app-nonexistent"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Decisions) != 0 || res.NextCursor != "" {
		t.Fatalf("no-match filter must be empty with no cursor, got %+v", res)
	}
}

// TestDecisions_FilterValueTooLong proves an oversized filter value is rejected
// with a request-invalid (HTTP 400) error rather than silently matching nothing.
func TestDecisions_FilterValueTooLong(t *testing.T) {
	s := decSvcRich()
	huge := strings.Repeat("x", maxFilterValueLen+1)
	for _, f := range []DecisionFilter{
		{PrincipalID: huge}, {ClientID: huge}, {ToolFingerprint: huge},
		{PolicySnapshotHash: huge}, {CredentialProfileRef: huge},
	} {
		if _, err := s.Search("gateway", "acme", "", 10, f); mcperr.ReasonOf(err) != mcperr.ReasonAdminRequestInvalid {
			t.Fatalf("oversized filter must be request-invalid, got %v", err)
		}
	}
	// A value exactly at the bound is accepted (boundary is inclusive).
	atBound := DecisionFilter{ClientID: strings.Repeat("x", maxFilterValueLen)}
	if _, err := s.Search("gateway", "acme", "", 10, atBound); err != nil {
		t.Fatalf("value at the length bound must be accepted, got %v", err)
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
