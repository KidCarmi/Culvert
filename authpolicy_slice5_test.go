package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// Phase 1 Slice 5 — AuthOutcome observability (no runtime wiring).
//
// Proves: (1) existing request logs are byte-identical when no auth decision is
// supplied; (2) populated auth fields serialize with the agreed low-cardinality
// keys; (3) the recordRequest call sites stay unchanged via the auth-aware core;
// (4) the metric is defined but not incremented by the request path; (5) no
// identity is carried for Exempt.

// ── Existing logs unchanged when auth fields are empty ───────────────────────

// findLogByHost scans the (newest-first) request log for an entry with the given
// host. It avoids len()-delta assertions, which are fragile under the determinism
// gate: the request-log ring is bounded at maxLogs and evicts the oldest entry
// once full, so a cumulative shuffled suite makes len() stop growing. A unique
// host per test is a stable discriminator the recent-entry scan can always find.
func findLogByHost(t *testing.T, host string) LogEntry {
	t.Helper()
	entries := logGet()
	for i := range entries { // index-based: LogEntry is large (avoids rangeValCopy)
		if entries[i].Host == host {
			return entries[i]
		}
	}
	t.Fatalf("no request-log entry found for host %q", host)
	return LogEntry{}
}

func TestSlice5_RecordRequest_NoAuthFields(t *testing.T) {
	const host = "slice5-noauth.example.test"
	recordRequest("198.51.100.7", "GET", host, "OK", "", "", "", "")
	e := findLogByHost(t, host)
	// Serialize and confirm none of the auth_* keys appear (byte-identical wire).
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(b)
	for _, key := range []string{
		"auth_outcome", "auth_policy_rule_id", "auth_policy_rule_name",
		"auth_subject_match_types", "auth_schema_version",
	} {
		if strings.Contains(out, key) {
			t.Errorf("recordRequest leaked auth key %q into wire output: %s", key, out)
		}
	}
	// The struct fields are zero.
	if e.AuthOutcome != "" || e.AuthPolicyRuleID != "" || e.AuthSubjectMatchTypes != nil || e.AuthSchemaVersion != 0 {
		t.Errorf("auth fields must be zero for a plain request: %+v", e)
	}
}

func TestSlice5_ZeroAuthLogFieldsAddNothing(t *testing.T) {
	e := LogEntry{TS: 1, Time: "00:00:00", IP: "1.2.3.4", Method: "GET", Host: "h", Status: "OK", Level: "INFO"}
	ref := e
	AuthLogFields{}.applyTo(&e)
	if !reflect.DeepEqual(e, ref) {
		t.Errorf("zero AuthLogFields must not mutate the entry:\n got %+v\nwant %+v", e, ref)
	}
}

// ── Populated auth fields serialization ──────────────────────────────────────

func TestSlice5_PopulatedAuthFieldsSerialize(t *testing.T) {
	e := LogEntry{TS: 1, Time: "00:00:00", IP: "10.0.5.7", Method: "GET", Host: "updates.example.com", Status: "OK", Level: "INFO"}
	AuthLogFields{
		Outcome:           OutcomeExempt,
		PolicyRuleID:      "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		PolicyRuleName:    "legacy-printer",
		SubjectMatchTypes: []string{"cidr"},
		SchemaVersion:     1,
	}.applyTo(&e)

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["auth_outcome"] != "Exempt" {
		t.Errorf("auth_outcome = %v, want Exempt", m["auth_outcome"])
	}
	if m["auth_policy_rule_id"] != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("auth_policy_rule_id = %v", m["auth_policy_rule_id"])
	}
	if m["auth_policy_rule_name"] != "legacy-printer" {
		t.Errorf("auth_policy_rule_name = %v", m["auth_policy_rule_name"])
	}
	if v, _ := m["auth_schema_version"].(float64); int(v) != 1 {
		t.Errorf("auth_schema_version = %v, want 1", m["auth_schema_version"])
	}
	types, ok := m["auth_subject_match_types"].([]any)
	if !ok || len(types) != 1 || types[0] != "cidr" {
		t.Errorf("auth_subject_match_types = %v, want [cidr]", m["auth_subject_match_types"])
	}
	// No identity must be present in the auth block (and none was supplied).
	if _, present := m["identity"]; present {
		t.Errorf("identity must not be logged for an Exempt decision: %s", b)
	}
}

// ── recordRequestBytesAuth populates the entry ───────────────────────────────

func TestSlice5_RecordRequestBytesAuth_PopulatesEntry(t *testing.T) {
	const host = "slice5-auth.example.test"
	recordRequestBytesAuth("10.0.5.9", "GET", host, "OK", "", "", "", 0, 0, "",
		AuthLogFields{Outcome: OutcomeExempt, PolicyRuleID: "RID", PolicyRuleName: "exempt-printer", SubjectMatchTypes: []string{"cidr"}, SchemaVersion: 1})
	e := findLogByHost(t, host)
	if e.AuthOutcome != "Exempt" || e.AuthPolicyRuleID != "RID" || e.AuthPolicyRuleName != "exempt-printer" {
		t.Errorf("auth fields not attached: %+v", e)
	}
	if e.Identity != "" {
		t.Errorf("identity must remain empty for an exempt log: %q", e.Identity)
	}
}

// ── authLogFieldsFor builder ─────────────────────────────────────────────────

func TestSlice5_AuthLogFieldsFor_Exempt(t *testing.T) {
	rule := &PolicyRule{
		ID:   "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Name: "legacy-printer",
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}},
		},
	}
	f := authLogFieldsFor(AuthDecision{Outcome: OutcomeExempt, Rule: rule})
	if f.Outcome != OutcomeExempt || f.PolicyRuleID != rule.ID || f.PolicyRuleName != rule.Name {
		t.Errorf("unexpected fields: %+v", f)
	}
	if f.SchemaVersion != 1 || len(f.SubjectMatchTypes) != 1 || f.SubjectMatchTypes[0] != "cidr" {
		t.Errorf("subject fields wrong: %+v", f)
	}
}

func TestSlice5_AuthLogFieldsFor_DefaultIsZero(t *testing.T) {
	if f := authLogFieldsFor(AuthDecision{Outcome: OutcomeDefault}); !reflect.DeepEqual(f, AuthLogFields{}) {
		t.Errorf("Default decision must yield zero AuthLogFields, got %+v", f)
	}
	// Exempt with a nil rule is also zero (defensive).
	if f := authLogFieldsFor(AuthDecision{Outcome: OutcomeExempt, Rule: nil}); !reflect.DeepEqual(f, AuthLogFields{}) {
		t.Errorf("Exempt+nil rule must yield zero AuthLogFields, got %+v", f)
	}
}

// Low cardinality: only predicate TYPE names are exposed, never the CIDR values.
func TestSlice5_SubjectMatchTypesLowCardinality(t *testing.T) {
	sm := &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
		{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24", "192.168.0.0/16"}},
	}}
	names := subjectPredicateTypeNames(sm)
	if len(names) != 1 || names[0] != "cidr" {
		t.Fatalf("want [cidr], got %v", names)
	}
	for _, n := range names {
		if strings.ContainsAny(n, "0123456789/.") {
			t.Errorf("predicate type name %q looks like a value (high-cardinality leak)", n)
		}
	}
	if subjectPredicateTypeNames(nil) != nil {
		t.Error("nil SubjectMatch must yield nil")
	}
}

// ── Metric: defined, but not incremented by the request path ─────────────────

func TestSlice5_AuthExemptMetric_DefinedNotIncrementedByRuntime(t *testing.T) {
	old := metricsToken
	metricsToken = ""
	t.Cleanup(func() { metricsToken = old })

	// The request-logging path must NOT touch the exempt counter.
	start := atomic.LoadInt64(&statAuthExempt)
	recordRequest("1.2.3.4", "GET", "example.com", "OK", "", "", "", "")
	recordRequestBytesAuth("10.0.5.9", "GET", "h", "OK", "", "", "", 0, 0, "",
		AuthLogFields{Outcome: OutcomeExempt, PolicyRuleID: "RID"})
	if got := atomic.LoadInt64(&statAuthExempt); got != start {
		t.Errorf("request path must not increment statAuthExempt: %d → %d", start, got)
	}

	// The metric is defined in the exposition.
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_auth_exempt_decisions_total counter",
		"culvert_auth_exempt_decisions_total ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestSlice5_IncAuthExemptBumpsCounter(t *testing.T) {
	start := atomic.LoadInt64(&statAuthExempt)
	incAuthExempt()
	t.Cleanup(func() { atomic.AddInt64(&statAuthExempt, -1) })
	if got := atomic.LoadInt64(&statAuthExempt); got != start+1 {
		t.Errorf("incAuthExempt: %d → %d, want +1", start, got)
	}
}
