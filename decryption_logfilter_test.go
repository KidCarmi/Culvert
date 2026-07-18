package main

import (
	"net/url"
	"testing"
)

// decryption_logfilter_test.go — ADR-0011 Phase 3a: the dec.* request-feed drill-down
// filter. buildLogFilterPredicate is shared by the in-memory ring and the history store,
// so these tests pin the predicate directly (both paths inherit the behavior).

func TestBuildLogFilterPredicate_DecFilters(t *testing.T) {
	inspected := &LogEntry{
		Host: "a.example",
		Dec:  &DecryptionBlock{Outcome: "inspected", DecisionSource: "policy_inspect", FailCategory: "none", ProfileID: "prof-1"},
	}
	failed := &LogEntry{
		Host: "b.example",
		Dec:  &DecryptionBlock{Outcome: "failed", DecisionSource: "no_fail_open_502", FailCategory: "certificate", ProfileID: "prof-2"},
	}
	noDec := &LogEntry{Host: "c.example"} // plain HTTP / no decryption decision — no dec block

	cases := []struct {
		name                              string
		q                                 url.Values
		wantInspected, wantFailed, wantNo bool
	}{
		{"no dec filter passes all", url.Values{}, true, true, true},
		{"dec_outcome=failed", url.Values{"dec_outcome": {"failed"}}, false, true, false},
		{"dec_outcome case-insensitive", url.Values{"dec_outcome": {"INSPECTED"}}, true, false, false},
		{"dec_decision_source", url.Values{"dec_decision_source": {"policy_inspect"}}, true, false, false},
		{"dec_fail_category", url.Values{"dec_fail_category": {"certificate"}}, false, true, false},
		{"dec_profile_id exact", url.Values{"dec_profile_id": {"prof-2"}}, false, true, false},
		{"dec_profile_id no partial", url.Values{"dec_profile_id": {"prof"}}, false, false, false},
		// no-dec records never match a dec.* filter, even an "absence-ish" query.
		{"dec_outcome=inspected excludes no-dec", url.Values{"dec_outcome": {"inspected"}}, true, false, false},
		// dec.* ANDs with existing filters: only the failed record is on b.example.
		{"dec + host AND", url.Values{"dec_outcome": {"failed"}, "filter": {"b.example"}}, false, true, false},
		{"dec + host AND misses", url.Values{"dec_outcome": {"failed"}, "filter": {"a.example"}}, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := buildLogFilterPredicate(c.q)
			if p(inspected) != c.wantInspected || p(failed) != c.wantFailed || p(noDec) != c.wantNo {
				t.Fatalf("got inspected=%v failed=%v noDec=%v; want %v/%v/%v",
					p(inspected), p(failed), p(noDec), c.wantInspected, c.wantFailed, c.wantNo)
			}
		})
	}
}
