package main

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// ─── The differential oracle ─────────────────────────────────────────────────
//
// The packed prefilter (policy_scanindex.go) is only safe because a row can
// prove a MISMATCH and nothing else. These tests pin that property against the
// real evaluator rather than against a restatement of the packing rules, so a
// future change to MatchFQDNNorm's branches, to normFQDN's precomputation or to
// the row layout fails here instead of silently changing an access decision.

// scanIndexFQDNShapes returns FQDN patterns covering every branch
// hostutil.MatchFQDNNorm takes, plus the shapes that sit on the prefilter's
// boundaries (same length as the probe host, shared 8-byte tail, shorter than
// the tail window, bare "*", bare "*.").
func scanIndexFQDNShapes() []string {
	return []string{
		"", // no destination scope at all
		"*",
		"*.",
		"*.example.com",
		"*.com",
		"*.a",
		"example.com",
		"target.example.com",
		"TARGET.EXAMPLE.COM",
		"target.example.co",
		"target.example.comm",
		"other.example.com",
		"arget.example.com",
		"t.example.com",
		"com",
		"m",
		"a",
		"xample.com",
		"sub.target.example.com",
		"target.example.com.",
		"no-match-1.example.invalid",
		"très-bien.example.com",
		"xn--trs-bien-j4a.example.com",
		"192.0.2.10",
		"[2001:db8::1]",
	}
}

// scanIndexProbeHosts returns the destination hosts the oracle drives, chosen
// to straddle every boundary above (shorter/equal/longer than the patterns,
// shared and unshared tails, empty, trailing dot, IDNA, IP literal).
func scanIndexProbeHosts() []string {
	return []string{
		"",
		"a",
		"m",
		"com",
		"example.com",
		"target.example.com",
		"TARGET.example.com",
		"target.example.com.",
		"target.example.co",
		"target.example.comm",
		"sub.target.example.com",
		"deep.sub.target.example.com",
		"other.example.org",
		"très-bien.example.com",
		"192.0.2.10",
		"2001:db8::1",
		strings.Repeat("x", 200) + ".example.com",
	}
}

// TestPolicyScanIndex_RowNeverRejectsAMatch is the core implication, checked
// directly against hostutil.MatchFQDNNorm: for every pattern shape and every
// probe host, a row that says "reject" must be describing a host the real
// matcher also refuses. A row that declines to reject is always acceptable —
// the scan then runs the full predicate — so only one direction is a defect.
func TestPolicyScanIndex_RowNeverRejectsAMatch(t *testing.T) {
	rejected, allowedThrough := 0, 0
	for _, pattern := range scanIndexFQDNShapes() {
		rule := &PolicyRule{DestFQDN: pattern}
		if pattern != "" {
			rule.normFQDN = normalizeHost(pattern)
		}
		row := policyScanRowFor(rule)
		for _, host := range scanIndexProbeHosts() {
			normHost := normalizeHost(host)
			hostTail := packHostTail(normHost)
			got := row.rejects(len(normHost), hostTail)
			// The predicate the scan would run for this rule, verbatim.
			want := rule.normFQDN != "" && hostutil.MatchFQDNNorm(rule.normFQDN, normHost)
			if got {
				rejected++
				if want {
					t.Errorf("row for DestFQDN=%q rejected host %q (norm %q) that MatchFQDNNorm MATCHES:\n"+
						"  row = {tail:%#x minLen:%d}\n"+
						"  the prefilter must only ever prove a mismatch", pattern, host, normHost,
						row.tail, row.minLen)
				}
			} else {
				allowedThrough++
			}
		}
	}
	// Non-vacuity: the matrix must actually exercise both outcomes, or the
	// assertion above proves nothing.
	if rejected == 0 {
		t.Fatalf("no row rejected any host — the matrix exercises nothing")
	}
	if allowedThrough == 0 {
		t.Fatalf("every row rejected every host — the matrix exercises nothing")
	}
	t.Logf("matrix: %d rejections proven, %d pairs passed through to the full predicate", rejected, allowedThrough)
}

// TestPolicyScanIndex_DifferentialOracle drives the REAL evaluator core twice
// over randomized rulebases — once with the published index and once with none
// — and requires the selected rule to be identical. This is the assertion that
// matters: the index may not change which rule a request matches, at any rule
// count, for any mixture of rule shapes.
func TestPolicyScanIndex_DifferentialOracle(t *testing.T) {
	setupProxyTest(t)

	rng := rand.New(rand.NewSource(0xC0FFEE)) //nolint:gosec // deterministic test corpus, not security
	patterns := scanIndexFQDNShapes()
	hosts := scanIndexProbeHosts()
	actions := []PolicyAction{ActionAllow, ActionBlockPage, ActionDrop}

	for _, size := range []int{1, 3, 17, 64, 257} {
		rules := make([]PolicyRule, size)
		for i := range rules {
			enabled := rng.Intn(10) != 0 // ~10% disabled
			rules[i] = PolicyRule{
				Priority: i + 1,
				Name:     fmt.Sprintf("r%d", i),
				DestFQDN: patterns[rng.Intn(len(patterns))],
				Action:   actions[rng.Intn(len(actions))],
				Enabled:  &enabled,
			}
			switch rng.Intn(6) {
			case 0: // a source-scoped rule, so the scan is not dest-only
				rules[i].SourceIP = "203.0.113.0/24"
			case 1: // a category-scoped rule: no suffix anchor, so no prefilter
				rules[i].DestCategory = "social-media"
			case 2: // a scheduled rule
				rules[i].Schedule = &PolicySchedule{Timezone: "UTC"}
			}
		}
		ps := &PolicyStore{}
		ps.ReplaceAll(rules)
		snap := ps.evaluationSnapshot()
		rows := scanIndexFor(&ps.scanIndex, snap)
		// rows may legitimately be nil when no rule in the revision carries a
		// prefilterable FQDN (see buildPolicyScanRows); the comparison below is
		// the assertion either way.
		if rows != nil && len(rows) != len(snap) {
			t.Fatalf("size=%d: index length %d does not describe %d rules", size, len(rows), len(snap))
		}
		for _, host := range hosts {
			for _, clientIP := range []string{"203.0.113.7", "198.51.100.9"} {
				in := accessEvalInput{
					clientIP:   clientIP,
					authSource: "unauth",
					host:       host,
					normHost:   normalizeHost(host),
				}
				now := func() time.Time { return time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC) }
				withIndex := evalAccessRules(snap, rows, &in, now, nil)
				noIndex := evalAccessRules(snap, nil, &in, now, nil)
				if withIndex != noIndex {
					t.Fatalf("size=%d host=%q ip=%s: the index changed the decision\n  with index: %s\n  without:    %s",
						size, host, clientIP, describeOracleRule(withIndex), describeOracleRule(noIndex))
				}
			}
		}
	}
}

func describeOracleRule(r *PolicyRule) string {
	if r == nil {
		return "<no match>"
	}
	return fmt.Sprintf("priority=%d name=%q destFQDN=%q action=%s", r.Priority, r.Name, r.DestFQDN, r.Action)
}

// TestPolicyScanIndex_NegativeControl is the differential oracle's companion:
// it proves the oracle can FAIL. A deliberately over-eager row (one that
// rejects every host) must be caught as a changed decision, so a future
// regression in the packing rules cannot slip past the test above because the
// comparison is vacuous.
func TestPolicyScanIndex_NegativeControl(t *testing.T) {
	setupProxyTest(t)

	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "match", DestFQDN: "target.example.com", Action: ActionBlockPage}})
	snap := ps.evaluationSnapshot()
	in := accessEvalInput{clientIP: "203.0.113.7", authSource: "unauth", host: "target.example.com", normHost: "target.example.com"}

	if got := evalAccessRules(snap, nil, &in, time.Now, nil); got == nil {
		t.Fatalf("control: the rule must match without an index")
	}
	// A row that claims every host is too short — the shape a packing bug would
	// produce. The scan must consult it, so the match must disappear.
	bogus := []policyScanRow{{minLen: 1 << 20}}
	if got := evalAccessRules(snap, bogus, &in, time.Now, nil); got != nil {
		t.Fatalf("control: an over-eager row was IGNORED (%s) — the prefilter is not actually wired, "+
			"so TestPolicyScanIndex_DifferentialOracle proves nothing", describeOracleRule(got))
	}
}

// TestPolicyScanIndex_TraceKeepsEveryRuleAndReason pins the Policy Tester's
// contract: the trace path must visit every rule and report the ORIGINAL skip
// reason, which is why the prefilter is off whenever trace != nil. Without that
// guard a destination-mismatched rule would vanish from the trace entirely.
func TestPolicyScanIndex_TraceKeepsEveryRuleAndReason(t *testing.T) {
	setupProxyTest(t)

	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "far", DestFQDN: "nowhere.example.invalid", Action: ActionBlockPage},
		{Priority: 2, Name: "hit", DestFQDN: "target.example.com", Action: ActionAllow},
	})
	snap := ps.evaluationSnapshot()
	rows := scanIndexFor(&ps.scanIndex, snap)
	in := accessEvalInput{clientIP: "203.0.113.7", authSource: "unauth", host: "target.example.com", normHost: "target.example.com"}

	var seen []string
	// Rows are passed even though a trace is supplied: the guard inside
	// evalAccessRules, not the caller, is what keeps the trace complete.
	matched := evalAccessRules(snap, rows, &in, time.Now, func(rule *PolicyRule, skip string) {
		seen = append(seen, fmt.Sprintf("%s:%s", rule.Name, skip))
	})
	if matched == nil || matched.Name != "hit" {
		t.Fatalf("trace path matched %s, want the rule named \"hit\"", describeOracleRule(matched))
	}
	want := []string{"far:" + accessSkipDest, "hit:"}
	if len(seen) != len(want) {
		t.Fatalf("trace visited %v, want %v (the prefilter must not shorten the trace)", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("trace[%d] = %q, want %q", i, seen[i], want[i])
		}
	}
}

// TestPolicyScanIndex_PairedByRevisionIdentity pins the drift guard: an index
// is only ever applied to the exact rule slice it was published for. A reader
// that paired rows with another revision by LENGTH would evaluate one
// revision's rules through another's prefilter.
func TestPolicyScanIndex_PairedByRevisionIdentity(t *testing.T) {
	setupProxyTest(t)

	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "a", DestFQDN: "a.example.com", Action: ActionAllow}})
	first := ps.evaluationSnapshot()
	if rows := scanIndexFor(&ps.scanIndex, first); len(rows) != 1 {
		t.Fatalf("no index published for the first revision (%d rows)", len(rows))
	}
	// A second revision of the SAME length. The old snapshot must no longer
	// resolve an index, and the new one must resolve its own.
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "b", DestFQDN: "b.example.org", Action: ActionBlockPage}})
	second := ps.evaluationSnapshot()
	if rows := scanIndexFor(&ps.scanIndex, first); rows != nil {
		t.Errorf("the superseded revision still resolved an index (%d rows) — rows must pair by slice identity", len(rows))
	}
	if rows := scanIndexFor(&ps.scanIndex, second); len(rows) != 1 {
		t.Fatalf("no index published for the second revision (%d rows)", len(rows))
	}
	// A store that never published anything resolves nothing, and the scan
	// falls back to the full predicate rather than to a wrong one.
	var fresh PolicyStore
	if rows := scanIndexFor(&fresh.scanIndex, second); rows != nil {
		t.Errorf("an unpublished store resolved %d rows", len(rows))
	}
}

// TestPolicyScanIndex_RowStaysSixteenBytes guards the whole point of the
// change. The row exists so the scan streams 16 bytes per rule instead of the
// 568-byte definition; a field added without thought would quietly give that
// back, and the benchmark gain with it.
func TestPolicyScanIndex_RowStaysSixteenBytes(t *testing.T) {
	const want = 16
	if got := int(unsafeSizeofScanRow()); got != want {
		t.Errorf("sizeof(policyScanRow) = %d, want %d.\n"+
			"The packed row's reason for existing is that the scan streams it instead of the %d-byte "+
			"PolicyRule. Re-measure BenchmarkPolicyEvaluate_NoMatch before widening it.",
			got, want, int(unsafeSizeofPolicyRule()))
	}
}

// TestPolicyScanIndex_UnprefilterableRevisionPublishesNoRows pins the cost
// decision in buildPolicyScanRows: a rulebase no row can reject from must not
// be charged for an index, because an armed prefilter would stream a row per
// rule and pack a host tail per evaluation to prove nothing.
func TestPolicyScanIndex_UnprefilterableRevisionPublishesNoRows(t *testing.T) {
	setupProxyTest(t)

	cases := []struct {
		name  string
		rules []PolicyRule
		want  int // expected row count; 0 means "no index"
	}{
		{"category only", []PolicyRule{
			{Priority: 1, Name: "cat", DestCategory: "social-media", Action: ActionBlockPage},
			{Priority: 2, Name: "cat2", DestCategory: "gambling", Action: ActionBlockPage},
		}, 0},
		{"source only", []PolicyRule{
			{Priority: 1, Name: "src", SourceIP: "203.0.113.0/24", Action: ActionAllow},
		}, 0},
		{"match-any wildcard only", []PolicyRule{
			{Priority: 1, Name: "any", DestFQDN: "*", Action: ActionAllow},
		}, 0},
		{"one prefilterable rule arms the revision", []PolicyRule{
			{Priority: 1, Name: "cat", DestCategory: "social-media", Action: ActionBlockPage},
			{Priority: 2, Name: "fqdn", DestFQDN: "example.com", Action: ActionAllow},
		}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := &PolicyStore{}
			ps.ReplaceAll(tc.rules)
			rows := scanIndexFor(&ps.scanIndex, ps.evaluationSnapshot())
			if len(rows) != tc.want {
				t.Errorf("published %d rows, want %d", len(rows), tc.want)
			}
		})
	}
}
