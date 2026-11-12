package main

// A rule's SourceIP is documented as "single IP or CIDR". The CIDR form is
// parsed, so it decides on the ADDRESS. The single-IP form was compared as a
// STRING against the peer address Go prints, so it decided on the SPELLING: a
// rule written "2001:DB8::10" or "2001:0db8:0000:0000:0000:0000:0000:0010"
// never matched the client 2001:db8::10, while the same rule written
// "2001:DB8::10/128" did. Nothing on the write path validates or canonicalizes
// SourceIP, so the API accepted such a rule and it was silently inert — for a
// Drop rule that is the fail-open direction under first-match-wins.

import (
	"testing"
)

// evalSourceLiteral publishes a Drop rule scoped to sourceIP above an
// allow-everything rule, through the real mutator, and returns the name of the
// rule the enforcement entry point selects for clientIP.
func evalSourceLiteral(t *testing.T, sourceIP, clientIP string) string {
	t.Helper()
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "drop-client", SourceIP: sourceIP, Action: ActionDrop},
		{Priority: 2, Name: "allow-all", Action: ActionAllow},
	})
	m := ps.Evaluate(clientIP, "", "unauth", "example.com", nil)
	if m == nil {
		t.Fatalf("SourceIP=%q client=%q: no rule matched; allow-all must at least match", sourceIP, clientIP)
	}
	return m.Rule.Name
}

func TestPolicyEvaluate_SourceIPLiteralMatchesByAddressNotSpelling(t *testing.T) {
	cases := []struct {
		name     string
		sourceIP string
		clientIP string // as net.Conn.RemoteAddr prints it: canonical
		want     string
	}{
		// Control: the spelling Go prints already matched before the fix.
		{"canonical v6", "2001:db8::10", "2001:db8::10", "drop-client"},
		{"canonical v4", "10.0.0.5", "10.0.0.5", "drop-client"},
		// Control: the CIDR form of the same spellings always matched.
		{"uppercase v6 as /128", "2001:DB8::10/128", "2001:db8::10", "drop-client"},
		// The finding: the same ADDRESS in another valid spelling.
		{"uppercase v6", "2001:DB8::10", "2001:db8::10", "drop-client"},
		{"expanded v6", "2001:0db8:0000:0000:0000:0000:0000:0010", "2001:db8::10", "drop-client"},
		{"zero-run v6", "2001:db8:0:0::10", "2001:db8::10", "drop-client"},
		{"v4-mapped rule, v4 client", "::ffff:10.0.0.5", "10.0.0.5", "drop-client"},
		// Negative controls: a different address must still fall through.
		{"other v6 address", "2001:DB8::10", "2001:db8::11", "allow-all"},
		{"other v4 address", "::ffff:10.0.0.5", "10.0.0.6", "allow-all"},
		{"v4 literal is not a prefix", "10.0.0.5", "10.0.0.50", "allow-all"},
		// Unparseable literals keep the old string comparison: they match
		// nothing a real peer address can spell.
		{"padded literal stays inert", " 10.0.0.5", "10.0.0.5", "allow-all"},
		{"range syntax stays inert", "10.0.0.1-10.0.0.9", "10.0.0.5", "allow-all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalSourceLiteral(t, tc.sourceIP, tc.clientIP); got != tc.want {
				t.Errorf("SourceIP=%q client=%q: matched %q, want %q", tc.sourceIP, tc.clientIP, got, tc.want)
			}
		})
	}
}

// A zoned literal is not an address netip can compare without the zone, and
// net.ParseIP (the pre-existing client-side oracle) rejects it. It keeps the
// exact-string comparison it always had: same string matches, nothing else.
func TestPolicyEvaluate_SourceIPZonedLiteralKeepsStringCompare(t *testing.T) {
	if got := evalSourceLiteral(t, "fe80::1%eth0", "fe80::1%eth0"); got != "drop-client" {
		t.Errorf("identical zoned literal: matched %q, want drop-client", got)
	}
	if got := evalSourceLiteral(t, "fe80::1%eth0", "fe80::1"); got != "allow-all" {
		t.Errorf("zoned rule vs unzoned client: matched %q, want allow-all", got)
	}
	if got := evalSourceLiteral(t, "FE80::1", "fe80::1%eth0"); got != "allow-all" {
		t.Errorf("unzoned rule vs zoned client: matched %q, want allow-all", got)
	}
}

// The fallback for a rule that never went through the mutators (no precomputed
// state) must reach the same verdict as the published path.
func TestMatchSource_UnpublishedLiteralMatchesByAddress(t *testing.T) {
	rule := &PolicyRule{SourceIP: "2001:DB8::10"}
	if !matchSource(rule, "2001:db8::10", "", "", nil) {
		t.Error("unpublished rule: uppercase literal did not match the same address")
	}
	if matchSource(rule, "2001:db8::11", "", "", nil) {
		t.Error("unpublished rule: literal matched a different address")
	}
}
