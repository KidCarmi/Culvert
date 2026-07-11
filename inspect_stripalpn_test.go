package main

import (
	"encoding/json"
	"testing"
)

// TestResolveStripALPN_PresenceSemantics locks the C2 resolver contract:
// absent (nil) and explicit-true both strip (HTTP/1.1 downgrade); only an
// explicit false enables native H2. This is the guard that an upgrade never
// silently switches existing rules to native H2.
func TestResolveStripALPN_PresenceSemantics(t *testing.T) {
	tru := true
	fls := false
	cases := []struct {
		name string
		val  *bool
		want bool
	}{
		{"absent-nil-preFeature", nil, true},
		{"explicit-true", &tru, true},
		{"explicit-false-nativeH2", &fls, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &PolicyMatch{Rule: &PolicyRule{StripALPN: c.val}}
			if got := resolveStripALPN(m); got != c.want {
				t.Fatalf("resolveStripALPN(%v) = %v, want %v", c.val, got, c.want)
			}
		})
	}

	// nil match / nil rule must fail safe to strip.
	if !resolveStripALPN(nil) {
		t.Fatal("resolveStripALPN(nil) must strip (fail-safe to today's behavior)")
	}
	if !resolveStripALPN(&PolicyMatch{}) {
		t.Fatal("resolveStripALPN(match with nil Rule) must strip")
	}
}

// TestResolveStripALPN_PreFeatureRuleJSON pins the migration invariant: a rule
// deserialized from config that predates the StripALPN field (no stripAlpn key)
// resolves to strip=true — byte-for-byte current downgrade behavior on upgrade.
func TestResolveStripALPN_PreFeatureRuleJSON(t *testing.T) {
	const preFeature = `{"priority":1,"name":"legacy-inspect","destFQDN":"*","sslAction":"Inspect","action":"allow"}`
	var r PolicyRule
	if err := json.Unmarshal([]byte(preFeature), &r); err != nil {
		t.Fatalf("unmarshal pre-feature rule: %v", err)
	}
	if r.StripALPN != nil {
		t.Fatalf("pre-feature rule must deserialize StripALPN as nil, got %v", *r.StripALPN)
	}
	if !resolveStripALPN(&PolicyMatch{Rule: &r}) {
		t.Fatal("pre-feature rule must resolve to strip=true (no silent H2 switch on upgrade)")
	}
}

// TestStripALPN_JSONOmitempty confirms an unset field is omitted from the wire
// form (presence semantics survive a round-trip; absence stays absent).
func TestStripALPN_JSONOmitempty(t *testing.T) {
	r := PolicyRule{Priority: 1, Name: "x", SSLAction: SSLInspect, Action: ActionAllow}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(b); containsSubstr(got, "stripAlpn") {
		t.Fatalf("unset StripALPN must be omitted from JSON, got: %s", got)
	}
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
