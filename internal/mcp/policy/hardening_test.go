package policy

import "testing"

// These tests pin the review/hardening fixes: quarantine-on-disposition backstop,
// out-of-range enum rejection, nil-input fail-closed, required obligation flags,
// and the full-obligation snapshot hash.

// TestQuarantine_DispositionBackstop: a catalog-QUARANTINED tool (DispQuarantined
// with an unresolved DriftUnset, as the runtime emits) is a VALID tuple and the
// engine quarantines it — it must NOT be mis-decisioned as INVALID_INPUT.
func TestQuarantine_DispositionBackstop(t *testing.T) {
	in := gwInput()
	in.Tool.Disposition = DispQuarantined
	in.Tool.Drift = DriftUnset
	if err := in.Validate(DefaultLimits()); err != nil {
		t.Fatalf("catalog-quarantined tuple must validate: %v", err)
	}
	// Even under a broad ALLOW the disposition backstop quarantines it.
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionQuarantine || !d.HardOverride {
		t.Fatalf("quarantined disposition must quarantine, got %v override=%v", d.Action, d.HardOverride)
	}
	if d.Reason == ReasonInvalidInput {
		t.Fatal("quarantined tool must not be reported as invalid input")
	}
}

// TestValidate_RejectsOutOfRangeEnums: a hostile tuple with an out-of-range catalog
// enum must fail closed at validation, never slip past the hard-override switch.
func TestValidate_RejectsOutOfRangeEnums(t *testing.T) {
	lim := DefaultLimits()
	cases := []struct {
		name   string
		mutate func(*DecisionInput)
	}{
		{"disposition 255", func(in *DecisionInput) { in.Tool.Disposition = Disposition(255) }},
		{"drift 255", func(in *DecisionInput) { in.Tool.Drift = DriftClass(255) }},
		{"verification 255", func(in *DecisionInput) { in.Server.Verification = ServerVerification(255) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := gwInput()
			tc.mutate(&in)
			if err := in.Validate(lim); err == nil {
				t.Fatalf("out-of-range enum must be rejected: %s", tc.name)
			}
			// And end-to-end it fails closed (never an allow) under a broad ALLOW.
			broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
			d, _, err := NewEngine(lim).Evaluate(mustCompile(t, gwSnap(broad)), &in)
			if err == nil || d.IsAllowClass() {
				t.Fatalf("%s: out-of-range enum permitted: %v err=%v", tc.name, d.Action, err)
			}
		})
	}
}

// TestEvaluate_NilInputFailsClosed: a nil decision tuple must return a typed error
// and a fail-closed decision, never panic.
func TestEvaluate_NilInputFailsClosed(t *testing.T) {
	snap := mustCompile(t, gwSnap(""))
	d, _, err := NewEngine(DefaultLimits()).Evaluate(snap, nil)
	if err == nil {
		t.Fatal("nil input must return an error")
	}
	if d.Action != ActionDeny || d.IsAllowClass() {
		t.Fatalf("nil input must fail closed, got %v", d.Action)
	}
	if d.Reason != ReasonInvalidInput {
		t.Fatalf("nil input reason = %v, want INVALID_INPUT", d.Reason)
	}
}

// TestCompile_RequiresSecurityObligationFlags: the security-critical obligation
// flags mandated by the action model are required at compile time.
func TestCompile_RequiresSecurityObligationFlags(t *testing.T) {
	bad := []string{
		// ALLOW_FOR_SESSION without session_bound.
		`{"id":"R","priority":1,"action":"ALLOW_FOR_SESSION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"session":{"ttl_seconds":300,"max_calls":5,"revoke_required":true},"logging":"standard"}}`,
		// ALLOW_FOR_SESSION without revoke_required.
		`{"id":"R","priority":1,"action":"ALLOW_FOR_SESSION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"session":{"session_bound":true,"ttl_seconds":300,"max_calls":5},"logging":"standard"}}`,
		// ALLOW_WITH_REDACTION without transformed_hash_required.
		`{"id":"R","priority":1,"action":"ALLOW_WITH_REDACTION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"redaction":{"profile_ref":"r1"},"logging":"standard"}}`,
	}
	for i, rule := range bad {
		if _, err := Compile([]byte(gwSnap(rule)), CreatedMeta{}, DefaultLimits()); err == nil {
			t.Fatalf("case %d: missing security obligation flag must fail compilation", i)
		}
	}
}

// TestHash_DistinguishesObligationPayload: two snapshots identical except for a
// session grant's TTL must hash differently (the hash carries the full payload, not
// just obligation IDs).
func TestHash_DistinguishesObligationPayload(t *testing.T) {
	mk := func(ttl int) string {
		return gwSnap(`{"id":"R","priority":1,"action":"ALLOW_FOR_SESSION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"session":{"session_bound":true,"ttl_seconds":` + itoaH(ttl) + `,"max_calls":5,"revoke_required":true},"logging":"standard"}}`)
	}
	a := mustCompile(t, mk(300))
	b := mustCompile(t, mk(3600))
	if a.Hash() == b.Hash() {
		t.Fatal("snapshots differing only in a session TTL must hash differently")
	}
}

func itoaH(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
