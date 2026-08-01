package policy

import (
	"testing"
)

// TestProperty_Deterministic: the SAME (snapshot, input) always yields the SAME
// decision + trace, over many repetitions. Evaluation is a pure function.
func TestProperty_Deterministic(t *testing.T) {
	doc := gwSnap(`{"id":"R1","priority":1,"action":"MONITOR","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"prefix","value":"read_"}],"obligations":{"logging":"full"}},{"id":"R2","priority":2,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_access","conditions":[]}`)
	snap := mustCompile(t, doc)
	in := gwInput()
	e := NewEngine(DefaultLimits())
	first, firstTr, _ := e.Evaluate(snap, &in)
	for i := 0; i < 500; i++ {
		d, tr, err := e.Evaluate(snap, &in)
		if err != nil {
			t.Fatalf("iter %d: unexpected error %v", i, err)
		}
		if d.Action != first.Action || d.Reason != first.Reason || d.MatchedRule != first.MatchedRule {
			t.Fatalf("iter %d: non-deterministic decision %v/%v/%v != %v/%v/%v",
				i, d.Action, d.Reason, d.MatchedRule, first.Action, first.Reason, first.MatchedRule)
		}
		if tr.Winner != firstTr.Winner || tr.Final != firstTr.Final || len(tr.Entries) != len(firstTr.Entries) {
			t.Fatalf("iter %d: non-deterministic trace", i)
		}
	}
}

// TestProperty_InputNotMutated: Evaluate must not mutate the caller's input,
// including its slices and maps (deeply immutable contract).
func TestProperty_InputNotMutated(t *testing.T) {
	snap := mustCompile(t, gwSnap(`{"id":"R","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"principal.groups","op":"contains_any","values":["developers"]}],"obligations":{"logging":"standard"}}`))
	in := gwInput()
	in.Resource = &Resource{Type: "repo", ID: "r1", Tenant: "tenant-a", Attrs: map[string]string{"branch": "main"}}
	groupsBefore := append([]string(nil), in.Principal.Groups...)
	toolNameBefore, toolDriftBefore := in.Tool.Name, in.Tool.Drift
	attrsBefore := in.Resource.Attrs["branch"]

	e := NewEngine(DefaultLimits())
	d, _, _ := e.Evaluate(snap, &in)

	// The returned obligations must be a clone: mutating them cannot reach into the
	// snapshot's compiled rule.
	if len(d.Obligations.IDs()) > 0 {
		d.Obligations.Session = &SessionGrant{TTLSeconds: 9999, MaxCalls: 1}
	}
	if len(in.Principal.Groups) != len(groupsBefore) || in.Principal.Groups[0] != groupsBefore[0] {
		t.Fatal("principal groups mutated by evaluation")
	}
	if in.Tool.Name != toolNameBefore || in.Tool.Drift != toolDriftBefore {
		t.Fatal("tool mutated by evaluation")
	}
	if in.Resource.Attrs["branch"] != attrsBefore {
		t.Fatal("resource attrs mutated by evaluation")
	}
	// A second evaluation must still see the pristine rule/obligations.
	d2, _, _ := e.Evaluate(snap, &in)
	if d2.Action != ActionAllow {
		t.Fatalf("second eval changed after obligation mutation: %v", d2.Action)
	}
}

// TestProperty_SnapshotHashStableAcrossKeyOrder: logically identical documents that
// differ only in object key order and set-value order compile to the same hash and
// yield identical decisions.
func TestProperty_SnapshotHashStableAcrossKeyOrder(t *testing.T) {
	a := gwSnap(`{"id":"R","priority":5,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"principal.groups","op":"contains_any","values":["ops","developers","sre"]}],"obligations":{"logging":"standard"}}`)
	b := `{"policy_revision":1,"capability":"gateway","default_action":"DENY","schema_version":1,"rules":[{"priority":5,"reason":"MCP.POLICY.RESOURCE_SCOPE","action":"ALLOW","obligations":{"logging":"standard"},"remediation":"none","id":"R","conditions":[{"values":["sre","developers","ops"],"op":"contains_any","field":"principal.groups"}]}]}`
	sa, sb := mustCompile(t, a), mustCompile(t, b)
	if sa.Hash() != sb.Hash() {
		t.Fatalf("hash not order-independent: %s != %s", sa.Hash(), sb.Hash())
	}
	in := gwInput()
	da, _ := eval(t, sa, in)
	db, _ := eval(t, sb, in)
	if da.Action != db.Action || da.Reason != db.Reason {
		t.Fatalf("order-equivalent snapshots decided differently: %v != %v", da.Action, db.Action)
	}
}

// TestProperty_HardOverrideUnweakenable: for EVERY user rule action, a broad rule
// with that action can NEVER weaken a hard security override (unknown tool). The
// override wins and stays QUARANTINE regardless of what the rule tried to allow.
func TestProperty_HardOverrideUnweakenable(t *testing.T) {
	for _, act := range AllActions() {
		obl := allowClassObligation(act)
		rule := `{"id":"BROAD","priority":1,"action":"` + act.String() + `","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]` + obl + `}`
		// Management-illegal actions won't compile as gateway either? They compile for
		// gateway. Skip DENY reason/remediation nuance by using request_access for DENY.
		if act == ActionDeny {
			rule = `{"id":"BROAD","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_access","conditions":[]}`
		}
		snap, err := Compile([]byte(gwSnap(rule)), CreatedMeta{}, DefaultLimits())
		if err != nil {
			t.Fatalf("compile broad %s: %v", act, err)
		}
		in := gwInput()
		in.Tool.Drift = DriftUnknownTool
		in.Tool.Disposition = DispQuarantined
		d, _ := eval(t, snap, in)
		if d.Action != ActionQuarantine || d.Reason != ReasonToolUnknown || !d.HardOverride {
			t.Fatalf("broad %s weakened the unknown-tool override: got %v/%v override=%v",
				act, d.Action, d.Reason, d.HardOverride)
		}
	}
}

// TestProperty_NamespaceIsolation: a Gateway snapshot never evaluates a Management
// input and vice-versa — the capability mismatch fails closed with an error, never
// a cross-namespace match.
func TestProperty_NamespaceIsolation(t *testing.T) {
	gw := mustCompile(t, gwSnap(`{"id":"G","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`))
	mg := mustCompile(t, mgmtSnap(`{"id":"M","priority":1,"action":"ALLOW","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`))
	e := NewEngine(DefaultLimits())

	mgIn := mgmtInput()
	d, _, err := e.Evaluate(gw, &mgIn) // management input vs gateway snapshot
	if err == nil || d.Action != ActionDeny || d.Reason != ReasonCapabilityMismatch {
		t.Fatalf("management input on gateway snapshot must fail closed: %v/%v err=%v", d.Action, d.Reason, err)
	}
	gwIn := gwInput()
	d2, _, err2 := e.Evaluate(mg, &gwIn) // gateway input vs management snapshot
	if err2 == nil || d2.Action != ActionDeny || d2.Reason != ReasonCapabilityMismatch {
		t.Fatalf("gateway input on management snapshot must fail closed: %v/%v err=%v", d2.Action, d2.Reason, err2)
	}
}

// TestProperty_AlwaysFailsClosedOnError: whenever Evaluate returns an error, the
// decision is a non-permit (a caller that ignores the error still cannot execute).
func TestProperty_AlwaysFailsClosedOnError(t *testing.T) {
	e := NewEngine(DefaultLimits())
	// nil snapshot
	in := gwInput()
	if d, _, err := e.Evaluate(nil, &in); err == nil || d.IsAllowClass() {
		t.Fatalf("nil snapshot must fail closed: %v err=%v", d.Action, err)
	}
	// invalid input
	snap := mustCompile(t, gwSnap(""))
	bad := gwInput()
	bad.Principal.Tenant = ""
	if d, _, err := e.Evaluate(snap, &bad); err == nil || d.IsAllowClass() {
		t.Fatalf("invalid input must fail closed: %v err=%v", d.Action, err)
	}
	// capability mismatch
	mgIn := mgmtInput()
	if d, _, err := e.Evaluate(snap, &mgIn); err == nil || d.IsAllowClass() {
		t.Fatalf("capability mismatch must fail closed: %v err=%v", d.Action, err)
	}
}

// allowClassObligation returns a minimally-valid obligation JSON fragment for an
// action so a broad single-action rule compiles.
func allowClassObligation(a Action) string {
	switch a {
	case ActionAllowOnce:
		return `,"obligations":{"once_call":true,"logging":"standard"}`
	case ActionAllowForSession:
		return `,"obligations":{"session":{"ttl_seconds":300,"max_calls":5,"revoke_required":true},"logging":"standard"}`
	case ActionAllowWithRedaction:
		return `,"obligations":{"redaction":{"profile_ref":"r1","transformed_hash_required":true},"logging":"standard"}`
	case ActionRequireApproval:
		return `,"obligations":{"approval":true}`
	case ActionRequireConfirmation:
		return `,"obligations":{"confirmation":true}`
	case ActionMonitor:
		return `,"obligations":{"logging":"full"}`
	default: // ActionAllow, ActionQuarantine
		return `,"obligations":{"logging":"standard"}`
	}
}
