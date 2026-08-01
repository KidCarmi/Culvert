package simulate

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

func testTime() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

// gwInput mirrors the policy package's well-formed Gateway tuple (the simulate
// package is a separate package, so it cannot use the policy test helpers).
func gwInput(tool string) policy.DecisionInput {
	return policy.DecisionInput{
		Capability: policy.CapGateway, PolicyRevision: 1, CatalogRevision: 7,
		RegistryRevision: 3, RuntimeRevision: 1, EvalTime: testTime(),
		Principal: policy.Principal{Kind: policy.SubjectHuman, SubjectID: "user-1", Tenant: "tenant-a",
			Groups: []string{"developers"}, Assurance: policy.AssuranceHigh, Issuer: "https://idp"},
		Client: policy.Client{ClientID: "client-g", Tenant: "tenant-a", Capability: policy.CapGateway, Trust: policy.TrustHigh},
		Server: &policy.Server{ServerID: "srv-1", Owner: "team", Environment: "prod",
			Enabled: true, Verification: policy.ServerVerified},
		Tool: &policy.Tool{Name: tool, ServerID: "srv-1", FingerprintHash: "abc123",
			Disposition: policy.DispUsable, Drift: policy.DriftNoMaterialChange, Destination: policy.DestinationApproved,
			CredentialPower: policy.PowerReadOnly, Reversibility: policy.Reversible},
		Operation: policy.Operation{Method: "tools/call", Class: policy.OpRead, Namespace: policy.NamespaceGatewayTool,
			Operand: tool, DecisionPoint: "policy_engine"},
	}
}

func gwSnap(t testing.TB, rules string) *policy.Snapshot {
	t.Helper()
	doc := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[` + rules + `]}`
	snap, err := policy.Compile([]byte(doc), policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, doc)
	}
	return snap
}

func gwSnapRev(t testing.TB, rev int, rules string) *policy.Snapshot {
	t.Helper()
	doc := `{"schema_version":1,"capability":"gateway","policy_revision":` +
		itoa(rev) + `,"default_action":"DENY","rules":[` + rules + `]}`
	snap, err := policy.Compile([]byte(doc), policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, doc)
	}
	return snap
}

func itoa(n int) string {
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

const allowRead = `{"id":"ALLOW_READ","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"exact","value":"read_file"}],"obligations":{"logging":"standard"}}`

// TestSingle_UsesSameEvaluator: the simulator's single result equals what the raw
// engine produces — there is no second evaluator.
func TestSingle_UsesSameEvaluator(t *testing.T) {
	snap := gwSnap(t, allowRead)
	in := gwInput("read_file")
	sim := New(policy.DefaultLimits())
	got := sim.Single(snap, &in)

	eng := policy.NewEngine(policy.DefaultLimits())
	want, wantTr, _ := eng.Evaluate(snap, &in)
	if got.Decision.Action != want.Action || got.Decision.Reason != want.Reason || got.Decision.MatchedRule != want.MatchedRule {
		t.Fatalf("simulator diverged from engine: %v vs %v", got.Decision.Action, want.Action)
	}
	if got.Trace.Winner != wantTr.Winner {
		t.Fatalf("simulator trace diverged: %v vs %v", got.Trace.Winner, wantTr.Winner)
	}
}

// TestSingle_NoSideEffects: simulating never mutates the snapshot or the input.
func TestSingle_NoSideEffects(t *testing.T) {
	snap := gwSnap(t, allowRead)
	hashBefore := snap.Hash()
	revBefore := snap.Revision()
	in := gwInput("read_file")
	toolBefore := in.Tool.Name

	sim := New(policy.DefaultLimits())
	for i := 0; i < 10; i++ {
		sim.Single(snap, &in)
	}
	if snap.Hash() != hashBefore || snap.Revision() != revBefore {
		t.Fatal("simulation mutated the snapshot")
	}
	if in.Tool.Name != toolBefore {
		t.Fatal("simulation mutated the input")
	}
}

// TestCorpus_Bounded: an over-limit corpus is rejected (no silent truncation).
func TestCorpus_Bounded(t *testing.T) {
	snap := gwSnap(t, allowRead)
	sim := New(policy.DefaultLimits())
	max := policy.DefaultLimits().MaxSimCases()
	cases := make([]Case, max+1)
	for i := range cases {
		cases[i] = Case{ID: itoa(i), Input: gwInput("read_file")}
	}
	if _, err := sim.Corpus(snap, cases); err == nil {
		t.Fatal("over-limit corpus must be rejected")
	}
	if res, err := sim.Corpus(snap, cases[:max]); err != nil || len(res) != max {
		t.Fatalf("at-limit corpus: err=%v len=%d", err, len(res))
	}
}

// TestCompare_NewAllowHighlighted: a proposed snapshot that newly permits a tool is
// flagged as a security-sensitive blast-radius change (NewAllow, NewAllowClass).
func TestCompare_NewAllowHighlighted(t *testing.T) {
	oldSnap := gwSnap(t, allowRead) // only read_file allowed
	newSnap := gwSnap(t, allowRead+`,{"id":"ALLOW_WRITE","priority":2,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"exact","value":"write_file"}],"obligations":{"logging":"standard"}}`)
	cases := []Case{
		{ID: "read", Input: gwInput("read_file")},   // unchanged (allowed both)
		{ID: "write", Input: gwInput("write_file")}, // newly allowed
	}
	sim := New(policy.DefaultLimits())
	cmp, err := sim.Compare(oldSnap, newSnap, cases)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if cmp.Total != 2 || cmp.Unchanged != 1 {
		t.Fatalf("totals: total=%d unchanged=%d", cmp.Total, cmp.Unchanged)
	}
	if cmp.NewAllow != 1 || cmp.ActionChanges != 1 {
		t.Fatalf("new-allow not highlighted: newAllow=%d actionChanges=%d", cmp.NewAllow, cmp.ActionChanges)
	}
	// The write case must appear as a sample flagged NewAllowClass.
	foundSample := false
	for _, s := range cmp.Samples {
		if s.ID == "write" {
			foundSample = true
			if !s.NewAllowClass {
				t.Fatal("write sample must be flagged NewAllowClass")
			}
			if s.NewAction != policy.ActionAllow || s.OldAction != policy.ActionDeny {
				t.Fatalf("write sample action transition: %v -> %v", s.OldAction, s.NewAction)
			}
		}
	}
	if !foundSample {
		t.Fatal("changed write case missing from samples")
	}
	if cmp.ByTool["write_file"] != 1 {
		t.Fatalf("blast-radius by tool: %v", cmp.ByTool)
	}
	if cmp.ByTenant["tenant-a"] != 1 {
		t.Fatalf("blast-radius by tenant: %v", cmp.ByTenant)
	}
}

// TestCompare_NewDeny: removing an allow rule is a NewDeny blast-radius change.
func TestCompare_NewDeny(t *testing.T) {
	oldSnap := gwSnap(t, allowRead)
	newSnap := gwSnap(t, "") // nothing allowed
	cases := []Case{{ID: "read", Input: gwInput("read_file")}}
	sim := New(policy.DefaultLimits())
	cmp, _ := sim.Compare(oldSnap, newSnap, cases)
	if cmp.NewDeny != 1 || cmp.NewAllow != 0 {
		t.Fatalf("expected a NewDeny, got newDeny=%d newAllow=%d", cmp.NewDeny, cmp.NewAllow)
	}
}

// TestCompare_Bounded: an over-limit comparison corpus is rejected.
func TestCompare_Bounded(t *testing.T) {
	snap := gwSnap(t, allowRead)
	sim := New(policy.DefaultLimits())
	cases := make([]Case, policy.DefaultLimits().MaxSimCases()+1)
	if _, err := sim.Compare(snap, snap, cases); err == nil {
		t.Fatal("over-limit compare must be rejected")
	}
}

// TestShadow_Relation: shadow evaluation reports the permissiveness relation of the
// candidate to the active snapshot without changing the active decision.
func TestShadow_Relation(t *testing.T) {
	active := gwSnap(t, "") // default deny everything
	broader := gwSnap(t, allowRead)
	in := gwInput("read_file")
	sim := New(policy.DefaultLimits())

	sr := sim.Shadow(active, broader, &in)
	if sr.Active.Action != policy.ActionDeny {
		t.Fatalf("active must still deny: %v", sr.Active.Action)
	}
	if sr.Candidate.Action != policy.ActionAllow {
		t.Fatalf("candidate must allow: %v", sr.Candidate.Action)
	}
	if sr.Relation != RelBroader || !sr.Changed {
		t.Fatalf("relation=%v changed=%v, want broader+changed", sr.Relation, sr.Changed)
	}
	// The reverse comparison is narrower.
	sr2 := sim.Shadow(broader, active, &in)
	if sr2.Relation != RelNarrower {
		t.Fatalf("reverse relation=%v, want narrower", sr2.Relation)
	}
	// Equal snapshots are equal + unchanged.
	sr3 := sim.Shadow(broader, broader, &in)
	if sr3.Relation != RelEqual || sr3.Changed {
		t.Fatalf("equal snapshots: relation=%v changed=%v", sr3.Relation, sr3.Changed)
	}
}

// TestCompare_RevisionAware: the comparison works across snapshots of different
// revisions (old vs new revision).
func TestCompare_RevisionAware(t *testing.T) {
	oldSnap := gwSnapRev(t, 1, allowRead)
	newSnap := gwSnapRev(t, 2, "")
	cases := []Case{{ID: "read", Input: gwInput("read_file")}}
	sim := New(policy.DefaultLimits())
	cmp, err := sim.Compare(oldSnap, newSnap, cases)
	if err != nil {
		t.Fatalf("compare across revisions: %v", err)
	}
	if cmp.NewDeny != 1 {
		t.Fatalf("expected NewDeny across revisions, got %d", cmp.NewDeny)
	}
}
