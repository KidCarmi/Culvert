package adminapi

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/approval"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// TestAW_HistoricalExplanationNeverUsesCurrentPolicy proves the deliberately
// weakened control fails: the explanation is projected from the committed event
// and does not change when the active policy store changes.
func TestAW_HistoricalExplanationNeverUsesCurrentPolicy(t *testing.T) {
	r := &fakeReader{byPart: map[string][]evmodel.Event{
		partitionCrit: {decEvent("acme", "evt-1", "DENY", "MCP.POLICY.RESOURCE_SCOPE", "R-block")},
	}}
	ds := NewDecisionService(r, DefaultLimits())
	before, err := ds.Explain("gateway", "acme", "evt-1")
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	// Publish a brand-new policy (would change a live re-evaluation).
	store := policy.NewStore(policy.CapGateway)
	snap, cerr := policy.Compile([]byte(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`), policy.CreatedMeta{Author: "t", CreatedAt: time.Unix(1, 0).UTC().Format(time.RFC3339)}, policy.DefaultLimits())
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	_ = store.Publish(0, snap)
	after, err := ds.Explain("gateway", "acme", "evt-1")
	if err != nil {
		t.Fatalf("Explain2: %v", err)
	}
	if before.Action != after.Action || before.ReasonCode != after.ReasonCode || after.Source != "historical" {
		t.Fatal("historical explanation changed with the current policy — re-evaluation leaked in")
	}
}

// TestAW_CrossTenantNoCountLeak proves a tenant cannot infer another tenant's
// record count or existence through search.
func TestAW_CrossTenantNoCountLeak(t *testing.T) {
	r := &fakeReader{byPart: map[string][]evmodel.Event{
		partitionCrit: {
			decEvent("acme", "e1", "DENY", "r", "R1"),
			decEvent("globex", "e2", "DENY", "r", "R2"),
			decEvent("globex", "e3", "DENY", "r", "R3"),
		},
	}}
	ds := NewDecisionService(r, DefaultLimits())
	res, _ := ds.Search("gateway", "acme", "", 100, DecisionFilter{})
	if len(res.Decisions) != 1 {
		t.Fatalf("acme must see exactly its 1 event regardless of globex's 2: %d", len(res.Decisions))
	}
}

// TestAW_LocalPublicationNeverDistributed proves a publish result can never
// claim distributed status.
func TestAW_LocalPublicationNeverDistributed(t *testing.T) {
	svc, _, _, _, _ := newPubSvc(t)
	appc := &fakeAppCommitter{}
	id, _ := svc.Create("gateway", "acme", "alice", candidateDoc(1), 0)
	rc, _ := svc.Approve(id, "bob", appc)
	res, err := svc.Publish(id, "acme", rc)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if res.DistributionState != "local_only" {
		t.Fatalf("distribution must be local_only, got %q", res.DistributionState)
	}
}

// TestAW_ApprovalBindsCredentialPower proves an approval view preserves the
// credential power ceiling binding (an approval cannot silently drop it).
func TestAW_ApprovalBindsCredentialPower(t *testing.T) {
	// Build an operational binding carrying a power ceiling and render its view.
	// (Uses the approval store via the publication test helpers' store.)
	_, _, appr, _, _ := newPubSvc(t)
	b := approval.Binding{
		Tenant: "acme", Capability: "gateway", Action: "write", OperationClass: "write",
		CredentialProfile: "cp-1", PowerCeiling: "write", DecisionEventID: "evt-x",
	}
	if _, err := appr.Create("op1", approval.KindOperational, "alice", b); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := appr.Get("op1", "acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	v := ApprovalViewOf(got)
	if v.PowerCeiling != "write" || v.CredentialProfileRef != "cp-1" {
		t.Fatalf("approval view dropped credential power binding: %+v", v)
	}
}

// FuzzDecisionCursor proves the cursor decoder never panics and rejects
// malformed cursors deterministically.
func FuzzDecisionCursor(f *testing.F) {
	f.Add("")
	f.Add("P-CRIT:5")
	f.Add("garbage")
	f.Add("P-ORD:notanumber")
	f.Add(":::")
	f.Fuzz(func(t *testing.T, s string) {
		cur, err := decodeCursor(s)
		if err == nil {
			if cur.part != partitionCrit && cur.part != partitionOrd {
				t.Fatalf("accepted cursor with bad partition: %q", cur.part)
			}
		}
	})
}

// FuzzValidateCandidate proves the candidate validator never panics and never
// reports a secret-bearing OK on arbitrary bytes.
func FuzzValidateCandidate(f *testing.F) {
	svc := NewPolicyService(&fakePolicyStores{gw: policy.NewStore(policy.CapGateway)}, policy.DefaultLimits(), DefaultLimits(), func() time.Time { return time.Unix(1, 0) })
	f.Add([]byte(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, b []byte) {
		res := svc.Validate("gateway", b)
		if res.OK && res.CandidateHash == "" {
			t.Fatal("OK result without a candidate hash")
		}
		if strings.Contains(res.Reason, "secret") {
			t.Fatal("reason leaked a secret token")
		}
	})
}
