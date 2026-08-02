package adminapi

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/approval"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// fakePolicyStores exposes a single gateway store.
type fakePolicyStores struct{ gw *policy.Store }

func (f *fakePolicyStores) Store(capability string) (*policy.Store, bool) {
	if capability == "gateway" {
		return f.gw, true
	}
	return nil, false
}

// fakeAppCommitter records approval-decision commits and can fail.
type fakeAppCommitter struct {
	calls int
	fail  bool
}

func (f *fakeAppCommitter) CommitDecision(_ *approval.Request, _ approval.State, _ approval.PrincipalID) (string, error) {
	f.calls++
	if f.fail {
		return "", mcperr.New(mcperr.ReasonEventDurabilityDegraded, "fake", "fail")
	}
	return "appdigest", nil
}

// fakePubCommitter records config-publication commits and can fail.
type fakePubCommitter struct {
	calls int
	fail  bool
}

func (f *fakePubCommitter) CommitPublication(_, _, _ string, _, _ uint64) (string, error) {
	f.calls++
	if f.fail {
		return "", mcperr.New(mcperr.ReasonEventDurabilityDegraded, "fake", "fail")
	}
	return "pubdigest", nil
}

func candidateDoc(rev uint64) []byte {
	return []byte(`{"schema_version":1,"capability":"gateway","policy_revision":` + strconv.FormatUint(rev, 10) + `,"default_action":"DENY","rules":[]}`)
}

func newPubSvc(t *testing.T) (*PublicationService, *policy.Store, *approval.Store, func() approval.ID, *fakePubCommitter) {
	t.Helper()
	gw := policy.NewStore(policy.CapGateway)
	stores := &fakePolicyStores{gw: gw}
	ps := NewPolicyService(stores, policy.DefaultLimits(), DefaultLimits(), func() time.Time { return time.Unix(1, 0) })
	appr := approval.NewStore(approval.Config{MaxPending: 100, MaxPerTenant: 50, TTL: time.Hour})
	var ctr int64
	idgen := func() approval.ID { return approval.ID("pub-" + strconv.FormatInt(atomic.AddInt64(&ctr, 1), 10)) }
	pub := &fakePubCommitter{}
	svc := NewPublicationService(ps, stores, appr, pub, idgen, func() time.Time { return time.Unix(1, 0) })
	return svc, gw, appr, idgen, pub
}

func TestPublish_HappyPath(t *testing.T) {
	svc, gw, _, _, pub := newPubSvc(t)
	appc := &fakeAppCommitter{}
	id, err := svc.Create("gateway", "acme", "alice", candidateDoc(1), 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rc, err := svc.Approve(id, "bob", appc)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	res, err := svc.Publish(id, "acme", rc)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if res.DistributionState != "local_only" || res.Revision != 1 {
		t.Fatalf("bad publish result: %+v", res)
	}
	if pub.calls != 1 {
		t.Fatalf("publication event must commit once: %d", pub.calls)
	}
	if gw.Current() == nil || uint64(gw.CurrentRevision()) != 1 {
		t.Fatal("policy store not published to revision 1")
	}
}

func TestPublish_SelfApprovalDenied(t *testing.T) {
	svc, _, _, _, _ := newPubSvc(t)
	appc := &fakeAppCommitter{}
	id, err := svc.Create("gateway", "acme", "alice", candidateDoc(1), 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Approve(id, "alice", appc); mcperr.ReasonOf(err) != mcperr.ReasonApprovalSelfApproval {
		t.Fatalf("want self_approval, got %v", err)
	}
}

func TestPublish_CommitFailurePublishesNothing(t *testing.T) {
	svc, gw, _, _, pub := newPubSvc(t)
	pub.fail = true
	appc := &fakeAppCommitter{}
	id, _ := svc.Create("gateway", "acme", "alice", candidateDoc(1), 0)
	rc, err := svc.Approve(id, "bob", appc)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := svc.Publish(id, "acme", rc); mcperr.ReasonOf(err) != mcperr.ReasonPublicationDurabilityRequired {
		t.Fatalf("want durability_required, got %v", err)
	}
	// Nothing published: store still empty.
	if gw.Current() != nil {
		t.Fatal("policy was published despite the publication-event commit failure")
	}
}

func TestPublish_StaleBaseRejected(t *testing.T) {
	svc, _, _, _, _ := newPubSvc(t)
	// Active base is 0; claim expected base 5.
	if _, err := svc.Create("gateway", "acme", "alice", candidateDoc(1), 5); mcperr.ReasonOf(err) != mcperr.ReasonPublicationStaleBase {
		t.Fatalf("want stale_base, got %v", err)
	}
}

func TestPublish_UnapprovedRejected(t *testing.T) {
	svc, _, _, _, _ := newPubSvc(t)
	id, _ := svc.Create("gateway", "acme", "alice", candidateDoc(1), 0)
	// Never approved; a forged zero receipt must not publish.
	if _, err := svc.Publish(id, "acme", approval.Receipt{}); mcperr.ReasonOf(err) != mcperr.ReasonPublicationNotApproved {
		t.Fatalf("want not_approved, got %v", err)
	}
}

func TestPublish_CrossTenantGetDenied(t *testing.T) {
	svc, _, _, _, _ := newPubSvc(t)
	appc := &fakeAppCommitter{}
	id, _ := svc.Create("gateway", "acme", "alice", candidateDoc(1), 0)
	rc, _ := svc.Approve(id, "bob", appc)
	// A different tenant cannot publish this request.
	if _, err := svc.Publish(id, "globex", rc); mcperr.ReasonOf(err) != mcperr.ReasonApprovalNotFound {
		t.Fatalf("want not_found for cross-tenant publish, got %v", err)
	}
}

func TestValidateSimulate(t *testing.T) {
	svc, _, _, _, _ := newPubSvc(t)
	vr := svc.policySvc.Validate("gateway", candidateDoc(1))
	if !vr.OK || vr.DefaultAction != "DENY" || vr.CandidateHash == "" {
		t.Fatalf("validate: %+v", vr)
	}
	bad := svc.policySvc.Validate("gateway", []byte(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"ALLOW","rules":[]}`))
	if bad.OK {
		t.Fatal("non-deny default must fail validation")
	}
}
