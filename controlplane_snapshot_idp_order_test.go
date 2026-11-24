package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// A snapshot whose IdP profiles are refused must change nothing. The IdP sync
// is the one step of a snapshot apply that can refuse after validation; it used
// to run AFTER the policy rules were replaced (and saved) and BEFORE the
// category groups those rules reference, so a refusal left the new rules over
// the old groups: a group-scoped Drop matched nothing and the destination fell
// to the default action.
func snapshotIdPOrderFixture(t *testing.T) (snap ConfigSnapshot, policyPath string) {
	t.Helper()
	bindFreshAdmissionOwners(t)
	refGateSetup(t)
	withTestIdPRegistry(t)
	prevDefault := defaultPolicyAction()
	setDefaultPolicyAction("allow")
	t.Cleanup(func() { setDefaultPolicyAction(prevDefault) })
	prevSaaS := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prevSaaS) })
	prevRefusal := policyStore.rulesetRefused.Load()
	t.Cleanup(func() { policyStore.rulesetRefused.Store(prevRefusal) })

	cats := []CategoryEntry{{Name: "gate-cat", Hosts: []string{"gc.example.com"}}}
	catStore.ReplaceAll(cats)
	globalCategoryGroups.ReplaceAll([]CategoryGroup{{ID: "grp-old", Name: "old-group", Categories: []string{"gate-cat"}}})
	policyStore.ReplaceAll([]PolicyRule{{
		Name: "deny-old", Priority: 1, Action: ActionDrop,
		DestCategoryGroup: "old-group", DestCategoryGroupID: "grp-old",
	}})
	policyPath = filepath.Join(t.TempDir(), "policy.json")
	policyStore.path = policyPath // restored by refGateSetup's policy-store snapshot
	if err := policyStore.SaveErr(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	bad := ldapTestProfile("ldap-bad", "Bad AD")
	bad.LDAP.URL = "https://not-ldap.example"
	snap = ConfigSnapshot{
		Version:        1 << 40,
		DefaultAction:  "allow",
		URLCategories:  cats,
		CategoryGroups: []CategoryGroup{{ID: "grp-new", Name: "new-group", Categories: []string{"gate-cat"}}},
		PolicyRules: []PolicyRule{{
			Name: "deny-new", Priority: 1, Action: ActionDrop,
			DestCategoryGroup: "new-group", DestCategoryGroupID: "grp-new",
		}},
		IdPProfiles: []*IdPProfile{bad},
	}
	if err := validateConfigSnapshot(snap); err != nil {
		t.Fatalf("premise: the snapshot must pass pre-mutation validation, got %v", err)
	}
	return snap, policyPath
}

func assertSnapshotIdPRefusalChangedNothing(t *testing.T, policyPath string) {
	t.Helper()
	if got := ruleNamesOf(policyStore.List()); got != "deny-old" {
		t.Errorf("active rules after the refused snapshot = [%s], want [deny-old]", got)
	}
	if got := strings.Join(listGroupNames(t), ","); got != "old-group" {
		t.Errorf("category groups after the refused snapshot = [%s], want [old-group]", got)
	}
	m := policyStore.Evaluate("192.0.2.1", "", "", "gc.example.com", nil)
	if m == nil || m.Rule.Name != "deny-old" {
		t.Errorf("the destination the Drop rule covered is no longer matched by it (match=%v): access expanded", m)
	}
	disk := &PolicyStore{}
	if err := disk.Load(policyPath); err != nil {
		t.Fatalf("reload persisted policy: %v", err)
	}
	if got := ruleNamesOf(disk.List()); got != "deny-old" {
		t.Errorf("persisted rules after the refused snapshot = [%s], want [deny-old]", got)
	}
}

func TestSnapshotIdPRefusal_FullApplyChangesNothing(t *testing.T) {
	snap, policyPath := snapshotIdPOrderFixture(t)
	if err := applyConfigSnapshot(snap); err == nil {
		t.Fatal("premise: the IdP sync must refuse this snapshot")
	}
	assertSnapshotIdPRefusalChangedNothing(t, policyPath)
}

// On the delta path the blocklist chain is applied and verified before the IdP
// step (so a delta refused for drift never touches IdP state, below). An IdP
// refusal therefore leaves the in-memory blocklist at the CP's verified target;
// what it must not do is replace or persist the policy.
func TestSnapshotIdPRefusal_DeltaApplyLeavesPolicyUntouched(t *testing.T) {
	snap, policyPath := snapshotIdPOrderFixture(t)
	chain := []blocklistDelta{{Added: []string{"delta-added.example"}}}
	target := blocklist.FeedSetFingerprint([]string{"delta-added.example"})
	if err := applyBlocklistDeltaSnapshot(snap, chain, target); err == nil {
		t.Fatal("premise: the IdP sync must refuse this delta")
	}
	assertSnapshotIdPRefusalChangedNothing(t, policyPath)
}

// A delta refused because the blocklist did not converge must leave the IdP
// registry and the external-auth settings as they were: the remainder belongs
// to a version whose blocklist could not be verified.
func TestSnapshotDeltaDrift_LeavesIdPAndExternalAuthUntouched(t *testing.T) {
	snap, policyPath := snapshotIdPOrderFixture(t)
	prevBase, prevTrust := proxyExternalBaseURL, trustForwardedHeaders
	t.Cleanup(func() { SetProxyBaseURL(prevBase); trustForwardedHeaders = prevTrust })
	SetProxyBaseURL("")
	trustForwardedHeaders = false

	snap.IdPProfiles = []*IdPProfile{ldapTestProfile("ldap-good", "Good AD")}
	snap.ProxyBaseURL = "https://new.example"
	snap.TrustForwardedHeaders = true
	chain := []blocklistDelta{{Added: []string{"delta-added.example"}}}
	if err := applyBlocklistDeltaSnapshot(snap, chain, "deadbeefdeadbeef"); err == nil {
		t.Fatal("premise: a wrong target fingerprint must be refused as drift")
	}
	if n := len(idpRegistry.All()); n != 0 {
		t.Errorf("%d IdP profile(s) registered from a delta refused for drift, want 0", n)
	}
	if got := proxyExternalBaseURL; got != "" {
		t.Errorf("proxy base URL = %q after a delta refused for drift, want unchanged", got)
	}
	if trustForwardedHeaders {
		t.Error("forwarded-header trust was switched on by a delta refused for drift")
	}
	assertSnapshotIdPRefusalChangedNothing(t, policyPath)
}

// Control: the same snapshot without the bad profile applies in full, so the
// tests above fail for the refusal and not for an unrelated fixture fault.
func TestSnapshotIdPRefusal_ControlAppliesWithoutTheBadProfile(t *testing.T) {
	snap, _ := snapshotIdPOrderFixture(t)
	snap.IdPProfiles = nil
	if err := applyConfigSnapshot(snap); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := ruleNamesOf(policyStore.List()); got != "deny-new" {
		t.Errorf("active rules = [%s], want [deny-new]", got)
	}
	m := policyStore.Evaluate("192.0.2.1", "", "", "gc.example.com", nil)
	if m == nil || m.Rule.Name != "deny-new" {
		t.Errorf("the new group-scoped rule does not match after a full apply (match=%v)", m)
	}
}
