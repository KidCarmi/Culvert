package main

// session_provider_cluster_test.go — CHAOS-88 §50.6d: the revocation lever
// must REACH the Data Plane, including when the profile removed was the LAST
// one.
//
// §50.4 reason 3 justified building the revocation as derived state rather
// than a `RevokeProvider` event partly on the claim that "`ConfigSnapshot.
// IdPProfiles` already carries the set fleet-wide, so a CP deletion reaches
// every DP on the next sync". That claim was FALSE in exactly the case an
// operator reaches for. `idpRegistry.All()` returns a non-nil EMPTY slice for
// an empty registry, `json:"idp_profiles,omitempty"` DROPPED it from the wire,
// the DP decoded nil, and `syncSnapshotIdPProfiles` returns early on nil — so
// deleting the only IdP left it stored, enabled and LIVE on every DP:
// `ProfileEnabled` answered true, every session it minted kept authenticating
// with its asserted groups for the full TTL, and new logins through it kept
// working. Removing a NON-last profile propagated fine, which is why nothing
// noticed.
//
// The apply side already implemented nil-skip / empty-wipe; only the struct
// tag erased the distinction on the wire, and the `config_surfaces` row
// labelled `semValidatedSkip` instead of `semNilSkipEmptyWipe` kept
// TestConfigSurfaces_SnapshotWireWipe — the wall that exists for precisely
// this bug class — from ever looking at this field.
//
// Every gate below drives the REAL encode/decode pair (`json.Marshal` on the
// CP, `json.Unmarshal` on the DP, as controlplane_server.go and
// controlplane_client.go do) rather than handing a struct straight to the
// sync: the defect lives in the tag, so a test that skips the wire cannot see
// it.

import (
	"encoding/json"
	"slices"
	"testing"
)

// c72Wire round-trips a snapshot through the CP's encoder and the DP's
// decoder, and reports whether the `idp_profiles` key survived.
func c72Wire(t *testing.T, snap ConfigSnapshot) (decoded ConfigSnapshot, keyPresent bool) {
	t.Helper()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("CP marshal: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatalf("wire decode: %v", err)
	}
	_, keyPresent = keys["idp_profiles"]
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("DP unmarshal: %v", err)
	}
	return decoded, keyPresent
}

// DEFECT GATE. Deleting the LAST IdP profile on the Control Plane must revoke
// that federation's sessions on a Data Plane node. Fails against the
// reintroduced `omitempty`.
func TestChaos88_DefectLastProfileRemovalReachesTheDataPlane(t *testing.T) {
	c72Setup(t, "live")

	// The node is a DP holding one live profile; its sessions authenticate.
	c72AssertAuthenticates(t, "a live synced provider")

	// The CP's admin deletes the only profile. CurrentConfigSnapshot captures
	// idpRegistry.All() — exercise the real accessor on an empty registry
	// rather than hand-writing the empty slice the defect hinges on.
	cpEmpty := &IdPRegistry{live: map[string]IdentityProvider{}}
	snap := ConfigSnapshot{IdPProfiles: cpEmpty.All()}
	if snap.IdPProfiles == nil {
		t.Fatal("precondition: All() on an empty registry must return a non-nil empty slice — " +
			"if it returns nil the wire shape is not what makes this reachable and this gate proves nothing")
	}

	decoded, present := c72Wire(t, snap)
	if !present {
		t.Fatal("the cleared profile set was DROPPED from the wire: the DP reads nil and " +
			"syncSnapshotIdPProfiles skips, so the removed federation stays live on every DP")
	}
	if decoded.IdPProfiles == nil {
		t.Fatal("the DP decoded nil for an explicitly cleared set, so the wipe is unreachable")
	}

	if err := syncSnapshotIdPProfiles(decoded); err != nil {
		t.Fatalf("DP sync of a cleared profile set: %v", err)
	}
	if idpRegistry.ProfileEnabled("corp") {
		t.Fatal("the DP still reports the deleted profile as enabled: the revocation did not reach it")
	}
	c72AssertRevoked(t, "deleting the LAST profile on the CP")
}

// CONTROL. A snapshot that does not carry the field at all — an older or
// rolled-back CP, or any surface that never populates it — must leave the DP's
// registry untouched. The cheapest way to pass the defect gate is to wipe
// whenever the field is not a non-empty list, which would delete the registry
// of every node syncing from such a CP.
func TestChaos88_ControlAbsentProfileSetDoesNotWipe(t *testing.T) {
	c72Setup(t, "live")

	var decoded ConfigSnapshot
	if err := json.Unmarshal([]byte(`{"version":7}`), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.IdPProfiles != nil {
		t.Fatalf("precondition: an absent key must decode to nil, got %#v", decoded.IdPProfiles)
	}
	if err := syncSnapshotIdPProfiles(decoded); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !idpRegistry.ProfileEnabled("corp") {
		t.Fatal("a snapshot that carries no profile set WIPED the DP registry: " +
			"nil means ABSENT, not cleared")
	}
	c72AssertAuthenticates(t, "a snapshot carrying no profile set")
}

// CONTROL, and the dangerous one. redactUnenrolledSnapshot sets IdPProfiles to
// nil for an unenrolled caller, and GetConfig is polled by a DP BEFORE
// enrollment completes — so a redacted snapshot reaches a real node that
// applies it. Without `omitempty` that nil now serialises as `null`; if null
// were ever read as an explicit clear, every enrolling node would wipe its own
// IdP registry, and an unauthenticated caller could drive it.
func TestChaos88_ControlRedactedSnapshotDoesNotWipeAnEnrollingNode(t *testing.T) {
	c72Setup(t, "live")

	snap := ConfigSnapshot{IdPProfiles: []*IdPProfile{{ID: "corp", Type: IdPTypeSAML, Enabled: true}}}
	redactUnenrolledSnapshot(&snap)
	if snap.IdPProfiles != nil {
		t.Fatalf("precondition: redaction must nil the field, got %#v", snap.IdPProfiles)
	}

	decoded, _ := c72Wire(t, snap)
	if decoded.IdPProfiles != nil {
		t.Fatalf("a redacted (nil) profile set decoded as %#v — it must stay nil, or an "+
			"unenrolled GetConfig wipes the registry of every enrolling DP", decoded.IdPProfiles)
	}
	if err := syncSnapshotIdPProfiles(decoded); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !idpRegistry.ProfileEnabled("corp") {
		t.Fatal("a REDACTED snapshot wiped the DP registry — an unenrolled caller must never " +
			"be able to clear a node's identity providers")
	}
	c72AssertAuthenticates(t, "a redacted snapshot served to an unenrolled caller")
}

// CONTROL. Removing a non-last profile already propagated and must keep doing
// so unchanged — this is the case that worked, and the one whose success hid
// the defect. The survivor is DISABLED so ReplaceAll stores it without
// compiling (no network from a unit test); storage, not compilation, is what
// ProfileEnabled reads.
func TestChaos88_ControlNonLastRemovalStillPropagates(t *testing.T) {
	c72Setup(t, "live")

	// A VALID profile shape: ReplaceAll validates every profile, enabled or
	// not, and only skips COMPILATION for a disabled one — which is what keeps
	// this gate off the network. The metadata URL is never fetched here.
	survivor := chaos87Profile("partner", "https://partner.example/metadata")
	survivor.Enabled = false
	decoded, present := c72Wire(t, ConfigSnapshot{IdPProfiles: []*IdPProfile{survivor}})
	if !present || len(decoded.IdPProfiles) != 1 {
		t.Fatalf("a surviving profile must reach the DP: present=%v len=%d", present, len(decoded.IdPProfiles))
	}
	if err := syncSnapshotIdPProfiles(decoded); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if idpRegistry.ProfileEnabled("corp") {
		t.Fatal("the removed profile is still enabled on the DP")
	}
	if idpRegistry.Get("partner") == nil {
		t.Fatal("the surviving profile was not stored on the DP")
	}
	c72AssertRevoked(t, "removing one of two profiles on the CP")
}

// DOCUMENTED RESIDUAL (AU-65, §50.6f). Re-enabling a provider under the SAME
// id revives the sessions it minted: the predicate is pure derived state, and
// §50.7 deliberately does not clear the cookie on refusal, so nothing durable
// records that a cut happened.
//
// This pins the AGREEMENT between the runbook and the code, not the gap — the
// CHAOS-65 ocspCoverage shape. `docs/operator/identity-provider-revocation.md`
// §4 now tells an operator this happens and names the three workarounds; the
// previous text promised the opposite, which is a recovery step that misleads
// mid-incident.
//
// WHEN A PROVIDER GENERATION IS STAMPED INTO THE COOKIE, THIS TEST MUST FAIL,
// and that is the point: invert it and correct §4 in the same change, so the
// runbook can never be left promising something the code stopped doing.
func TestChaos88_DocumentedResidual_SameIDRestoration(t *testing.T) {
	c72Setup(t, "live")
	c72AssertAuthenticates(t, "the live provider")

	// Captured before the incident so the restoration check below can compare
	// the actual groups rather than how many there are.
	preIncident, _, _ := c72Resolve(t, "corp")
	preIncidentGroups := slices.Clone(preIncident.groups)
	if len(preIncidentGroups) == 0 {
		t.Fatal("precondition: the fixture session must carry groups, or the " +
			"restoration assertion below proves nothing about authorization")
	}
	resetSessionProviderBoundsForTest()

	p := idpRegistry.Get("corp")
	if p == nil {
		t.Fatal("precondition: the fixture must store a profile")
	}
	disabled := *p
	disabled.Enabled = false
	idpRegistry.profiles = []*IdPProfile{&disabled}
	idpRegistry.live = map[string]IdentityProvider{}
	c72AssertRevoked(t, "disabling the provider")

	// The operator investigates and re-enables the same profile id.
	resetSessionProviderBoundsForTest()
	idpRegistry.profiles = []*IdPProfile{p}

	out, proceed, code := c72Resolve(t, "corp")
	// Compare the group VALUES, not their count. The whole claim of AU-65 is
	// that the groups the provider asserted BEFORE the incident come back, and
	// those groups go straight to policyStore.Evaluate — a length check would
	// pass on two entirely different groups, i.e. on a changed authorization
	// outcome.
	if !proceed || out.identity != "alice@corp.example" || !slices.Equal(out.groups, preIncidentGroups) {
		t.Fatalf("documented residual no longer holds — a pre-incident cookie is no longer "+
			"revived by re-enabling the same profile id: proceed=%v identity=%q groups=%v "+
			"(want %v) status=%d.\n"+
			"If you stamped a provider generation into the cookie, that is the AU-65 fix: invert "+
			"this gate and correct §4 of docs/operator/identity-provider-revocation.md in the "+
			"same change, so the runbook stops describing behaviour the code no longer has.",
			proceed, out.identity, out.groups, preIncidentGroups, code)
	}
}
