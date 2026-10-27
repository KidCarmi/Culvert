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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
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

// ── AU-65 (§50.6f): a same-id restoration revives no session ────────────────
//
// Before the fix, re-enabling a provider under the SAME id revived every
// session it had minted: the predicate was pure derived state ("is this profile
// stored and enabled right now"), §50.7 deliberately does not clear the cookie
// on refusal, and nothing durable recorded that a cut happened. Disable a
// compromised IdP, investigate, re-enable inside the 8 h TTL, and every cookie
// minted before the incident, an attacker's included, authenticated again with
// the subject and groups asserted BEFORE it.
//
// The fix is one server-owned field, IdPProfile.SessionsNotBefore, stamped by
// Upsert on create and on a disabled-to-enabled transition and compared with
// the cookie's mint second per request. These gates drive the OPERATOR's real
// lever, the admin handler, rather than assigning registry fields, because the
// stamp lives on that write path and a gate that skips it cannot see it.

// c72ResolveMintedAt resolves a request carrying a cookie minted at iat.
func c72ResolveMintedAt(t *testing.T, provider string, iat int64) (outcome authOutcome, proceed bool) {
	t.Helper()
	w := httptest.NewRecorder()
	return resolveRequestAuth(w, c72RequestMintedAt(t, provider, iat), "192.0.2.10", "chaos-88")
}

// c72AdminPutProfile drives PUT /api/idp/{id} through the real handler, which
// is the operator's toggle and also the same-id re-create path.
func c72AdminPutProfile(t *testing.T, p *IdPProfile) {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+p.ID, p), p.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/idp/%s: status %d body %q", p.ID, w.Code, w.Body.String())
	}
}

// c72AdminDeleteProfile drives DELETE /api/idp/{id} through the real handler.
func c72AdminDeleteProfile(t *testing.T, id string) {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/"+id, nil), id)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE /api/idp/%s: status %d body %q", id, w.Code, w.Body.String())
	}
}

// c72StoredCopy returns a COPY of the stored profile to use as a request body.
// Get returns the published pointer, so editing it in place would change the
// registry before the handler runs and hide the create-vs-edit decision.
func c72StoredCopy(t *testing.T, id string) *IdPProfile {
	t.Helper()
	p := idpRegistry.Get(id)
	if p == nil {
		t.Fatalf("precondition: profile %q is not stored", id)
	}
	cp := cloneIdPProfiles([]*IdPProfile{p})[0]
	return cp
}

// c72SeedPreUpgradeProfiles stores enabled, compiled profiles the way a node
// holds them before this change: through ReplaceAll (boot load and the CP->DP
// snapshot take the same verbatim path), so SessionsNotBefore is ZERO.
func c72SeedPreUpgradeProfiles(t *testing.T, ids ...string) {
	t.Helper()
	idp := newChaos87IdP(t)
	profiles := make([]*IdPProfile, 0, len(ids))
	for _, id := range ids {
		profiles = append(profiles, chaos87Profile(id, idp.URL()))
	}
	if err := idpRegistry.ReplaceAll(profiles); err != nil {
		t.Fatalf("seed ReplaceAll: %v", err)
	}
	for _, id := range ids {
		if got := idpRegistry.Get(id); got == nil || got.SessionsNotBefore != 0 {
			t.Fatalf("precondition: %q must be stored with no cutoff, got %+v", id, got)
		}
	}
}

// c72MintedByTheRealMinter mints a cookie through setSessionCookie itself and
// returns its iat, so the "a fresh login works" half proves the production
// minter stamps the field rather than trusting the test fixture to.
func c72MintedByTheRealMinter(t *testing.T, provider string) int64 {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "http://example.com/callback", http.NoBody)
	if err := setSessionCookie(w, r, &Identity{Sub: "alice@corp.example", Provider: provider}); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name != sessionCookieName {
			continue
		}
		s, err := decodeSession(c.Value)
		if err != nil {
			t.Fatalf("decode the minted cookie: %v", err)
		}
		return s.Iat
	}
	t.Fatal("setSessionCookie set no session cookie")
	return 0
}

// THE FINDING, inverted. Disable then re-enable the same profile through the
// admin handler: the pre-incident cookie stays refused, groups included, while
// a login made after the re-enable authenticates.
func TestChaos88_SameIDReEnableRevivesNoSession(t *testing.T) {
	c72Setup(t, "deleted")
	chaos87Env(t)
	c72SeedPreUpgradeProfiles(t, "corp")

	// Minted an hour before the incident.
	preIncident := time.Now().Add(-time.Hour).Unix()
	before, proceed := c72ResolveMintedAt(t, "corp", preIncident)
	if !proceed || before.identity != "alice@corp.example" || len(before.groups) == 0 {
		t.Fatalf("precondition: the pre-incident cookie must authenticate with groups: proceed=%v identity=%q groups=%v",
			proceed, before.identity, before.groups)
	}
	preIncidentGroups := slices.Clone(before.groups)

	// The operator disables the compromised IdP.
	disabled := c72StoredCopy(t, "corp")
	disabled.Enabled = false
	c72AdminPutProfile(t, disabled)
	if out, ok := c72ResolveMintedAt(t, "corp", preIncident); ok || out.identity != "" {
		t.Fatalf("disabling did not refuse the session: proceed=%v identity=%q", ok, out.identity)
	}

	// ... investigates, and re-enables the SAME id. The body also tries to
	// LOWER the cutoff: the field is server-owned, so it must be ignored.
	stampedAfter := time.Now().Unix()
	reenabled := c72StoredCopy(t, "corp")
	reenabled.Enabled = true
	reenabled.SessionsNotBefore = 1
	c72AdminPutProfile(t, reenabled)

	stored := idpRegistry.Get("corp")
	if stored == nil || !stored.Enabled {
		t.Fatalf("precondition: the profile must be stored and enabled after the re-enable, got %+v", stored)
	}
	if stored.SessionsNotBefore < stampedAfter {
		t.Fatalf("the re-enable did not stamp a session cutoff (or honoured the body's value): "+
			"sessionsNotBefore=%d, want >= %d", stored.SessionsNotBefore, stampedAfter)
	}

	resetSessionProviderBoundsForTest()
	out, proceed := c72ResolveMintedAt(t, "corp", preIncident)
	if proceed || out.identity != "" || len(out.groups) != 0 {
		t.Fatalf("AU-65: re-enabling the same profile id REVIVED a pre-incident session: "+
			"proceed=%v identity=%q groups=%v (pre-incident groups %v)",
			proceed, out.identity, out.groups, preIncidentGroups)
	}
	if got := sessionProviderRevokedCount(); got == 0 {
		t.Fatal("the refused pre-incident session was not counted")
	}
	// A cookie that predates the iat field cannot prove it postdates the cut.
	if out, ok := c72ResolveMintedAt(t, "corp", 0); ok || out.identity != "" {
		t.Fatalf("a legacy cookie with no iat rode the re-enabled profile: proceed=%v identity=%q", ok, out.identity)
	}

	// CONTROL: a login after the re-enable authenticates, with its groups,
	// and the production minter stamps the iat that admits it.
	freshIat := c72MintedByTheRealMinter(t, "corp")
	if freshIat < stored.SessionsNotBefore {
		t.Fatalf("setSessionCookie minted iat=%d, before the cutoff %d", freshIat, stored.SessionsNotBefore)
	}
	resetSessionProviderBoundsForTest()
	fresh, ok := c72ResolveMintedAt(t, "corp", freshIat)
	if !ok || fresh.identity != "alice@corp.example" || !slices.Equal(fresh.groups, preIncidentGroups) {
		t.Fatalf("a login made after the re-enable was refused: proceed=%v identity=%q groups=%v",
			ok, fresh.identity, fresh.groups)
	}
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("a post-re-enable login charged the revocation counter: %d", got)
	}
}

// Delete, then re-create under the SAME id through PUT /api/idp/{id}. The new
// incarnation must not honour a cookie the old one minted.
func TestChaos88_SameIDRecreateRevivesNoSession(t *testing.T) {
	c72Setup(t, "deleted")
	chaos87Env(t)
	c72SeedPreUpgradeProfiles(t, "corp")

	minted := time.Now().Add(-time.Hour).Unix()
	if _, ok := c72ResolveMintedAt(t, "corp", minted); !ok {
		t.Fatal("precondition: the old incarnation's cookie must authenticate")
	}
	original := c72StoredCopy(t, "corp")

	c72AdminDeleteProfile(t, "corp")
	recreated := *original
	recreated.SessionsNotBefore = 0 // what a client re-posting the old body sends
	c72AdminPutProfile(t, &recreated)
	if p := idpRegistry.Get("corp"); p == nil || !p.Enabled || p.SessionsNotBefore == 0 {
		t.Fatalf("the same-id re-create stamped no cutoff: %+v", p)
	}

	resetSessionProviderBoundsForTest()
	if out, ok := c72ResolveMintedAt(t, "corp", minted); ok || out.identity != "" || len(out.groups) != 0 {
		t.Fatalf("AU-65: a profile re-created under the same id honoured a cookie its "+
			"previous incarnation minted: proceed=%v identity=%q groups=%v", ok, out.identity, out.groups)
	}
	if _, ok := c72ResolveMintedAt(t, "corp", time.Now().Unix()); !ok {
		t.Fatal("control: a login through the re-created profile must authenticate")
	}
}

// NEGATIVE CONTROLS. The cutoff must cost nothing it was not asked to cut:
//   - a profile nobody touched keeps its zero cutoff, so a cookie minted
//     before the upgrade (or with no iat at all) still authenticates, and
//     re-enabling a DIFFERENT profile does not move it — no mass logout;
//   - an edit of an enabled profile does not move the cutoff;
//   - reachability never moves it: a staleness retirement darkens the
//     provider (§50.6c, degraded availability) and the old cookie survives.
func TestChaos88_ControlCutoffMovesOnlyOnCreateAndReEnable(t *testing.T) {
	c72Setup(t, "deleted")
	chaos87Env(t)
	c72SeedPreUpgradeProfiles(t, "corp", "partner")
	old := time.Now().Add(-time.Hour).Unix()

	// Cycle "corp" through disable and re-enable.
	p := c72StoredCopy(t, "corp")
	p.Enabled = false
	c72AdminPutProfile(t, p)
	p = c72StoredCopy(t, "corp")
	p.Enabled = true
	c72AdminPutProfile(t, p)

	if got := idpRegistry.Get("partner").SessionsNotBefore; got != 0 {
		t.Fatalf("re-enabling corp moved partner's cutoff to %d", got)
	}
	for _, iat := range []int64{old, 0} {
		if out, ok := c72ResolveMintedAt(t, "partner", iat); !ok || out.identity == "" {
			t.Fatalf("an untouched zero-cutoff profile refused a cookie minted at iat=%d", iat)
		}
	}

	// An ordinary edit of the enabled profile keeps its cutoff.
	cut := idpRegistry.Get("corp").SessionsNotBefore
	edited := c72StoredCopy(t, "corp")
	edited.Name = "Corp SSO (renamed)"
	edited.SessionsNotBefore = 0
	c72AdminPutProfile(t, edited)
	if got := idpRegistry.Get("corp").SessionsNotBefore; got != cut {
		t.Fatalf("an edit of an enabled profile moved its cutoff from %d to %d", cut, got)
	}

	// Reachability: retire partner at the staleness ceiling. Dark, still
	// enabled, cutoff untouched, and its pre-upgrade cookie survives.
	src := idpRemoteDocumentSource(idpRegistry.Get("partner"))
	if !idpRegistry.retireStaleProvider("partner", src, chaos87SeedStaleServe("partner", src)) {
		t.Fatal("setup: partner must be retired")
	}
	if _, live := idpRegistry.LiveProvider("partner"); live {
		t.Fatal("setup: retirement must leave partner dark")
	}
	if got := idpRegistry.Get("partner").SessionsNotBefore; got != 0 {
		t.Fatalf("a staleness retirement moved the cutoff to %d: an unreachable IdP is not a revocation", got)
	}
	resetSessionProviderBoundsForTest()
	if out, ok := c72ResolveMintedAt(t, "partner", old); !ok || out.identity == "" {
		t.Fatal("a staleness retirement revoked a pre-upgrade session")
	}
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("revocation counter = %d after a retirement, want 0", got)
	}
}

// The stamp table, pinned on the helper itself: server-owned, moved only by a
// create or a disabled-to-enabled transition, whatever the body carried.
func TestChaos88_SessionsNotBeforeIsServerOwned(t *testing.T) {
	const prevCut, bodyCut = int64(1_700_000_000), int64(42)
	for _, tc := range []struct {
		name      string
		prev      *IdPProfile
		nextOn    bool
		wantStamp bool // true: moved to now; false: kept prev's value
	}{
		{"create enabled", nil, true, true},
		{"create disabled", nil, false, true},
		{"re-enable", &IdPProfile{Enabled: false, SessionsNotBefore: prevCut}, true, true},
		{"edit enabled", &IdPProfile{Enabled: true, SessionsNotBefore: prevCut}, true, false},
		{"disable", &IdPProfile{Enabled: true, SessionsNotBefore: prevCut}, false, false},
		{"edit disabled", &IdPProfile{Enabled: false, SessionsNotBefore: prevCut}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := &IdPProfile{Enabled: tc.nextOn, SessionsNotBefore: bodyCut}
			lo := time.Now().Unix()
			stampSessionsNotBefore(tc.prev, next)
			hi := time.Now().Unix()
			if tc.wantStamp {
				if next.SessionsNotBefore < lo || next.SessionsNotBefore > hi {
					t.Fatalf("want a stamp in [%d,%d], got %d", lo, hi, next.SessionsNotBefore)
				}
				return
			}
			if next.SessionsNotBefore != prevCut {
				t.Fatalf("want the stored cutoff %d kept, got %d (the body carried %d)",
					prevCut, next.SessionsNotBefore, bodyCut)
			}
		})
	}
}

// FLEET-WIDE. The Control Plane's stamp reaches a Data Plane node verbatim
// through the real snapshot encode/decode, and the DP refuses the revived
// cookie with no admin action of its own. A DP must NOT restamp its own clock,
// or the first sync on a fresh node would log every session out.
func TestChaos88_SessionCutoffReachesTheDataPlaneVerbatim(t *testing.T) {
	c72Setup(t, "deleted")
	chaos87Env(t)
	idp := newChaos87IdP(t)

	cut := time.Now().Add(-10 * time.Minute).Unix()
	cpProfile := chaos87Profile("corp", idp.URL())
	cpProfile.SessionsNotBefore = cut
	decoded, present := c72Wire(t, ConfigSnapshot{IdPProfiles: []*IdPProfile{cpProfile}})
	if !present || len(decoded.IdPProfiles) != 1 {
		t.Fatalf("the profile must reach the DP: present=%v len=%d", present, len(decoded.IdPProfiles))
	}
	if err := syncSnapshotIdPProfiles(decoded); err != nil {
		t.Fatalf("DP sync: %v", err)
	}
	if got := idpRegistry.Get("corp").SessionsNotBefore; got != cut {
		t.Fatalf("the DP stored cutoff %d, want the CP's %d verbatim", got, cut)
	}
	if out, ok := c72ResolveMintedAt(t, "corp", cut-60); ok || out.identity != "" {
		t.Fatalf("the DP admitted a cookie minted before the CP's cutoff: proceed=%v identity=%q", ok, out.identity)
	}
	if _, ok := c72ResolveMintedAt(t, "corp", cut+60); !ok {
		t.Fatal("control: the DP must admit a cookie minted after the cutoff")
	}
}
