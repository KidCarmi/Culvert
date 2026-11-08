package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
)

func swapIdPRegistryForPersistenceTest(t *testing.T, r *IdPRegistry) {
	t.Helper()
	orig := idpRegistry
	idpRegistry = r
	t.Cleanup(func() { idpRegistry = orig })
}

func TestCheckIdPPersistence(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		profiles int
		want     string
	}{
		{"in-memory with profiles warns", "", 2, diagWarn},
		{"in-memory empty is ok", "", 0, diagOK},
		{"persisted with profiles is ok", filepath.Join(t.TempDir(), "idp.json"), 2, diagOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &IdPRegistry{path: tc.path, live: map[string]IdentityProvider{}}
			for i := 0; i < tc.profiles; i++ {
				r.profiles = append(r.profiles, &IdPProfile{ID: string(rune('a' + i))})
			}
			swapIdPRegistryForPersistenceTest(t, r)
			c := checkIdPPersistence()
			if c.Code != "idp_profiles_persistence" || c.Status != tc.want {
				t.Fatalf("got %s/%s, want status %s", c.Code, c.Status, tc.want)
			}
			if (c.Status == diagWarn) != (c.OperatorAction != "") {
				t.Fatalf("OperatorAction %q inconsistent with status %s", c.OperatorAction, c.Status)
			}
			// TestApiDiagnostics_NoSensitiveValues forbids raw filesystem paths
			// in the report; pin it here, where the warn row is guaranteed.
			if strings.Contains(c.Message+c.OperatorAction, "/data/") {
				t.Fatalf("row leaks a filesystem path: %q / %q", c.Message, c.OperatorAction)
			}
		})
	}
}

func TestCheckIdPPersistence_RegisteredInOperatorContract(t *testing.T) {
	r := &IdPRegistry{live: map[string]IdentityProvider{}, profiles: []*IdPProfile{{ID: "x"}}}
	swapIdPRegistryForPersistenceTest(t, r)
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "idp_profiles_persistence" {
			if c.Status != diagWarn {
				t.Fatalf("status = %s, want warn", c.Status)
			}
			return
		}
	}
	t.Fatal("idp_profiles_persistence missing from the operator contract")
}

// An enrolled DP without -idp-profiles-file still survives a restart: the
// full snapshot it persists as last-known-good carries IdPProfiles, and
// applyDPLastGoodConfigSnapshot re-syncs them into the registry at startup
// (dp_enrollment.go). That DP must not be told its profiles will be lost. Every
// other in-memory registry keeps the warning.
func TestCheckIdPPersistence_DPLastGoodSnapshotPersistsProfiles(t *testing.T) {
	withDPLastGoodConfigTestGlobals(t)
	origDP := audit.DPMode()
	origClient := activeDPClient.Load()
	t.Cleanup(func() {
		audit.SetDPMode(origDP)
		activeDPClient.Store(origClient)
	})
	profiles := []*IdPProfile{{ID: "a"}, {ID: "b"}}
	r := &IdPRegistry{live: map[string]IdentityProvider{}, profiles: profiles}
	swapIdPRegistryForPersistenceTest(t, r)

	steps := []struct {
		name  string
		setup func()
		want  string
	}{
		{"standalone node, no snapshot", func() { audit.SetDPMode(false); activeDPClient.Store(nil) }, diagWarn},
		{"DP that never received a snapshot", func() { audit.SetDPMode(true); activeDPClient.Store(&DataPlaneClient{}) }, diagWarn},
		{"DP persisted a snapshot without IdP profiles (unenrolled/redacted)", func() {
			persistDPLastGoodConfigSnapshot(ConfigSnapshot{Version: 3})
		}, diagWarn},
		{"DP persisted a snapshot carrying the IdP profiles", func() {
			persistDPLastGoodConfigSnapshot(ConfigSnapshot{Version: 4, IdPProfiles: profiles})
		}, diagOK},
		{"DP restored the profiles from the last-good snapshot at startup", func() {
			dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{})
			if _, err := loadDPLastGoodConfigSnapshot(); err != nil {
				t.Fatalf("load last-good snapshot: %v", err)
			}
		}, diagOK},
		{"DP whose latest last-good persist failed", func() {
			setDPLastGoodConfigSnapshotSaveError(5, errors.New("disk full"))
		}, diagWarn},
		{"same snapshot state but not a data plane", func() {
			persistDPLastGoodConfigSnapshot(ConfigSnapshot{Version: 6, IdPProfiles: profiles})
			audit.SetDPMode(false)
		}, diagWarn},
	}
	for _, s := range steps {
		s.setup()
		c := checkIdPPersistence()
		if c.Status != s.want {
			t.Fatalf("%s: status = %s (%q), want %s", s.name, c.Status, c.Message, s.want)
		}
		if (c.Status == diagWarn) != (c.OperatorAction != "") {
			t.Fatalf("%s: OperatorAction %q inconsistent with status %s", s.name, c.OperatorAction, c.Status)
		}
	}
}

// The last-good exemption holds only while the registry still equals what the
// on-disk snapshot restores. A local create, update or delete on the DP
// (apiIdPList/apiIdPItem allow them) changes the registry but not the
// last-good file, so a restart reverts it: the row must warn until a persisted
// snapshot matches the registry again.
func TestCheckIdPPersistence_DPLocalMutationInvalidatesLastGoodExemption(t *testing.T) {
	withDPLastGoodConfigTestGlobals(t)
	origDP := audit.DPMode()
	origClient := activeDPClient.Load()
	t.Cleanup(func() {
		audit.SetDPMode(origDP)
		activeDPClient.Store(origClient)
	})
	audit.SetDPMode(true)
	activeDPClient.Store(&DataPlaneClient{})
	r := &IdPRegistry{live: map[string]IdentityProvider{}}
	swapIdPRegistryForPersistenceTest(t, r)

	profile := func(id, name string) *IdPProfile {
		return &IdPProfile{ID: id, Name: name, Type: IdPTypeOIDC, EmailDomains: []string{"corp.example"},
			KnownGroups: []string{}, OIDC: &OIDCProfileConfig{Issuer: "https://idp.example.com", ClientID: id}}
	}
	expect := func(step, want string) {
		t.Helper()
		c := checkIdPPersistence()
		if c.Status != want {
			t.Fatalf("%s: status = %s (%q), want %s", step, c.Status, c.Message, want)
		}
		if (c.Status == diagWarn) != (c.OperatorAction != "") {
			t.Fatalf("%s: OperatorAction %q inconsistent with status %s", step, c.OperatorAction, c.Status)
		}
	}
	applyAndPersist := func(version int64, profiles []*IdPProfile) {
		t.Helper()
		snap := ConfigSnapshot{Version: version, IdPProfiles: profiles}
		if err := syncSnapshotIdPProfiles(snap); err != nil {
			t.Fatalf("sync snapshot v%d: %v", version, err)
		}
		persistDPLastGoodConfigSnapshot(snap)
	}
	mustDo := func(step string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}

	// The review scenario: the CP sent IdPProfiles: [] and a provider is then
	// created locally. A restart restores the empty set.
	applyAndPersist(1, []*IdPProfile{})
	expect("empty snapshot, empty registry", diagOK)
	mustDo("local create", r.Upsert(profile("lg-new", "Created")))
	expect("local create after an empty snapshot", diagWarn)

	// Snapshot X applied and persisted: registry == X.
	snapX := []*IdPProfile{profile("lg-a", "A"), profile("lg-b", "B")}
	applyAndPersist(2, snapX)
	expect("registry equals persisted snapshot X", diagOK)

	// The same after a cold start from the on-disk file.
	dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{})
	restored, err := loadDPLastGoodConfigSnapshot()
	mustDo("load last-good", err)
	mustDo("restore last-good", syncSnapshotIdPProfiles(restored))
	expect("registry restored from persisted snapshot X", diagOK)

	mustDo("local create", r.Upsert(profile("lg-c", "C")))
	expect("local create after snapshot X", diagWarn)
	mustDo("local delete of the created profile", r.Delete("lg-c"))
	expect("local create undone by a delete", diagOK)

	mustDo("local update", r.Upsert(profile("lg-a", "A renamed")))
	expect("local update after snapshot X", diagWarn)
	mustDo("local update reverted", r.Upsert(profile("lg-a", "A")))
	expect("local update reverted", diagOK)

	mustDo("local delete", r.Delete("lg-b"))
	expect("local delete after snapshot X", diagWarn)

	// The next applied and persisted snapshot re-establishes the exemption.
	applyAndPersist(3, snapX)
	expect("snapshot X re-applied and persisted", diagOK)

	// A persist failure still withdraws it even when the registry matches.
	setDPLastGoodConfigSnapshotSaveError(4, errors.New("disk full"))
	expect("matching registry but the latest persist failed", diagWarn)
}
