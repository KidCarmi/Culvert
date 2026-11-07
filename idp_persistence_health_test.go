package main

import (
	"path/filepath"
	"testing"
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
