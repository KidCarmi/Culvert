package registry

import (
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

func newReg(t *testing.T) *Registry {
	t.Helper()
	return New(limits.DefaultCatalog())
}

func goodReg(id ServerID) Registration {
	return Registration{
		ID:                id,
		Endpoint:          "mcp://" + Endpoint(id) + ".example",
		PinnedIdentity:    "spiffe://culvert/" + Identity(id),
		Capability:        protocol.Gateway,
		CredentialProfile: "cred-" + CredentialProfile(id),
		OwnerScope:        "tenant-a",
	}
}

func TestRegisterValid(t *testing.T) {
	r := newReg(t)
	rec, err := r.Register(goodReg("s1"))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !rec.Usable() || rec.Verification != VerifyVerified || !rec.Enabled {
		t.Fatalf("new record not usable/verified: %+v", rec)
	}
	if r.Current().Len() != 1 || r.Current().Revision() != 1 {
		t.Fatalf("snapshot len/rev = %d/%d", r.Current().Len(), r.Current().Revision())
	}
	got, ok := r.Current().Get("s1")
	if !ok || got.ID != "s1" {
		t.Fatal("registered server not retrievable")
	}
}

func TestRegisterRejections(t *testing.T) {
	r := newReg(t)
	cases := map[string]Registration{
		"empty-id":         {ID: "", Endpoint: "e", PinnedIdentity: "i", Capability: protocol.Gateway},
		"empty-endpoint":   {ID: "s", Endpoint: "", PinnedIdentity: "i", Capability: protocol.Gateway},
		"missing-identity": {ID: "s", Endpoint: "e", PinnedIdentity: "", Capability: protocol.Gateway},
		"management-ns":    {ID: "s", Endpoint: "e", PinnedIdentity: "i", Capability: protocol.Management},
		"endpoint-ws":      {ID: "s", Endpoint: "e p", PinnedIdentity: "i", Capability: protocol.Gateway},
		"id-control":       {ID: "s\x01", Endpoint: "e", PinnedIdentity: "i", Capability: protocol.Gateway},
	}
	for name, in := range cases {
		if _, err := r.Register(in); mcperr.ReasonOf(err) != mcperr.ReasonInvalidRegistration {
			t.Fatalf("%s: want invalid_registration, got %v", name, err)
		}
	}
}

func TestRegisterDuplicateID(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(goodReg("s1")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(goodReg("s1")); mcperr.ReasonOf(err) != mcperr.ReasonInvalidRegistration {
		t.Fatalf("duplicate id: want invalid_registration, got %v", err)
	}
	if r.Current().Len() != 1 {
		t.Fatal("duplicate registration mutated the registry")
	}
}

func TestRegisterConflictingEndpoint(t *testing.T) {
	r := newReg(t)
	a := goodReg("s1")
	b := goodReg("s2")
	b.Endpoint = a.Endpoint // same canonical endpoint, different id
	if _, err := r.Register(a); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(b); mcperr.ReasonOf(err) != mcperr.ReasonInvalidRegistration {
		t.Fatalf("endpoint alias collision: want invalid_registration, got %v", err)
	}
}

func TestExactIdentityMatch(t *testing.T) {
	r := newReg(t)
	in := goodReg("s1")
	_, _ = r.Register(in)
	v, rec, err := r.VerifyIdentity("s1", in.PinnedIdentity)
	if err != nil || v != VerifyVerified || !rec.Usable() {
		t.Fatalf("exact match should verify cleanly: v=%v err=%v", v, err)
	}
}

func TestIdentityMismatchDisables(t *testing.T) {
	r := newReg(t)
	in := goodReg("s1")
	_, _ = r.Register(in)
	v, rec, err := r.VerifyIdentity("s1", "spiffe://evil/imposter")
	if v != VerifyIdentityMismatch || mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("mismatch: v=%v err=%v", v, err)
	}
	if rec.Enabled || rec.Usable() || rec.Verification != VerifyIdentityMismatch {
		t.Fatalf("server not disabled on mismatch: %+v", rec)
	}
	// The stored snapshot reflects the disable.
	cur, _ := r.Current().Get("s1")
	if cur.Usable() {
		t.Fatal("snapshot still shows the server usable after mismatch")
	}
	// A mismatched server cannot be re-enabled by an admin flag.
	if _, err := r.SetEnabled("s1", true); mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("re-enable of mismatched server should fail, got %v", err)
	}
}

func TestRepinRecoversMismatchedServer(t *testing.T) {
	r := newReg(t)
	in := goodReg("s1")
	_, _ = r.Register(in)
	// Mismatch disables the server.
	if _, _, err := r.VerifyIdentity("s1", "spiffe://evil/x"); mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("verify: %v", err)
	}
	if cur, _ := r.Current().Get("s1"); cur.Usable() {
		t.Fatal("precondition: server should be disabled")
	}
	// Repin to a freshly verified identity restores it under the stable id.
	rec, err := r.Repin("s1", "spiffe://culvert/s1-rotated", time.Unix(2000, 0))
	if err != nil {
		t.Fatalf("repin: %v", err)
	}
	if !rec.Usable() || rec.Verification != VerifyVerified || rec.PinnedIdentity != "spiffe://culvert/s1-rotated" {
		t.Fatalf("repinned record not usable/re-pinned: %+v", rec)
	}
	// The new identity now verifies; the old one mismatches.
	if v, _, err := r.VerifyIdentity("s1", "spiffe://culvert/s1-rotated"); v != VerifyVerified || err != nil {
		t.Fatalf("new identity should verify: v=%v err=%v", v, err)
	}
	// Repin of an unknown id fails.
	if _, err := r.Repin("nope", "x", time.Unix(2000, 0)); mcperr.ReasonOf(err) != mcperr.ReasonUnregisteredServer {
		t.Fatalf("repin unknown: want unregistered_server, got %v", err)
	}
	// Repin with an empty identity fails.
	if _, err := r.Repin("s1", "", time.Unix(2000, 0)); mcperr.ReasonOf(err) != mcperr.ReasonInvalidRegistration {
		t.Fatalf("repin empty identity: want invalid_registration, got %v", err)
	}
}

func TestVerifyUnregistered(t *testing.T) {
	r := newReg(t)
	if _, _, err := r.VerifyIdentity("nope", "x"); mcperr.ReasonOf(err) != mcperr.ReasonUnregisteredServer {
		t.Fatalf("verify unknown: want unregistered_server, got %v", err)
	}
}

func TestSnapshotImmutability(t *testing.T) {
	r := newReg(t)
	_, _ = r.Register(goodReg("s1"))
	snap1 := r.Current()
	_, _ = r.Register(goodReg("s2"))
	// The captured snapshot did not grow.
	if snap1.Len() != 1 {
		t.Fatalf("old snapshot mutated: len = %d", snap1.Len())
	}
	if r.Current().Len() != 2 {
		t.Fatal("new snapshot missing the second server")
	}
	// A returned record copy cannot mutate the store.
	rec, _ := snap1.Get("s1")
	rec.Enabled = false
	again, _ := r.Current().Get("s1")
	if !again.Enabled {
		t.Fatal("mutating a returned record copy changed the store")
	}
}

func TestServerCapacity(t *testing.T) {
	cfg := smallCatalog(t)
	r := New(cfg)
	// MaxServers is 2 in the small config.
	if _, err := r.Register(goodReg("s1")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(goodReg("s2")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(goodReg("s3")); mcperr.ReasonOf(err) != mcperr.ReasonCapacityExceeded {
		t.Fatalf("capacity: want capacity_exceeded, got %v", err)
	}
}

func TestConcurrentRegistrationAndVerify(t *testing.T) {
	r := newReg(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := ServerID(rune('a'+i%26)) + ServerID(itoa(i))
			_, _ = r.Register(goodReg(id))
		}(i)
	}
	// Concurrent readers must never see a torn snapshot.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = r.Current().Servers()
			}
		}()
	}
	wg.Wait()
	if r.Current().Len() == 0 {
		t.Fatal("no servers registered under concurrency")
	}
}

func smallCatalog(t *testing.T) limits.CatalogLimits {
	t.Helper()
	c, err := limits.NewCatalog(limits.CatalogConfig{
		MaxServers: 2, MaxToolsPerServer: 4, MaxCatalogEntries: 8,
		MaxDiscoveryBytes: 65536, MaxSchemaBytes: 4096, MaxDescriptionBytes: 1024,
		MaxSchemaDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64, MaxDiffOps: 4096,
		MaxNameBytes: 128, MaxEndpointBytes: 512, MaxIdentityBytes: 512,
		MaxServerIDBytes: 128, MaxCredProfileBytes: 128, MaxOwnerScopeBytes: 128,
	})
	if err != nil {
		t.Fatalf("small catalog limits: %v", err)
	}
	return c
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
