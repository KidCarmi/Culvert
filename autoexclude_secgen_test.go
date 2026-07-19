package main

import (
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// PR2 integration: a learned adaptive-decryption exclusion is fenced to the owning
// profile's security generation. These tests drive the REAL hot path
// (resolveSSLAction → failOpenScopeForRule → Contains) so the profile-store gen and
// the cache gen are proven to agree end-to-end.

// foByID seeds a fail-open profile with the given security fields and returns a match
// whose rule references it BY ID (rename-safe), plus the profile's scope ID.
func foByID(t *testing.T, p DecryptionProfile) (match *PolicyMatch, scopeID string) {
	t.Helper()
	p.OnInspectError = "fail-open"
	added, err := globalDecryptionProfiles.Add(p)
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	m := &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect,
		Rule: &PolicyRule{Name: "r-" + p.Name, SSLAction: SSLInspect, DecryptionProfile: p.Name, DecryptionProfileID: added.ID}}
	return m, added.ID
}

// learn seeds an active exclusion under the profile's CURRENT gen (what the
// production learn path would stamp).
func learn(t *testing.T, scope, host string) {
	t.Helper()
	p := globalDecryptionProfiles.GetByID(scope)
	if p == nil {
		t.Fatalf("profile %q gone", scope)
	}
	autoExclude().Observe(scope, p.SecurityGen(), p.Name, host, autoexclude.ReasonUnsupportedParams, "id:seed")
}

// TestSecGen_RenamePreservesExclusion — a rename is cosmetic: the gen is unchanged,
// so the learned exclusion still self-heals.
func TestSecGen_RenamePreservesExclusion(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	m, scope := foByID(t, DecryptionProfile{Name: "fo", CertVerification: "strict"})
	learn(t, scope, "host.example")
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLBypass {
		t.Fatal("precondition: excluded host must bypass")
	}
	if _, err := globalDecryptionProfiles.Rename(scope, "fo-renamed"); err != nil {
		t.Fatal(err)
	}
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLBypass {
		t.Fatalf("rename must PRESERVE the exclusion (gen unchanged): got %v", a)
	}
}

// TestSecGen_NoopEditPreservesExclusion — re-saving identical security fields (a
// display-only / no-op edit) keeps the gen, so the exclusion survives.
func TestSecGen_NoopEditPreservesExclusion(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	m, scope := foByID(t, DecryptionProfile{Name: "fo", CertVerification: "strict", MinTLSVersion: "1.2"})
	learn(t, scope, "host.example")
	if err := globalDecryptionProfiles.Update(DecryptionProfile{Name: "fo", OnInspectError: "fail-open", CertVerification: "strict", MinTLSVersion: "1.2"}); err != nil {
		t.Fatal(err)
	}
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLBypass {
		t.Fatalf("a no-op edit must preserve the exclusion: got %v", a)
	}
}

// securityEditCases drives each security-effective field: an edit must INVALIDATE
// the learned exclusion (re-inspect immediately).
func TestSecGen_SecurityEditInvalidates(t *testing.T) {
	cases := []struct {
		name  string
		start DecryptionProfile
		edit  DecryptionProfile // full replacement body (name "fo", OnInspectError fail-open kept)
	}{
		{"cert-verification", DecryptionProfile{Name: "fo", CertVerification: "strict"}, DecryptionProfile{Name: "fo", OnInspectError: "fail-open", CertVerification: "skip"}},
		{"tls-floor", DecryptionProfile{Name: "fo", MinTLSVersion: "1.2"}, DecryptionProfile{Name: "fo", OnInspectError: "fail-open", MinTLSVersion: "1.3"}},
		{"tls-cap", DecryptionProfile{Name: "fo", MinTLSVersion: "1.2", MaxTLSVersion: "1.3"}, DecryptionProfile{Name: "fo", OnInspectError: "fail-open", MinTLSVersion: "1.2"}},
		{"on-unsupported", DecryptionProfile{Name: "fo", OnUnsupported: "fail-close"}, DecryptionProfile{Name: "fo", OnInspectError: "fail-open", OnUnsupported: "fail-open"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
			swapProfiles(t)
			m, scope := foByID(t, c.start)
			learn(t, scope, "host.example")
			if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLBypass {
				t.Fatal("precondition: excluded host must bypass")
			}
			if err := globalDecryptionProfiles.Update(c.edit); err != nil {
				t.Fatalf("edit: %v", err)
			}
			if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLInspect {
				t.Fatalf("a %s edit must INVALIDATE the exclusion (re-inspect): got %v", c.name, a)
			}
		})
	}
}

// TestSecGen_InspectHTTP2ChangeInvalidates — the inspection-mode (native-H2 vs
// strip) posture is security-effective; flipping it invalidates the exclusion.
func TestSecGen_InspectHTTP2ChangeInvalidates(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	h2 := true
	m, scope := foByID(t, DecryptionProfile{Name: "fo", InspectHTTP2: &h2})
	learn(t, scope, "host.example")
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLBypass {
		t.Fatal("precondition: excluded host must bypass")
	}
	no := false
	if err := globalDecryptionProfiles.Update(DecryptionProfile{Name: "fo", OnInspectError: "fail-open", InspectHTTP2: &no}); err != nil {
		t.Fatal(err)
	}
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("an InspectHTTP2 change must invalidate the exclusion: got %v", a)
	}
}

// TestSecGen_FailOpenToFailCloseImmediate — flipping to fail-close both (a) removes
// the fail-open gate so the cache is never consulted, AND (b) changes the gen. The
// previously-excluded host re-inspects immediately.
func TestSecGen_FailOpenToFailCloseImmediate(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	m, scope := foByID(t, DecryptionProfile{Name: "fo", CertVerification: "strict"})
	learn(t, scope, "host.example")
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLBypass {
		t.Fatal("precondition: excluded host must bypass")
	}
	if err := globalDecryptionProfiles.Update(DecryptionProfile{Name: "fo", OnInspectError: "fail-close", CertVerification: "strict"}); err != nil {
		t.Fatal(err)
	}
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("fail-open→fail-close must stop consulting the cache immediately: got %v", a)
	}
}

// TestSecGen_DeletedRecreatedIsolated — deleting and recreating a profile mints a
// NEW ID, so the old scope's exclusion is naturally isolated (unchanged from today).
func TestSecGen_DeletedRecreatedIsolated(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	_, oldScope := foByID(t, DecryptionProfile{Name: "fo", CertVerification: "strict"})
	learn(t, oldScope, "host.example")
	if err := globalDecryptionProfiles.Delete("fo"); err != nil {
		t.Fatal(err)
	}
	m2, newScope := foByID(t, DecryptionProfile{Name: "fo", CertVerification: "strict"})
	if newScope == oldScope {
		t.Fatal("recreated profile must get a new ID")
	}
	if a := resolveSSLAction(m2, "host.example", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("recreated profile (new ID) must not consume the old scope's exclusion: got %v", a)
	}
}

// TestSecGen_CPtoDPDeterministic — two independent stores (CP and DP) fed the same
// profile fields derive the SAME gen, so a snapshot round-trip cannot silently
// disagree about which exclusions are valid.
func TestSecGen_CPtoDPDeterministic(t *testing.T) {
	fields := DecryptionProfile{Name: "fo", OnInspectError: "fail-open", CertVerification: "strict", MinTLSVersion: "1.2", OnUnsupported: "fail-close"}
	cp := decryptprofile.New()
	dp := decryptprofile.New()
	cpAdded, _ := cp.Add(fields)
	// DP receives the profile via the sync path (ReplaceAll), preserving the ID.
	dp.ReplaceAll([]DecryptionProfile{{ID: cpAdded.ID, Name: fields.Name, OnInspectError: fields.OnInspectError, CertVerification: fields.CertVerification, MinTLSVersion: fields.MinTLSVersion, OnUnsupported: fields.OnUnsupported}})
	_, cpGen, _ := cp.FailOpenScopeByID(cpAdded.ID)
	_, dpGen, ok := dp.FailOpenScopeByID(cpAdded.ID)
	if !ok || cpGen == "" || cpGen != dpGen {
		t.Fatalf("CP gen %q != DP gen %q (snapshot would disagree)", cpGen, dpGen)
	}
}

// TestSecGen_ConcurrentEditAndResolveRaceFree — a profile edit concurrent with the
// per-CONNECT resolve path must be race-free (store mutex + cache RWMutex), under
// -race. Also asserts the terminal state is self-consistent.
func TestSecGen_ConcurrentEditAndResolveRaceFree(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	m, scope := foByID(t, DecryptionProfile{Name: "fo", CertVerification: "strict"})
	learn(t, scope, "host.example")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Editors flip a security field back and forth (each flip changes the gen).
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cv := []string{"strict", "skip"}
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				_ = globalDecryptionProfiles.Update(DecryptionProfile{Name: "fo", OnInspectError: "fail-open", CertVerification: cv[(i+j)%2]})
			}
		}(i)
	}
	// Resolvers hammer the read path.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				_ = resolveSSLAction(m, "host.example", "1.2.3.4")
			}
		}()
	}
	// Let the resolvers run, then stop the editors.
	for i := 0; i < 20000; i++ {
		_ = resolveSSLAction(m, "host.example", "1.2.3.4")
	}
	close(stop)
	wg.Wait()

	// Terminal consistency: resolve once more; whatever the final gen, the decision
	// is either a clean bypass (entry matches the final gen — impossible here since
	// we only ever learned under the initial gen and never re-learned) or inspect.
	// It must be a valid SSL action, and must not panic (the real assertion is -race).
	if a := resolveSSLAction(m, "host.example", "1.2.3.4"); a != SSLInspect && a != SSLBypass {
		t.Fatalf("terminal resolve produced an invalid action %v", a)
	}
}
