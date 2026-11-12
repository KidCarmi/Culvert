package pseudonym

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// MintID's contract, and the reason it exists: an id-only caller must get a
// usable id without touching the key state and without spending a key.
//
// NOTE ON WHAT IS NOT TESTED HERE, because the absence is deliberate. mintID's
// counter fallback and MintPair's error leg are unreachable on the pinned
// toolchain: crypto/rand.Read never returns an error and instead crashes the
// program irrecoverably (go.dev/issue/66821), so swapping crypto/rand.Reader for
// a failing source does not exercise the fallback — it kills the test binary.
// The gates below therefore pin the reachable contract, and mintID's comment
// records the dead branch rather than this file pretending to cover it.

// MintID must never return the empty string. "" is the value KeyID reports for
// "no key is installed", so publishing it beside a VALID key would make an
// active node read as keyless on the admin API and give a client resolving an
// unknown-outcome rotation nothing to compare.
func TestMintID_ReturnsAUsableID(t *testing.T) {
	p := New()
	for i := 0; i < 8; i++ {
		id := p.MintID()
		if id == "" {
			t.Fatal("MintID returned the empty id — indistinguishable from no key installed")
		}
		if len(id) != 16 {
			t.Fatalf("MintID = %q (len %d), want 16 hex characters", id, len(id))
		}
		if strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("MintID = %q, want lowercase hex only", id)
		}
	}
}

// MintID mints an id and NOTHING else: it must not install, rotate or otherwise
// disturb the key state, and it must not spend a 32-byte key the caller throws
// away. Checked on a KEYED pseudonymizer, where a silent Set would be visible as
// a changed token.
func TestMintID_DoesNotTouchKeyState(t *testing.T) {
	p := New()
	key := make([]byte, KeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	p.SetPair(key, "feedfacecafebabe")
	before := p.Pseudonymize("news.example.test")

	if id := p.MintID(); id == "" {
		t.Fatal("MintID returned the empty id")
	}
	if got := p.KeyID(); got != "feedfacecafebabe" {
		t.Fatalf("KeyID = %q after MintID, want the installed id unchanged", got)
	}
	if got := p.Pseudonymize("news.example.test"); got != before {
		t.Fatalf("token changed after MintID: %q -> %q (the key was disturbed)", before, got)
	}
	if !bytes.Equal(p.Key(), key) {
		t.Fatal("MintID replaced the installed key")
	}
}

// The id is minted independently of key material: two pseudonymizers holding the
// SAME key must not mint the same id, which is what "never derived from the key"
// means operationally (nothing derivable from the key leaves the node).
func TestMintID_IndependentOfKeyMaterial(t *testing.T) {
	key := make([]byte, KeyLen)
	for i := range key {
		key[i] = 0xAB
	}
	a, b := New(), New()
	a.SetPair(key, "aaaaaaaaaaaaaaaa")
	b.SetPair(key, "bbbbbbbbbbbbbbbb")
	if ida, idb := a.MintID(), b.MintID(); ida == idb {
		t.Fatalf("two pseudonymizers with the same key minted the same id %q", ida)
	}
}

// Concurrent minting: every id is non-empty and distinct. MintID takes no lock,
// so this is also the race gate for the id path under -race.
func TestMintID_ConcurrentIDsAreUniqueAndNonEmpty(t *testing.T) {
	p := New()
	const n = 64
	ids := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) { defer wg.Done(); ids[i] = p.MintID() }(i)
	}
	wg.Wait()
	seen := make(map[string]bool, n)
	for _, id := range ids {
		if id == "" {
			t.Fatal("concurrent MintID returned the empty id")
		}
		if seen[id] {
			t.Fatalf("duplicate id %q across concurrent mints", id)
		}
		seen[id] = true
	}
}
