package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withRevocationsFile points the package persistence path at a temp file for
// the duration of t.
func withRevocationsFile(t *testing.T) string {
	t.Helper()
	prev := RevocationsPath()
	path := filepath.Join(t.TempDir(), "revocations.json")
	SetRevocationsPath(path)
	t.Cleanup(func() { SetRevocationsPath(prev) })
	return path
}

// More than MaxRevocationEntries VERIFIED revocations must all survive a
// reload: the untrusted-entry cap applied on reload silently dropped the
// excess, and which sessions resurrected depended on map order (Codex P2,
// CodeRabbit, PR #1591).
func TestProvenance_VerifiedRevocationsReloadPastTheCap(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	withRevocationsFile(t)

	n := MaxRevocationEntries + 50
	exp := time.Now().Add(time.Hour)
	Revoked.mu.Lock()
	for i := 0; i < n; i++ {
		tok := fmt.Sprintf("verified-%06d", i)
		Revoked.tokens[tok] = exp
		Revoked.verified[tok] = struct{}{}
	}
	Revoked.mu.Unlock()
	if err := Revoked.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}

	Revoked.SwapForTest() // the restart; restored by withFreshRevocationList
	if err := Revoked.LoadRevocations(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := Revoked.Tracked(); got != n {
		t.Fatalf("after reload %d entries; want %d — verified revocations were dropped at the cap", got, n)
	}
}

// Persisted entries WITHOUT a valid provenance MAC stay untrusted: an
// oversized one is refused, and so is one whose MAC was copied from another
// entry or computed for a different expiry.
func TestProvenance_UnauthenticatedPersistedEntriesStayBounded(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	path := withRevocationsFile(t)
	ResetRefusalCountersForTest()
	t.Cleanup(ResetRefusalCountersForTest)

	exp := time.Now().Add(time.Hour).Unix()
	big := strings.Repeat("x", MaxRevocationTokenLen+1)
	entries := []RevocationEntry{
		{Token: big, Expiry: exp},                                            // no MAC
		{Token: big + "y", Expiry: exp, Prov: provenanceMAC(big, exp)},       // MAC for another token
		{Token: big + "z", Expiry: exp, Prov: provenanceMAC(big+"z", exp+1)}, // MAC for another expiry
		{Token: "ok-but-unverified", Expiry: exp},                            // ordinary untrusted entry
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Revoked.LoadRevocations(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := Revoked.Tracked(); got != 1 {
		t.Fatalf("loaded %d entries; want 1 (only the in-bound untrusted entry)", got)
	}
	if got := Refused(RevokeOversize); got != 3 {
		t.Errorf("oversize refusals = %d; want 3", got)
	}
}

// The provenance MAC is written to the persistence file only; the gossip
// export is unchanged, and the MAC is never the cookie signature.
func TestProvenance_NotOnTheWireAndNotACookieSignature(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	Revoked.mu.Lock()
	Revoked.tokens["tok"] = time.Now().Add(time.Hour)
	Revoked.verified["tok"] = struct{}{}
	Revoked.mu.Unlock()

	for _, e := range Revoked.ExportRevocations() {
		if e.Prov != "" {
			t.Fatalf("gossip export carries a provenance MAC: %+v", e)
		}
	}
	persisted := Revoked.exportPersisted()
	if len(persisted) != 1 || persisted[0].Prov == "" {
		t.Fatalf("persisted export = %+v; want one entry with a provenance MAC", persisted)
	}
	if persisted[0].Prov == mac("tok") {
		t.Fatal("the provenance MAC equals the cookie signature; the file would hold a usable cookie")
	}
}
