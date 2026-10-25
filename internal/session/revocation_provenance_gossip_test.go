package session

// revocation_provenance_gossip_test.go — CHAOS-73, review round.
//
// The provenance MAC waives the key-size bound AND the entry cap, and exactly
// one token separates the two origins that may claim it:
//
//	if persisted && validProvenance(e) { … }
//
// Drop `persisted &&` and the gossip path inherits both exemptions. That is
// not a hypothetical edit: the whole fleet shares one session signing key
// (SessionHMAC is distributed CP→DP so sessions work on every node), so a
// peer can COMPUTE a valid provenance MAC. The `persisted` flag — not the
// cryptography — is what keeps a peer out of the local path's exemptions.
//
// Measured before adding this file: removing `persisted &&` passes every
// other CHAOS-73 and provenance gate. The code comments say gossip keeps the
// bound; nothing enforced it.
//
// Note on severity, so the gate is not over-sold: a peer holding the signing
// key can already mint session cookies, so this is not an authentication
// boundary. It is the RESOURCE boundary CHAOS-73's caps exist for — the
// difference between a malfunctioning or compromised node costing this one a
// bounded amount of memory and costing it an unbounded amount.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A gossip entry carrying a VALID provenance MAC must still be bounded.
func TestProvenance_GossipCannotClaimTheLocalExemptions(t *testing.T) {
	t.Run("oversized entry is refused despite valid provenance", func(t *testing.T) {
		withFreshSigningKey(t)
		withFreshRevocationList(t)
		ResetRefusalCountersForTest()

		token := strings.Repeat("p", MaxRevocationTokenLen+1)
		expiry := time.Now().Add(time.Hour).Unix()
		e := RevocationEntry{Token: token, Expiry: expiry, Prov: provenanceMAC(token, expiry)}

		// The MAC really is valid — otherwise this gate proves nothing about
		// the trust boundary, only that a bad MAC is rejected.
		if !validProvenance(e) {
			t.Fatal("setup: the provenance MAC does not verify, so this gate is vacuous")
		}

		if added := Revoked.MergeRevocations([]RevocationEntry{e}); added != 0 {
			t.Errorf("gossip admitted %d oversized entries by presenting a provenance MAC; "+
				"the persisted-only exemption has leaked to the wire", added)
		}
		if Revoked.Tracked() != 0 {
			t.Error("the oversized gossip entry is live in the list")
		}
		if Refused(RevokeOversize) == 0 {
			t.Error("the refusal was not counted as oversize")
		}
	})

	t.Run("cap still applies despite valid provenance", func(t *testing.T) {
		withFreshSigningKey(t)
		withFreshRevocationList(t)
		ResetRefusalCountersForTest()

		// Fill to the cap with ordinary untrusted entries.
		exp := time.Now().Add(time.Hour)
		Revoked.mu.Lock()
		for i := 0; i < MaxRevocationEntries; i++ {
			Revoked.tokens[fmt.Sprintf("filler-%06d", i)] = exp
		}
		Revoked.mu.Unlock()

		token := "gossip-past-the-cap"
		expiry := exp.Unix()
		e := RevocationEntry{Token: token, Expiry: expiry, Prov: provenanceMAC(token, expiry)}
		if !validProvenance(e) {
			t.Fatal("setup: the provenance MAC does not verify, so this gate is vacuous")
		}

		if added := Revoked.MergeRevocations([]RevocationEntry{e}); added != 0 {
			t.Errorf("gossip admitted %d entries past the cap by presenting a provenance "+
				"MAC; a peer can grow this node's list without bound", added)
		}
		if Refused(RevokeCapacity) == 0 {
			t.Error("the refusal was not counted as capacity")
		}
	})

	// THE CONTROL. The cheapest way to pass both cases above is to stop
	// honouring provenance at all, which would re-break the reload the
	// provenance MAC exists to fix. The SAME entry, arriving on the PERSISTED
	// path, must still be admitted past the bound.
	t.Run("control: the same entry is admitted from the file", func(t *testing.T) {
		withFreshSigningKey(t)
		withFreshRevocationList(t)
		ResetRefusalCountersForTest()

		token := strings.Repeat("p", MaxRevocationTokenLen+1)
		expiry := time.Now().Add(time.Hour).Unix()
		e := RevocationEntry{Token: token, Expiry: expiry, Prov: provenanceMAC(token, expiry)}

		if added := Revoked.mergeUntrusted([]RevocationEntry{e}, true); added != 1 {
			t.Fatalf("the persisted path admitted %d entries; want 1 — a genuine oversized "+
				"revocation is no longer restored across a restart", added)
		}
		if !Revoked.IsRevoked(token) {
			t.Error("the restored revocation is not enforced")
		}
	})
}
