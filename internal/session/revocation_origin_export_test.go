package session

// revocation_origin_export_test.go — AU-50 (PR #1437, Codex P1 on the
// revocation gossip request). ExportRevocationsByOrigin is what lets the Data
// Plane send ITS OWN logouts first when the gossip request has to be budgeted.
// The split may decide order only: an entry missing from both halves would be
// a revocation this node silently stopped telling the fleet about.

import (
	"sort"
	"strings"
	"testing"
	"time"
)

func TestAU50_ExportByOriginSplitsVerifiedFromLearned(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)

	raw, err := Encode(&Session{Sub: "au50-local", Exp: time.Now().Add(time.Hour).Unix(), Jti: NewJti()})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if changed, reason := Revoked.RevokeVerified(raw); !changed {
		t.Fatalf("precondition: RevokeVerified refused a genuine cookie (%s)", reason)
	}
	localKey := raw[:strings.LastIndex(raw, ".")]

	exp := time.Now().Add(time.Hour).Unix()
	if n := Revoked.MergeRevocations([]RevocationEntry{
		{Token: "au50-gossiped-token", Expiry: exp},
		{Token: userRevocationTokenPrefix + "au50-user", Expiry: exp, User: "au50-user"},
	}); n != 2 {
		t.Fatalf("precondition: merged %d gossip entries, want 2", n)
	}
	Revoked.RevokeUser("au50-deleted-here")

	local, other := Revoked.ExportRevocationsByOrigin()
	if len(local) != 1 || local[0].Token != localKey {
		t.Errorf("local = %+v, want exactly the MAC-verified logout %q", local, localKey)
	}
	for _, e := range local {
		if e.User != "" || e.Prov != "" {
			t.Errorf("local entry %+v carries User/Prov; the gossip wire must stay unchanged", e)
		}
	}

	// Membership: the union is exactly ExportRevocations.
	tokens := func(es ...[]RevocationEntry) []string {
		var out []string
		for _, s := range es {
			for _, e := range s {
				out = append(out, e.Token)
			}
		}
		sort.Strings(out)
		return out
	}
	got, want := tokens(local, other), tokens(Revoked.ExportRevocations())
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("by-origin union %v != ExportRevocations %v: the split changed membership, not just order", got, want)
	}
	if len(want) != 4 {
		t.Errorf("ExportRevocations returned %d entries, want 4 (1 local token, 1 gossip token, 2 accounts)", len(want))
	}
}

// Negative control: a token learned ONLY from gossip is never reported as
// local, even when it is the token of a real session of ours. Ranking a
// peer's claim as this node's own logout would let a peer occupy the slot
// the budget reserves for the logouts nobody else can propagate.
func TestAU50_ControlGossipedTokenIsNeverLocal(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)

	raw, err := Encode(&Session{Sub: "au50-peer", Exp: time.Now().Add(time.Hour).Unix(), Jti: NewJti()})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	key := raw[:strings.LastIndex(raw, ".")]
	if n := Revoked.MergeRevocations([]RevocationEntry{{Token: key, Expiry: time.Now().Add(time.Hour).Unix()}}); n != 1 {
		t.Fatalf("precondition: gossip merge added %d, want 1", n)
	}
	local, other := Revoked.ExportRevocationsByOrigin()
	if len(local) != 0 {
		t.Errorf("a gossip-only entry was exported as local: %+v", local)
	}
	if len(other) != 1 || other[0].Token != key {
		t.Errorf("other = %+v, want the gossiped token", other)
	}
}
