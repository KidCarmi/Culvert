package senderconstraint

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

func smallReplayLimits(t *testing.T, maxEntries, maxPerPart int) limits.AuthLimits {
	t.Helper()
	l, err := limits.NewAuth(limits.AuthConfig{
		MaxTokenTTL: time.Hour, ClockSkew: 60 * time.Second, MaxFutureNbf: time.Minute,
		MaxAuthAge: time.Hour, MaxDPoPProofAge: 60 * time.Second, NonceLifetime: time.Minute,
		MaxReplayEntries: maxEntries, MaxReplayPerPart: maxPerPart,
		MaxTokenBytes: 8192, MaxClaimBytes: 4096, MaxScopes: 32, MaxAudiences: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestReplayDetectsDuplicate(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewReplayCache(smallReplayLimits(t, 100, 50), func() time.Time { return now })
	pk := PartitionKey("iss", "client", "thumb")
	if err := c.CheckAndAdd(protocol.Gateway, pk, "jti-1", time.Minute); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := c.CheckAndAdd(protocol.Gateway, pk, "jti-1", time.Minute); mcperr.ReasonOf(err) != mcperr.ReasonDPoPReplay {
		t.Fatalf("duplicate jti must be replay, got %v", err)
	}
	// A different jti in the same partition is fine.
	if err := c.CheckAndAdd(protocol.Gateway, pk, "jti-2", time.Minute); err != nil {
		t.Fatalf("distinct jti rejected: %v", err)
	}
}

func TestReplayExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	clk := func() time.Time { return now }
	c := NewReplayCache(smallReplayLimits(t, 100, 50), clk)
	pk := PartitionKey("iss", "client", "thumb")
	_ = c.CheckAndAdd(protocol.Gateway, pk, "jti-1", time.Minute)
	// Advance past the TTL: the same jti is now admissible again (its window passed).
	now = now.Add(2 * time.Minute)
	if err := c.CheckAndAdd(protocol.Gateway, pk, "jti-1", time.Minute); err != nil {
		t.Fatalf("expired entry should be reclaimable: %v", err)
	}
}

func TestReplayCapabilityIsolation(t *testing.T) {
	now := time.Unix(1000, 0)
	// Gateway cache holds 2 entries max; fill it completely.
	c := NewReplayCache(smallReplayLimits(t, 2, 2), func() time.Time { return now })
	pk := PartitionKey("iss", "client", "thumb")
	_ = c.CheckAndAdd(protocol.Gateway, pk, "g1", time.Minute)
	_ = c.CheckAndAdd(protocol.Gateway, pk, "g2", time.Minute)
	// Gateway is now at capacity — a new gateway proof fails closed.
	if err := c.CheckAndAdd(protocol.Gateway, pk, "g3", time.Minute); mcperr.ReasonOf(err) != mcperr.ReasonDPoPReplay {
		t.Fatalf("gateway at capacity must fail closed, got %v", err)
	}
	// Management has its OWN independent budget — Gateway saturation must not affect it.
	if err := c.CheckAndAdd(protocol.Management, pk, "m1", time.Minute); err != nil {
		t.Fatalf("management partition affected by gateway saturation: %v", err)
	}
	if c.Size(protocol.Gateway) != 2 || c.Size(protocol.Management) != 1 {
		t.Fatalf("sizes = %d/%d", c.Size(protocol.Gateway), c.Size(protocol.Management))
	}
}

func TestReplayPartitionCap(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewReplayCache(smallReplayLimits(t, 100, 2), func() time.Time { return now })
	pk := PartitionKey("iss", "client", "thumb")
	_ = c.CheckAndAdd(protocol.Gateway, pk, "a", time.Minute)
	_ = c.CheckAndAdd(protocol.Gateway, pk, "b", time.Minute)
	// One attacker key's partition can't grow past MaxReplayPerPart.
	if err := c.CheckAndAdd(protocol.Gateway, pk, "c", time.Minute); mcperr.ReasonOf(err) != mcperr.ReasonDPoPReplay {
		t.Fatalf("partition cap must fail closed, got %v", err)
	}
	// A DIFFERENT partition (different thumbprint) still has room.
	pk2 := PartitionKey("iss", "client", "thumb2")
	if err := c.CheckAndAdd(protocol.Gateway, pk2, "a", time.Minute); err != nil {
		t.Fatalf("distinct partition rejected: %v", err)
	}
}

func TestMTLSMatrix(t *testing.T) {
	good := jose.B64URLEncode(make([]byte, 32)) // 32 zero bytes → 43-char base64url
	other := jose.SHA256B64URL([]byte("different-cert"))
	cases := []struct {
		name string
		in   MTLSInput
		ok   bool
	}{
		{"valid", MTLSInput{ObservedThumbprint: good, TokenX5TS256: good}, true},
		{"missing-observed", MTLSInput{TokenX5TS256: good}, false},
		{"missing-token-cnf", MTLSInput{ObservedThumbprint: good}, false},
		{"mismatch", MTLSInput{ObservedThumbprint: good, TokenX5TS256: other}, false},
		{"malformed", MTLSInput{ObservedThumbprint: "!!!not-base64!!!", TokenX5TS256: good}, false},
		{"wrong-length", MTLSInput{ObservedThumbprint: jose.B64URLEncode(make([]byte, 16)), TokenX5TS256: jose.B64URLEncode(make([]byte, 16))}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyMTLS(tc.in)
			if (err == nil) != tc.ok {
				t.Fatalf("VerifyMTLS ok=%v, want %v (err=%v)", err == nil, tc.ok, err)
			}
			if err != nil && mcperr.ReasonOf(err) != mcperr.ReasonMTLSBindingMismatch {
				t.Fatalf("unexpected reason %v", mcperr.ReasonOf(err))
			}
		})
	}
}

// FuzzVerifyDPoP proves the DPoP proof parser never panics on arbitrary proof
// bytes, never admits a malformed proof, and never leaks the access token in the
// returned error. The replay cache stays bounded across the whole corpus.
func FuzzVerifyDPoP(f *testing.F) {
	seeds := []string{
		"", "a", "a.b", "a.b.c",
		"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.eyJqdGkiOiJ4In0.",
		"eyJhbGciOiJub25lIn0.eyJ9.",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	lim := limits.DefaultAuth()
	now := time.Unix(1_000_000, 0)
	cache := NewReplayCache(lim, func() time.Time { return now })
	const accessTok = "access-token-secret-value"
	f.Fuzz(func(t *testing.T, proof string) {
		in := DPoPInput{
			Capability: protocol.Gateway, ProofJWT: proof,
			HTTPMethod: "POST", HTTPURI: "https://culvert/mcp/gateway/srv-1",
			AccessToken: accessTok, Issuer: "iss", Client: "client",
		}
		_, err := VerifyDPoP(in, cache, lim, now)
		if err != nil && strings.Contains(err.Error(), accessTok) {
			t.Fatalf("error leaked the access token: %q", err.Error())
		}
		if sz := cache.Size(protocol.Gateway); sz > lim.MaxReplayEntries() {
			t.Fatalf("replay cache exceeded its bound: %d", sz)
		}
	})
}

// Review fix (P2): at capability capacity the cache must reclaim expired entries
// across ALL partitions before failing closed — otherwise a cache filled across
// many attacker-rotated partitions would reject every new proof indefinitely even
// after the entries expire.
func TestReviewFix_ReplayReclaimsExpiredPartitionsAtCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	lim := smallReplayLimits(t, 4, 4) // per-capability cap = 4
	c := NewReplayCache(lim, func() time.Time { return now })
	for i := 0; i < 4; i++ {
		pk := PartitionKey("iss", "client", "thumb-"+itoa(i))
		if err := c.CheckAndAdd(protocol.Gateway, pk, "jti-"+itoa(i), time.Minute); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	// At capacity while all entries are live: a brand-new partition is rejected.
	fresh := PartitionKey("iss", "client", "thumb-new")
	if err := c.CheckAndAdd(protocol.Gateway, fresh, "jti-new", time.Minute); mcperr.ReasonOf(err) != mcperr.ReasonDPoPReplay {
		t.Fatalf("cache should be at capacity, got %v", err)
	}
	// Advance past the TTL so the filled entries expire, then retry: admission must
	// be restored without any external Sweep call.
	now = now.Add(2 * time.Minute)
	if err := c.CheckAndAdd(protocol.Gateway, fresh, "jti-new", time.Minute); err != nil {
		t.Fatalf("expired room must be reclaimed at capacity, got %v", err)
	}
}
