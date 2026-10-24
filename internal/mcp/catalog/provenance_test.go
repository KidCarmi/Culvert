package catalog

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// provTool is the one tool every case here ingests. Its bytes are IDENTICAL whichever entrypoint
// carries them, which is the whole point: the two provenances must be distinguishable by how the
// record was obtained, never by what it contains — a seeded result is deliberately shaped exactly
// like a real tools/list, because seedTools produces one by re-encoding operator JSON.
const provTool = `{"name":"read","inputSchema":{"type":"object"}}`

// provRig returns a catalog plus the registry Ingest consults, for the default test server.
func provRig(tb testing.TB) (*Catalog, *registry.Registry) {
	tb.Helper()
	l := limits.DefaultCatalog()
	return New(l), oneServerReg(tb, l)
}

func provRecord(tb testing.TB, c *Catalog) ToolRecord {
	tb.Helper()
	rec, ok := c.Current().Get(ToolKey{Server: testServer, Name: "read"})
	if !ok {
		tb.Fatal("expected the ingested tool to be present")
	}
	return rec
}

// TestProvenance_SeedIsNeverPeerObserved is the property blocker 11 rests on: the operator-seed
// entrypoint cannot produce peer evidence, however the seed is shaped or repeated.
func TestProvenance_SeedIsNeverPeerObserved(t *testing.T) {
	c, reg := provRig(t)
	if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)}); err != nil {
		t.Fatalf("seed ingest: %v", err)
	}
	rec := provRecord(t, c)
	if got := rec.Provenance(); got != OperatorSeeded {
		t.Fatalf("a seeded record must be OperatorSeeded, got %v", got)
	}
	if rec.Observed.Present() {
		t.Fatalf("a seeded record must carry no observation, got %+v", rec.Observed)
	}
	if !rec.Observed.At.IsZero() || rec.Observed.Identity != "" {
		t.Fatalf("a seeded record's observation must be the zero value, got %+v", rec.Observed)
	}
}

// TestProvenance_ObservedEntrypointStampsTheEvidence is the positive control. Without it every
// negative below could be satisfied by an implementation that simply never records an
// observation at all — which would pass each "must not be observed" assertion while making
// peer-observed freshness unreachable.
func TestProvenance_ObservedEntrypointStampsTheEvidence(t *testing.T) {
	c, reg := provRig(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	if _, _, err := c.IngestObserved(reg,
		DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)},
		PeerObservation{At: at, Identity: testIdentity}); err != nil {
		t.Fatalf("observed ingest: %v", err)
	}
	rec := provRecord(t, c)
	if got := rec.Provenance(); got != PeerObserved {
		t.Fatalf("an observed record must be PeerObserved, got %v", got)
	}
	if !rec.Observed.At.Equal(at) {
		t.Fatalf("observation timestamp not recorded: got %v want %v", rec.Observed.At, at)
	}
	if rec.Observed.Identity != testIdentity {
		t.Fatalf("observation identity not recorded: got %q want %q", rec.Observed.Identity, testIdentity)
	}
}

// TestProvenance_ObservedIngestRefusesIncompleteEvidence pins the boundary validation. Half an
// observation is not a weaker observation — it is no observation, and it is refused where it
// enters rather than stored and filtered by some later reader that might forget to.
func TestProvenance_ObservedIngestRefusesIncompleteEvidence(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name string
		obs  PeerObservation
	}{
		{"no timestamp", PeerObservation{Identity: testIdentity}},
		{"no identity", PeerObservation{At: at}},
		{"nothing at all", PeerObservation{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, reg := provRig(t)
			_, _, err := c.IngestObserved(reg,
				DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)}, tc.obs)
			if err == nil {
				t.Fatal("an incomplete observation must be refused")
			}
			if c.Current().Len() != 0 {
				t.Fatal("a refused observation must publish nothing")
			}
		})
	}
}

// TestProvenance_ObservedIdentityMustMatchTheIngestIdentity stops an observation of one peer
// being filed as evidence about another. The ingest identity is itself checked against the LIVE
// registry pin by the common path, so agreeing with it is what ties the evidence to this server.
func TestProvenance_ObservedIdentityMustMatchTheIngestIdentity(t *testing.T) {
	c, reg := provRig(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	_, _, err := c.IngestObserved(reg,
		DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)},
		PeerObservation{At: at, Identity: registry.Identity("spiffe://culvert/someone-else")})
	if mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("a mismatched observation identity must be refused as an identity mismatch, got %v", err)
	}
	if c.Current().Len() != 0 {
		t.Fatal("a refused observation must publish nothing")
	}
}

// TestProvenance_ReseedDowngradesAnObservedRecord is the anti-renewal rule, and it holds for a
// BYTE-IDENTICAL reseed — the case an implementation that "preserves provenance when nothing
// changed" would get wrong. An operator re-running provisioning is not a new sighting of the
// peer; if it preserved the observation, an operator could keep a long-dead peer's freshness
// alive forever without that peer ever answering again.
func TestProvenance_ReseedDowngradesAnObservedRecord(t *testing.T) {
	c, reg := provRig(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	in := DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)}
	if _, _, err := c.IngestObserved(reg, in, PeerObservation{At: at, Identity: testIdentity}); err != nil {
		t.Fatalf("observed ingest: %v", err)
	}
	before := provRecord(t, c)
	if before.Provenance() != PeerObserved {
		t.Fatal("premise: the record must start out peer-observed")
	}

	// The SAME bytes, through the seed entrypoint.
	if _, _, err := c.Ingest(reg, in); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	after := provRecord(t, c)
	if !after.Fingerprint.Equal(before.Fingerprint) {
		t.Fatal("premise: the reseed must not move the fingerprint, or this proves something else")
	}
	if got := after.Provenance(); got != OperatorSeeded {
		t.Fatalf("an identical reseed must DOWNGRADE to OperatorSeeded, got %v", got)
	}
	if after.Observed.Present() {
		t.Fatalf("an identical reseed must clear the observation, got %+v", after.Observed)
	}
}

// TestProvenance_RediscoveryRefreshesAnUnchangedRecord is the other half of the same rule, in the
// direction that must NOT be conservative: the peer answering again is a new sighting, and the
// fingerprint being identical is what makes it good news rather than drift. An implementation
// that skipped the write when nothing changed would leave the timestamp frozen and let a live,
// healthy peer's record age out.
func TestProvenance_RediscoveryRefreshesAnUnchangedRecord(t *testing.T) {
	c, reg := provRig(t)
	first := time.Unix(1_700_000_000, 0).UTC()
	second := first.Add(90 * time.Minute)
	in := DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)}

	if _, _, err := c.IngestObserved(reg, in, PeerObservation{At: first, Identity: testIdentity}); err != nil {
		t.Fatalf("first observation: %v", err)
	}
	before := provRecord(t, c)
	if _, _, err := c.IngestObserved(reg, in, PeerObservation{At: second, Identity: testIdentity}); err != nil {
		t.Fatalf("second observation: %v", err)
	}
	after := provRecord(t, c)

	if !after.Fingerprint.Equal(before.Fingerprint) {
		t.Fatal("premise: an unchanged peer must not move the fingerprint")
	}
	if !after.Observed.At.Equal(second) {
		t.Fatalf("re-observing an unchanged tool must REFRESH the timestamp: got %v want %v", after.Observed.At, second)
	}
}

// TestProvenance_PromoteAndDemoteNeitherMintNorDestroyEvidence pins the three record writers that
// are NOT ingest paths. Trust and lifecycle actions must not be able to manufacture peer
// freshness — that is the "shadow promotion / live approval marks fresh" hole — and equally must
// not erase it, because the peer did advertise this record at that time and a promotion is not
// evidence to the contrary.
func TestProvenance_PromoteAndDemoteNeitherMintNorDestroyEvidence(t *testing.T) {
	c, reg := provRig(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	key := ToolKey{Server: testServer, Name: "read"}

	t.Run("promotion does not mint evidence", func(t *testing.T) {
		if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		seeded := provRecord(t, c)
		if _, err := c.Promote(key, seeded.Fingerprint); err != nil {
			t.Fatalf("promote: %v", err)
		}
		rec := provRecord(t, c)
		if rec.Eligibility != Usable {
			t.Fatalf("premise: promotion must have made the record Usable, got %v", rec.Eligibility)
		}
		if rec.Provenance() != OperatorSeeded || rec.Observed.Present() {
			t.Fatalf("promotion must not manufacture peer evidence, got %v %+v", rec.Provenance(), rec.Observed)
		}
	})

	t.Run("promotion and demotion preserve real evidence", func(t *testing.T) {
		c2, reg2 := provRig(t)
		if _, _, err := c2.IngestObserved(reg2,
			DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(provTool)},
			PeerObservation{At: at, Identity: testIdentity}); err != nil {
			t.Fatalf("observed ingest: %v", err)
		}
		observed, _ := c2.Current().Get(key)
		if _, err := c2.Promote(key, observed.Fingerprint); err != nil {
			t.Fatalf("promote: %v", err)
		}
		rec, _ := c2.Current().Get(key)
		if rec.Provenance() != PeerObserved || !rec.Observed.At.Equal(at) {
			t.Fatalf("promotion must preserve the observation, got %v %+v", rec.Provenance(), rec.Observed)
		}
		if _, err := c2.Demote(key); err != nil {
			t.Fatalf("demote: %v", err)
		}
		rec, _ = c2.Current().Get(key)
		if rec.Provenance() != PeerObserved || !rec.Observed.At.Equal(at) {
			t.Fatalf("demotion must preserve the observation, got %v %+v", rec.Provenance(), rec.Observed)
		}
	})
}
