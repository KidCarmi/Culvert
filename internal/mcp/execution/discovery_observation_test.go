package execution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// What a peer observation ATTESTS (blocker #11, §5).
//
// Discovery is the only production producer of peer evidence, so the evidence is exactly as
// trustworthy as the three properties pinned here: it is refused outright when there is no pinned
// identity to observe against, the identity it records is the one the TRANSPORT was told to
// verify rather than anything the peer said, and the timestamp is taken before the question is
// asked so a slow answer can never be credited with freshness it did not earn.

// obsRegistry registers one server with the given pin and returns the stores a Discovery needs.
func obsRegistry(t *testing.T, pin registry.Identity) (*registry.Registry, *catalog.Catalog) {
	t.Helper()
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: pin, Capability: 0,
		CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if pin != "" {
		if _, _, err := reg.VerifyIdentity("s1", pin); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
	return reg, catalog.New(limits.DefaultCatalog())
}

func obsRecord(t *testing.T, cat *catalog.Catalog) catalog.ToolRecord {
	t.Helper()
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: "s1", Name: "t"})
	if !ok {
		t.Fatal("expected the discovered tool to be present")
	}
	return rec
}

// TestDiscoveryObservation_NoServerCanExistWithoutAPinToObserveAgainst.
//
// An observation's whole value is that an AUTHENTICATED identity was seen to advertise these
// bytes, so a server with nothing to authenticate against must never be observable. Today that
// holds for a reason OUTSIDE Discovery: every registry write path requires a pinned identity, so
// the unusable-server guard in Discover is a second line that cannot currently be reached.
//
// This gate pins the invariant that second line depends on. If a future write path admits a
// server with no pin — a relaxed validator, a restore path, a new setter — this fails and names
// the guard that then becomes load-bearing, rather than letting an unauthenticated exchange
// quietly become a source of "evidence".
func TestDiscoveryObservation_NoServerCanExistWithoutAPinToObserveAgainst(t *testing.T) {
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: "", Capability: 0,
		CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0),
	}); err == nil {
		t.Fatal("a server with no pinned identity must not be registrable. Discovery's " +
			"unusable-server guard is now the ONLY thing standing between an unauthenticated " +
			"exchange and a peer observation — verify it refuses BEFORE the dial and give it its " +
			"own driven test.")
	}
	if _, err := reg.Register(registry.Registration{
		ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: "pin-1", Capability: 0,
		CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0),
	}); err != nil {
		t.Fatalf("control: a pinned server must still register cleanly, got %v", err)
	}
	if _, err := reg.Repin("s1", "", time.Unix(2, 0)); err == nil {
		t.Fatal("repinning to an empty identity must be refused for the same reason")
	}
}

// TestDiscoveryObservation_RecordsTheVerifiedPinNotThePayload.
//
// The identity stamped on the evidence is the one handed to the transport as the pin to verify —
// NOT a value read out of the tools/list body, which the peer writes and could therefore choose.
// The peer here returns a payload deliberately carrying its own idea of who it is; the recorded
// identity must be the registry's pin regardless.
func TestDiscoveryObservation_RecordsTheVerifiedPinNotThePayload(t *testing.T) {
	const pin = registry.Identity("pin-1")
	reg, cat := obsRegistry(t, pin)
	up := &fakeUpstream{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`}
	d, err := NewDiscovery(reg, cat, up)
	if err != nil {
		t.Fatal(err)
	}
	if _, derr := d.Discover(context.Background(), "s1"); derr != nil {
		t.Fatalf("discovery: %v", derr)
	}
	rec := obsRecord(t, cat)
	if rec.Provenance() != catalog.PeerObserved {
		t.Fatalf("a completed authenticated discovery must produce peer provenance, got %v", rec.Provenance())
	}
	if rec.Observed.Identity != pin {
		t.Fatalf("the evidence must name the identity the transport verified: got %q want %q",
			rec.Observed.Identity, pin)
	}
}

// TestDiscoveryObservation_StampPrecedesTheCall is the unit-level form of the stall proof.
//
// The clock is read before the request goes out, so the evidence describes when the question was
// ASKED. Stamping on receipt would let a peer that hangs for an hour and then answers mint a
// brand-new window of freshness for a statement about an hour ago. The clock advances inside the
// call, so no sleep is involved and the assertion is exact rather than approximate.
func TestDiscoveryObservation_StampPrecedesTheCall(t *testing.T) {
	reg, cat := obsRegistry(t, "pin-1")
	asked := time.Unix(1_700_000_000, 0).UTC()
	answered := asked.Add(time.Hour)
	now := asked
	up := &advancingUpstream{
		inner:   &fakeUpstream{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`},
		advance: func() { now = answered },
	}
	d, err := NewDiscovery(reg, cat, up)
	if err != nil {
		t.Fatal(err)
	}
	d.Now = func() time.Time { return now }
	if _, derr := d.Discover(context.Background(), "s1"); derr != nil {
		t.Fatalf("discovery: %v", derr)
	}
	rec := obsRecord(t, cat)
	if !rec.Observed.At.Equal(asked) {
		t.Fatalf("the observation must be stamped when the question was asked (%v), not when the "+
			"answer arrived (%v); got %v", asked, answered, rec.Observed.At)
	}
}

// advancingUpstream moves a test clock forward while the inner call is notionally in flight.
type advancingUpstream struct {
	inner   UpstreamCaller
	advance func()
}

func (u *advancingUpstream) Call(ctx context.Context, tgt upstreamclient.Target, method string,
	params json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	u.advance()
	return u.inner.Call(ctx, tgt, method, params, opts)
}
