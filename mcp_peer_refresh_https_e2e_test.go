package main

// mcp_peer_refresh_https_e2e_test.go — CONTROLLED LOCAL HTTPS end-to-end proof that the governed
// refresh really observes a peer over the real authenticated transport (blocker 11, §7/§12).
//
// WHY A REAL SERVER. Every other test of this path scripts the upstream at the Go interface,
// which measures what the refresh INTENDED to send. The claim blocker 11 rests on is stronger:
// that the freshness evidence was produced by an authenticated exchange with an actual peer whose
// SPKI matched the registry pin. TLS verification lives below the interface seam, so an
// interface-level fake proves nothing about it — a fake would happily "observe" a peer whose
// identity was never checked.
//
// These tests therefore drive the REAL production-shaped upstream client (retry-free limits, the
// production destination/TLS/pin behaviour) against a local httptest TLS server, and assert on
// what lands in the catalog.
//
// CONTAINMENT. Loopback only, via the existing ssrf.AllowLoopbackForTest seam and a resolver
// pinned to the peer's own address, so no DNS is used and nothing outside the test is reachable.
// No Canary is activated, no live tier is armed, no credential exists.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// startToolsPeer boots a local TLS peer that answers with whatever tools/list result the test
// scripts, and keeps its SPKI pin.
//
// The JSON-RPC id is not echoed from the body — the shared harness drains that before the
// responder runs — but it does not need to be: Discovery sets an explicit, deterministic wire id
// ("disc-" + serverID), so the peer can answer the exact id the client will match against. If
// that convention ever changes, these tests fail loudly on a response-id mismatch rather than
// quietly passing, which is the right direction.
func startToolsPeer(t *testing.T, toolsResult *string) *controlledPeer {
	t.Helper()
	return startControlledPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"disc-controlled","result":`+*toolsResult+`}`)
	})
}

// realPeerRefreshRig registers the controlled peer as the one server, seeds the catalog with the
// OPERATOR-DECLARED tool (F1), and points the refresh engine at the real client.
func realPeerRefreshRig(t *testing.T, p *controlledPeer, seededSchema string, pinOverride string) *catalog.Catalog {
	t.Helper()
	restore := ssrf.AllowLoopbackForTest()
	t.Cleanup(restore)
	restoreMCPInventory(t)

	pin := p.pin
	if pinOverride != "" {
		pin = pinOverride
	}
	lim := limits.DefaultCatalog()
	reg := registry.New(lim)
	if _, err := reg.Register(registry.Registration{
		ID:             "controlled",
		Endpoint:       registry.Endpoint(p.srv.URL),
		PinnedIdentity: registry.Identity(pin),
		Capability:     protocol.Gateway,
	}); err != nil {
		t.Fatalf("register controlled peer: %v", err)
	}
	if _, _, err := reg.VerifyIdentity("controlled", registry.Identity(pin)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	cat := catalog.New(lim)
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID: "controlled",
		Identity: registry.Identity(pin),
		Raw:      []byte(`{"tools":[{"name":"t","inputSchema":` + seededSchema + `}]}`),
	}); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)

	prev := mcpPeerRefreshUpstream
	mcpPeerRefreshUpstream = func() (execution.UpstreamCaller, error) { return realUpstreamFor(t, p), nil }
	t.Cleanup(func() { mcpPeerRefreshUpstream = prev })
	return cat
}

func e2eRecord(t *testing.T, cat *catalog.Catalog) catalog.ToolRecord {
	t.Helper()
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"})
	if !ok {
		t.Fatal("expected the controlled tool to be present")
	}
	return rec
}

func fpHexOf(rec catalog.ToolRecord) string {
	sum := rec.Fingerprint.Sum()
	return hex.EncodeToString(sum[:])
}

// TestPeerRefreshE2E_SeededF1RealPeerF2 is the headline blocker-11 proof.
//
// The operator inventory says F1. The REAL authenticated peer advertises F2. Before the
// observation the catalog knows only the operator's claim; after it, the catalog holds F2 with
// peer provenance and F1 can no longer masquerade as what the peer offers.
//
// This is the defect stated positively: before this change there was no production path that
// could ever discover the disagreement, so F1 stayed "current" forever.
func TestPeerRefreshE2E_SeededF1RealPeerF2(t *testing.T) {
	tools := `{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}`
	p := startToolsPeer(t, &tools)
	cat := realPeerRefreshRig(t, p, `{"type":"object"}`, "")

	seeded := e2eRecord(t, cat)
	if seeded.Provenance() != catalog.OperatorSeeded {
		t.Fatalf("premise: the catalog must start from the operator's claim, got %v", seeded.Provenance())
	}
	f1 := fpHexOf(seeded)

	out, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled")
	if reason != "" || err != nil {
		t.Fatalf("authenticated refresh must succeed against the controlled peer: %q %v", reason, err)
	}
	if p.count() == 0 {
		t.Fatal("the peer recorded no request — the refresh never reached the wire")
	}
	if out.Observations != 1 {
		t.Fatalf("expected one observed tool, got %d", out.Observations)
	}

	observed := e2eRecord(t, cat)
	if observed.Provenance() != catalog.PeerObserved {
		t.Fatalf("after a real authenticated exchange the record must be peer-observed, got %v", observed.Provenance())
	}
	if observed.Observed.Identity != registry.Identity(p.pin) {
		t.Fatalf("the observation must bind the SPKI the TLS handshake verified: got %q want %q",
			observed.Observed.Identity, p.pin)
	}
	if observed.Observed.At.IsZero() {
		t.Fatal("a real observation must carry a timestamp")
	}
	f2 := fpHexOf(observed)
	if f2 == f1 {
		t.Fatal("the peer advertises a different tool than the operator declared; the catalog " +
			"must no longer hold F1")
	}
	if observed.Eligibility == catalog.Usable {
		t.Fatal("observing F2 must not bless it — refresh observes, it does not approve")
	}
}

// TestPeerRefreshE2E_AgreeingPeerIsTheControl is the positive control for the test above. If the
// peer advertises exactly what the operator declared, the fingerprint must NOT move and the
// record must still become peer-observed — otherwise "F1 stopped being current" above would be
// explained by the refresh mangling every record rather than by the disagreement.
func TestPeerRefreshE2E_AgreeingPeerIsTheControl(t *testing.T) {
	tools := `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`
	p := startToolsPeer(t, &tools)
	cat := realPeerRefreshRig(t, p, `{"type":"object"}`, "")
	before := fpHexOf(e2eRecord(t, cat))

	if _, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled"); reason != "" || err != nil {
		t.Fatalf("refresh against an agreeing peer must succeed: %q %v", reason, err)
	}
	rec := e2eRecord(t, cat)
	if fpHexOf(rec) != before {
		t.Fatal("an agreeing peer must not move the fingerprint")
	}
	if rec.Provenance() != catalog.PeerObserved {
		t.Fatalf("an agreeing peer still produces real evidence, got %v", rec.Provenance())
	}
}

// TestPeerRefreshE2E_WrongSPKIObservesNothing is the negative control, and it is the one that
// makes "authenticated" mean something.
//
// The registry pins an identity the peer does not hold. The TLS handshake must fail, so nothing
// is ingested, no provenance is stamped, and freshness does not advance. A refresh that "worked"
// here would mean the evidence model rests on reaching SOME server rather than THE server.
func TestPeerRefreshE2E_WrongSPKIObservesNothing(t *testing.T) {
	tools := `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`
	p := startToolsPeer(t, &tools)
	// A syntactically valid, deliberately WRONG pin.
	wrong := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cat := realPeerRefreshRig(t, p, `{"type":"object"}`, wrong)
	before := e2eRecord(t, cat)
	revBefore := cat.Current().Revision()

	_, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled")
	if reason == "" {
		t.Fatal("a peer whose identity does not match the pin must NOT be observed")
	}
	if err == nil {
		t.Fatal("the identity failure must surface as an error")
	}
	// WHERE it failed matters as much as that it failed. The peer must have recorded NO HTTP
	// request: the pin is checked during the TLS handshake, so a correct refusal happens before
	// a single byte of MCP is exchanged. Without this the test would still pass if the pin check
	// were removed and the failure came from somewhere later and weaker.
	if got := p.count(); got != 0 {
		t.Fatalf("a pin mismatch must be refused during the handshake, before any request "+
			"reaches the peer; the peer saw %d", got)
	}
	after := e2eRecord(t, cat)
	if after.Provenance() != catalog.OperatorSeeded {
		t.Fatalf("a failed identity check must stamp no provenance, got %v", after.Provenance())
	}
	if after.Observed.Present() {
		t.Fatalf("no observation may be recorded, got %+v", after.Observed)
	}
	if fpHexOf(after) != fpHexOf(before) {
		t.Fatal("nothing may be ingested from an unverified peer")
	}
	if cat.Current().Revision() != revBefore {
		t.Fatal("no catalog snapshot may be published from an unverified peer")
	}
}
