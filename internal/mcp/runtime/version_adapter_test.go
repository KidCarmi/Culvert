package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// SEC-MCP-12. protocol.Adapter is the documented boundary that keeps protocol
// version out of every downstream stage (MCP-PROTO-011) — and it was declared,
// tested in isolation, and never invoked by the request path. The boundary did
// not exist at runtime, so a future revision with real wire differences had
// nowhere to land except by threading a version through the whole pipeline.
//
// This asserts the seam is REACHED for every supported revision.
func TestVersionAdapter_IsReachedForEverySupportedRevision(t *testing.T) {
	for _, v := range protocol.SupportedVersions() {
		got, ok := wireVersion(Request{HasVersionHeader: true, ProtocolVersion: string(v)})
		if !ok || got != v {
			t.Fatalf("supported revision %q did not resolve to an adapter version (%q, ok=%v)", v, got, ok)
		}
		if _, ok := protocol.AdapterFor(got); !ok {
			t.Fatalf("no adapter registered for supported revision %q", v)
		}
	}
	// No version header ⇒ the primary revision, never "no adapter".
	if got, ok := wireVersion(Request{}); !ok || got != protocol.VersionPrimary {
		t.Fatalf("missing version header must resolve to the primary, got %q ok=%v", got, ok)
	}
}

// A PRESENT-but-unsupported version must NOT be silently normalized to the
// primary. MCP-PROTO-010 forbids best-effort downgrade, and resolveSession owns
// the specific unsupported-version rejection — normalizing first would launder an
// unsupported revision into a supported one before that check ran.
func TestVersionAdapter_UnsupportedRevisionIsNotLaunderedToThePrimary(t *testing.T) {
	for _, v := range []string{"2026-07-28", "2025-03-26", "2024-11-05", "not-a-version", ""} {
		if _, ok := wireVersion(Request{HasVersionHeader: true, ProtocolVersion: v}); ok {
			t.Fatalf("unsupported revision %q resolved to an adapter version", v)
		}
	}

	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	tok := gwToken(k)
	sid := doInit(t, p, tok)

	req := gwRequest(tok, pingBody(2))
	req.SessionID, req.HasSession = sid, true
	req.ProtocolVersion, req.HasVersionHeader = "2026-07-28", true
	out := p.Process(context.Background(), req, fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("an unsupported protocol version must be rejected, got %v", out.Disposition)
	}
}

// Normalization must be transparent for V1: the two supported revisions share an
// envelope shape, so the adapter is the identity and no admitted request changes.
func TestVersionAdapter_IsTransparentForV1(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	for _, v := range protocol.SupportedVersions() {
		tok := gwToken(k)
		sid := doInit(t, p, tok)
		req := gwRequest(tok, pingBody(3))
		req.SessionID, req.HasSession = sid, true
		req.ProtocolVersion, req.HasVersionHeader = string(v), true
		out := p.Process(context.Background(), req, fixedClock())
		if out.Status != 200 || out.Disposition != DispKernelTerminal {
			t.Fatalf("revision %q: ping should still complete, got %d/%v/%v", v, out.Status, out.Disposition, out.Reason)
		}
	}
}

// An internally-inconsistent message the adapter refuses is a 400, not a
// pass-through: the adapter is the LAST version-aware stage and must not hand a
// malformed message downstream.
func TestVersionAdapter_RefusedMessageIsRejected(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	_, err := p.normalizeForVersion(Request{}, jsonrpc.Message{Class: jsonrpc.ClassInvalid})
	if err == nil {
		t.Fatal("the adapter must refuse an unclassified message")
	}
}

// Anti-weakening: the request path must actually CALL the adapter. A future
// refactor that drops the call would leave every behavioural test above passing
// (the V1 adapters are the identity) while silently deleting the boundary again.
func TestVersionAdapter_RequestPathInvokesTheSeam(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean("pipeline.go"))
	if err != nil {
		t.Fatalf("read pipeline.go: %v", err)
	}
	if !strings.Contains(string(src), "protocol.AdapterFor(") {
		t.Fatal("the request path no longer invokes protocol.AdapterFor: " +
			"the version-normalization boundary has been removed")
	}
	if !strings.Contains(string(src), "p.normalizeForVersion(req, msg)") {
		t.Fatal("processPost no longer normalizes the decoded message for its wire version")
	}
}
