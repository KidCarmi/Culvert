package main

import (
	"context"
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// TestF3b2Probe_Harness de-risks the harness: the fake verifier drives a full
// valid acquisition end-to-end, and the real kernel rejects a forged envelope.
func TestF3b2Probe_Harness(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})

	// Real kernel rejects a forged envelope (genuine verify-before-parse).
	if _, err := realFeedVerifier(t).VerifyEnvelope(forgedEnvelope(t, g.ManifestBytes)); err == nil {
		t.Fatal("real verifier accepted a forged envelope")
	}

	// Fake verifier accepts the exact good bytes and rejects anything else.
	fv := newFakeVerifier(g)
	m, err := fv.VerifyEnvelope(g.EnvelopeBytes)
	if err != nil || m == nil || m.FeedVersion != 42 {
		t.Fatalf("fake VerifyEnvelope: m=%+v err=%v", m, err)
	}
	if _, err := fv.VerifyEnvelope([]byte("nope")); !errors.Is(err, urlcatfeed.ErrVerify) {
		t.Fatalf("fake should reject unknown envelope: %v", err)
	}
	a, err := fv.VerifyArtifact(g.ArtifactBytes, g.BundleBytes, m)
	if err != nil || a == nil {
		t.Fatalf("fake VerifyArtifact: a=%+v err=%v", a, err)
	}
}

// TestF3b2Probe_TLSOriginFetch de-risks the TLS origin + fetcher: a manifest fetch
// over the pinned-SNI loopback origin returns the served envelope bytes, and the
// transport dialed the resolved public IP.
func TestF3b2Probe_TLSOriginFetch(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	mux := newFeedMux(g)
	fo := newFeedOrigin(t, mux)

	out, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err != nil {
		t.Fatalf("fetchManifest: %v", err)
	}
	if string(out.Body) != string(g.EnvelopeBytes) {
		t.Fatalf("manifest body mismatch")
	}
	if fo.dialedAddr != "127.0.0.1:443" {
		t.Fatalf("dialed %q; want the resolved public IP 127.0.0.1:443", fo.dialedAddr)
	}
	if fo.sniName != saasFeedOfficialHost {
		t.Fatalf("SNI = %q; want %q", fo.sniName, saasFeedOfficialHost)
	}
	if mux.artifactHits.Load() != 0 {
		t.Fatalf("manifest fetch triggered %d artifact hits", mux.artifactHits.Load())
	}
}
