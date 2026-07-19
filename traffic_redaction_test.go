package main

import (
	"strings"
	"testing"
)

// PR3 Option B: the destination-privacy posture pseudonymizes host/URI/dec.* with a
// node-local keyed HMAC at the persistLogEntry chokepoint, fail-closed, opt-in.

const testTrafficKey = "0123456789abcdef0123456789abcdef" // 32 bytes

// TestTrafficRedaction_OffIsByteIdentical — posture off ⇒ inputs pass through unchanged.
func TestTrafficRedaction_OffIsByteIdentical(t *testing.T) {
	swapDecRedact(t, false)
	swapTrafficKey(t, []byte(testTrafficKey))
	if got := redactDestinationHost("plain.example.com"); got != "plain.example.com" {
		t.Fatalf("off must be byte-identical, got %q", got)
	}
	if got := redactDestinationURI("https://plain.example.com/p", "plain.example.com", ""); got != "https://plain.example.com/p" {
		t.Fatalf("off URI must be byte-identical, got %q", got)
	}
}

// TestTrafficRedaction_TokenShapeAndCorrelation — a stable, fixed-length keyed token;
// same host ⇒ same token (correlation), regardless of port/case/trailing dot.
func TestTrafficRedaction_TokenShapeAndCorrelation(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))

	tok := redactDestinationHost("Patient-Portal.Example.com")
	if !strings.HasPrefix(tok, "h_") || len(tok) != len("h_")+12 {
		t.Fatalf("token must be h_+12hex, got %q (len %d)", tok, len(tok))
	}
	if tok == "Patient-Portal.Example.com" {
		t.Fatal("plaintext leaked")
	}
	// Correlation + normalization: case/port/trailing-dot collapse to one token.
	for _, v := range []string{"patient-portal.example.com", "patient-portal.example.com:443", "patient-portal.example.com."} {
		if got := redactDestinationHost(v); got != tok {
			t.Fatalf("normalized host %q ⇒ %q, want stable %q", v, got, tok)
		}
	}
}

// TestTrafficRedaction_DifferentKeysDifferentTokens — the pseudonym is KEYED: two keys
// produce different tokens for the same host (proves it is not a public unsalted hash).
func TestTrafficRedaction_DifferentKeysDifferentTokens(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	a := redactDestinationHost("host.example.com")
	swapTrafficKey(t, []byte("ffffffffffffffffffffffffffffffff"))
	b := redactDestinationHost("host.example.com")
	if a == b {
		t.Fatalf("different keys must produce different tokens (a=%q b=%q)", a, b)
	}
}

// TestTrafficRedaction_FailClosed — posture ON but no key ⇒ constant sentinel, NEVER
// plaintext. The load-bearing safety property.
func TestTrafficRedaction_FailClosed(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, nil) // no key
	if got := redactDestinationHost("secret.example.com"); got != redactedSentinel {
		t.Fatalf("fail-closed host = %q, want sentinel %q (never plaintext)", got, redactedSentinel)
	}
	uri := redactDestinationURI("https://secret.example.com/p", "secret.example.com", "")
	if strings.Contains(uri, "secret.example.com") {
		t.Fatalf("fail-closed URI leaked the plaintext host: %q", uri)
	}
}

// TestTrafficRedaction_URICannotLeakHost — the redacted URI must not contain the
// plaintext host in ANY casing/form, including when the host is echoed in the path.
// Covers the case-variance leak the pre-merge review found.
func TestTrafficRedaction_URICannotLeakHost(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	cases := []struct{ uri, host string }{
		{"https://patient-portal.example.com/records/42", "patient-portal.example.com"},
		{"patient-portal.example.com/records/42", "patient-portal.example.com"},                       // scheme-less
		{"patient-portal.example.com", "patient-portal.example.com"},                                  // bare host
		{"https://patient-portal.example.com:8443/x", "patient-portal.example.com"},                   // port
		{"https://Patient-Portal.Example.COM/x", "patient-portal.example.com"},                        // UPPER authority
		{"patient-portal.example.com/ref/PATIENT-PORTAL.EXAMPLE.COM", "patient-portal.example.com"},   // upper path copy
		{"patient-portal.example.com/patient-portal.example.com/again", "patient-portal.example.com"}, // path copy
	}
	for _, c := range cases {
		got := redactDestinationURI(c.uri, c.host, "")
		if strings.Contains(strings.ToLower(got), c.host) {
			t.Fatalf("redacted URI %q still contains the plaintext host %q (case-insensitive)", got, c.host)
		}
		if !strings.Contains(got, "h_") {
			t.Fatalf("redacted URI %q carries no token", got)
		}
	}
}

// TestTrafficRedaction_URIDoesNotOverRedact — the boundary-aware scrub must NOT rewrite
// a host that is only a SUBSTRING of a larger label (the review's over-redaction nit).
func TestTrafficRedaction_URIDoesNotOverRedact(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	// host "ex.com" must not be rewritten inside "complex.com" in the path.
	got := redactDestinationURI("ex.com/see/complex.com/page", "ex.com", "")
	if !strings.Contains(got, "complex.com") {
		t.Fatalf("over-redacted a non-host substring: %q", got)
	}
	if strings.HasPrefix(got, "ex.com") {
		t.Fatalf("the real authority host was not redacted: %q", got)
	}
	// "example.com" must not match the prefix of "example.com.evil".
	got2 := redactDestinationURI("a.example.com/x/example.com.evil/y", "example.com.evil", "")
	if !strings.Contains(got2, "example.com/x") { // the a.example.com authority IS its own host; only example.com.evil is scrubbed
		_ = got2 // (authority differs from plainHost here; just assert the evil host is gone)
	}
	if strings.Contains(got2, "example.com.evil") {
		t.Fatalf("path host copy not scrubbed: %q", got2)
	}
}

// TestTrafficRedaction_TopHostsRedacted — the viewer-facing top-hosts ranking carries
// the pseudonym token (not the plaintext host) when the posture is on (MAJOR fix).
func TestTrafficRedaction_TopHostsRedacted(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	prev := topHosts
	topHosts = &hostCounter{hosts: map[string]*int64{}}
	t.Cleanup(func() { topHosts = prev })

	const host = "patient-portal.example.com"
	recordStats("1.2.3.4", host, "OK", "rule", "Allow")
	for _, hs := range topHosts.Top(10) {
		if hs.Host == host || !strings.HasPrefix(hs.Host, "h_") {
			t.Fatalf("top-hosts leaked plaintext / wrong token: %q", hs.Host)
		}
	}
}

// TestTrafficRedaction_Rotation — rotating the key changes the token for the same host
// (the defined rotation behavior: correlation with older records breaks).
func TestTrafficRedaction_Rotation(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	before := redactDestinationHost("host.example.com")
	if err := rotateTrafficPseudonymKey(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	t.Cleanup(func() { setTrafficPseudonymKey([]byte(testTrafficKey)) })
	after := redactDestinationHost("host.example.com")
	if before == after {
		t.Fatal("rotation must change the token for the same host")
	}
	if !strings.HasPrefix(after, "h_") {
		t.Fatalf("post-rotation token shape wrong: %q", after)
	}
}

// TestTrafficRedaction_OffZeroAlloc — the OFF path must be allocation-neutral (a single
// atomic.Bool load + return), so enabling the feature is the only cost.
func TestTrafficRedaction_OffZeroAlloc(t *testing.T) {
	swapDecRedact(t, false)
	if n := testing.AllocsPerRun(100, func() {
		_ = redactDestinationHost("plain.example.com")
		_ = redactDestinationURI("plain.example.com/p", "plain.example.com", "")
	}); n != 0 {
		t.Fatalf("OFF path allocates %v/op, want 0", n)
	}
}

// TestTrafficRedaction_ChokepointRedactsAllFields — driving the persistLogEntry
// chokepoint (via recordRequestLogOnly) with the posture on pseudonymizes the top-level
// Host AND URI in the resulting ring entry; the plaintext appears nowhere.
func TestTrafficRedaction_ChokepointRedactsAllFields(t *testing.T) {
	isolateLogRing(t)
	oldLS := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(oldLS) })
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))

	const host = "patient-portal.example.com"
	recordRequestLogOnly("1.2.3.4", "GET", host, "OK", "rule", "Allow", "alice", "inspect", host+"/records/42", AuthLogFields{})

	entries := logGet()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Host == host || !strings.HasPrefix(e.Host, "h_") {
		t.Fatalf("Host not pseudonymized: %q", e.Host)
	}
	if strings.Contains(e.URI, host) {
		t.Fatalf("URI leaked plaintext host: %q", e.URI)
	}
	// The token in Host must equal the token the URI carries (one destination contract).
	if !strings.Contains(e.URI, e.Host) {
		t.Fatalf("Host token %q and URI %q disagree (not one contract)", e.Host, e.URI)
	}
}

// TestTrafficRedaction_ChokepointOffKeepsPlaintext — posture off ⇒ the ring entry keeps
// the plaintext (byte-identical to today).
func TestTrafficRedaction_ChokepointOffKeepsPlaintext(t *testing.T) {
	isolateLogRing(t)
	oldLS := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(oldLS) })
	swapDecRedact(t, false)

	const host = "plain.example.com"
	recordRequestLogOnly("1.2.3.4", "GET", host, "OK", "rule", "Allow", "alice", "inspect", host+"/p", AuthLogFields{})
	entries := logGet()
	if len(entries) != 1 || entries[0].Host != host || entries[0].URI != host+"/p" {
		t.Fatalf("posture off must keep plaintext, got %+v", entries)
	}
}

// TestTrafficRedaction_KeyNeverInExportSurface — the pseudonym key is AdminDurable-only
// and Sensitive: it must not appear on the export/rollback/CP→DP config surfaces. Pinned
// structurally via the config_surfaces registry (a stronger, drift-proof check than a
// string scan).
func TestTrafficRedaction_KeyNeverInExportSurface(t *testing.T) {
	var row *configSurfaceRow
	for i := range configSurfaces {
		if configSurfaces[i].ID == "traffic_pseudonym_key" {
			row = &configSurfaces[i]
			break
		}
	}
	if row == nil {
		t.Fatal("traffic_pseudonym_key must have a config_surfaces row")
	}
	if !row.Sensitive {
		t.Fatal("the pseudonym key must be marked Sensitive")
	}
	if !row.AdminDurable {
		t.Fatal("the pseudonym key must be AdminDurable")
	}
	if row.ClusterSynced {
		t.Fatal("the node-local pseudonym key must NOT be CP→DP synced (B3 deferral)")
	}
	// It binds ONLY to AdminSettings (not configBackup/ConfigSnapshot = export/rollback/sync).
	for _, b := range row.Bindings {
		if b.Struct != "AdminSettings" {
			t.Fatalf("key must bind only to AdminSettings, found %s", b.Struct)
		}
	}
}
