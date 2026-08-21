package destination

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func gwLim() limits.InspectionLimits { return limits.DefaultGatewayInspection() }

func httpsAndHTTP() Policy {
	p, err := NewPolicy(PolicyConfig{Schemes: []string{"https", "http"}, ResolverRevision: 7})
	if err != nil {
		panic(err)
	}
	return p
}

// fakeResolver returns fixed addresses; no real DNS.
type fakeResolver struct {
	addrs []netip.Addr
	err   error
}

func (f fakeResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	return f.addrs, f.err
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestCanonicalize_SchemesAndForms(t *testing.T) {
	pol := httpsAndHTTP()
	cases := []struct {
		raw    string
		reason mcperr.Reason // ReasonNone ⇒ accept
	}{
		{"https://example.com/x", mcperr.ReasonNone},
		{"https://203.0.113.5:8443/y", mcperr.ReasonNone},
		{"file:///etc/passwd", mcperr.ReasonDestinationSchemeRejected},
		{"data:text/plain;base64,QQ==", mcperr.ReasonDestinationSchemeRejected},
		{"javascript:alert(1)", mcperr.ReasonDestinationSchemeRejected},
		{"gopher://x", mcperr.ReasonDestinationSchemeRejected},
		{"ftp://x/y", mcperr.ReasonDestinationSchemeRejected},
		{"https://user:pass@example.com/", mcperr.ReasonDestinationMalformed}, // userinfo
		{"https://example.com/#frag", mcperr.ReasonDestinationMalformed},      // fragment
		{"https://example.com:99999/", mcperr.ReasonDestinationMalformed},     // bad port
		{"https://café.com/", mcperr.ReasonDestinationMalformed},              // non-ascii host
		{"https://0177.0.0.1/", mcperr.ReasonDestinationMalformed},            // octal ip
		{"https://2130706433/", mcperr.ReasonDestinationMalformed},            // decimal ip
		{"https://127.1/", mcperr.ReasonDestinationMalformed},                 // short ip
		{"https:// example.com/", mcperr.ReasonDestinationMalformed},          // control/space
	}
	for _, tc := range cases {
		_, _, err := Canonicalize(tc.raw, pol, gwLim())
		if got := mcperr.ReasonOf(err); got != tc.reason {
			t.Errorf("%q: reason=%v want=%v (err=%v)", tc.raw, got, tc.reason, err)
		}
	}
}

func TestCanonicalize_IPClasses(t *testing.T) {
	pol := httpsAndHTTP()
	cases := []struct {
		raw   string
		class Class
	}{
		{"https://203.0.113.5/", ClassPublic},
		{"https://127.0.0.1/", ClassLoopback},
		{"https://10.0.0.1/", ClassPrivate},
		{"https://192.168.1.1/", ClassPrivate},
		{"https://169.254.1.1/", ClassLinkLocal},
		{"https://169.254.169.254/", ClassMetadata},
		{"https://[::1]/", ClassLoopback},
		{"https://[fe80::1]/", ClassLinkLocal},
		{"https://[::ffff:10.0.0.1]/", ClassPrivate}, // mapped bypass caught
	}
	for _, tc := range cases {
		_, class, err := Canonicalize(tc.raw, pol, gwLim())
		if err != nil {
			t.Errorf("%q: unexpected err %v", tc.raw, err)
			continue
		}
		if class != tc.class {
			t.Errorf("%q: class=%v want=%v", tc.raw, class, tc.class)
		}
	}
}

func TestResolve_PublicPinned(t *testing.T) {
	pol := httpsAndHTTP()
	c, _, err := Canonicalize("https://example.com/", pol, gwLim())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	pin, st, err := Resolve(context.Background(), c, pol, fakeResolver{addrs: []netip.Addr{mustAddr("203.0.113.5"), mustAddr("203.0.113.6")}}, gwLim(), now, time.Minute)
	if err != nil || st.Class != ClassPublic {
		t.Fatalf("expected public pin, got st=%v err=%v", st.Class, err)
	}
	if len(pin.AllowedIPs) != 2 {
		t.Fatalf("expected 2 pinned addrs, got %d", len(pin.AllowedIPs))
	}
	if pin.ResolverRevision != 7 {
		t.Fatalf("resolver revision not stamped: %d", pin.ResolverRevision)
	}
}

func TestResolve_MixedAnswerFailsClosed(t *testing.T) {
	pol := httpsAndHTTP()
	c, _, _ := Canonicalize("https://example.com/", pol, gwLim())
	now := time.Unix(1000, 0)
	_, st, err := Resolve(context.Background(), c, pol, fakeResolver{addrs: []netip.Addr{mustAddr("203.0.113.5"), mustAddr("10.0.0.1")}}, gwLim(), now, time.Minute)
	if mcperr.ReasonOf(err) != mcperr.ReasonDNSAnswerMixed {
		t.Fatalf("mixed answer must fail with DNSAnswerMixed, got %v (st=%v)", err, st.Reason)
	}
}

func TestResolve_AllPrivateBlocked(t *testing.T) {
	pol := httpsAndHTTP()
	c, _, _ := Canonicalize("https://internal/", pol, gwLim())
	_, _, err := Resolve(context.Background(), c, pol, fakeResolver{addrs: []netip.Addr{mustAddr("10.0.0.1")}}, gwLim(), time.Unix(1, 0), time.Minute)
	if mcperr.ReasonOf(err) != mcperr.ReasonSSRFBlocked {
		t.Fatalf("all-private answer must be SSRFBlocked, got %v", err)
	}
}

func TestResolve_EmptyAndError(t *testing.T) {
	pol := httpsAndHTTP()
	c, _, _ := Canonicalize("https://example.com/", pol, gwLim())
	_, _, err := Resolve(context.Background(), c, pol, fakeResolver{addrs: nil}, gwLim(), time.Unix(1, 0), time.Minute)
	if mcperr.ReasonOf(err) != mcperr.ReasonDNSResolutionFailed {
		t.Fatalf("empty answer: %v", err)
	}
	_, _, err = Resolve(context.Background(), c, pol, fakeResolver{err: errors.New("boom")}, gwLim(), time.Unix(1, 0), time.Minute)
	if mcperr.ReasonOf(err) != mcperr.ReasonDNSResolutionFailed {
		t.Fatalf("resolver error: %v", err)
	}
}

func TestResolve_AddressCountLimit(t *testing.T) {
	cfg := gwConfigForTest()
	cfg.MaxDNSAddresses = 2
	lim, _ := limits.NewInspection(cfg)
	pol := httpsAndHTTP()
	c, _, _ := Canonicalize("https://example.com/", pol, lim)
	_, _, err := Resolve(context.Background(), c, pol, fakeResolver{addrs: []netip.Addr{mustAddr("203.0.113.5"), mustAddr("203.0.113.6"), mustAddr("203.0.113.7")}}, lim, time.Unix(1, 0), time.Minute)
	if mcperr.ReasonOf(err) != mcperr.ReasonDNSResolutionFailed {
		t.Fatalf("address overflow: %v", err)
	}
}

func TestVerifyPeer_RebindingMatrix(t *testing.T) {
	pol := httpsAndHTTP()
	now := time.Unix(1000, 0)
	pin := PinnedDestination{Scheme: "https", Host: "example.com", Port: "443",
		AllowedIPs: []netip.Addr{mustAddr("203.0.113.5"), mustAddr("203.0.113.6")}, Expiry: now.Add(time.Minute)}

	// peer in pinned set + public → ok
	if err := VerifyPeer(pin, mustAddr("203.0.113.5"), pol, now); err != nil {
		t.Fatalf("pinned public peer must pass: %v", err)
	}
	// peer public but NOT in pinned set (answer changed) → pin mismatch
	if err := VerifyPeer(pin, mustAddr("203.0.113.9"), pol, now); mcperr.ReasonOf(err) != mcperr.ReasonDNSPinMismatch {
		t.Fatalf("peer outside pin must be DNSPinMismatch, got %v", err)
	}
	// peer private (rebinding to internal) → SSRF blocked (ssrf.Control executes)
	if err := VerifyPeer(pin, mustAddr("10.0.0.1"), pol, now); mcperr.ReasonOf(err) != mcperr.ReasonSSRFBlocked {
		t.Fatalf("private peer must be SSRFBlocked, got %v", err)
	}
	// stale pin → mismatch
	if err := VerifyPeer(pin, mustAddr("203.0.113.5"), pol, now.Add(2*time.Minute)); mcperr.ReasonOf(err) != mcperr.ReasonDNSPinMismatch {
		t.Fatalf("stale pin must be DNSPinMismatch, got %v", err)
	}
}

func TestRedirect_Matrix(t *testing.T) {
	pol := httpsAndHTTP()
	lim := gwLim()
	start, _, _ := Canonicalize("https://example.com/a", pol, lim)

	// same-origin allowed (relative)
	g := NewRedirectGuard(start, pol, lim)
	if _, err := g.Next("/b"); err != nil {
		t.Fatalf("same-origin relative redirect must pass: %v", err)
	}
	// cross-origin rejected
	g = NewRedirectGuard(start, pol, lim)
	if _, err := g.Next("https://evil.com/b"); mcperr.ReasonOf(err) != mcperr.ReasonRedirectRejected {
		t.Fatalf("cross-origin must be rejected: %v", err)
	}
	// https→http downgrade rejected (same host)
	g = NewRedirectGuard(start, pol, lim)
	if _, err := g.Next("http://example.com/b"); mcperr.ReasonOf(err) != mcperr.ReasonRedirectRejected {
		t.Fatalf("downgrade must be rejected: %v", err)
	}
	// public→private (IP literal) rejected
	g = NewRedirectGuard(start, pol, lim)
	if _, err := g.Next("https://10.0.0.1/b"); mcperr.ReasonOf(err) != mcperr.ReasonRedirectRejected {
		t.Fatalf("public->private must be rejected: %v", err)
	}
	// public→metadata rejected
	g = NewRedirectGuard(start, pol, lim)
	if _, err := g.Next("https://169.254.169.254/b"); mcperr.ReasonOf(err) != mcperr.ReasonRedirectRejected {
		t.Fatalf("public->metadata must be rejected: %v", err)
	}
	// userinfo (credential-bearing) rejected
	g = NewRedirectGuard(start, pol, lim)
	if _, err := g.Next("https://u:p@example.com/b"); mcperr.ReasonOf(err) != mcperr.ReasonRedirectRejected {
		t.Fatalf("credential redirect must be rejected: %v", err)
	}
}

func TestRedirect_LoopAndHopLimit(t *testing.T) {
	pol := httpsAndHTTP()
	cfg := gwConfigForTest()
	cfg.MaxRedirectHops = 3
	cfg.MaxRedirectEvidence = 3
	lim, _ := limits.NewInspection(cfg)
	crossOK, _ := NewPolicy(PolicyConfig{Schemes: []string{"https"}, AllowCrossOriginRedirect: true})
	start, _, _ := Canonicalize("https://a.example/", crossOK, lim)

	// loop: a -> b -> a
	g := NewRedirectGuard(start, crossOK, lim)
	if _, err := g.Next("https://b.example/"); err != nil {
		t.Fatalf("hop1: %v", err)
	}
	if _, err := g.Next("https://a.example/"); mcperr.ReasonOf(err) != mcperr.ReasonRedirectRejected {
		t.Fatalf("loop back must be rejected: %v", err)
	}
	_ = pol

	// hop overflow
	g = NewRedirectGuard(start, crossOK, lim)
	_, _ = g.Next("https://b.example/")
	_, _ = g.Next("https://c.example/")
	_, _ = g.Next("https://d.example/")
	if _, err := g.Next("https://e.example/"); mcperr.ReasonOf(err) != mcperr.ReasonRedirectLimitExceeded {
		t.Fatalf("hop overflow must be RedirectLimitExceeded: %v", err)
	}
}

func TestRedirect_ForwardAuthAcrossOrigin(t *testing.T) {
	crossOK, _ := NewPolicy(PolicyConfig{Schemes: []string{"https"}, AllowCrossOriginRedirect: true})
	lim := gwLim()
	start, _, _ := Canonicalize("https://a.example/", crossOK, lim)
	g := NewRedirectGuard(start, crossOK, lim)
	next, err := g.Next("https://b.example/")
	if err != nil {
		t.Fatalf("cross-origin allowed here: %v", err)
	}
	// After moving to b.example, forwarding auth to a DIFFERENT origin is disallowed.
	other, _, _ := Canonicalize("https://c.example/", crossOK, lim)
	if g.ForwardAuthAllowed(other) {
		t.Fatal("auth must not be forwarded across origin")
	}
	if !g.ForwardAuthAllowed(next) {
		t.Fatal("same-origin auth forward should be allowed")
	}
}

func TestExtract_ModeledAndHeuristic(t *testing.T) {
	lim := gwLim()
	rules, err := CompileRules([]string{"/target"}, true, lim)
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.Decode([]byte(`{"target":"https://api.example/x","webhook":"https://hook.example/y","note":"not a url"}`),
		canonical.Bounds{MaxBytes: 1 << 20, MaxDepth: 32, MaxObjectMembers: 64, MaxArrayElements: 64, MaxStringBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	cands, err := rules.Extract(v, lim)
	if err != nil {
		t.Fatal(err)
	}
	var modeled, heuristic int
	for _, c := range cands {
		if c.Modeled {
			modeled++
		} else {
			heuristic++
		}
	}
	if modeled != 1 || heuristic < 1 {
		t.Fatalf("expected 1 modeled + >=1 heuristic, got modeled=%d heuristic=%d (%+v)", modeled, heuristic, cands)
	}
}

func gwConfigForTest() limits.InspectionConfig {
	return limits.InspectionConfig{
		MaxSchemaBytes: 256 << 10, MaxSchemaNodes: 8192, MaxSchemaAlternatives: 512,
		MaxValidationOps: 1 << 18, MaxArgNodes: 8192, MaxOutputBytes: 4 << 20,
		MaxOutputNodes: 8192, MaxStringsScanned: 8192, MaxBytesPerString: 256 << 10,
		MaxTotalScanBytes: 8 << 20, MaxFindings: 1024, MaxRedactions: 1024,
		MaxExtractionPaths: 256, MaxExtractedDests: 64, MaxURLBytes: 4096,
		MaxHostBytes: 512, MaxQueryBytes: 2048, MaxDNSConcurrency: 16,
		MaxDNSAddresses: 32, MaxDNSWork: 16, MaxRedirectHops: 8, MaxRedirectEvidence: 8,
		MaxInjectionOps: 1 << 18, MaxTransformedBytes: 4 << 20, MaxSafeResultBytes: 64 << 10,
		MaxTruncatedTextBytes: 32 << 10,
	}
}
