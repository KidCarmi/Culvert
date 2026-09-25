package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/idna"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// ─── CHAOS-67 — the client-supplied destination authority on the proxy path ───
//
// The proxy port is reachable by every client on the network and nothing bounded
// the destination authority. net/http admits its 1 MiB default of request line
// plus headers, and every byte reached two rotating sinks AND the label walks in
// urlcat (quadratic suffix probes) and catdb (one BadgerDB transaction per
// label). Measured through the real handleRequest with one ordinary
// DestCategoryGroup rule and the Layer-2 feed present: 251 B → 0.45 ms,
// 4 095 B → 19.6 ms, 16 383 B → 260 ms, 65 535 B → 3.94 s. Quadratic, so
// ~16 minutes of a core at the 1 MiB header default, spent before
// authentication, with all three front-door limiters shipping disabled.
//
// The gates below split deliberately. TestChaos67_Defect* FAIL against the
// pre-fix tree. TestChaos67_Control* prove the bound did not break the data
// plane it sits in front of — a gate that refused every destination would pass
// every defect gate while being a total egress outage, which is far worse than
// the defect.

// chaos66Host builds a dot-dense authority of exactly n bytes. Dot density is
// what makes the matcher walks quadratic (a label boundary every other byte), so
// this is the shape the finding is measured in, not an arbitrary long string.
func chaos66Host(n int) string {
	if n <= 0 {
		return ""
	}
	h := strings.Repeat("a.", (n/2)+1)
	h = h[:n]
	// Never end on a '.': a trailing dot is trimmed by normalization, which
	// would make the byte count the gate sees differ from the one asserted.
	if h[len(h)-1] == '.' {
		h = h[:len(h)-1] + "a"
	}
	return h
}

// chaos66CaptureLog swaps the process logger for a buffer and restores it.
func chaos66CaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = prev })
	return &buf
}

// chaos66Isolate resets the proxy globals plus this sweep's own counter and log
// gate. Both are process-wide, so a test asserting on either must isolate them.
func chaos66Isolate(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	resetOversizeHostStateForTest()
	t.Cleanup(resetOversizeHostStateForTest)
}

// ───────────────────────── DEFECT GATES ─────────────────────────

// TestChaos67_DefectOversizeAuthorityRefusedBeforeAnyState is the primary gate.
// Pre-fix the request ran the whole pipeline and answered 403 (default deny)
// after writing the megabyte into both sinks; post-fix it is refused 400 with
// nothing retained.
func TestChaos67_DefectOversizeAuthorityRefusedBeforeAnyState(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	host := chaos66Host(64 * 1024)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — an authority no resolver can answer for reached the pipeline", w.Code, http.StatusBadRequest)
	}
	if got := proxyOversizeHostRejected.Load(); got != 1 {
		t.Errorf("proxyOversizeHostRejected = %d, want 1 — the rejection is invisible to an operator", got)
	}
	// The refusal must not echo the value back: reflecting it is the same
	// amplification arriving by a third road (§32 had to suppress its own test
	// output for exactly this reason).
	if w.Body.Len() > 256 {
		t.Errorf("response body is %d bytes — the refusal is echoing the oversize authority", w.Body.Len())
	}
}

// TestChaos67_DefectConnectFormIsBounded covers the DOMINANT traffic class. A
// CONNECT request carries its authority in the request target rather than a Host
// header, net/http puts it in r.Host either way, and every HTTPS request through
// this proxy is one — so a gate proven only against the plain-HTTP form is
// proven against the minority of traffic. It also pins that the refusal happens
// BEFORE the tunnel is established: a 400 on the CONNECT means no 200, no
// hijack, and no drain registration.
func TestChaos67_DefectConnectFormIsBounded(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	host := chaos66Host(64 * 1024)
	r := httptest.NewRequest(http.MethodConnect, "http://"+host+":443", http.NoBody)
	r.Host = host + ":443"
	r.RequestURI = host + ":443"
	r.RemoteAddr = "198.51.100.7:51234"
	w := httptest.NewRecorder()
	handleRequest(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("CONNECT status = %d, want %d — the bound does not cover the form every HTTPS request uses", w.Code, http.StatusBadRequest)
	}
	if got := proxyOversizeHostRejected.Load(); got != 1 {
		t.Errorf("proxyOversizeHostRejected = %d, want 1 on the CONNECT form", got)
	}
	for _, e := range reqlog.Get() {
		if len(e.Host) > maxRawDestAuthorityBytes {
			t.Fatalf("CONNECT retained a %d-byte Host field", len(e.Host))
		}
	}
}

// TestChaos67_ControlRefusalIsAccountedAsABlock pins that the two gates agree
// about whether the refusal happened. The first version of this change counted
// statBlocked on the SOCKS5 path and not on the HTTP one — two refusals of the
// same class disagreeing about their own accounting, which is the kind of split
// that makes a dashboard figure quietly wrong.
func TestChaos67_ControlRefusalIsAccountedAsABlock(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	before := atomic.LoadInt64(&statBlocked)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+chaos66Host(64*1024)+"/", nil))
	if got := atomic.LoadInt64(&statBlocked); got != before+1 {
		t.Errorf("statBlocked = %d, want %d — the HTTP refusal is not accounted the way its INVALID_HOST twin is", got, before+1)
	}
}

// TestChaos67_DefectProcessLogStaysBounded measures the BYTES one oversize
// request commits to the process log — a rotating file capped at 50 MB keeping
// ONE archive, which also holds the diagnostics for every other incident.
//
// Pre-fix a 256 KiB authority wrote 262 228 bytes from ONE request (measured);
// eight requests here would cost ~2 MiB. Post-fix the whole run is a few hundred
// bytes, because the rate-limited rejection line names the LENGTH and never the
// value.
func TestChaos67_DefectProcessLogStaysBounded(t *testing.T) {
	chaos66Isolate(t)
	logs := chaos66CaptureLog(t)

	const attempts, hostBytes = 8, 256 * 1024
	host := chaos66Host(hostBytes)
	for i := 0; i < attempts; i++ {
		w := httptest.NewRecorder()
		handleRequest(w, makeRequest("http://"+host+"/", nil))
	}

	// A generous ceiling: the bounded lines cost hundreds of bytes, the pre-fix
	// shape costs ~2 MiB. Anything in between is still a regression.
	const ceiling = 8 * 1024
	if logs.Len() > ceiling {
		t.Errorf("process log grew to %d bytes from %d oversize requests (limit %d) — "+
			"client-chosen bytes are reaching the forensic record", logs.Len(), attempts, ceiling)
	}
	if strings.Contains(logs.String(), strings.Repeat("a.a.", 16)) {
		t.Error("the process log contains a run of the oversize authority — the value is being echoed, not just measured")
	}
}

// TestChaos67_DefectRequestLogNeverCarriesOversizeHost pins the durable JSONL
// feed. The Host field is written verbatim; pre-fix it carried the full 262 143
// bytes on the default-deny path.
func TestChaos67_DefectRequestLogNeverCarriesOversizeHost(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	host := chaos66Host(64 * 1024)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	for _, e := range reqlog.Get() {
		if len(e.Host) > maxRawDestAuthorityBytes {
			t.Fatalf("request-log entry carries a %d-byte Host field (limit %d, status %q) — "+
				"the durable feed is retaining client-chosen bytes", len(e.Host), maxRawDestAuthorityBytes, e.Status)
		}
	}
}

// TestChaos67_DefectIPBlockedPathDoesNotRetainTheAuthority is the ORDERING gate,
// and it is the one that decides where the bound may live. IP_BLOCKED and
// RATE_LIMITED both write r.Host into the request log, and they run BEFORE the
// host-canonicalization step where RISK-013's IDNA gate sits — so a bound placed
// at that gate (the intuitive home for a host check) would sit behind two sinks
// that had already retained the value. This test fails against that shape as
// well as against the pre-fix tree.
func TestChaos67_DefectIPBlockedPathDoesNotRetainTheAuthority(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	// Deny every source, so the request takes the IP_BLOCKED branch.
	//
	// The ipf global is SAVED AND RESTORED, following the pattern every other test
	// that touches it uses (config_surfaces_test.go, connlimit_startup_test.go,
	// controlplane_delta_apply_test.go). Mutating it and leaving it set leaks a
	// deny-everything IP filter into whatever runs next: setupProxyTest rebuilds
	// ipf, so any test that calls it is safe, but SEVEN test files drive
	// handleRequest without it and would see 403 instead of their expected
	// outcome. Under -shuffle that is a determinism failure whose cause is
	// nowhere near the test that reports it.
	// The REPLACEMENT is what makes the restore real: SetMode mutates the filter
	// in place, so saving and restoring the pointer alone would hand back the same
	// mutated object. The other call sites swap in a fresh filter first for
	// exactly this reason; getting it wrong is silent, because the restore looks
	// present.
	origIPF := ipf
	t.Cleanup(func() { ipf = origIPF })
	ipf = &IPFilter{single: map[string]bool{}}
	ipf.SetMode("allow") // allowlist mode with an empty list denies everything
	host := chaos66Host(64 * 1024)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — the bound must be decided ahead of the IP filter, "+
			"whose own branch retains r.Host", w.Code, http.StatusBadRequest)
	}
	for _, e := range reqlog.Get() {
		if len(e.Host) > maxRawDestAuthorityBytes {
			t.Fatalf("IP_BLOCKED retained a %d-byte Host field — the bound is behind a sink", len(e.Host))
		}
	}
}

// TestChaos67_DefectCostIsFlatInAuthorityLength is the CPU gate, expressed as a
// RATIO measured in ONE run so it is machine-independent (the repo's standing
// rule after the sanitizeLog and connlimit episodes: a gate whose bound has to
// be re-baselined per machine gets muted).
//
// Pre-fix the ratio was ~8 700x (3.94 s against 0.45 ms). Post-fix the oversize
// request takes the O(1) reject path and is CHEAPER than the ordinary one, so
// the ratio is below 1. The bound of 20x is orders of magnitude clear of both.
func TestChaos67_DefectCostIsFlatInAuthorityLength(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	// One ordinary category-group rule plus the default taxonomy: the shape that
	// reaches hostCatScratch.fusion() → urlcat's quadratic suffix walk.
	if _, err := globalCategoryGroups.Add("chaos66-group", []string{"Gambling"}); err != nil {
		t.Fatalf("category group: %v", err)
	}
	t.Cleanup(func() { _ = globalCategoryGroups.Delete("chaos66-group") })
	policyStore.Add(PolicyRule{
		Priority: 1, Name: "chaos66-block", Action: ActionBlockPage,
		DestCategoryGroup: "chaos66-group",
	})

	timeOne := func(host string) time.Duration {
		// Best of three: this asserts an ORDER OF MAGNITUDE, and the cheap arm
		// is microseconds, so scheduler noise on a shared runner must not decide
		// the verdict.
		best := time.Duration(1 << 62)
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			r := makeRequest("http://"+host+"/", nil)
			st := time.Now()
			handleRequest(w, r)
			if d := time.Since(st); d < best {
				best = d
			}
		}
		return best
	}

	small := timeOne(chaos66Host(64))
	large := timeOne(chaos66Host(64 * 1024))
	if small <= 0 {
		t.Skip("clock resolution too coarse to form a ratio")
	}
	const bound = 20.0
	if ratio := float64(large) / float64(small); ratio > bound {
		t.Errorf("a 64 KiB authority cost %v against %v for a 64-byte one (ratio %.1fx, bound %.1fx) — "+
			"the quadratic destination-matcher walk is reachable from the network", large, small, ratio, bound)
	}
}

// TestChaos67_DefectTopHostsNeverRetainsAnOversizeKey pins the KEY-SIZE axis of
// the top-hosts counter. Its documented bound is topHostsMaxEntries (10 000)
// distinct hosts, which is a bound on the ENTRY COUNT and never was one on the
// key size — the identical blindness §32 found in internal/lockout, whose
// Cleanup doc claimed the maps were bounded "against an unbounded-memory DoS".
// At the cap, 1 MiB keys are ~10 GiB of resident heap in an in-line gateway
// whose OOM is a total traffic outage.
func TestChaos67_DefectTopHostsNeverRetainsAnOversizeKey(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	// Default-allow posture: the only branch that reaches topHosts.Record.
	// SAVE the previous action rather than hardcoding "deny" on the way out.
	// Hardcoding a restore value is the same class of error as restoring a pointer
	// to a mutated object (see the ipf note above): it looks like a restore and
	// silently imposes this test's assumption on whatever ran before. The repo
	// pattern is prevAction := defaultPolicyAction()
	// (authpolicy_slice8_test.go, dc_final_test.go, config_surfaces_test.go).
	prevAction := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prevAction) })
	setDefaultPolicyAction("allow")
	prevTop := topHosts
	topHosts = &hostCounter{}
	t.Cleanup(func() { topHosts = prevTop })

	host := chaos66Host(64 * 1024)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	for _, h := range topHosts.Top(50) {
		if len(h.Host) > maxDestAuthorityLen {
			t.Fatalf("topHosts retained a %d-byte key (limit %d) — the cap bounds the entry count, not the key size", len(h.Host), maxRawDestAuthorityBytes)
		}
	}
}

// TestChaos67_DefectSOCKS5RefusesOversizeDestination covers the other data-path
// protocol, and it is deliberately written to be NON-VACUOUS. RFC 1928 §4
// length-prefixes DOMAINNAME with one byte, so the protocol caps the destination
// at 255 — BELOW the 261-byte authority bound. The first version of this fix
// applied the authority predicate here, which made the gate permanently dead
// code, and the first version of this test asserted only "no oversize host
// reached the request log", which passes vacuously at 255 bytes. So this now
// asserts the REFUSAL and the counter: a gate that cannot fire fails here.
func TestChaos67_DefectSOCKS5RefusesOversizeDestination(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	// The bound this path enforces must be reachable within what the protocol
	// can carry — otherwise the gate is unreachable by construction. The RAW
	// pre-cap (1 KiB) is NOT reachable here, which is why this path enforces the
	// CANONICAL bound instead; asserting both keeps that distinction honest.
	if maxDestHostLen >= 255 {
		t.Fatalf("maxDestHostLen = %d: the SOCKS5 canonical gate cannot fire, since RFC 1928 caps DOMAINNAME at 255", maxDestHostLen)
	}
	if maxRawDestAuthorityBytes < 255 {
		t.Fatalf("maxRawDestAuthorityBytes = %d is below what RFC 1928 can carry (255); a raw gate here would be live and this comment wrong", maxRawDestAuthorityBytes)
	}

	ln := startSOCKS5Listener(t)
	// DialContext, not DialTimeout: the repo convention (CLAUDE.md "HTTP
	// contexts") and what the noctx linter enforces. The pre-existing SOCKS5
	// harness in socks5_test.go still uses DialTimeout, which is why copying it
	// tripped the diff-scoped lint here rather than there.
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(dialCtx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup; the handler owns the conn and may already have closed it

	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatalf("greeting: %v", err)
	}

	// The longest DOMAINNAME the protocol can carry: 255 bytes, two above the
	// 253 a resolvable name can occupy.
	// 255 ASCII bytes: two above the 253 a resolvable name can occupy, and ASCII
	// does not shrink under IDNA, so this reaches the canonical gate.
	host := chaos66Host(255)
	if !canonicalHostOversize(host) {
		t.Fatalf("a %d-byte SOCKS5 destination is not considered oversize — the gate is dead code", len(host))
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))} // #nosec G115 -- 255 by construction
	req = append(req, host...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, 443)
	req = append(req, port...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("request: %v", err)
	}

	// The handler must answer a failure reply (0x02) and charge the counter.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("no SOCKS5 reply to an oversize destination: %v", err)
	}
	if reply[1] != 0x02 {
		t.Errorf("SOCKS5 reply code = 0x%02x, want 0x02 — the oversize destination was not refused", reply[1])
	}
	if got := proxyOversizeHostRejected.Load(); got != 1 {
		t.Errorf("proxyOversizeHostRejected = %d, want 1 — the SOCKS5 refusal is invisible to an operator", got)
	}
	// And the destination must never have reached the request log.
	for _, e := range reqlog.Get() {
		if len(e.Host) > maxRawDestAuthorityBytes {
			t.Fatalf("SOCKS5 retained a %d-byte Host field in the request log", len(e.Host))
		}
	}
}

// TestChaos67_DefectAdminURLLookupIsBounded covers the admin plane. The
// url-lookup endpoint reaches the SAME two-tier fusion from a query string
// inside the 1 MiB header block, so pre-fix an authenticated VIEWER could park
// an admin-plane goroutine for minutes with one GET.
func TestChaos67_DefectAdminURLLookupIsBounded(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	before := proxyOversizeHostRejected.Load()
	r := httptest.NewRequest(http.MethodGet, "/api/url-categories/lookup?host="+chaos66Host(64*1024), http.NoBody)
	r = withRole(r, RoleAdmin)
	w := httptest.NewRecorder()
	apiURLCatLookup(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — the admin lookup reaches the quadratic fusion unbounded", w.Code, http.StatusBadRequest)
	}
	if got := proxyOversizeHostRejected.Load(); got != before+1 {
		t.Errorf("proxyOversizeHostRejected = %d, want %d — the admin-plane refusal is uncounted", got, before+1)
	}
}

// ───────────────────────── CONTROLS ─────────────────────────

// TestChaos67_ControlBoundIsInclusiveAndDerived pins the arithmetic in code, so
// the derivation stays checkable rather than living only in a comment, and pins
// that the limit is INCLUSIVE — an off-by-one here refuses a legal destination.
func TestChaos67_ControlBoundIsInclusiveAndDerived(t *testing.T) {
	// "[" + host + "]" + ":" + "65535"
	if want := 1 + maxDestHostLen + 1 + 1 + 5; maxDestAuthorityLen != want {
		t.Errorf("maxDestAuthorityLen = %d, want %d (1 + %d + 1 + 1 + 5) — the constant no longer matches its stated derivation",
			maxDestAuthorityLen, want, maxDestHostLen)
	}
	if maxDestHostLen != 253 {
		t.Errorf("maxDestHostLen = %d, want 253 (RFC 1035 §2.3.4 wire limit of 255 octets in RFC 1123 presentation form)", maxDestHostLen)
	}
	if rawAuthorityOversize(chaos66Host(maxRawDestAuthorityBytes)) {
		t.Errorf("a raw authority of exactly %d bytes was refused; the limit is inclusive", maxRawDestAuthorityBytes)
	}
	if !rawAuthorityOversize(chaos66Host(maxRawDestAuthorityBytes + 1)) {
		t.Errorf("a raw authority of %d bytes was admitted; the pre-cap is not enforced", maxRawDestAuthorityBytes+1)
	}
	if canonicalHostOversize(chaos66Host(maxDestHostLen)) {
		t.Errorf("a canonical host of exactly %d bytes was refused; the limit is inclusive", maxDestHostLen)
	}
	if !canonicalHostOversize(chaos66Host(maxDestHostLen + 1)) {
		t.Errorf("a canonical host of %d bytes was admitted; the canonical bound is not enforced", maxDestHostLen+1)
	}
	// The RAW pre-cap must be STRICTLY looser than the canonical bound. If it
	// were not, it would refuse legitimate IDN input before normalization could
	// shrink it — which is exactly the Codex P2 regression this two-tier shape
	// exists to fix, and a single-tier design is what reintroduces it.
	if maxRawDestAuthorityBytes <= maxDestAuthorityLen {
		t.Errorf("maxRawDestAuthorityBytes (%d) is not looser than the canonical authority bound (%d) — "+
			"a raw bound at the DNS limit refuses legitimate internationalized domains",
			maxRawDestAuthorityBytes, maxDestAuthorityLen)
	}
	// The canonical bound must be reachable within what each protocol can
	// deliver, or its gate is dead code — the first self-review finding.
	if maxDestHostLen >= 255 {
		t.Errorf("maxDestHostLen (%d) exceeds what RFC 1928 §4 can carry (255) — the SOCKS5 gate would be unreachable", maxDestHostLen)
	}
}

// TestChaos67_ControlOrdinaryDestinationStillProxies is the control that matters
// most: the cheapest way to pass every defect gate above is to refuse every
// destination, which is a total egress outage. This drives the real allow path
// end to end against a live backend.
func TestChaos67_ControlOrdinaryDestinationStillProxies(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)
	hostPort := strings.TrimPrefix(backend.URL, "http://")
	hostOnly := hostPort[:strings.LastIndex(hostPort, ":")]
	policyStore.Add(PolicyRule{Priority: 1, Name: "chaos66-allow", Action: ActionAllow, DestFQDN: hostOnly})

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest(backend.URL+"/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("an ordinary destination was not proxied: status %d — the bound is refusing legitimate traffic", w.Code)
	}
	if got := proxyOversizeHostRejected.Load(); got != 0 {
		t.Errorf("proxyOversizeHostRejected = %d after an ordinary request, want 0", got)
	}
}

// TestChaos67_ControlLegitimateAuthorityShapesAreAccepted pins the shapes the
// register warned the bound had to answer for before it could ship.
//
// **The IDN cases are here because their absence let a real regression through.**
// The first version of this control tested ASCII shapes only, and the first
// version of the bound applied the DNS limit to RAW bytes — which refuses any
// internationalized name whose UTF-8 form exceeds 261 bytes even though IDNA
// shrinks it well inside DNS limits. Codex caught it on PR #1446 (P2). A forward
// proxy that cannot reach international destinations is a customer outage, so
// these cases are not decoration: they are the control that makes the raw tier's
// generosity load-bearing rather than arbitrary.
func TestChaos67_ControlLegitimateAuthorityShapesAreAccepted(t *testing.T) {
	for _, tc := range []struct{ what, authority string }{
		{"plain", "example.com"},
		{"with port", "example.com:8443"},
		{"trailing dot", "example.com."},
		{"IPv4 literal", "10.1.2.3:3128"},
		{"IPv6 literal", "[2001:db8::1]:443"},
		{"IPv6 with zone", "[fe80::1%25eth0]:443"},
		{"bare bracketed literal", "[2001:db8::1]"},
		{"longest possible name", chaos66Host(maxDestHostLen)},
		{"longest name with port", chaos66Host(maxDestHostLen) + ":65535"},
		// Codex's example verbatim: 323 raw UTF-8 bytes, 187 A-label bytes.
		{"IDN, Codex's case", chaos66IDN(40, 4)},
		{"IDN with port", chaos66IDN(40, 4) + ":443"},
		{"IDN, single label", chaos66IDN(40, 1) + ".example.com"},
		// The worst legitimate expansion found by driving the real idna.ToASCII:
		// 899 raw bytes normalizing to 255 A-label bytes.
		{"IDN, maximal expansion", chaos66MaxIDN(t)},
	} {
		if rawAuthorityOversize(tc.authority) {
			t.Errorf("%s: a legitimate authority was refused by the RAW pre-cap (%d bytes, cap %d)",
				tc.what, len(tc.authority), maxRawDestAuthorityBytes)
			continue
		}
		// And it must survive the CANONICAL tier too, which is the one an IDN
		// has to shrink past. Strip any port/brackets the way the dispatch path
		// does before normalizing.
		host := tc.authority
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		norm, ok := normalizeHostStrict(host)
		if !ok {
			t.Errorf("%s: %q failed canonicalization, so this case proves nothing about the bound", tc.what, tc.what)
			continue
		}
		if canonicalHostOversize(norm) {
			t.Errorf("%s: a legitimate authority was refused by the CANONICAL bound "+
				"(raw %d bytes, canonical %d, limit %d) — this is the IDN regression Codex found",
				tc.what, len(tc.authority), len(norm), maxDestHostLen)
		}
	}
}

// chaos66IDN builds an internationalized host of labelRunes 2-byte runes per
// label, across labels labels. "é" is the character Codex's example used.
func chaos66IDN(labelRunes, labels int) string {
	parts := make([]string, labels)
	for i := range parts {
		parts[i] = strings.Repeat("é", labelRunes)
	}
	return strings.Join(parts, ".")
}

// chaos66MaxIDN returns the widest legitimate raw-to-canonical expansion this
// build's idna can produce: it searches label sizes and label counts for the
// largest RAW UTF-8 host whose canonical A-label form still fits DNS.
//
// It is computed against the REAL idna.ToASCII rather than asserted from a
// constant, so an x/net change that alters the expansion ratio moves this fixture
// instead of silently invalidating the raw cap's derivation. 4-byte runes are
// used because they are the worst case: Punycode emits at least one byte per
// encoded code point, so the raw:canonical ratio is maximised by the widest
// UTF-8 encoding.
func chaos66MaxIDN(t *testing.T) string {
	t.Helper()
	best := ""
	for runes := 1; runes <= 80; runes++ {
		label := strings.Repeat("\U0001D11E", runes) // U+1D11E, 4 UTF-8 bytes
		if a, err := idna.ToASCII(label); err != nil || len(a) > 63 {
			continue // not a valid DNS label
		}
		for labels := 1; labels <= 16; labels++ {
			parts := make([]string, labels)
			for i := range parts {
				parts[i] = label
			}
			host := strings.Join(parts, ".")
			a, err := idna.ToASCII(host)
			if err != nil || len(a) > maxDestHostLen {
				continue
			}
			if len(host) > len(best) {
				best = host
			}
		}
	}
	if best == "" {
		t.Fatal("could not build a maximal legitimate IDN host")
	}
	return best
}

// TestChaos67_ControlRawCapExceedsMaximumIDNExpansion is the DERIVATION control
// for the raw pre-cap. The cap is only safe if no host whose canonical form fits
// in DNS can exceed it in raw UTF-8 — otherwise the proxy refuses a destination
// that resolves. It measures the widest expansion this build's idna actually
// produces rather than trusting the arithmetic in the comment.
func TestChaos67_ControlRawCapExceedsMaximumIDNExpansion(t *testing.T) {
	maxIDN := chaos66MaxIDN(t)
	canonical, err := idna.ToASCII(maxIDN)
	if err != nil {
		t.Fatalf("idna.ToASCII: %v", err)
	}
	t.Logf("maximal legitimate IDN: raw=%d bytes canonical=%d bytes (raw cap %d)",
		len(maxIDN), len(canonical), maxRawDestAuthorityBytes)
	if len(maxIDN) > maxRawDestAuthorityBytes {
		t.Fatalf("the widest legitimate IDN is %d raw bytes but the pre-cap is %d — "+
			"the proxy refuses a destination that resolves", len(maxIDN), maxRawDestAuthorityBytes)
	}
	// And the margin must be real, not accidental: if the cap sat barely above
	// the measured maximum, an idna change could push a legitimate name past it.
	if margin := maxRawDestAuthorityBytes - len(maxIDN); margin < 64 {
		t.Errorf("only %d bytes of margin between the raw pre-cap (%d) and the widest legitimate IDN (%d)",
			margin, maxRawDestAuthorityBytes, len(maxIDN))
	}
}

// TestChaos67_DefectDotDenseASCIIIsStillRefusedByTheCanonicalTier is the gate
// that keeps the raw tier's generosity from being a hole. The raw pre-cap has to
// be 1 KiB to admit IDN expansion, and on its own that still admits a 1 000-byte
// dot-dense ASCII authority costing ~1.3 ms of matcher walk. ASCII does not
// shrink under IDNA, so the canonical tier refuses exactly that shape.
func TestChaos67_DefectDotDenseASCIIIsStillRefusedByTheCanonicalTier(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	host := chaos66Host(1000) // inside the raw pre-cap, far outside DNS
	if rawAuthorityOversize(host) {
		t.Fatalf("a %d-byte authority is refused by the RAW tier, so this gate cannot reach the canonical one", len(host))
	}
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — a %d-byte dot-dense ASCII authority passed both tiers",
			w.Code, http.StatusBadRequest, len(host))
	}
	if got := proxyOversizeHostRejected.Load(); got != 1 {
		t.Errorf("proxyOversizeHostRejected = %d, want 1 — the canonical refusal is uncounted", got)
	}
	for _, e := range reqlog.Get() {
		if len(e.Host) > maxDestAuthorityLen {
			t.Fatalf("the canonical tier let a %d-byte Host field reach the request log", len(e.Host))
		}
	}
}

// TestChaos67_ControlRejectionIsStillRecorded is the evidence control. Bounding
// the bytes must not delete the fact that the proxy port is being probed —
// exactly the trade §32 made for the audit entry. The line carries the LENGTH
// and the cumulative count; the magnitude must never live only in the counter
// with nothing in the log to point at it.
func TestChaos67_ControlRejectionIsStillRecorded(t *testing.T) {
	chaos66Isolate(t)
	logs := chaos66CaptureLog(t)

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+chaos66Host(64*1024)+"/", nil))

	line := logs.String()
	if !strings.Contains(line, "OVERSIZE_HOST") {
		t.Fatalf("the rejection left no trace in the process log: %q", line)
	}
	if !strings.Contains(line, "bytes=65536") && !strings.Contains(line, "bytes=6553") {
		t.Errorf("the log line does not name the length, which is the only fact that distinguishes a probe from a broken client: %q", line)
	}
	if !strings.Contains(line, "total=1") {
		t.Errorf("the log line does not carry the cumulative count: %q", line)
	}
}

// TestChaos67_ControlLogIsRateLimited pins that the mitigation is not itself a
// write amplifier: a flood must cost at most one line per window.
func TestChaos67_ControlLogIsRateLimited(t *testing.T) {
	chaos66Isolate(t)
	logs := chaos66CaptureLog(t)

	const attempts = 50
	for i := 0; i < attempts; i++ {
		w := httptest.NewRecorder()
		handleRequest(w, makeRequest("http://"+chaos66Host(4096)+"/", nil))
	}
	if n := strings.Count(logs.String(), "OVERSIZE_HOST"); n != 1 {
		t.Errorf("%d oversize requests emitted %d log lines, want exactly 1 — the rejection log is not rate-limited", attempts, n)
	}
	if got := proxyOversizeHostRejected.Load(); got != attempts {
		t.Errorf("proxyOversizeHostRejected = %d, want %d — the counter must carry the magnitude the log suppresses", got, attempts)
	}
}
