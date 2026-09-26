package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/idna"

	"github.com/KidCarmi/Culvert/internal/reqlog"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// ─── CHAOS-69 — the client-supplied destination authority on the proxy path ───
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
// The gates below split deliberately. TestChaos69_Defect* FAIL against the
// pre-fix tree. TestChaos69_Control* prove the bound did not break the data
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

// TestChaos69_DefectOversizeAuthorityRefusedBeforeAnyState is the primary gate.
// Pre-fix the request ran the whole pipeline and answered 403 (default deny)
// after writing the megabyte into both sinks; post-fix it is refused 400 with
// nothing retained.
func TestChaos69_DefectOversizeAuthorityRefusedBeforeAnyState(t *testing.T) {
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

// TestChaos69_DefectConnectFormIsBounded covers the DOMINANT traffic class. A
// CONNECT request carries its authority in the request target rather than a Host
// header, net/http puts it in r.Host either way, and every HTTPS request through
// this proxy is one — so a gate proven only against the plain-HTTP form is
// proven against the minority of traffic. It also pins that the refusal happens
// BEFORE the tunnel is established: a 400 on the CONNECT means no 200, no
// hijack, and no drain registration.
func TestChaos69_DefectConnectFormIsBounded(t *testing.T) {
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

// TestChaos69_ControlRefusalIsAccountedAsABlock pins that the two gates agree
// about whether the refusal happened. The first version of this change counted
// statBlocked on the SOCKS5 path and not on the HTTP one — two refusals of the
// same class disagreeing about their own accounting, which is the kind of split
// that makes a dashboard figure quietly wrong.
func TestChaos69_ControlRefusalIsAccountedAsABlock(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	before := atomic.LoadInt64(&statBlocked)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+chaos66Host(64*1024)+"/", nil))
	if got := atomic.LoadInt64(&statBlocked); got != before+1 {
		t.Errorf("statBlocked = %d, want %d — the HTTP refusal is not accounted the way its INVALID_HOST twin is", got, before+1)
	}
}

// TestChaos69_DefectProcessLogStaysBounded measures the BYTES one oversize
// request commits to the process log — a rotating file capped at 50 MB keeping
// ONE archive, which also holds the diagnostics for every other incident.
//
// Pre-fix a 256 KiB authority wrote 262 228 bytes from ONE request (measured);
// eight requests here would cost ~2 MiB. Post-fix the whole run is a few hundred
// bytes, because the rate-limited rejection line names the LENGTH and never the
// value.
func TestChaos69_DefectProcessLogStaysBounded(t *testing.T) {
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

// TestChaos69_DefectRequestLogNeverCarriesOversizeHost pins the durable JSONL
// feed. The Host field is written verbatim; pre-fix it carried the full 262 143
// bytes on the default-deny path.
func TestChaos69_DefectRequestLogNeverCarriesOversizeHost(t *testing.T) {
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

// TestChaos69_DefectIPBlockedPathDoesNotRetainTheAuthority is the ORDERING gate,
// and it is the one that decides where the bound may live. IP_BLOCKED and
// RATE_LIMITED both write r.Host into the request log, and they run BEFORE the
// host-canonicalization step where RISK-013's IDNA gate sits — so a bound placed
// at that gate (the intuitive home for a host check) would sit behind two sinks
// that had already retained the value. This test fails against that shape as
// well as against the pre-fix tree.
func TestChaos69_DefectIPBlockedPathDoesNotRetainTheAuthority(t *testing.T) {
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

// TestChaos69_DefectCostIsFlatInAuthorityLength is the CPU gate, expressed as a
// RATIO measured in ONE run so it is machine-independent (the repo's standing
// rule after the sanitizeLog and connlimit episodes: a gate whose bound has to
// be re-baselined per machine gets muted).
//
// Pre-fix the ratio was ~8 700x (3.94 s against 0.45 ms). Post-fix the oversize
// request takes the O(1) reject path and is CHEAPER than the ordinary one, so
// the ratio is below 1. The bound of 20x is orders of magnitude clear of both.
func TestChaos69_DefectCostIsFlatInAuthorityLength(t *testing.T) {
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

// TestChaos69_DefectTopHostsNeverRetainsAnOversizeKey pins the KEY-SIZE axis of
// the top-hosts counter. Its documented bound is topHostsMaxEntries (10 000)
// distinct hosts, which is a bound on the ENTRY COUNT and never was one on the
// key size — the identical blindness §32 found in internal/lockout, whose
// Cleanup doc claimed the maps were bounded "against an unbounded-memory DoS".
// At the cap, 1 MiB keys are ~10 GiB of resident heap in an in-line gateway
// whose OOM is a total traffic outage.
func TestChaos69_DefectTopHostsNeverRetainsAnOversizeKey(t *testing.T) {
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

// TestChaos69_DefectSOCKS5RefusesOversizeDestination covers the other data-path
// protocol, and it is deliberately written to be NON-VACUOUS. RFC 1928 §4
// length-prefixes DOMAINNAME with one byte, so the protocol caps the destination
// at 255 — BELOW the 261-byte authority bound. The first version of this fix
// applied the authority predicate here, which made the gate permanently dead
// code, and the first version of this test asserted only "no oversize host
// reached the request log", which passes vacuously at 255 bytes. So this now
// asserts the REFUSAL and the counter: a gate that cannot fire fails here.
func TestChaos69_DefectSOCKS5RefusesOversizeDestination(t *testing.T) {
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

// TestChaos69_DefectAdminURLLookupIsBounded covers the admin plane. The
// url-lookup endpoint reaches the SAME two-tier fusion from a query string
// inside the 1 MiB header block, so pre-fix an authenticated VIEWER could park
// an admin-plane goroutine for minutes with one GET.
func TestChaos69_DefectAdminURLLookupIsBounded(t *testing.T) {
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

// TestChaos69_ControlBoundIsInclusiveAndDerived pins the arithmetic in code, so
// the derivation stays checkable rather than living only in a comment, and pins
// that the limit is INCLUSIVE — an off-by-one here refuses a legal destination.
func TestChaos69_ControlBoundIsInclusiveAndDerived(t *testing.T) {
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

// TestChaos69_ControlOrdinaryDestinationStillProxies is the control that matters
// most: the cheapest way to pass every defect gate above is to refuse every
// destination, which is a total egress outage. This drives the real allow path
// end to end against a live backend.
func TestChaos69_ControlOrdinaryDestinationStillProxies(t *testing.T) {
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

// TestChaos69_ControlLegitimateAuthorityShapesAreAccepted pins the shapes the
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
func TestChaos69_ControlLegitimateAuthorityShapesAreAccepted(t *testing.T) {
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
		// 883 raw bytes normalizing to 251 A-label bytes.
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

// TestChaos69_ControlRawCapExceedsMaximumIDNExpansion is the DERIVATION control
// for the raw pre-cap. The cap is only safe if no host whose canonical form fits
// in DNS can exceed it in raw UTF-8 — otherwise the proxy refuses a destination
// that resolves. It measures the widest expansion this build's idna actually
// produces rather than trusting the arithmetic in the comment.
func TestChaos69_ControlRawCapExceedsMaximumIDNExpansion(t *testing.T) {
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

// TestChaos69_DefectDotDenseASCIIIsStillRefusedByTheCanonicalTier is the gate
// that keeps the raw tier's generosity from being a hole. The raw pre-cap has to
// be 1 KiB to admit IDN expansion, and on its own that still admits a 1 000-byte
// dot-dense ASCII authority costing ~1.3 ms of matcher walk. ASCII does not
// shrink under IDNA, so the canonical tier refuses exactly that shape.
func TestChaos69_DefectDotDenseASCIIIsStillRefusedByTheCanonicalTier(t *testing.T) {
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

// TestChaos69_ControlRejectionIsStillRecorded is the evidence control. Bounding
// the bytes must not delete the fact that the proxy port is being probed —
// exactly the trade §32 made for the audit entry. The line carries the LENGTH
// and the cumulative count; the magnitude must never live only in the counter
// with nothing in the log to point at it.
func TestChaos69_ControlRejectionIsStillRecorded(t *testing.T) {
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

// TestChaos69_ControlLogIsRateLimited pins that the mitigation is not itself a
// write amplifier: a flood must cost at most one line per window.
func TestChaos69_ControlLogIsRateLimited(t *testing.T) {
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

// ─────────────── DEFECT GATES: the canonical tier's POSITION ───────────────
//
// Both gates below close Codex P2 findings on PR #1446, and they share one root
// cause: the RAW tier was applied at all four entry points from the start, the
// CANONICAL tier was applied only where a normalized host already happened to be
// in scope. Enforcing one tier of a two-tier contract is not enforcing it.
//
// They are also the THIRD instance of one lesson in this sweep. The IDN
// regression happened because the control sampled one REPRESENTATION of the
// input; these happened because the gates sampled one PATH to the matcher.
// DefectDotDenseASCIIIsStillRefusedByTheCanonicalTier drove the plain-HTTP proxy
// path and passed, while the auth path and both admin paths were open.

// TestChaos69_DefectCanonicalTierPrecedesStage1Auth pins that the canonical bound
// runs ahead of Stage-1 authentication.
//
// The canonical tier used to sit at the RISK-013 canonicalization gate, ~60 lines
// below the raw one, justified by the raw pre-cap having already bounded what the
// sinks in between could RETAIN. That justification is about retention only. The
// canonical tier's other job is bounding the QUADRATIC MATCHER WALK, and Stage-1
// auth runs a matcher: authRuleMatchesScratch calls matchDestNorm with
// authMatchScratch.hostCat(), the same category fusion. Worse, a terminal auth
// outcome returns before the gate is reached at all, so a 1 000-byte dot-dense
// authority collected a 407 and the refusal never happened — uncounted, so an
// operator watching culvert_proxy_oversize_host_rejected_total saw nothing.
func TestChaos69_DefectCanonicalTierPrecedesStage1Auth(t *testing.T) {
	setupAuthGateTest(t) // configures auth; an uncredentialed request is challenged
	resetOversizeHostStateForTest()
	t.Cleanup(resetOversizeHostStateForTest)
	chaos66CaptureLog(t)

	// PRECONDITION. Without this the gate could pass vacuously on a build where
	// Stage-1 never challenges — the not-vacuous-check rule this sweep recorded
	// after shipping a SOCKS5 gate that could not fire.
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://ordinary-precondition.example.test/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("precondition failed: an uncredentialed request must terminate in Stage-1 with 407, got %d — "+
			"this gate proves nothing about ordering unless auth really would have answered first", w.Code)
	}

	host := chaos66Host(1000) // inside the 1 KiB raw pre-cap, far outside DNS
	if rawAuthorityOversize(host) {
		t.Fatalf("a %d-byte authority is refused by the RAW tier, so this gate cannot reach the canonical one", len(host))
	}
	before := proxyOversizeHostRejected.Load()

	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	if w.Code == http.StatusProxyAuthRequired {
		t.Fatalf("a %d-byte dot-dense authority terminated in Stage-1 auth with a 407: the canonical tier sits BEHIND "+
			"authentication, so a category-scoped auth rule pays the quadratic walk and the bound never runs", len(host))
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — the canonical tier did not refuse ahead of authentication", w.Code, http.StatusBadRequest)
	}
	if got := proxyOversizeHostRejected.Load(); got != before+1 {
		t.Errorf("proxyOversizeHostRejected = %d, want %d — the refusal is uncounted, so the operator surface is blind to it",
			got, before+1)
	}
}

// TestChaos69_DefectAdminEntryPointsApplyTheCanonicalTier pins that both admin
// matcher entry points enforce BOTH tiers, not just the raw pre-cap.
//
// The raw cap is deliberately generous (1 KiB) so IDN expansion is not refused,
// which on its own still admits the 1 000-byte dot-dense ASCII shape costing
// ~1.3 ms of fusion — and apiPolicyTest can invoke the fusion more than once per
// call. Both are reachable by a VIEWER, the lowest role the product has.
func TestChaos69_DefectAdminEntryPointsApplyTheCanonicalTier(t *testing.T) {
	host := chaos66Host(1000)
	if rawAuthorityOversize(host) {
		t.Fatalf("a %d-byte host is refused by the RAW tier, so this gate cannot reach the canonical one", len(host))
	}

	t.Run("url-category-lookup", func(t *testing.T) {
		chaos66Isolate(t)
		chaos66CaptureLog(t)
		before := proxyOversizeHostRejected.Load()

		r := withRole(httptest.NewRequest(http.MethodGet, "/api/url-categories/lookup?host="+host, http.NoBody), RoleViewer)
		w := httptest.NewRecorder()
		apiURLCatLookup(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d — a viewer reached lookupHostCategory with a %d-byte dot-dense host",
				w.Code, http.StatusBadRequest, len(host))
		}
		if got := proxyOversizeHostRejected.Load(); got != before+1 {
			t.Errorf("proxyOversizeHostRejected = %d, want %d — the admin-plane canonical refusal is uncounted", got, before+1)
		}
	})

	t.Run("policy-test", func(t *testing.T) {
		chaos66Isolate(t)
		chaos66CaptureLog(t)
		before := proxyOversizeHostRejected.Load()

		w := httptest.NewRecorder()
		apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": host}))

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d — a viewer reached walkPolicyTestRules and the fusion with a %d-byte dot-dense host",
				w.Code, http.StatusBadRequest, len(host))
		}
		if got := proxyOversizeHostRejected.Load(); got != before+1 {
			t.Errorf("proxyOversizeHostRejected = %d, want %d — the admin-plane canonical refusal is uncounted", got, before+1)
		}
	})
}

// TestChaos69_RunbookLogExampleMatchesTheEmitter pins the runbook's OVERSIZE_HOST
// examples against what noteOversizeHostRejection really emits, per tier.
//
// It exists because the example DRIFTED: the two-tier rework changed the line's
// shape (it gained tier=, and limit= became the bound actually applied) while the
// runbook kept a single pre-rework line showing no tier and limit=261 — the
// derivation-only maxDestAuthorityLen, which this emitter never prints. An
// operator building log parsing or an incident-response step from that example
// could not match real output and could not tell WHICH bound fired, which is the
// one question the two tiers exist to answer (Codex review, PR #1446).
//
// Prose cannot be unit-tested, but an example CAN: the doc is compared against
// the emitter's own output rather than against a regex rewritten here, so a
// future change to the format string fails the build until the runbook is
// updated in the same commit. total= is normalised because it carries the live
// cumulative count, which no example can pin.
//
// It deliberately does NOT dictate HOW MANY examples the runbook shows or which
// tiers it picks — that is the doc author's call, and a gate that imposed it
// would fail the build over formatting rather than over a wrong line. What it
// enforces is narrower and is the actual contract: every OVERSIZE_HOST line the
// runbook prints must be one this emitter really produces, and must name the
// tier that fired (the field whose absence was half the original defect).
func TestChaos69_RunbookLogExampleMatchesTheEmitter(t *testing.T) {
	const runbook = "docs/operator/destination-host-bounds.md"
	doc, err := os.ReadFile(runbook)
	if err != nil {
		t.Fatalf("read %s: %v", runbook, err)
	}

	totals := regexp.MustCompile(`total=\d+`)
	normalise := func(s string) string { return totals.ReplaceAllString(strings.TrimSpace(s), "total=N") }

	var examples []string
	for _, line := range strings.Split(string(doc), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "OVERSIZE_HOST ") {
			examples = append(examples, strings.TrimSpace(line))
		}
	}

	// Not-vacuous check: a runbook that stopped showing the line entirely must
	// FAIL rather than pass by having nothing left to compare.
	if len(examples) == 0 {
		t.Fatal("runbook shows no OVERSIZE_HOST example — nothing to pin against the emitter")
	}

	for _, want := range examples {
		fields := strings.Fields(want)
		if len(fields) < 4 {
			t.Fatalf("unparseable example %q", want)
		}
		proto, clientIP := fields[1], fields[2]

		var tier string
		var nbytes int
		for _, f := range fields {
			f = strings.Trim(f, "{}")
			switch {
			case strings.HasPrefix(f, "tier="):
				tier = strings.TrimPrefix(f, "tier=")
			case strings.HasPrefix(f, "bytes="):
				if nbytes, err = strconv.Atoi(strings.TrimPrefix(f, "bytes=")); err != nil {
					t.Fatalf("example %q: bytes= is not a number: %v", want, err)
				}
			}
		}
		if tier == "" {
			t.Errorf("example %q names no tier — an operator cannot tell which bound fired", want)
			continue
		}
		resetOversizeHostStateForTest()
		buf := chaos66CaptureLog(t)
		noteOversizeHostRejection(proto, clientIP, nbytes, tier)

		got := normalise(buf.String())
		if got == "" {
			t.Fatalf("emitter produced no line for tier=%s", tier)
		}
		if got != normalise(want) {
			t.Errorf("runbook example does not match the emitter\n doc: %s\nreal: %s", normalise(want), got)
		}
	}
}

// chaos69Unnormalizable builds an authority inside the RAW pre-cap that
// canonicalDestHost CANNOT normalize: dot-dense (so the suffix walk is
// quadratic) with a malformed ACE label, which idna.ToASCII refuses.
func chaos69Unnormalizable(n int) string {
	h := ""
	for len(h) < n-5 {
		h += "a."
	}
	return h + "xn--0"
}

// TestChaos69_DefectUnnormalizableHostIsStillBounded closes the hole the
// round-2 hoist left behind: the canonical tier was guarded by
// `destNormOK && …`, so an authority with NO canonical form skipped it
// entirely and reached Stage-1's matcher at full length.
//
// The band is real and narrow: > maxDestHostLen bare bytes but <=
// maxRawDestAuthorityBytes raw, so neither tier fires. HTTP's INVALID_HOST
// refusal sits AFTER resolveRequestAuth (deliberately — it carries the
// authenticated identity), so a terminal 407 returned before the request was
// ever refused and the counter never moved (Codex P2, PR #1446).
//
// SOCKS5 was never exposed: it refuses INVALID_HOST at the normalization point,
// ahead of its canonical tier and every matcher — the shape HTTP lacked.
//
// Bounding an unnormalizable host on its RAW bytes does NOT reintroduce the
// round-1 IDN regression, and the reason is specific: that regression refused
// LEGITIMATE internationalized names whose canonical form fitted. Here
// normalization FAILED, so there is no canonical form and the host cannot be
// resolved by anybody — refusing it on length cannot reject a destination that
// could have been served, and the status class (400) is what INVALID_HOST
// already answered.
func TestChaos69_DefectUnnormalizableHostIsStillBounded(t *testing.T) {
	setupAuthGateTest(t)
	resetOversizeHostStateForTest()
	t.Cleanup(resetOversizeHostStateForTest)
	chaos66CaptureLog(t)

	host := chaos69Unnormalizable(1000)

	// The band this gate lives in must actually exist, or it proves nothing.
	if rawAuthorityOversize(host) {
		t.Fatalf("a %d-byte authority is refused by the RAW tier — this gate cannot reach the unnormalizable band", len(host))
	}
	if _, ok := canonicalDestHost(host); ok {
		t.Fatalf("host normalized, so the CANONICAL tier covers it — this gate must use a host with no canonical form")
	}

	// PRECONDITION: Stage-1 really would answer first on this build.
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://ordinary-precondition.example.test/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("precondition failed: an uncredentialed request must terminate in Stage-1 with 407, got %d", w.Code)
	}

	before := proxyOversizeHostRejected.Load()
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	if w.Code == http.StatusProxyAuthRequired {
		t.Fatalf("a %d-byte unnormalizable dot-dense authority terminated in Stage-1 with a 407: the request paid the "+
			"quadratic matcher walk and was never refused", len(host))
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if got := proxyOversizeHostRejected.Load(); got != before+1 {
		t.Errorf("proxyOversizeHostRejected = %d, want %d — the refusal is uncounted", got, before+1)
	}
}

// ControlShortUnnormalizableHostKeepsItsInvalidHostRefusal is the CONTROL: the
// cheapest way to pass the gate above is to refuse every unnormalizable host at
// the entry point, which would delete the identity-bearing INVALID_HOST audit
// row that ordinary malformed destinations produce. Only the OVERSIZE band may
// change.
func TestChaos69_ControlShortUnnormalizableHostKeepsItsInvalidHostRefusal(t *testing.T) {
	setupAuthGateTest(t)
	resetOversizeHostStateForTest()
	t.Cleanup(resetOversizeHostStateForTest)
	chaos66CaptureLog(t)

	const short = "xn--0" // unnormalizable, far inside every bound
	if _, ok := canonicalDestHost(short); ok {
		t.Fatalf("%q normalized — this control needs an unnormalizable host", short)
	}

	before := proxyOversizeHostRejected.Load()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+short+"/", nil))

	if got := proxyOversizeHostRejected.Load(); got != before {
		t.Errorf("a SHORT unnormalizable host was charged to the oversize counter (%d -> %d): the length bound is "+
			"firing on hosts that are merely invalid, which destroys the INVALID_HOST signal", before, got)
	}
}

// TestChaos69_DefectAdminEntryPointsBoundUnnormalizableHosts is the admin-plane
// half of the unnormalizable band. The reviewer named both handlers explicitly:
// they carried the same `ok && oversize` shape, so a VIEWER could drive a
// ~1 KiB dot-dense host with a malformed ACE label into lookupHostCategory and
// (via apiPolicyTest) into the fusion more than once per call.
func TestChaos69_DefectAdminEntryPointsBoundUnnormalizableHosts(t *testing.T) {
	host := chaos69Unnormalizable(1000)
	if rawAuthorityOversize(host) {
		t.Fatalf("a %d-byte host is refused by the RAW tier — this gate cannot reach the unnormalizable band", len(host))
	}
	if _, ok := canonicalDestHost(host); ok {
		t.Fatalf("host normalized — this gate needs a host with no canonical form")
	}

	t.Run("url-category-lookup", func(t *testing.T) {
		chaos66Isolate(t)
		chaos66CaptureLog(t)
		before := proxyOversizeHostRejected.Load()

		r := withRole(httptest.NewRequest(http.MethodGet, "/api/url-categories/lookup?host="+host, http.NoBody), RoleViewer)
		w := httptest.NewRecorder()
		apiURLCatLookup(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d — a viewer reached lookupHostCategory with a %d-byte unnormalizable host",
				w.Code, http.StatusBadRequest, len(host))
		}
		if got := proxyOversizeHostRejected.Load(); got != before+1 {
			t.Errorf("proxyOversizeHostRejected = %d, want %d — the refusal is uncounted", got, before+1)
		}
	})

	t.Run("policy-test", func(t *testing.T) {
		chaos66Isolate(t)
		chaos66CaptureLog(t)
		before := proxyOversizeHostRejected.Load()

		w := httptest.NewRecorder()
		apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": host}))

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d — a viewer reached the fusion with a %d-byte unnormalizable host",
				w.Code, http.StatusBadRequest, len(host))
		}
		if got := proxyOversizeHostRejected.Load(); got != before+1 {
			t.Errorf("proxyOversizeHostRejected = %d, want %d — the refusal is uncounted", got, before+1)
		}
	})
}

// ─── ROUND 5 — measure-vs-use: the bound must govern the string the matchers get ──
//
// net.SplitHostPort does NOT require a numeric port. So `a:` followed by a
// 1 000-byte dot-dense string is a 1 003-byte authority whose bare host is ONE
// byte: the raw tier passes (1 003 < 1 024), canonicalDestHost strips the port
// and normalizes "a", and the canonical tier passes on a length of 1 — while
// the matchers below received the full 1 003 bytes and paid the quadratic
// suffix walk both tiers exist to prevent.
//
// Bounding the ORIGINAL at 253 is NOT the fix: that is round 1's IDN regression
// (a legitimate internationalized host measures 883 raw / 251 canonical). The
// fix is to MEASURE AND USE THE SAME STRING, which is what these gates pin.
//
// They are behavioural, not structural, and deliberately so: the observable is
// whether a one-entry taxonomy MATCHES. urlcat's suffix walk probes the host
// and then each remainder after a `.`, so a payload of "bb." labels can never
// reach the pattern "a" — the bounded value resolves the category and the raw
// value resolves nothing. That differential needs no populated feed and no
// timing, which is what made the first attempt at this gate vacuous: the cost
// ratio it measured is invisible without a large taxonomy this test cannot
// build, so it passed against the pre-fix shape.

// chaos69PortShaped returns the round-5 attack authority together with the bare
// host every tier measured. Labels are "bb" so no suffix of the payload can
// equal the taxonomy pattern by accident — an authority ending in ".a" would
// match through the suffix walk and hide the defect.
func chaos69PortShaped() (authority, bare string) {
	authority = "a:" + strings.Repeat("bb.", 333) + "bb"
	return authority, "a"
}

// TestChaos69_DefectAdminMatchersReceiveTheBoundedHost drives both viewer-role
// admin entry points with the port-shaped authority and requires the category
// fusion to answer for the BARE host. Pre-fix the raw authority reached the
// fusion, which resolves nothing for it, so every assertion below fails.
func TestChaos69_DefectAdminMatchersReceiveTheBoundedHost(t *testing.T) {
	authority, bare := chaos69PortShaped()

	// Prove the shape really does slip every tier — otherwise this gate would be
	// asserting against a request that was refused for an unrelated reason.
	if rawAuthorityOversize(authority) {
		t.Fatalf("raw tier refused a %d-byte authority; this gate needs one that passes", len(authority))
	}
	norm, ok := canonicalDestHost(authority)
	if !ok || canonicalHostOversize(norm) {
		t.Fatalf("canonical tier refused %q (ok=%v); this gate needs an authority that passes both tiers", norm, ok)
	}
	if norm != bare {
		t.Fatalf("canonicalDestHost(%d bytes) = %q, want %q", len(authority), norm, bare)
	}

	t.Run("url-category-lookup", func(t *testing.T) {
		chaos66Isolate(t)
		swapCatStore(t, []*urlcat.Entry{{Name: "Social Media", Hosts: []string{bare}}})

		r := withRole(httptest.NewRequest(http.MethodGet,
			"/api/url-categories/lookup?host="+authority, http.NoBody), RoleViewer)
		w := httptest.NewRecorder()
		apiURLCatLookup(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d: body=%s", w.Code, http.StatusOK, w.Body.String())
		}
		var got struct {
			Category  string `json:"category"`
			Tier      string `json:"tier"`
			MatchedBy string `json:"matchedBy"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Category != "Social Media" || got.Tier != "admin" || got.MatchedBy != bare {
			t.Errorf("category = (%q, %q, %q), want (\"Social Media\", \"admin\", %q): the fusion received the "+
				"%d-byte authority, not the %d-byte host every tier measured — the quadratic suffix walk the "+
				"tiers exist to prevent still runs",
				got.Category, got.Tier, got.MatchedBy, bare, len(authority), len(bare))
		}
	})

	t.Run("policy-test", func(t *testing.T) {
		chaos66Isolate(t)
		swapCatStore(t, []*urlcat.Entry{{Name: "Social Media", Hosts: []string{bare}}})

		w := httptest.NewRecorder()
		apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": authority}))

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d: body=%s", w.Code, http.StatusOK, w.Body.String())
		}
		var got struct {
			HostCategory struct {
				Category  string `json:"category"`
				Tier      string `json:"tier"`
				MatchedBy string `json:"matchedBy"`
			} `json:"hostCategory"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		hc := got.HostCategory
		if hc.Category != "Social Media" || hc.Tier != "admin" || hc.MatchedBy != bare {
			t.Errorf("hostCategory = (%q, %q, %q), want (\"Social Media\", \"admin\", %q): the fusion received the "+
				"%d-byte authority, not the %d-byte host every tier measured",
				hc.Category, hc.Tier, hc.MatchedBy, bare, len(authority), len(bare))
		}
	})
}

// TestChaos69_DefectPolicyTesterStage1MatchesTheRuntimeHost is the third call
// site inside the SAME handler, and it is the round-2 lesson landing again:
// STAGE-1 AUTH RUNS A MATCHER. simulateAuthOutcome →
// resolveAuthOutcomeFrom → authRuleMatchesScratch → matchDestNorm → the
// category fusion, so enumerating the Stage-2 matchers and missing this one
// left the walk reachable through the function that had just been fixed.
//
// It is also a FIDELITY defect, which is the more serious half. The runtime
// Stage-1 gate strips the port with exactly this operation
// (authRequestContext, authpolicy.go), so pre-fix the tester reported
// outcome=Default — "this exemption does not apply" — for traffic the live
// gate exempts. An admin auditing the blast radius of an auth exemption was
// shown a NARROWER scope than production enforces.
func TestChaos69_DefectPolicyTesterStage1MatchesTheRuntimeHost(t *testing.T) {
	chaos66Isolate(t)
	// draftTestSetup snapshots the policy store, resets the draft candidate and
	// pins requireCommit=false with restore. All three matter here and none is
	// optional: apiPolicyTest evaluates effectivePolicySnapshot(), so a leaked
	// armed Draft Mode would have it read an empty candidate instead of the rule
	// below — an order-dependent failure visible only under -shuffle.
	draftTestSetup(t)
	// The Exempt kill switch is a process-global atomic any test can set, and a
	// leaked one suppresses a matching Exempt rule (resolveAuthOutcomeFrom
	// continues past it), so this gate would fail for a reason that has nothing
	// to do with what it measures. Pin it explicitly rather than inheriting it.
	prevKill := authExemptDisabledRuntime.Load()
	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(prevKill) })
	if authExemptKillSwitchEngaged() {
		t.Skip("the Exempt kill switch is engaged by the environment (CULVERT_AUTH_BYPASS_DISABLE); " +
			"this gate measures a scoped Exempt rule and cannot run under it")
	}
	authority, bare := chaos69PortShaped()
	swapCatStore(t, []*urlcat.Entry{{Name: "Social Media", Hosts: []string{bare}}})

	enabled := true
	policyStore.ReplaceAll([]PolicyRule{{
		Name: "chaos69-auth-exempt", RuleType: ruleTypeAuth, Enabled: &enabled, Priority: 1,
		DestCategory: URLCategory("Social Media"),
		SubjectMatch: &SubjectMatch{SchemaVersion: 1,
			All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.0.0/8"}}}},
		Auth: &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "chaos69"},
	}})
	// Assert on what the HANDLER will evaluate, not on the running store: if the
	// two ever disagree the gate must fail here with a clear reason rather than
	// later with a confusing one.
	effective, rulebase := effectivePolicySnapshot()
	if len(effective) != 1 {
		t.Fatalf("effectivePolicySnapshot() has %d rules (rulebase=%q), want 1 — the auth rule was dropped on "+
			"replace or a leaked Draft Mode is shadowing the running store", len(effective), rulebase)
	}

	// The runtime gate's own answer for this authority, via the production
	// strip — the value the simulator must agree with.
	runtime := resolveAuthOutcomeFrom(effective, authRequestContext(
		&http.Request{Method: http.MethodGet, Host: authority, Header: http.Header{}}, "10.1.2.3"))
	if runtime.Outcome != OutcomeExempt || runtime.Rule == nil {
		t.Fatalf("runtime Stage-1 = %q (ruleNil=%v); this gate needs the live gate to exempt this authority",
			runtime.Outcome, runtime.Rule == nil)
	}

	w := httptest.NewRecorder()
	apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{
		"host": authority, "sourceIP": "10.1.2.3", "protocol": "http", "method": http.MethodGet,
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got struct {
		Auth struct {
			Outcome          string `json:"outcome"`
			Stage2AuthSource string `json:"stage2AuthSource"`
			FromDefault      bool   `json:"fromDefault"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Auth.Outcome != string(OutcomeExempt) {
		t.Errorf("simulator Stage-1 outcome = %q, want %q: the simulator handed the %d-byte authority to the "+
			"Stage-1 matcher while the runtime gate strips the port, so the tester reports a NARROWER exemption "+
			"scope than production enforces",
			got.Auth.Outcome, OutcomeExempt, len(authority))
	}
	if got.Auth.Stage2AuthSource != authSourceExempt {
		t.Errorf("stage2AuthSource = %q, want %q", got.Auth.Stage2AuthSource, authSourceExempt)
	}
	if got.Auth.FromDefault {
		t.Error("fromDefault = true: the simulator fell through to the global default instead of matching the scoped rule")
	}
}

// TestChaos69_ControlPortShapedAuthorityIsStillAnswered is the control for the
// three gates above. The cheapest way to pass them is to refuse any authority
// carrying a port, which would break every ordinary explicit-port destination
// on both admin surfaces. An ordinary host:port must be ANSWERED, must not be
// charged to the oversize counter, and must resolve the category for its bare
// host — proving the strip is the production strip and not a colon ban.
func TestChaos69_ControlPortShapedAuthorityIsStillAnswered(t *testing.T) {
	const authority = "shop.example.com:8443"
	const bare = "shop.example.com"

	t.Run("url-category-lookup", func(t *testing.T) {
		chaos66Isolate(t)
		swapCatStore(t, []*urlcat.Entry{{Name: "Shopping", Hosts: []string{bare}}})
		before := proxyOversizeHostRejected.Load()

		r := withRole(httptest.NewRequest(http.MethodGet,
			"/api/url-categories/lookup?host="+authority, http.NoBody), RoleViewer)
		w := httptest.NewRecorder()
		apiURLCatLookup(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("an ordinary %q was refused %d: %s", authority, w.Code, w.Body.String())
		}
		var got struct {
			Category string `json:"category"`
			Host     string `json:"host"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Category != "Shopping" {
			t.Errorf("category = %q, want \"Shopping\": an ordinary explicit-port destination no longer resolves", got.Category)
		}
		// The ECHOED host stays exactly what the admin typed — the strip governs
		// what the matchers receive, never what the answer reports back.
		if got.Host != authority {
			t.Errorf("host echo = %q, want %q", got.Host, authority)
		}
		if after := proxyOversizeHostRejected.Load(); after != before {
			t.Errorf("proxyOversizeHostRejected moved %d -> %d on an ordinary host:port", before, after)
		}
	})

	t.Run("policy-test", func(t *testing.T) {
		chaos66Isolate(t)
		swapCatStore(t, []*urlcat.Entry{{Name: "Shopping", Hosts: []string{bare}}})
		before := proxyOversizeHostRejected.Load()

		w := httptest.NewRecorder()
		apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": authority}))

		if w.Code != http.StatusOK {
			t.Fatalf("an ordinary %q was refused %d: %s", authority, w.Code, w.Body.String())
		}
		var got struct {
			HostCategory struct {
				Category string `json:"category"`
			} `json:"hostCategory"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.HostCategory.Category != "Shopping" {
			t.Errorf("hostCategory.category = %q, want \"Shopping\"", got.HostCategory.Category)
		}
		if after := proxyOversizeHostRejected.Load(); after != before {
			t.Errorf("proxyOversizeHostRejected moved %d -> %d on an ordinary host:port", before, after)
		}
	})
}

// TestChaos69_DefectEveryAdminMatcherTakesTheBoundedHost is the COMPLETENESS
// half. The behavioural gates above observe three of the matcher arguments;
// this one walks the AST of both handlers and requires EVERY host argument
// handed to a matcher to be an identifier assigned from bareDestHost — so a
// fourth matcher added later, or one of these quietly reverted to the raw
// authority in a way no current assertion observes, fails the build.
//
// It checks the ASSIGNMENT, not the identifier's name. The first version of
// this wall compared the name against a set of blessed spellings and therefore
// PASSED against the pre-fix shape written as `lookupHost := host` — a wall
// that cannot fail for its own defect.
func TestChaos69_DefectEveryAdminMatcherTakesTheBoundedHost(t *testing.T) {
	// matcher name → index of its host parameter.
	hostArg := map[string]int{
		"lookupHostCategory":  0,
		"IsBlocked":           0,
		"walkPolicyTestRules": 4,
		"simulateAuthOutcome": 2,
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "ui_policy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ui_policy.go: %v", err)
	}

	checked := 0
	for _, handler := range []string{"apiURLCatLookup", "apiPolicyTest"} {
		fn := chaos69FuncDecl(t, file, handler)
		derived := chaos69BareDerivedIdents(fn)

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := chaos69CalleeName(call.Fun)
			idx, watched := hostArg[name]
			if !watched || idx >= len(call.Args) {
				return true
			}
			checked++
			pos := fset.Position(call.Pos())
			arg, isIdent := call.Args[idx].(*ast.Ident)
			if !isIdent {
				t.Errorf("%s:%d: %s receives a non-identifier host argument — it must be a value derived from "+
					"bareDestHost, or the tiers measure one string and the matchers walk another",
					handler, pos.Line, name)
				return true
			}
			if !derived[arg.Name] {
				t.Errorf("%s:%d: %s receives %q, which is not assigned from bareDestHost in this handler — "+
					"the two tiers above measure the bare host while this matcher walks the full authority "+
					"(net.SplitHostPort accepts a non-numeric port, so `a:`+1 000 dot-dense bytes passes both "+
					"tiers on a 1-byte host)",
					handler, pos.Line, name, arg.Name)
			}
			return true
		})
	}

	// A selector that stopped matching would let this wall pass forever.
	if checked != 5 {
		t.Fatalf("the wall inspected %d bounded matcher arguments, want 5 — it is no longer finding the call "+
			"sites and must be re-aimed, not deleted", checked)
	}
}

// chaos69FuncDecl returns the named top-level function, failing loudly if a
// rename has left the wall aimed at nothing.
func chaos69FuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name && fn.Body != nil {
			return fn
		}
	}
	t.Fatalf("%s not found in ui_policy.go — this wall must be re-aimed, not deleted", name)
	return nil
}

// chaos69BareDerivedIdents collects the local names assigned from a
// bareDestHost call anywhere in fn. Assignment, not spelling, is the invariant:
// the pre-fix shape re-spelled as `lookupHost := host` keeps the name and loses
// the bound.
func chaos69BareDerivedIdents(fn *ast.FuncDecl) map[string]bool {
	derived := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || i >= len(assign.Rhs) {
				continue
			}
			call, ok := assign.Rhs[i].(*ast.CallExpr)
			if !ok {
				continue
			}
			if chaos69CalleeName(call.Fun) == "bareDestHost" {
				derived[id.Name] = true
			}
		}
		return true
	})
	return derived
}

// chaos69CalleeName is the bare function name of a call target, for both
// `f(...)` and `recv.f(...)`.
func chaos69CalleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
