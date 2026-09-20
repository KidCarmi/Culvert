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

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// ─── CHAOS-66 — the client-supplied destination authority on the proxy path ───
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
// The gates below split deliberately. TestChaos66_Defect* FAIL against the
// pre-fix tree. TestChaos66_Control* prove the bound did not break the data
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

// TestChaos66_DefectOversizeAuthorityRefusedBeforeAnyState is the primary gate.
// Pre-fix the request ran the whole pipeline and answered 403 (default deny)
// after writing the megabyte into both sinks; post-fix it is refused 400 with
// nothing retained.
func TestChaos66_DefectOversizeAuthorityRefusedBeforeAnyState(t *testing.T) {
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

// TestChaos66_DefectConnectFormIsBounded covers the DOMINANT traffic class. A
// CONNECT request carries its authority in the request target rather than a Host
// header, net/http puts it in r.Host either way, and every HTTPS request through
// this proxy is one — so a gate proven only against the plain-HTTP form is
// proven against the minority of traffic. It also pins that the refusal happens
// BEFORE the tunnel is established: a 400 on the CONNECT means no 200, no
// hijack, and no drain registration.
func TestChaos66_DefectConnectFormIsBounded(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	host := chaos66Host(64 * 1024)
	r := httptest.NewRequest(http.MethodConnect, "http://"+host+":443", nil)
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
		if len(e.Host) > maxDestAuthorityLen {
			t.Fatalf("CONNECT retained a %d-byte Host field", len(e.Host))
		}
	}
}

// TestChaos66_ControlRefusalIsAccountedAsABlock pins that the two gates agree
// about whether the refusal happened. The first version of this change counted
// statBlocked on the SOCKS5 path and not on the HTTP one — two refusals of the
// same class disagreeing about their own accounting, which is the kind of split
// that makes a dashboard figure quietly wrong.
func TestChaos66_ControlRefusalIsAccountedAsABlock(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	before := atomic.LoadInt64(&statBlocked)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+chaos66Host(64*1024)+"/", nil))
	if got := atomic.LoadInt64(&statBlocked); got != before+1 {
		t.Errorf("statBlocked = %d, want %d — the HTTP refusal is not accounted the way its INVALID_HOST twin is", got, before+1)
	}
}

// TestChaos66_DefectProcessLogStaysBounded measures the BYTES one oversize
// request commits to the process log — a rotating file capped at 50 MB keeping
// ONE archive, which also holds the diagnostics for every other incident.
//
// Pre-fix a 256 KiB authority wrote 262 228 bytes from ONE request (measured);
// eight requests here would cost ~2 MiB. Post-fix the whole run is a few hundred
// bytes, because the rate-limited rejection line names the LENGTH and never the
// value.
func TestChaos66_DefectProcessLogStaysBounded(t *testing.T) {
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

// TestChaos66_DefectRequestLogNeverCarriesOversizeHost pins the durable JSONL
// feed. The Host field is written verbatim; pre-fix it carried the full 262 143
// bytes on the default-deny path.
func TestChaos66_DefectRequestLogNeverCarriesOversizeHost(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	host := chaos66Host(64 * 1024)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	for _, e := range reqlog.Get() {
		if len(e.Host) > maxDestAuthorityLen {
			t.Fatalf("request-log entry carries a %d-byte Host field (limit %d, status %q) — "+
				"the durable feed is retaining client-chosen bytes", len(e.Host), maxDestAuthorityLen, e.Status)
		}
	}
}

// TestChaos66_DefectIPBlockedPathDoesNotRetainTheAuthority is the ORDERING gate,
// and it is the one that decides where the bound may live. IP_BLOCKED and
// RATE_LIMITED both write r.Host into the request log, and they run BEFORE the
// host-canonicalization step where RISK-013's IDNA gate sits — so a bound placed
// at that gate (the intuitive home for a host check) would sit behind two sinks
// that had already retained the value. This test fails against that shape as
// well as against the pre-fix tree.
func TestChaos66_DefectIPBlockedPathDoesNotRetainTheAuthority(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	// Deny every source, so the request takes the IP_BLOCKED branch.
	ipf.SetMode("allow") // allowlist mode with an empty list denies everything
	host := chaos66Host(64 * 1024)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d — the bound must be decided ahead of the IP filter, "+
			"whose own branch retains r.Host", w.Code, http.StatusBadRequest)
	}
	for _, e := range reqlog.Get() {
		if len(e.Host) > maxDestAuthorityLen {
			t.Fatalf("IP_BLOCKED retained a %d-byte Host field — the bound is behind a sink", len(e.Host))
		}
	}
}

// TestChaos66_DefectCostIsFlatInAuthorityLength is the CPU gate, expressed as a
// RATIO measured in ONE run so it is machine-independent (the repo's standing
// rule after the sanitizeLog and connlimit episodes: a gate whose bound has to
// be re-baselined per machine gets muted).
//
// Pre-fix the ratio was ~8 700x (3.94 s against 0.45 ms). Post-fix the oversize
// request takes the O(1) reject path and is CHEAPER than the ordinary one, so
// the ratio is below 1. The bound of 20x is orders of magnitude clear of both.
func TestChaos66_DefectCostIsFlatInAuthorityLength(t *testing.T) {
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

// TestChaos66_DefectTopHostsNeverRetainsAnOversizeKey pins the KEY-SIZE axis of
// the top-hosts counter. Its documented bound is topHostsMaxEntries (10 000)
// distinct hosts, which is a bound on the ENTRY COUNT and never was one on the
// key size — the identical blindness §32 found in internal/lockout, whose
// Cleanup doc claimed the maps were bounded "against an unbounded-memory DoS".
// At the cap, 1 MiB keys are ~10 GiB of resident heap in an in-line gateway
// whose OOM is a total traffic outage.
func TestChaos66_DefectTopHostsNeverRetainsAnOversizeKey(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	// Default-allow posture: the only branch that reaches topHosts.Record.
	setDefaultPolicyAction("allow")
	t.Cleanup(func() { setDefaultPolicyAction("deny") })
	prevTop := topHosts
	topHosts = &hostCounter{}
	t.Cleanup(func() { topHosts = prevTop })

	host := chaos66Host(64 * 1024)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	for _, h := range topHosts.Top(50) {
		if len(h.Host) > maxDestAuthorityLen {
			t.Fatalf("topHosts retained a %d-byte key (limit %d) — the cap bounds the entry count, not the key size", len(h.Host), maxDestAuthorityLen)
		}
	}
}

// TestChaos66_DefectSOCKS5RefusesOversizeDestination covers the other data-path
// protocol, and it is deliberately written to be NON-VACUOUS. RFC 1928 §4
// length-prefixes DOMAINNAME with one byte, so the protocol caps the destination
// at 255 — BELOW the 261-byte authority bound. The first version of this fix
// applied the authority predicate here, which made the gate permanently dead
// code, and the first version of this test asserted only "no oversize host
// reached the request log", which passes vacuously at 255 bytes. So this now
// asserts the REFUSAL and the counter: a gate that cannot fire fails here.
func TestChaos66_DefectSOCKS5RefusesOversizeDestination(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	// The bound this path enforces must be reachable within what the protocol
	// can carry — otherwise the gate is unreachable by construction.
	if maxDestHostLen >= 255 {
		t.Fatalf("maxDestHostLen = %d: the SOCKS5 gate cannot fire, since RFC 1928 caps DOMAINNAME at 255", maxDestHostLen)
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
	defer conn.Close() //nolint:errcheck

	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatalf("greeting: %v", err)
	}

	// The longest DOMAINNAME the protocol can carry: 255 bytes, two above the
	// 253 a resolvable name can occupy.
	host := chaos66Host(255)
	if !destHostOversize(host) {
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
		if len(e.Host) > maxDestHostLen {
			t.Fatalf("SOCKS5 retained a %d-byte Host field in the request log", len(e.Host))
		}
	}
}

// TestChaos66_DefectAdminURLLookupIsBounded covers the admin plane. The
// url-lookup endpoint reaches the SAME two-tier fusion from a query string
// inside the 1 MiB header block, so pre-fix an authenticated VIEWER could park
// an admin-plane goroutine for minutes with one GET.
func TestChaos66_DefectAdminURLLookupIsBounded(t *testing.T) {
	chaos66Isolate(t)
	chaos66CaptureLog(t)

	before := proxyOversizeHostRejected.Load()
	r := httptest.NewRequest(http.MethodGet, "/api/url-categories/lookup?host="+chaos66Host(64*1024), nil)
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

// TestChaos66_ControlBoundIsInclusiveAndDerived pins the arithmetic in code, so
// the derivation stays checkable rather than living only in a comment, and pins
// that the limit is INCLUSIVE — an off-by-one here refuses a legal destination.
func TestChaos66_ControlBoundIsInclusiveAndDerived(t *testing.T) {
	// "[" + host + "]" + ":" + "65535"
	if want := 1 + maxDestHostLen + 1 + 1 + 5; maxDestAuthorityLen != want {
		t.Errorf("maxDestAuthorityLen = %d, want %d (1 + %d + 1 + 1 + 5) — the constant no longer matches its stated derivation",
			maxDestAuthorityLen, want, maxDestHostLen)
	}
	if maxDestHostLen != 253 {
		t.Errorf("maxDestHostLen = %d, want 253 (RFC 1035 §2.3.4 wire limit of 255 octets in RFC 1123 presentation form)", maxDestHostLen)
	}
	if destAuthorityOversize(chaos66Host(maxDestAuthorityLen)) {
		t.Errorf("an authority of exactly %d bytes was refused; the limit is inclusive", maxDestAuthorityLen)
	}
	if !destAuthorityOversize(chaos66Host(maxDestAuthorityLen + 1)) {
		t.Errorf("an authority of %d bytes was admitted; the limit is not enforced", maxDestAuthorityLen+1)
	}
	if destHostOversize(chaos66Host(maxDestHostLen)) {
		t.Errorf("a host of exactly %d bytes was refused; the limit is inclusive", maxDestHostLen)
	}
	if !destHostOversize(chaos66Host(maxDestHostLen + 1)) {
		t.Errorf("a host of %d bytes was admitted; the limit is not enforced", maxDestHostLen+1)
	}
	// The host bound must be STRICTLY tighter than the authority bound, or the
	// two predicates are interchangeable and the reason for having both is gone.
	if maxDestHostLen >= maxDestAuthorityLen {
		t.Errorf("maxDestHostLen (%d) is not tighter than maxDestAuthorityLen (%d) — the split serves no purpose",
			maxDestHostLen, maxDestAuthorityLen)
	}
	// Both bounds must be reachable within what each protocol can deliver. The
	// SOCKS5 DOMAINNAME is one length-prefixed byte, so a gate above 255 there is
	// dead code — the defect this control exists to keep closed.
	if maxDestHostLen >= 255 {
		t.Errorf("maxDestHostLen (%d) exceeds what RFC 1928 §4 can carry (255) — the SOCKS5 gate would be unreachable", maxDestHostLen)
	}
}

// TestChaos66_ControlOrdinaryDestinationStillProxies is the control that matters
// most: the cheapest way to pass every defect gate above is to refuse every
// destination, which is a total egress outage. This drives the real allow path
// end to end against a live backend.
func TestChaos66_ControlOrdinaryDestinationStillProxies(t *testing.T) {
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

// TestChaos66_ControlLegitimateAuthorityShapesAreAccepted pins the shapes the
// register warned the bound had to answer for before it could ship: a
// maximum-length FQDN, an FQDN with a port, a trailing-dot FQDN, a bare IPv4
// literal and a BRACKETED IPv6 literal with a port.
func TestChaos66_ControlLegitimateAuthorityShapesAreAccepted(t *testing.T) {
	for _, authority := range []string{
		"example.com",
		"example.com:8443",
		"example.com.",
		"10.1.2.3:3128",
		"[2001:db8::1]:443",
		"[fe80::1%25eth0]:443",
		chaos66Host(maxDestHostLen),            // longest possible name
		chaos66Host(maxDestHostLen) + ":65535", // …with a port
		"[" + "2001:db8::1" + "]",              // bare bracketed literal
	} {
		if destAuthorityOversize(authority) {
			t.Errorf("a legitimate authority was refused (%d bytes): %.40q…", len(authority), authority)
		}
	}
}

// TestChaos66_ControlRejectionIsStillRecorded is the evidence control. Bounding
// the bytes must not delete the fact that the proxy port is being probed —
// exactly the trade §32 made for the audit entry. The line carries the LENGTH
// and the cumulative count; the magnitude must never live only in the counter
// with nothing in the log to point at it.
func TestChaos66_ControlRejectionIsStillRecorded(t *testing.T) {
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

// TestChaos66_ControlLogIsRateLimited pins that the mitigation is not itself a
// write amplifier: a flood must cost at most one line per window.
func TestChaos66_ControlLogIsRateLimited(t *testing.T) {
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
