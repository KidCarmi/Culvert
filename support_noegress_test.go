package main

// support_noegress_test.go — the NO-OUTBOUND-NETWORK wall for the support/
// diagnose surface (#788 merge-gate invariant). The supportability appliance is
// offline-only and consent-gated: building a bundle or running a diagnose verb
// must never phone home, and the ONLY sanctioned dials on the diagnose surface
// are the THREE audited seams, each pinned by exact count below:
//   1. tlsHandshakeProbe's net.Dialer — SSRF-guarded (ssrfControl) + TLS1.2 + 5s.
//   2. diagnoseLookupIP's bounded resolver lookup — SSRF-guarded (private-IP refusal).
//   3. diagnoseEtcd's globalHA.probeLeaseBackend — a read-only Provider.Read of
//      the HA fencing-lease backend. Its target is the OPERATOR-CONFIGURED etcd
//      endpoint (startup config, NOT attacker-controllable), so it is reviewed
//      as non-SSRF-relevant and is bounded by a 5s context instead of an
//      isPrivateHost guard (a fencing etcd normally lives on a private address,
//      which such a guard would wrongly refuse). Adding it here — rather than
//      hiding the dial behind globalHA — keeps this wall's guarantee honest: a
//      NEW dial site on the diagnose surface still fails the pin.
//
// Three layers, mirroring the repo's wall conventions (C1/C1.5, crashguard):
//  1. IMPORT WALL — internal/support (the engine) may not import any
//     net-capable or process-spawning package at all.
//  2. SOURCE WALL — the package-main support/diagnose files may not introduce
//     outbound-call identifiers; diagnose.go's two audited seams are pinned by
//     exact count so a NEW dial site fails the wall.
//  3. RUNTIME CANARY — a full standard bundle build runs with the default
//     HTTP transport and resolver replaced by recording tripwires; the build
//     must succeed with ZERO network attempts. It runs in a re-executed,
//     single-test copy of this binary whose tripwires are installed at package
//     init, so the canary never writes those process globals while another
//     test's goroutine (e.g. a gRPC addrConn redial) reads them.

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// forbiddenEngineImports are packages the offline-only support ENGINE must
// never link: outbound network and process execution.
var forbiddenEngineImports = map[string]bool{
	"net": true, "net/http": true, "net/smtp": true, "net/rpc": true,
	"net/url": true, "os/exec": true, "syscall": true,
}

func TestSupportEngine_ImportWall(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir("internal/support")
	if err != nil {
		t.Fatalf("read internal/support: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join("internal", "support", e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if forbiddenEngineImports[p] {
				t.Errorf("%s imports %q — the support engine is offline-only and must never link network/exec packages", path, p)
			}
		}
	}
}

// outboundIdents are call-site markers that indicate outbound network or
// process execution. Kept string-level (like TestNoBareGoWithoutRecover) so
// the wall stays cheap and obvious.
var outboundIdents = []string{
	"http.Get(", "http.Post(", "http.PostForm(", "http.Head(",
	"http.DefaultClient", "http.Client{", "http.NewRequest",
	"net.Dial(", "net.DialTimeout(", "net.Dialer{", "tls.Dial", "exec.Command", "exec.CommandContext",
	"DefaultResolver",
	".probeLeaseBackend(", // diagnose etcd's HA fencing-lease reachability seam
}

// diagnoseSeamCounts pins diagnose.go's audited dial seams by exact marker
// count. Adding ANY new dial/lookup site to diagnose.go fails this wall and
// forces a deliberate review of its SSRF guard.
var diagnoseSeamCounts = map[string]int{
	"net.Dialer{":         1, // tlsHandshakeProbe — ssrfControl + MinVersion TLS1.2 + 5s bound
	"DefaultResolver":     1, // diagnoseLookupIP — bounded ctx + private-IP refusal
	".probeLeaseBackend(": 1, // diagnoseEtcd — read-only Provider.Read of the operator-configured etcd fencing endpoint (startup config, not attacker input → non-SSRF); 5s ctx bound
}

func TestSupportSurface_NoOutboundCallSites(t *testing.T) {
	files, err := filepath.Glob("support*.go")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "ui_support.go")
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(b)
		for _, ident := range outboundIdents {
			if strings.Contains(src, ident) {
				t.Errorf("%s contains outbound-call marker %q — the support surface is offline-only", path, ident)
			}
		}
	}

	// diagnose.go: the two audited seams, pinned by exact count.
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), "diagnose.go"))
	if err != nil {
		t.Fatalf("read diagnose.go: %v", err)
	}
	src := string(b)
	for _, ident := range outboundIdents {
		want, allowed := diagnoseSeamCounts[ident]
		got := strings.Count(src, ident)
		switch {
		case !allowed && got > 0:
			t.Errorf("diagnose.go contains unaudited outbound marker %q (%d occurrence[s])", ident, got)
		case allowed && got != want:
			t.Errorf("diagnose.go %q seam count = %d, want exactly %d — a new dial site needs its own SSRF review AND this pin updated", ident, got, want)
		}
	}
}

// ── RUNTIME CANARY ──────────────────────────────────────────────────────────
//
// net.DefaultResolver and http.DefaultTransport are process globals read,
// without synchronisation, by every dial and default-client request in the
// process. Swapping them inside the shared test binary raced any goroutine an
// earlier test left dialing (a gRPC addrConn redial reads net.DefaultResolver
// in (*net.Dialer).DialContext, and ClientConn.Close does not wait for it), so
// the race detector failed the canary under -race -shuffle=on. Injecting a
// resolver/transport seam into the support path instead would only see
// egress routed THROUGH that seam: a collector reaching a main-package helper
// that dials or resolves via the process defaults would escape it, and that
// transitive path is exactly what this end-to-end canary exists to catch.
//
// So the canary keeps the process-default tripwires and moves them into a
// child process: the parent re-executes this test binary to run ONLY
// TestSupportBundle_NoOutboundNetworkAtRuntime with noEgressChildEnv set; the
// child's package init installs the tripwires before TestMain or any test
// starts a goroutine, and never restores them (the child exits after the one
// test), so no goroutine can observe the globals mid-write.

const (
	noEgressChildEnv    = "CULVERT_SUPPORT_NOEGRESS_CHILD"
	noEgressModeBundle  = "bundle"       // the production collector roster only
	noEgressModeDNS     = "control-dns"  // + a probe collector resolving via net.DefaultResolver
	noEgressModeDial    = "control-dial" // + a probe collector dialing a hostname with a zero net.Dialer
	noEgressModeHTTP    = "control-http" // + a probe collector using http.DefaultClient
	noEgressResultMark  = "support-noegress-child attempts="
	noEgressCanaryHost  = "support-egress-canary.example"
	noEgressChildSelect = "-test.run=^TestSupportBundle_NoOutboundNetworkAtRuntime$"
)

// noEgressAttempts counts every DNS dial and HTTP round trip the child's
// tripwires intercept. It is only ever incremented in the child process.
var noEgressAttempts atomic.Int64

func init() {
	if os.Getenv(noEgressChildEnv) == "" {
		return
	}
	// Installed once, at package init of the child process and before any
	// test goroutine exists; never restored. Every later reader is ordered
	// after this write, so the child itself cannot race on these globals.
	http.DefaultTransport = tripwireRT{hits: &noEgressAttempts}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			noEgressAttempts.Add(1)
			return nil, errors.New("no-egress wall: DNS dial attempted during bundle build")
		},
	}
}

// TestSupportBundle_NoOutboundNetworkAtRuntime builds a full standard bundle
// (every registered collector) with the process-default HTTP transport and DNS
// resolver replaced by recording tripwires. The bundle must build successfully
// with ZERO attempts on either — the offline-only guarantee, enforced end to
// end rather than by code review. The build itself runs in an isolated child
// process (see the RUNTIME CANARY note above); this parent only launches it
// and checks its verdict.
func TestSupportBundle_NoOutboundNetworkAtRuntime(t *testing.T) {
	if mode := os.Getenv(noEgressChildEnv); mode != "" {
		runNoEgressChild(t, mode)
		return
	}
	attempts, out, err := runNoEgressChildProcess(t, os.Args[0], noEgressModeBundle)
	if err != nil {
		t.Fatalf("isolated bundle build failed: %v\n%s", err, out)
	}
	if attempts != 0 {
		t.Fatalf("bundle build attempted %d network operation(s); the support path must be offline-only\n%s", attempts, out)
	}
}

// TestSupportBundle_NoEgressCanaryCatchesCollectorEgress is the negative
// control for the runtime canary: the same isolated child, with one extra
// probe collector that reaches the network through the process defaults the
// way a careless collector (or a helper it calls) would, must record the
// attempt and fail. If any of these pass, the canary above proves nothing.
func TestSupportBundle_NoEgressCanaryCatchesCollectorEgress(t *testing.T) {
	for _, mode := range []string{noEgressModeDNS, noEgressModeDial, noEgressModeHTTP} {
		t.Run(mode, func(t *testing.T) {
			attempts, out, err := runNoEgressChildProcess(t, os.Args[0], mode)
			if attempts < 1 {
				t.Fatalf("canary recorded %d attempt(s) for a collector that reaches the network (%s); the tripwire is not on the bundle path\n%s", attempts, mode, out)
			}
			if err == nil {
				t.Fatalf("child passed despite %d recorded attempt(s) (%s); the canary must fail on egress\n%s", attempts, mode, out)
			}
		})
	}
}

// runNoEgressChildProcess re-executes bin — this test binary, os.Args[0] at
// every call site — to run ONLY the runtime canary in the given mode, and
// returns the attempt count the child reported, its combined output, and its
// exit error. The selector is a fixed literal and mode one of the fixed
// noEgressMode* constants, so no external input reaches the command line. A
// child that never reached the report line (wrong selector, crash before the
// build) is fatal here, so neither the canary nor its control can pass
// vacuously.
func runNoEgressChildProcess(t *testing.T, bin, mode string) (attempts int64, out string, err error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, noEgressChildSelect, "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), noEgressChildEnv+"="+mode)
	raw, err := cmd.CombinedOutput()
	out = string(raw)
	i := strings.LastIndex(out, noEgressResultMark)
	if i < 0 {
		t.Fatalf("isolated no-egress child (%s) reported no result (exit %v):\n%s", mode, err, out)
	}
	field, _, _ := strings.Cut(out[i+len(noEgressResultMark):], "\n")
	attempts, perr := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
	if perr != nil {
		t.Fatalf("isolated no-egress child (%s) result %q: %v", mode, field, perr)
	}
	return attempts, out, err
}

// runNoEgressChild is the child half: it runs in the re-executed process
// whose init installed the tripwires, builds the bundle and reports the
// attempt count on stdout for the parent before asserting on it.
func runNoEgressChild(t *testing.T, mode string) {
	if _, ok := http.DefaultTransport.(tripwireRT); !ok {
		t.Fatalf("no-egress child (%s): tripwires were not installed at init", mode)
	}
	switch mode {
	case noEgressModeBundle:
	case noEgressModeDNS, noEgressModeDial, noEgressModeHTTP:
		support.Register(egressProbeCollector{mode: mode})
	default:
		t.Fatalf("unknown no-egress child mode %q", mode)
	}
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prevDir })

	res, err := createSupportBundle(context.Background(), "standard", support.L2, "")
	fmt.Printf("%s%d\n", noEgressResultMark, noEgressAttempts.Load())
	if err != nil {
		t.Fatalf("bundle build must succeed fully offline: %v", err)
	}
	if res.Manifest.Format != support.BundleFormat {
		t.Fatalf("unexpected bundle format %q", res.Manifest.Format)
	}
	if n := noEgressAttempts.Load(); n != 0 {
		t.Fatalf("bundle build attempted %d network operation(s); the support path must be offline-only", n)
	}
}

// egressProbeCollector is registered ONLY in a negative-control child. It
// reaches the network through the process defaults, as an accidental
// collector (or a main-package helper it calls) would.
type egressProbeCollector struct{ mode string }

func (egressProbeCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "noegress_probe", Path: "sections/noegress_probe.json", Owner: "test", SchemaVersion: 1,
		Description: "no-egress negative control", Timeout: 2 * time.Second,
		ByteBudget: 4 << 10, MinLevel: support.L0,
		MaxClass: redaction.ClassPublic, Sensitivity: redaction.ClassPublic,
	}
}

func (p egressProbeCollector) Collect(ctx context.Context, _ support.CollectInput, _ support.SectionSink) support.Result {
	var err error
	switch p.mode {
	case noEgressModeDNS:
		_, err = net.DefaultResolver.LookupHost(ctx, noEgressCanaryHost)
	case noEgressModeDial:
		var c net.Conn
		if c, err = (&net.Dialer{}).DialContext(ctx, "tcp", noEgressCanaryHost+":443"); err == nil {
			_ = c.Close()
		}
	case noEgressModeHTTP:
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+noEgressCanaryHost+"/", http.NoBody); err == nil {
			var resp *http.Response
			if resp, err = http.DefaultClient.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
	if err != nil {
		return support.Result{Status: support.StatusUnavailable, Note: "egress refused"}
	}
	return support.Result{Status: support.StatusOK}
}

type tripwireRT struct{ hits *atomic.Int64 }

func (rt tripwireRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.hits.Add(1)
	return nil, fmt.Errorf("no-egress wall: HTTP request to %s during bundle build", r.URL.Host)
}
