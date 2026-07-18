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
//     must succeed with ZERO network attempts.

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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

// TestSupportBundle_NoOutboundNetworkAtRuntime builds a full standard bundle
// (every registered collector) with the process-default HTTP transport and DNS
// resolver replaced by recording tripwires. The bundle must build successfully
// with ZERO attempts on either — the offline-only guarantee, enforced end to
// end rather than by code review.
func TestSupportBundle_NoOutboundNetworkAtRuntime(t *testing.T) {
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prevDir })

	var attempts atomic.Int64

	prevRT := http.DefaultTransport
	http.DefaultTransport = tripwireRT{hits: &attempts}
	t.Cleanup(func() { http.DefaultTransport = prevRT })

	prevResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			attempts.Add(1)
			return nil, errors.New("no-egress wall: DNS dial attempted during bundle build")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = prevResolver })

	res, err := createSupportBundle(context.Background(), "standard", support.L2, "")
	if err != nil {
		t.Fatalf("bundle build must succeed fully offline: %v", err)
	}
	if res.Manifest.Format != support.BundleFormat {
		t.Fatalf("unexpected bundle format %q", res.Manifest.Format)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("bundle build attempted %d network operation(s); the support path must be offline-only", n)
	}
}

type tripwireRT struct{ hits *atomic.Int64 }

func (rt tripwireRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.hits.Add(1)
	return nil, fmt.Errorf("no-egress wall: HTTP request to %s during bundle build", r.URL.Host)
}
