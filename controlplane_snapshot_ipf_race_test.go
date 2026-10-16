package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ── RISK-030: the CP→DP snapshot apply must not reassign the IP filter ──────
//
// applySnapshotAdmission used to build a fresh *IPFilter and store it into the
// package-level composition handle (`ipf = newIPF`). proxy.go and socks5.go
// read that handle on every request with no synchronisation, so a snapshot
// apply on a data-plane node was a data race on the FIRST admission gate of an
// inline security gateway — undefined behaviour under the Go memory model.
// The filter itself already publishes an immutable view through an atomic
// pointer (ADR-0038/0039); the unsynchronised word was the handle in main.
//
// The fix replaces the filter's contents IN PLACE through IPFilter.Replace:
// one writer lock, one view publish, the handle never changes. That is the
// posture every other live writer already has (rl is Configure'd in place; bl
// is ReplaceFeedEntries'd in place — "the previous wholesale `bl = newBL`
// pattern" was retired for the same class of defect).

// snapshotIPFixture binds a FRESH filter and a FRESH limiter into the
// composition handles for the duration of the test and restores both previous
// owners afterwards. Both are required: applySnapshotAdmission now mutates the
// installed owners in place, so saving the old pointer and applying over it
// would "restore" an object that already carries this test's allowlist, and
// the apply's rl side effects land on whichever limiter is installed: it calls
// rl.Configure only when the snapshot RPM differs from rl.Limit() (so a
// snapshot without a rate limit zeroes a configured limiter) and
// rl.ReplaceExemptions only when RateLimitExempt is non-nil. Either leak makes
// later root tests order-dependent under -shuffle / -count=2.
func snapshotIPFixture(t *testing.T) *IPFilter {
	t.Helper()
	oldIPF, oldRL := ipf, rl
	f := newIPFilter()
	ipf, rl = f, newRateLimiter()
	t.Cleanup(func() { ipf, rl = oldIPF, oldRL })
	return f
}

// TestRISK030_SnapshotApplyDoesNotRaceRequestPath drives applySnapshotAdmission
// while request-path readers call ipf.Allowed concurrently, exactly as
// handleRequest and handleSOCKS5 do. Under -race the pre-fix shape reports the
// unsynchronised write of the handle against those reads and the test FAILS;
// the in-place shape publishes through the filter's atomic view and is clean.
// Without -race the functional assertions still hold: no reader ever admits
// an address the allowlist does not contain and every reader admits the one
// it does, in the middle of thousands of applies.
func TestRISK030_SnapshotApplyDoesNotRaceRequestPath(t *testing.T) {
	snapshotIPFixture(t)

	snap := ConfigSnapshot{IPFilterMode: "allow", IPList: []string{"10.0.0.1", "198.51.100.0/24"}}
	applySnapshotAdmission(snap)

	const (
		outside = "192.0.2.77"   // never on the allowlist
		listed  = "10.0.0.1"     // single
		inRange = "198.51.100.9" // CIDR member
	)
	var stop atomic.Bool
	var wrongAllow, wrongDeny, reads atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if ipf.Allowed(outside) {
					wrongAllow.Add(1)
				}
				if !ipf.Allowed(listed) || !ipf.Allowed(inRange) {
					wrongDeny.Add(1)
				}
				reads.Add(1)
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		applySnapshotAdmission(snap)
	}
	stop.Store(true)
	wg.Wait()

	if reads.Load() == 0 {
		t.Fatal("no concurrent reads happened; the gate exercised nothing")
	}
	if n := wrongAllow.Load(); n != 0 {
		t.Errorf("%d request(s) admitted an address outside the allowlist during snapshot apply (fail-open window)", n)
	}
	if n := wrongDeny.Load(); n != 0 {
		t.Errorf("%d request(s) refused an allowlisted address during snapshot apply", n)
	}
}

// TestRISK030_SnapshotApplyKeepsTheCompositionHandle: the handle the request
// path reads must be the SAME object before and after an apply. A new object
// is only reachable through an unsynchronised store into the global.
func TestRISK030_SnapshotApplyKeepsTheCompositionHandle(t *testing.T) {
	before := snapshotIPFixture(t)
	applySnapshotAdmission(ConfigSnapshot{IPFilterMode: "block", IPList: []string{"203.0.113.5"}})
	if ipf != before {
		t.Fatal("applySnapshotAdmission replaced the ipf composition handle; the request path reads it unsynchronised")
	}
	if ipf.Allowed("203.0.113.5") || !ipf.Allowed("203.0.113.6") {
		t.Fatal("in-place apply did not install the snapshot's blocklist")
	}
}

// TestRISK030_SnapshotApplyVerdictsUnchanged is the differential control:
// for every mode (including the fail-closed corrupt one), with singles, CIDRs,
// an invalid entry, a mapped address, and a repeated apply over a populated
// filter, the in-place apply must answer exactly as the pre-fix shape did —
// a FRESH filter built with SetMode + AddAll. Mode and the reported entry list
// must match too, since CurrentConfigSnapshot and the admin API read them.
func TestRISK030_SnapshotApplyVerdictsUnchanged(t *testing.T) {
	snapshotIPFixture(t)
	probes := []string{
		"10.0.0.1", "10.0.0.2", "198.51.100.9", "198.51.100.255", "198.51.101.1",
		"203.0.113.5", "::ffff:10.0.0.1", "2001:db8::1", "2001:db8::2", "192.0.2.77", "not-an-ip",
	}
	snaps := []ConfigSnapshot{
		{IPFilterMode: "allow", IPList: []string{"10.0.0.1", "198.51.100.0/24", "2001:db8::1"}},
		{IPFilterMode: "block", IPList: []string{"203.0.113.5", "2001:db8::/64", "bogus-entry"}},
		{IPFilterMode: "", IPList: []string{"10.0.0.1"}},
		{IPFilterMode: "corrupt", IPList: nil},
		{IPFilterMode: "allow", IPList: nil},
		{IPFilterMode: "block", IPList: []string{}},
	}
	// Apply each snapshot in sequence over the SAME live filter (the way a DP
	// node sees successive CP versions) and compare against a fresh one.
	for i, snap := range snaps {
		applySnapshotAdmission(snap)

		fresh := newIPFilter()
		fresh.SetMode(snap.IPFilterMode)
		_ = fresh.AddAll(snap.IPList)

		if got, want := ipf.Mode(), fresh.Mode(); got != want {
			t.Errorf("snapshot %d: mode %q, want %q", i, got, want)
		}
		got, want := ipf.List(), fresh.List()
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("snapshot %d: list %v, want %v", i, got, want)
		}
		for _, p := range probes {
			if g, w := ipf.Allowed(p), fresh.Allowed(p); g != w {
				t.Errorf("snapshot %d (mode %q): Allowed(%q) = %v, pre-fix shape says %v", i, snap.IPFilterMode, p, g, w)
			}
		}
	}
}

// ── Structural wall ─────────────────────────────────────────────────────────

// admissionHandleAssignments reports every assignment whose left-hand side is
// one of the bare admission composition handles (ipf, rl). The declaring
// `var` in admission.go is a GenDecl, not an AssignStmt, so it is not counted.
func admissionHandleAssignments(file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && (id.Name == "ipf" || id.Name == "rl") {
				out = append(out, id.Name)
			}
		}
		return true
	})
	return out
}

// TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles pins the
// contract the fix restores: in production code the composition handles ipf
// and rl are written ONCE, by their declaration, and every live configuration
// path mutates the owner in place. A reassignment anywhere in package main's
// non-test files is a data race against the request path (ADR-0038: "No
// production reassignment of rl"; this wall extends it to ipf). Tests may
// still bind their own owner into the handle — they are excluded by name.
func TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles(t *testing.T) {
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var scanned, declared int
	var offenders []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		scanned++
		for _, d := range file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				for _, name := range s.(*ast.ValueSpec).Names {
					if name.Name == "ipf" || name.Name == "rl" {
						declared++
					}
				}
			}
		}
		for _, name := range admissionHandleAssignments(file) {
			offenders = append(offenders, path+": "+name)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no production files; the wall is looking at the wrong directory")
	}
	if declared != 2 {
		t.Fatalf("expected the two handle declarations (ipf, rl) in package main, found %d; the wall's selector has gone stale", declared)
	}
	if len(offenders) > 0 {
		t.Errorf("production code reassigns an admission composition handle: %v — the request path reads "+
			"ipf/rl unsynchronised, so a reassignment is a data race; mutate the owner in place "+
			"(IPFilter.Replace / RateLimiter.Configure) instead (RISK-030)", offenders)
	}

	// CONTROL: the exact pre-fix shape must be rejected, and in-place use accepted.
	for name, tc := range map[string]struct {
		src  string
		want int
	}{
		"pre-fix reassignment": {`package main
func applySnapshotAdmission(snap ConfigSnapshot) {
	newIPF := newIPFilter()
	ipf = newIPF
}`, 1},
		"limiter reassignment": {`package main
func f() { rl = newRateLimiter() }`, 1},
		"in-place mutation": {`package main
func applySnapshotAdmission(snap ConfigSnapshot) {
	for _, bad := range ipf.Replace(snap.IPFilterMode, snap.IPList) { _ = bad }
	rl.Configure(1, 0)
}`, 0},
	} {
		cfile, err := parser.ParseFile(token.NewFileSet(), "control.go", tc.src, 0)
		if err != nil {
			t.Fatalf("parse %s control: %v", name, err)
		}
		if got := len(admissionHandleAssignments(cfile)); got != tc.want {
			t.Errorf("control %q: wall reported %d assignment(s), want %d — the wall is matching the wrong thing", name, got, tc.want)
		}
	}
}
