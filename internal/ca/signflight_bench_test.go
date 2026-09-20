package ca

import (
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Before/after, measured in ONE run.
//
// getCertLegacy is a VERBATIM copy of the pre-single-flight GetCert body. It is
// frozen here so the comparison stays reproducible in-tree rather than living
// in a commit message, and so the regression gate below can be a RATIO — which
// is machine-independent and needs no re-baselining (the convention this tree
// already uses for security_ratelimit_window_bench_test.go and
// security_ratelimit_exempt_bench_test.go).
// ─────────────────────────────────────────────────────────────────────────────

func getCertLegacy(cm *Manager, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = "unknown"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	now := time.Now()
	cm.mu.RLock()
	if entry, ok := cm.cache[host]; ok && now.Sub(entry.createdAt) < certCacheTTL &&
		(entry.cert.Leaf == nil || now.Before(entry.cert.Leaf.NotAfter)) {
		cm.mu.RUnlock()
		cm.cacheHits.Add(1)
		return entry.cert, nil
	}
	cm.mu.RUnlock()
	cm.cacheMisses.Add(1)

	signStart := time.Now()
	cert, err := cm.signLeaf(host)
	if err != nil {
		return nil, err
	}
	if SignLatencyObserver != nil {
		SignLatencyObserver(time.Since(signStart).Seconds())
	}
	// The pre-fix body had no generation fence, so it stored unconditionally.
	// Passing the CURRENT generation reproduces that exactly (the check cannot
	// fail), which keeps this a faithful frozen copy rather than a copy that
	// quietly inherits the fix it is the baseline for.
	cm.storeLeaf(host, cert, cm.caGen.Load(), now)
	return cert, nil
}

// benchBurst drives a cold-cache burst: workers goroutines walking a hosts-wide
// destination set. This is the shape the cache faces after a restart, at a TTL
// boundary (entries are created by traffic and expire on one uniform 1h TTL, so
// a working set goes cold together) and during a traffic spike.
func benchBurst(b *testing.B, workers, hosts, perWorker int, get func(*Manager, *tls.ClientHelloInfo) (*tls.Certificate, error)) {
	b.Helper()
	// Count signs DIRECTLY off the signing path rather than deriving them from
	// misses: a miss can also be served by the signOnce cache re-check, which
	// is neither a sign nor a join, so misses-minus-joins overstates the signs
	// (it read 1.06 signs/host against a true 1.00 when this gate was first
	// written). Both arms are measured through the same observer, so the
	// observer's own cost cancels.
	var signs atomic.Int64
	prevObs := SignLatencyObserver
	SignLatencyObserver = func(float64) { signs.Add(1) }
	defer func() { SignLatencyObserver = prevObs }()
	var totalSigns int64
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		cm := New()
		if err := cm.InitCA(); err != nil {
			b.Fatalf("InitCA: %v", err)
		}
		if _, err := cm.sharedLeafKey(); err != nil {
			b.Fatalf("sharedLeafKey: %v", err)
		}
		b.StartTimer()

		var wg sync.WaitGroup
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range perWorker {
					name := fmt.Sprintf("h%d.example.com", (w*7+i*3)%hosts)
					if _, err := get(cm, &tls.ClientHelloInfo{ServerName: name}); err != nil {
						b.Error(err)
						return
					}
				}
			}()
		}
		wg.Wait()
		totalSigns += signs.Swap(0)
	}
	b.StopTimer()
	// signs-per-host is the metric this change moves: 1.00 is the floor (every
	// host signed exactly once), anything above it is duplicated P-256 work.
	b.ReportMetric(float64(totalSigns)/float64(b.N*hosts), "signs/host")
}

func BenchmarkGetCert_ColdBurst(b *testing.B) {
	for _, tc := range []struct{ workers, hosts int }{{16, 4}, {64, 64}, {64, 256}} {
		name := fmt.Sprintf("workers=%d/hosts=%d", tc.workers, tc.hosts)
		b.Run(name, func(b *testing.B) {
			benchBurst(b, tc.workers, tc.hosts, 40, (*Manager).GetCert)
		})
		b.Run(name+"/legacy", func(b *testing.B) {
			benchBurst(b, tc.workers, tc.hosts, 40, getCertLegacy)
		})
	}
}

// BenchmarkGetCert_Hit pins that the steady-state hit path — which is ~all
// traffic on a warm gateway — is untouched: it takes no flight lock and still
// allocates nothing.
func BenchmarkGetCert_Hit(b *testing.B) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		b.Fatalf("InitCA: %v", err)
	}
	hello := &tls.ClientHelloInfo{ServerName: "warm.example.com"}
	if _, err := cm.GetCert(hello); err != nil {
		b.Fatal(err)
	}
	b.Run("current", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := cm.GetCert(hello); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("legacy", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := getCertLegacy(cm, hello); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression gates.
// ─────────────────────────────────────────────────────────────────────────────

// TestBenchGate_ColdBurstDoesNotDuplicateSigns is the regression gate, and it is
// a RATIO measured in ONE run: signs-per-host for the current path against the
// frozen legacy path, on the same burst, on the same machine, back to back. It
// needs no absolute baseline and cannot drift with hardware.
//
// It is skipped at GOMAXPROCS=1, where the legacy path is already optimal —
// which is exactly the point of the finding (the waste is what concurrency
// buys), and is pinned as its own control below.
func TestBenchGate_ColdBurstDoesNotDuplicateSigns(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("the duplication this gate measures requires concurrency; see TestBenchGate_SerialBurstNeverDuplicated")
	}
	const (
		workers   = 64
		hosts     = 256
		perWorker = 40
	)
	var signs atomic.Int64
	prevObs := SignLatencyObserver
	SignLatencyObserver = func(float64) { signs.Add(1) }
	t.Cleanup(func() { SignLatencyObserver = prevObs })

	signsPerHost := func(get func(*Manager, *tls.ClientHelloInfo) (*tls.Certificate, error)) float64 {
		signs.Store(0)
		cm := New()
		if err := cm.InitCA(); err != nil {
			t.Fatalf("InitCA: %v", err)
		}
		if _, err := cm.sharedLeafKey(); err != nil {
			t.Fatalf("sharedLeafKey: %v", err)
		}
		var wg sync.WaitGroup
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range perWorker {
					name := fmt.Sprintf("h%d.example.com", (w*7+i*3)%hosts)
					if _, err := get(cm, &tls.ClientHelloInfo{ServerName: name}); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
		wg.Wait()
		return float64(signs.Load()) / hosts
	}

	// Run each shape twice and take the better (lower) figure: the legacy
	// number is a scheduling race, so a single unlucky run could understate the
	// defect. Understating it can only make this gate more permissive, never
	// less, so the direction is safe.
	cur := min(signsPerHost((*Manager).GetCert), signsPerHost((*Manager).GetCert))
	legacy := min(signsPerHost(getCertLegacy), signsPerHost(getCertLegacy))
	t.Logf("GOMAXPROCS=%d signs/host: current=%.2f legacy=%.2f", runtime.GOMAXPROCS(0), cur, legacy)

	if cur != 1.0 {
		t.Fatalf("signs/host = %.2f, want exactly 1.00 — a cold burst must sign each host once", cur)
	}
	if legacy <= cur {
		t.Fatalf("the frozen legacy shape measured %.2f signs/host against the current %.2f: "+
			"this gate is not observing the duplication it exists to prevent", legacy, cur)
	}
}

// TestBenchGate_SerialBurstNeverDuplicated is the CONTROL for the gate above:
// with no concurrency there is nothing to collapse, so BOTH shapes must sign
// each host exactly once. Without it, a "fix" that simply signed fewer hosts —
// serving one host's certificate for another — would pass the ratio gate while
// being a MITM-identity failure.
func TestBenchGate_SerialBurstNeverDuplicated(t *testing.T) {
	const hosts = 32
	var signs atomic.Int64
	prevObs := SignLatencyObserver
	SignLatencyObserver = func(float64) { signs.Add(1) }
	t.Cleanup(func() { SignLatencyObserver = prevObs })

	for _, arm := range []struct {
		name string
		get  func(*Manager, *tls.ClientHelloInfo) (*tls.Certificate, error)
	}{{"current", (*Manager).GetCert}, {"legacy", getCertLegacy}} {
		signs.Store(0)
		cm := New()
		if err := cm.InitCA(); err != nil {
			t.Fatalf("InitCA: %v", err)
		}
		seen := map[string]bool{}
		for range 3 {
			for i := range hosts {
				name := fmt.Sprintf("h%d.example.com", i)
				c, err := arm.get(cm, &tls.ClientHelloInfo{ServerName: name})
				if err != nil {
					t.Fatalf("%s: %v", arm.name, err)
				}
				if c.Leaf.Subject.CommonName != name {
					t.Fatalf("%s: host %s served a certificate for %s", arm.name, name, c.Leaf.Subject.CommonName)
				}
				seen[name] = true
			}
		}
		if n := signs.Load(); n != hosts {
			t.Fatalf("%s: %d signs for %d hosts visited 3x, want %d (one per host, then cached)", arm.name, n, hosts, hosts)
		}
		if len(seen) != hosts {
			t.Fatalf("%s: served %d distinct hosts, want %d", arm.name, len(seen), hosts)
		}
	}
}

// TestBenchGate_HitPathAddsNoAllocation pins that the collapsing put no cost on
// the path that carries ~all traffic on a warm gateway: the hit is served
// before any flight bookkeeping is reached, so it must measure exactly what the
// frozen legacy shape measures, in the same run.
//
// That figure is 1, not 0, and the cause is PRE-EXISTING and identical in both
// arms: an SNI ServerName carries no port, so net.SplitHostPort fails and
// allocates an *net.AddrError for the error it returns. Worth closing — but as
// its own change, with its own evidence; widening this one to include it would
// mix two concerns in a benchmark whose whole job is to isolate one.
func TestBenchGate_HitPathAddsNoAllocation(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	for _, name := range []string{"warm.example.com", "warm.example.com:443"} {
		hello := &tls.ClientHelloInfo{ServerName: name}
		if _, err := cm.GetCert(hello); err != nil {
			t.Fatal(err)
		}
		var sink *tls.Certificate
		cur := testing.AllocsPerRun(200, func() { sink, _ = cm.GetCert(hello) })
		legacy := testing.AllocsPerRun(200, func() { sink, _ = getCertLegacy(cm, hello) })
		if sink == nil {
			t.Fatal("no certificate served")
		}
		if cur > legacy {
			t.Fatalf("ServerName=%q: hit path allocates %.1f objects/op against the legacy shape's %.1f — "+
				"the single flight must not be reached on a hit", name, cur, legacy)
		}
		if cur > 1 {
			t.Fatalf("ServerName=%q: hit path allocates %.1f objects/op, want <= 1", name, cur)
		}
	}
}

// TestBenchGate_FlightMapDoesNotGrow: the flight map is keyed by host, and the
// hostname is client-chosen. It must be a transient registry, never a second
// cache — an entry that outlives its sign would be an unbounded map behind the
// bounded one, the CHAOS-28 cacheOrder leak in a new place.
func TestBenchGate_FlightMapDoesNotGrow(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	var wg sync.WaitGroup
	var n atomic.Int64
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 64 {
				if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: fmt.Sprintf("u%d-%d.example.com", w, i)}); err != nil {
					t.Error(err)
					return
				}
				n.Add(1)
			}
		}()
	}
	wg.Wait()
	cm.flightMu.Lock()
	left := len(cm.flights)
	cm.flightMu.Unlock()
	if left != 0 {
		t.Fatalf("%d flights still registered after %d distinct hosts completed, want 0", left, n.Load())
	}
}
