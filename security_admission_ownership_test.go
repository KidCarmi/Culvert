package main

import (
	"sync"
	"testing"
	"time"
)

// Each worker owns a limiter while all workers use the same client IP. One
// owner's publication, enable switch and episode latch must be invisible to all
// others. t.Parallel also exercises these owners alongside other local fixtures.
func TestDistributedAdmission_IndependentOwners(t *testing.T) {
	t.Parallel()
	const ip = "198.51.100.71"
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r := newRateLimiter()
			r.Configure(10000, time.Minute)
			<-start
			for i := 0; i < 100; i++ {
				r.SetClusterEnabled(true)
				r.ApplyRemoteCounts(map[string]int{ip: 10000 + n})
				if r.AllowAuto(ip) {
					t.Errorf("owner %d admitted at remote cap", n)
					return
				}
				if got := r.remoteCounts.FreshCount(ip, time.Now(), time.Minute); got != 10000+n {
					t.Errorf("owner %d received another count: %d", n, got)
					return
				}
				r.SetClusterEnabled(false)
				if !r.AllowAuto(ip) || r.ClusterFreshness().Armed {
					t.Errorf("owner %d inherited enablement", n)
					return
				}
				r.SetClusterEnabled(true)
				r.remoteCounts.applyAtForTest(nil, time.Now().Add(-2*time.Minute))
				r.noteClusterRateLimitFreshness()
				r.noteClusterRateLimitFreshness()
				r.ApplyRemoteCounts(nil)
				r.noteClusterRateLimitFreshness()
				if st := r.ClusterFreshness(); st.Stale || st.Episodes != int64(i+1) {
					t.Errorf("owner %d inherited diagnostic history: %+v", n, st)
					return
				}
			}
		}(n)
	}
	close(start)
	wg.Wait()
}

func TestDistributedAdmission_ConstructionAndRetainedState(t *testing.T) {
	for name, r := range map[string]*RateLimiter{"constructor": newRateLimiter(), "zero": new(RateLimiter), "literal": {}} {
		t.Run(name, func(t *testing.T) {
			if r.ClusterEnabled() || r.RemoteIPCount() != 0 || r.ClusterFreshness().Applied || !r.AllowAuto("192.0.2.1") {
				t.Fatal("new owner did not start disabled and empty")
			}
			r.SetClusterEnabled(true)
			r.ApplyRemoteCounts(map[string]int{"192.0.2.1": 10})
			if st := r.ClusterFreshness(); st.Armed || st.Stale || !st.Applied || r.RemoteIPCount() != 1 {
				t.Fatalf("unconfigured owner diagnostics: %+v", st)
			}
		})
	}
	r := withClusterRateLimiter(t, 10, time.Minute)
	const ip = "192.0.2.1"
	r.ApplyRemoteCounts(map[string]int{ip: 10})
	r.SetClusterEnabled(false)
	if !r.AllowAuto(ip) {
		t.Fatal("disabled gossip must use local budget")
	}
	r.SetClusterEnabled(true)
	if r.AllowAuto(ip) {
		t.Fatal("re-enable discarded a retained fresh broadcast")
	}
	r.Configure(0, time.Minute)
	if !r.AllowAuto(ip) || r.ClusterFreshness().Armed {
		t.Fatal("disabled limiter enforced or alarmed")
	}
	r.Configure(10, time.Minute)
	if r.AllowAuto(ip) {
		t.Fatal("Configure discarded remote state")
	}
	if err := r.AddExemption(ip); err != nil {
		t.Fatal(err)
	}
	if !r.AllowAuto(ip) {
		t.Fatal("remote cap overrode exemption")
	}
	r.ReplaceExemptions(nil)
	r.ApplyRemoteCounts(nil)
	if r.RemoteIPCount() != 0 || r.ClusterFreshness().Stale || !r.AllowAuto(ip) {
		t.Fatal("empty successful broadcast did not clear remote counts and restore local admission")
	}
	// The earlier standalone admission still counts locally across the switches.
	for i := 2; i < 10; i++ {
		if !r.AllowAuto(ip) {
			t.Fatalf("local budget ended at %d", i)
		}
	}
	if r.AllowAuto(ip) {
		t.Fatal("enable/config switches cleared local history")
	}
}

func TestIPFilterView_IndependentPublicationObservers(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			f := &IPFilter{}
			rec := recordIPFilterPublishes(f)
			// Different publication counts make cross-owner delivery observable.
			for i := 0; i <= n; i++ {
				f.SetMode("block")
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.events) != n+1 {
				t.Errorf("filter %d observed %d publications", n, len(rec.events))
				return
			}
			for _, ev := range rec.events {
				if ev.method != "SetMode" || ev.view.mode != "block" {
					t.Errorf("filter %d received foreign publication: %+v", n, ev)
				}
			}
			if rec.events[n].view != f.view.Load() {
				t.Errorf("filter %d observed another receiver", n)
			}
		}(n)
	}
	wg.Wait()
}

func BenchmarkDistributedAdmission(b *testing.B) {
	for _, mode := range []string{"standalone", "fresh", "stale", "future", "disabled", "exempt"} {
		b.Run(mode, func(b *testing.B) {
			r := newRateLimiter()
			r.Configure(1, time.Hour)
			const ip = "198.51.100.71"
			_ = r.Allow(ip) // prime a stable at-cap bucket: no growth/expiry allocations
			r.SetClusterEnabled(mode != "standalone")
			stamp := time.Now()
			if mode == "stale" {
				stamp = stamp.Add(-2 * time.Hour)
			}
			if mode == "future" {
				stamp = stamp.Add(2 * time.Hour)
			}
			r.remoteCounts.applyAtForTest(map[string]int{ip: 1}, stamp)
			if mode == "disabled" {
				r.Configure(0, time.Hour)
			}
			if mode == "exempt" {
				if err := r.AddExemption(ip); err != nil {
					b.Fatal(err)
				}
			}
			want := mode == "disabled" || mode == "exempt"
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if r.AllowAuto(ip) != want {
					b.Fatalf("unexpected %s verdict", mode)
				}
			}
		})
	}
}
