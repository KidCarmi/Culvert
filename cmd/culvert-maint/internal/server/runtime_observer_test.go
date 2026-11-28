package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"culvert-maint/internal/health"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/runtimehealth"
)

var (
	obsImgGood  = "sha256:" + strings.Repeat("1", 64)
	obsImgOther = "sha256:" + strings.Repeat("2", 64)
	obsCtr      = strings.Repeat("c", 64)
	obsCtr2     = strings.Repeat("d", 64)
	obsDigest   = "sha256:" + strings.Repeat("9", 64)
	obsRef      = "ghcr.io/kidcarmi/culvert@" + obsDigest
	obsLocalRef = "culvert/proxy@" + obsDigest
)

// obsDocker is a scripted observerDocker. reads counts ReadProxyContainer
// calls; next returns the answer for the n-th one (1-based).
type obsDocker struct {
	mu    sync.Mutex
	reads int
	next  func(n int) (*runner.ProxyContainer, error)
	tag   string
	tagEr error
}

func (d *obsDocker) ReadProxyContainer(context.Context) (*runner.ProxyContainer, error) {
	d.mu.Lock()
	d.reads++
	n := d.reads
	d.mu.Unlock()
	return d.next(n)
}

func (d *obsDocker) PinnedTagImageID(context.Context) (string, error) { return d.tag, d.tagEr }

func runningOn(img, ctr string, refs ...string) func(int) (*runner.ProxyContainer, error) {
	return func(int) (*runner.ProxyContainer, error) {
		return &runner.ProxyContainer{Present: true, Running: true, ContainerID: ctr, ImageID: img, RepoDigests: refs}, nil
	}
}

type obsRig struct {
	srv    *Server
	store  *runtimehealth.Store
	docker *obsDocker
	ready  atomic.Int32 // HTTP status /ready answers
	state  string
}

func newObsRig(t *testing.T) *obsRig {
	t.Helper()
	r := &obsRig{}
	r.ready.Store(http.StatusOK)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/ready" {
			w.WriteHeader(int(r.ready.Load()))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hs.Close)
	base, _ := url.Parse(hs.URL)
	srv := newDrainTestServer(t, time.Second)
	r.state = srv.opts.StateDir
	st, err := runtimehealth.Open(r.state)
	if err != nil {
		t.Fatal(err)
	}
	srv.opts.Cfg.ProxyRepo = "ghcr.io/kidcarmi/culvert"
	srv.opts.Cfg.ImageAllowlist = regexp.MustCompile(`^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`)
	srv.opts.Cfg.RuntimeHealthInterval = time.Minute
	srv.opts.RuntimeHealth = st
	srv.opts.HealthProbeFactory = func() health.Probe {
		return health.Probe{BaseURL: base, HealthPath: "/health", ReadyPath: "/ready", Budget: 300 * time.Millisecond, PollInterval: 30 * time.Millisecond, RequestTimeout: 200 * time.Millisecond}
	}
	r.docker = &obsDocker{next: runningOn(obsImgGood, obsCtr, obsRef), tag: obsImgGood}
	srv.observer.docker = r.docker
	r.srv, r.store = srv, st
	return r
}

func (r *obsRig) latest(t *testing.T) *runtimehealth.Sample {
	t.Helper()
	smp, err := r.store.ReadLatest()
	if err != nil {
		t.Fatalf("ReadLatest: %v", err)
	}
	return smp
}

func (r *obsRig) lastGoodBytes(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.store.Dir(), "last_good.json"))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestObserver_GatedRecordsLastGood(t *testing.T) {
	r := newObsRig(t)
	if out := r.srv.observeOnce(context.Background()); out != obsRecordedAndGood {
		t.Fatalf("observeOnce = %s, want %s", out, obsRecordedAndGood)
	}
	smp := r.latest(t)
	if smp.State != runtimehealth.StateGated || smp.ImageID != obsImgGood || smp.ContainerID != obsCtr || smp.Reason != obsReasonGateOK {
		t.Fatalf("latest = %+v", smp)
	}
	lg, err := r.store.ReadLastGood()
	if err != nil || lg == nil || lg.ImageID != obsImgGood || lg.Ref != obsRef || lg.Digest != obsDigest || lg.Gate != runtimehealth.GateRuntimeObserver {
		t.Fatalf("last_good = %+v, %v", lg, err)
	}
	if r.docker.reads != 2 {
		t.Fatalf("identity read %d times, want 2 (before and after the probe)", r.docker.reads)
	}
}

// A gated image whose only reference is local (or foreign) is reported gated
// but never becomes last_good: nothing could resolve it as a trusted target.
func TestObserver_GatedWithoutValidatedRefIsNotLastGood(t *testing.T) {
	for name, refs := range map[string][]string{
		"no reference":       nil,
		"local-only":         {obsLocalRef},
		"foreign repository": {"docker.io/evil/culvert@" + obsDigest},
		"a tag, not digest":  {"ghcr.io/kidcarmi/culvert:latest"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newObsRig(t)
			r.docker.next = runningOn(obsImgGood, obsCtr, refs...)
			if out := r.srv.observeOnce(context.Background()); out != obsRecorded {
				t.Fatalf("observeOnce = %s", out)
			}
			if smp := r.latest(t); smp.State != runtimehealth.StateGated || smp.Reason != obsReasonGateOKNoRef {
				t.Fatalf("latest = %+v", smp)
			}
			if b := r.lastGoodBytes(t); b != "" {
				t.Fatalf("last_good written: %s", b)
			}
		})
	}
}

// An unreadable fixed tag is unknown, not a value two reads agree on: with it
// unreadable before the probe nothing is gated and last_good stays; with it
// unreadable only after, the sample is discarded.
func TestObserver_UnreadableTagNeverGates(t *testing.T) {
	t.Run("unreadable before", func(t *testing.T) {
		r := newObsRig(t)
		if out := r.srv.observeOnce(context.Background()); out != obsRecordedAndGood {
			t.Fatalf("first observation = %s", out)
		}
		good := r.lastGoodBytes(t)
		r.docker.tag, r.docker.tagEr = "", errors.New("no such image: culvert/proxy:pinned")
		probed := false
		r.srv.observer.afterProbe = func() { probed = true }
		if out := r.srv.observeOnce(context.Background()); out != obsRecorded {
			t.Fatalf("observeOnce = %s", out)
		}
		if smp := r.latest(t); smp.State != runtimehealth.StateUnknown || smp.Reason != obsReasonTagUnreadable {
			t.Fatalf("latest = %+v", smp)
		}
		if probed {
			t.Fatal("the gate ran with the fixed tag unreadable")
		}
		if got := r.lastGoodBytes(t); got != good {
			t.Fatalf("last_good changed:\nbefore %s\nafter  %s", good, got)
		}
	})
	t.Run("unreadable after", func(t *testing.T) {
		r := newObsRig(t)
		r.srv.observer.afterProbe = func() { r.docker.tag, r.docker.tagEr = "", errors.New("inspect failed") }
		if out := r.srv.observeOnce(context.Background()); out != obsDiscarded {
			t.Fatalf("observeOnce = %s, want %s", out, obsDiscarded)
		}
		if b := r.lastGoodBytes(t); b != "" {
			t.Fatalf("last_good written: %s", b)
		}
	})
}

// The repository binding holds even when the operator's image allowlist is
// broader than the configured proxy repository.
func TestObserver_LastGoodIsRepoBoundWhateverTheAllowlist(t *testing.T) {
	r := newObsRig(t)
	r.srv.opts.Cfg.ImageAllowlist = regexp.MustCompile(`.*`)
	r.docker.next = runningOn(obsImgGood, obsCtr, "docker.io/evil/culvert@"+obsDigest)
	if out := r.srv.observeOnce(context.Background()); out != obsRecorded {
		t.Fatalf("observeOnce = %s", out)
	}
	if b := r.lastGoodBytes(t); b != "" {
		t.Fatalf("a foreign-repository image became last_good: %s", b)
	}
}

// An image the operator's allowlist no longer admits is never a trusted
// target, even from the configured repository.
func TestObserver_LastGoodHonoursANarrowAllowlist(t *testing.T) {
	r := newObsRig(t)
	r.srv.opts.Cfg.ImageAllowlist = regexp.MustCompile(`^ghcr\.io/kidcarmi/culvert@sha256:0{64}$`)
	if out := r.srv.observeOnce(context.Background()); out != obsRecorded {
		t.Fatalf("observeOnce = %s", out)
	}
	if b := r.lastGoodBytes(t); b != "" {
		t.Fatalf("an image outside the allowlist became last_good: %s", b)
	}
}

// Owner decision 5: no unhealthy, unknown or stale observation overwrites or
// clears the last-known-good evidence.
func TestObserver_BadObservationsKeepLastGood(t *testing.T) {
	cases := map[string]func(r *obsRig){
		"gate fails": func(r *obsRig) { r.ready.Store(http.StatusServiceUnavailable) },
		"docker unreadable": func(r *obsRig) {
			r.docker.next = func(int) (*runner.ProxyContainer, error) { return nil, errors.New("daemon down") }
		},
		"no container": func(r *obsRig) {
			r.docker.next = func(int) (*runner.ProxyContainer, error) { return &runner.ProxyContainer{}, nil }
		},
		"container stopped": func(r *obsRig) {
			r.docker.next = func(int) (*runner.ProxyContainer, error) {
				return &runner.ProxyContainer{Present: true, ContainerID: obsCtr, ImageID: obsImgGood}, nil
			}
		},
		"another image, unhealthy": func(r *obsRig) {
			r.docker.next = runningOn(obsImgOther, obsCtr2, obsRef)
			r.ready.Store(http.StatusServiceUnavailable)
		},
	}
	want := map[string]string{
		"gate fails":               runtimehealth.StateUnhealthy,
		"docker unreadable":        runtimehealth.StateUnknown,
		"no container":             runtimehealth.StateUnhealthy,
		"container stopped":        runtimehealth.StateUnhealthy,
		"another image, unhealthy": runtimehealth.StateUnhealthy,
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			r := newObsRig(t)
			if out := r.srv.observeOnce(context.Background()); out != obsRecordedAndGood {
				t.Fatalf("first observation = %s", out)
			}
			good := r.lastGoodBytes(t)
			breakIt(r)
			for i := 0; i < 3; i++ {
				if out := r.srv.observeOnce(context.Background()); out != obsRecorded {
					t.Fatalf("bad observation %d = %s", i, out)
				}
			}
			if smp := r.latest(t); smp.State != want[name] {
				t.Fatalf("latest = %+v, want state %s", smp, want[name])
			}
			if got := r.lastGoodBytes(t); got != good {
				t.Fatalf("last_good changed:\nbefore %s\nafter  %s", good, got)
			}
		})
	}
}

// A probe is evidence only about the container it was taken against: a
// change of container, image, running state or fixed tag between the two
// identity reads discards the sample.
func TestObserver_IdentityChangeAcrossTheProbeDiscards(t *testing.T) {
	changes := map[string]func(n int) (*runner.ProxyContainer, error){
		"container recreated": func(n int) (*runner.ProxyContainer, error) {
			if n == 1 {
				return runningOn(obsImgGood, obsCtr, obsRef)(n)
			}
			return runningOn(obsImgGood, obsCtr2, obsRef)(n)
		},
		"image changed": func(n int) (*runner.ProxyContainer, error) {
			if n == 1 {
				return runningOn(obsImgOther, obsCtr, obsRef)(n)
			}
			return runningOn(obsImgGood, obsCtr, obsRef)(n)
		},
		"stopped": func(n int) (*runner.ProxyContainer, error) {
			if n == 1 {
				return runningOn(obsImgGood, obsCtr, obsRef)(n)
			}
			return &runner.ProxyContainer{Present: true, ContainerID: obsCtr, ImageID: obsImgGood}, nil
		},
		"docker unreadable after": func(n int) (*runner.ProxyContainer, error) {
			if n == 1 {
				return runningOn(obsImgGood, obsCtr, obsRef)(n)
			}
			return nil, errors.New("daemon down")
		},
	}
	for name, next := range changes {
		t.Run(name, func(t *testing.T) {
			r := newObsRig(t)
			r.docker.next = next
			if out := r.srv.observeOnce(context.Background()); out != obsDiscarded {
				t.Fatalf("observeOnce = %s, want %s", out, obsDiscarded)
			}
			if smp := r.latest(t); smp != nil {
				t.Fatalf("a discarded sample was written: %+v", smp)
			}
			if b := r.lastGoodBytes(t); b != "" {
				t.Fatalf("last_good written from a discarded sample: %s", b)
			}
		})
	}
	t.Run("fixed tag moved", func(t *testing.T) {
		r := newObsRig(t)
		r.srv.observer.afterProbe = func() { r.docker.tag = obsImgOther }
		if out := r.srv.observeOnce(context.Background()); out != obsDiscarded {
			t.Fatalf("observeOnce = %s, want %s", out, obsDiscarded)
		}
		if b := r.lastGoodBytes(t); b != "" {
			t.Fatalf("last_good written: %s", b)
		}
	})
}

func TestObserver_SkipsWhileTheLockIsHeldOrTheWindowIsOpen(t *testing.T) {
	t.Run("lock held", func(t *testing.T) {
		r := newObsRig(t)
		if _, err := r.srv.opts.Ops.Begin(ops.SyntheticStateChangingKind, "test", "", nil); err != nil {
			t.Fatal(err)
		}
		if out := r.srv.observeOnce(context.Background()); out != obsSkippedLock {
			t.Fatalf("observeOnce = %s", out)
		}
		if r.docker.reads != 0 {
			t.Fatalf("Docker read %d times while the lock was held", r.docker.reads)
		}
	})
	t.Run("lock taken during the probe", func(t *testing.T) {
		r := newObsRig(t)
		r.srv.observer.afterProbe = func() {
			if _, err := r.srv.opts.Ops.Begin(ops.SyntheticStateChangingKind, "test", "", nil); err != nil {
				t.Error(err)
			}
		}
		if out := r.srv.observeOnce(context.Background()); out != obsDiscardedLock {
			t.Fatalf("observeOnce = %s", out)
		}
		if smp := r.latest(t); smp != nil {
			t.Fatalf("sample written: %+v", smp)
		}
	})
	t.Run("settle window open", func(t *testing.T) {
		r := newObsRig(t)
		r.srv.opts.Cfg.InterruptedSettle = time.Hour
		r.srv.startHazard = true
		if out := r.srv.observeOnce(context.Background()); out != obsSkippedSettle {
			t.Fatalf("observeOnce = %s", out)
		}
		if r.docker.reads != 0 {
			t.Fatalf("Docker read %d times inside the settle window", r.docker.reads)
		}
	})
}

// The observer writes nothing but the health directory: no journal record, no
// audit entry, no marker.
func TestObserver_WritesOnlyTheHealthDirectory(t *testing.T) {
	r := newObsRig(t)
	snapshot := func() []string {
		var out []string
		_ = filepath.Walk(r.state, func(p string, info os.FileInfo, err error) error {
			if err == nil && !strings.HasPrefix(p, r.store.Dir()) {
				rel, _ := filepath.Rel(r.state, p)
				out = append(out, fmt.Sprintf("%s|%s|%d", rel, info.ModTime(), info.Size()))
			}
			return nil
		})
		sort.Strings(out)
		return out
	}
	before := snapshot()
	for _, ready := range []int32{http.StatusOK, http.StatusServiceUnavailable, http.StatusOK} {
		r.ready.Store(ready)
		r.srv.observeOnce(context.Background())
	}
	if after := snapshot(); strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("state_dir outside health/ changed:\nbefore %v\nafter  %v", before, after)
	}
}

func TestObserver_OffStartsNothing(t *testing.T) {
	r := newObsRig(t)
	r.srv.opts.Cfg.RuntimeHealthInterval = 0
	r.srv.startRuntimeObserver(context.Background())
	if !r.srv.drainOps() {
		t.Fatal("a goroutine was started with the observer off")
	}
}

// The loop runs under goOp and ends with its context, so the shutdown drain
// does not wait on it.
func TestObserver_LoopSamplesAndStopsWithItsContext(t *testing.T) {
	r := newObsRig(t)
	r.srv.opts.Cfg.RuntimeHealthInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	r.srv.startRuntimeObserver(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for r.lastGoodBytes(t) == "" {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the loop never recorded a sample")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if !r.srv.drainOps() {
		t.Fatal("the loop did not end with its context")
	}
}

func TestObserver_EnabledNeedsEveryDependency(t *testing.T) {
	r := newObsRig(t)
	if !r.srv.runtimeObserverEnabled() {
		t.Fatal("fully wired observer reports disabled")
	}
	r.srv.opts.RuntimeHealth = nil
	if r.srv.runtimeObserverEnabled() {
		t.Fatal("observer enabled without a store")
	}
	r2 := newObsRig(t)
	r2.srv.opts.HealthProbeFactory = nil
	if r2.srv.runtimeObserverEnabled() {
		t.Fatal("observer enabled without a probe")
	}
}
