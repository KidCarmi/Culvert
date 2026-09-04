package upstream

// publication_race_red_test.go — 2F-C correction round 2 RED matrix, written
// against the exact head 42336a8e BEFORE the product correction. The blocker:
// rebuildLocked reuses a published *Proxy whenever ID+authorityHash is
// unchanged and overwrites its Entry under Pool.mu, while a selected request
// (ProxyFunc → authenticatedURL), a probe (probeProxySelector) and the
// attribution slot read Entry WITHOUT that lock. Every interleaving below is
// channel/handshake-controlled (no sleeps): the operation is parked after
// selection, the publication completes, then the parked operation continues.
// The required semantics: an in-flight operation observes the COMPLETE old
// generation (the one it selected) — never a new entry with an old credential
// verdict or vice versa — and a fresh selection observes the new generation.
//
//   PR-1 credential replace on the same authority races a selected request
//   PR-2 credential clear on the same authority races a selected request
//   PR-3 same-authority entry PUT (revision bump) races a selected request
//   PR-4 credential replace races a selected probe
//   PR-5 the exported data-plane reads race the publication (race detector)
//   PR-6 no untracked direct fallback and no password on any surface across the mutation

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type prEnv struct {
	pool *Pool
	key  *Keyring
	spec Spec
	id   string
}

func prSetup(t *testing.T, withCredential bool) *prEnv {
	t.Helper()
	dir := t.TempDir()
	k, err := OpenKey(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := Normalize(Spec{Scheme: "http", Host: "parent.example", Port: 3128, Username: "svc"})
	id := NewManagedID()
	e := ManagedEntry{ID: id, Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username, Revision: 1, Source: SourceManaged}
	if withCredential {
		sealed, err := k.Seal("pw-old", id, spec.AuthorityHash(), "t", "admin")
		if err != nil {
			t.Fatal(err)
		}
		e.Credential = sealed
	}
	pool := &Pool{}
	pool.SetKey(k, "")
	if err := pool.SetDocument(Document{Entries: []ManagedEntry{e}}); err != nil {
		t.Fatal(err)
	}
	return &prEnv{pool: pool, key: k, spec: spec, id: id}
}

func (e *prEnv) entry(rev int64, pw string) ManagedEntry {
	me := ManagedEntry{ID: e.id, Scheme: e.spec.Scheme, Host: e.spec.Host, Port: e.spec.Port, Username: e.spec.Username, Revision: rev, Source: SourceManaged}
	if pw != "" {
		sealed, err := e.key.Seal(pw, e.id, e.spec.AuthorityHash(), "t", "admin")
		if err != nil {
			panic(err)
		}
		me.Credential = sealed
	}
	return me
}

// prInterleave runs op in a goroutine that selects a proxy, parks, and after
// the publication completes finishes with the selected proxy. publish runs
// on the test goroutine while the op is parked. Returns the op's outcome.
func prInterleave(t *testing.T, pool *Pool, publish func(), finish func(up *Proxy) (*url.URL, error)) (selected *Proxy, u *url.URL, err error) {
	t.Helper()
	parked := make(chan *Proxy)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		up := pool.Next()
		parked <- up
		<-release
		u, err = finish(up)
	}()
	select {
	case selected = <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("selection never parked")
	}
	if selected == nil {
		t.Fatal("no proxy selected")
	}
	publish()
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parked operation never finished")
	}
	return selected, u, err
}

func prPassword(u *url.URL) (string, bool) {
	if u == nil || u.User == nil {
		return "", false
	}
	return u.User.Password()
}

// PR-1: a request selected while the entry was credential-free must complete
// with the OLD generation (no credential), never with the credential that a
// same-authority replace published underneath it.
func TestPublicationRace_PR1_CredentialReplaceRacesSelectedRequest(t *testing.T) {
	env := prSetup(t, false)
	selected, u, err := prInterleave(t, env.pool, func() {
		if err := env.pool.SetDocument(Document{Revision: 2, Entries: []ManagedEntry{env.entry(2, "pw-new")}}); err != nil {
			t.Fatal(err)
		}
	}, func(up *Proxy) (*url.URL, error) {
		if st := up.CredentialState(); st != CredentialNone {
			return nil, errors.New("selected generation was credential-free; verdict changed underneath the request to " + st)
		}
		return env.pool.authenticatedURL(up)
	})
	if err != nil {
		t.Fatalf("mixed generation: %v", err)
	}
	if pw, ok := prPassword(u); ok {
		t.Fatalf("a request selected on the credential-free generation must not send the credential published later (got password %q, selected entry rev %d)", strings.Repeat("*", len(pw)), selected.Entry.Revision)
	}
	// A fresh selection observes the NEW generation completely.
	fresh, err := env.pool.ProxyFunc()(nil)
	if err != nil || fresh == nil {
		t.Fatalf("fresh selection: %v %v", fresh, err)
	}
	if pw, _ := prPassword(fresh); pw != "pw-new" {
		t.Fatalf("fresh selection must observe the new generation, got %q", pw)
	}
}

// PR-2: a request selected while the credential was configured must complete
// with that credential even though a clear was published underneath it.
func TestPublicationRace_PR2_CredentialClearRacesSelectedRequest(t *testing.T) {
	env := prSetup(t, true)
	_, u, err := prInterleave(t, env.pool, func() {
		if err := env.pool.SetDocument(Document{Revision: 2, Entries: []ManagedEntry{env.entry(2, "")}}); err != nil {
			t.Fatal(err)
		}
	}, func(up *Proxy) (*url.URL, error) {
		if st := up.CredentialState(); st != CredentialConfigured {
			return nil, errors.New("selected generation was configured; verdict changed underneath the request to " + st)
		}
		return env.pool.authenticatedURL(up)
	})
	if err != nil {
		t.Fatalf("mixed generation: %v", err)
	}
	if pw, _ := prPassword(u); pw != "pw-old" {
		t.Fatalf("a request selected on the configured generation must complete with that credential, got %q", pw)
	}
	if fresh, _ := env.pool.ProxyFunc()(nil); fresh == nil || fresh.User != nil && func() bool { _, ok := fresh.User.Password(); return ok }() {
		t.Fatalf("fresh selection must observe the cleared generation, got %v", fresh)
	}
}

// PR-3: a same-authority entry PUT (revision bump) must not rewrite the entry
// a selected request is holding.
func TestPublicationRace_PR3_SameAuthorityPutRacesSelectedRequest(t *testing.T) {
	env := prSetup(t, true)
	var rev0 int64
	selected, _, err := prInterleave(t, env.pool, func() {
		if err := env.pool.SetDocument(Document{Revision: 2, Entries: []ManagedEntry{env.entry(7, "pw-old")}}); err != nil {
			t.Fatal(err)
		}
	}, func(up *Proxy) (*url.URL, error) {
		rev0 = up.Entry.Revision
		return env.pool.authenticatedURL(up)
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Entry.Revision != 1 || rev0 != 1 {
		t.Fatalf("the selected generation must stay immutable (entry revision 1), got selected=%d read=%d", selected.Entry.Revision, rev0)
	}
	if fresh := env.pool.Next(); fresh == nil || fresh.Entry.Revision != 7 {
		t.Fatalf("fresh selection must observe the new generation, got %+v", fresh)
	}
}

// PR-4: a probe whose selector was built on the credential-free generation
// must not dial with a credential published underneath it.
func TestPublicationRace_PR4_CredentialReplaceRacesSelectedProbe(t *testing.T) {
	env := prSetup(t, false)
	_, u, err := prInterleave(t, env.pool, func() {
		if err := env.pool.SetDocument(Document{Revision: 2, Entries: []ManagedEntry{env.entry(2, "pw-new")}}); err != nil {
			t.Fatal(err)
		}
	}, func(up *Proxy) (*url.URL, error) {
		return env.pool.probeProxySelector(up)(nil)
	})
	if err != nil {
		t.Fatalf("probe selector: %v", err)
	}
	if pw, ok := prPassword(u); ok {
		t.Fatalf("a probe built on the credential-free generation must not dial with the credential published later (got %q)", strings.Repeat("*", len(pw)))
	}
	// The reverse: a probe built on the configured generation keeps it.
	env2 := prSetup(t, true)
	_, u2, err := prInterleave(t, env2.pool, func() {
		if err := env2.pool.SetDocument(Document{Revision: 2, Entries: []ManagedEntry{env2.entry(2, "")}}); err != nil {
			t.Fatal(err)
		}
	}, func(up *Proxy) (*url.URL, error) { return env2.pool.probeProxySelector(up)(nil) })
	if err != nil {
		t.Fatalf("probe selector: %v", err)
	}
	if pw, _ := prPassword(u2); pw != "pw-old" {
		t.Fatalf("a probe built on the configured generation must keep its credential, got %q", pw)
	}
}

// PR-5: the data-plane reads a selected proxy performs after selection
// (Entry fields via authenticatedURL / Attribution.Record) are unsynchronized
// with the publication; under -race this is a reported DATA RACE on the head
// that overwrites Entry in place. Handshake: the reader spins on the entry
// until it observes the publisher's flag, so the read in its final iteration
// is guaranteed to follow the publication in real time without any
// happens-before edge to it.
func TestPublicationRace_PR5_PublicationRacesDataPlaneReads(t *testing.T) {
	env := prSetup(t, true)
	up := env.pool.Next()
	if up == nil {
		t.Fatal("no proxy")
	}
	var published atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	var lastRev int64
	go func() {
		defer wg.Done()
		for {
			// The exact reads the request/probe/attribution paths perform.
			lastRev = up.Entry.Revision
			_ = up.Entry.Authority()
			_ = up.Entry.Credential
			if published.Load() {
				return
			}
		}
	}()
	if err := env.pool.SetDocument(Document{Revision: 2, Entries: []ManagedEntry{env.entry(9, "pw-new")}}); err != nil {
		t.Fatal(err)
	}
	published.Store(true)
	wg.Wait()
	if lastRev != 1 {
		t.Fatalf("the selected generation must stay immutable across the publication, reader observed revision %d", lastRev)
	}
	// Attribution against the selected generation still records against a
	// coherent entry.
	ctx, att := WithAttribution(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://origin.example/", http.NoBody)
	if _, err := env.pool.ProxyFunc()(req); err != nil {
		t.Fatal(err)
	}
	att.Record(errors.New("parent failed"))
}

// PR-6: across the interleavings the pool never records an untracked direct
// fallback and no surface carries a password.
func TestPublicationRace_PR6_NoUntrackedFallbackNoPasswordSurface(t *testing.T) {
	env := prSetup(t, false)
	prInterleave(t, env.pool, func() {
		if err := env.pool.SetDocument(Document{Revision: 2, Entries: []ManagedEntry{env.entry(2, "pw-new")}}); err != nil {
			t.Fatal(err)
		}
	}, func(up *Proxy) (*url.URL, error) { return env.pool.authenticatedURL(up) })
	if active, total := env.pool.DirectFallback(); active || total != 0 {
		t.Fatalf("no direct fallback may be recorded by a publication race: active=%v total=%d", active, total)
	}
	if eff := env.pool.Effective(); eff.Mode != ModeChained || eff.Eligible != 1 {
		t.Fatalf("effective = %+v, want chained/1", eff)
	}
	for _, st := range env.pool.List() {
		if strings.Contains(st.URL, "pw-") || strings.Contains(st.Authority, "pw-") || strings.Contains(st.Probe.Reason, "pw-") {
			t.Fatalf("surface carries a password: %+v", st)
		}
	}
	for _, e := range env.pool.Entries() {
		if strings.Contains(e.URL, "pw-") {
			t.Fatalf("legacy entries carry a password: %+v", e)
		}
	}
}
