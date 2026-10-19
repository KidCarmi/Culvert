package pac

// store_durability_chaos_test.go — CHAOS-77 gates for the LEGACY PAC config
// store as a durability surface.
//
// The sibling store in this same package states the contract these gates
// pin: ProfileStore.setLocked is "the persist-before-swap commit (2F-B, C1):
// the durable write is the commit point. Memory is replaced only after the
// file is durably written, so a failed write leaves the in-memory (and
// therefore the cluster-synced) view exactly where it was — never a torn
// 'memory says candidate, disk says previous' state."
//
// Store.Set backs /proxy.pac and /pac/default.pac — the artifact the entire
// unauthenticated client fleet fetches — and three of its four production
// callers discard or merely log its error (config-version rollback, the Data
// Plane's snapshot apply, config import). A swap-before-persist Set therefore
// turns a full or read-only volume into a fleet-visible routing change that
// nothing recorded and that reverts on the next restart.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unwritableStorePath returns a path whose PARENT is a regular file, so every
// write beneath it fails with ENOTDIR. Chosen over a mode-0500 directory
// because the test suite can run as root, and root bypasses mode bits —
// ENOTDIR is enforced by the kernel for every uid.
func unwritableStorePath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	return filepath.Join(blocker, "pac_config.json")
}

// TestChaos77_FailedLegacyWriteLeavesTheServingConfigUnchanged is the core
// invariant: when the durable write cannot land, Set must report the failure
// AND leave the serving view exactly where it was. Before the fix Set
// assigned s.cfg, advanced the revision and stamped modTime before marshalling
// and writing, so a failed write left the new config live in memory — served
// to every PAC client — while the disk kept the previous one.
func TestChaos77_FailedLegacyWriteLeavesTheServingConfigUnchanged(t *testing.T) {
	const (
		goodHost = "proxy.corp.example"
		badHost  = "attacker-chosen.example"
	)
	s := &Store{}
	s.Restore(State{
		Cfg:     Config{ProxyHost: goodHost, ProxyPort: 8080, Exclusions: []string{"intranet.corp.example"}},
		Path:    unwritableStorePath(t),
		ModTime: time.Now(),
	})
	before := s.Get()
	beforeMod := s.ModTime()

	err := s.Set(Config{ProxyHost: badHost, ProxyPort: 3128})
	if err == nil {
		t.Fatal("Set on an unwritable store path returned nil; the failure must be reported")
	}

	after := s.Get()
	if after.ProxyHost != goodHost {
		t.Errorf("serving ProxyHost = %q after a failed write, want %q: the fleet is being served a config that was never persisted",
			after.ProxyHost, goodHost)
	}
	if after.ProxyPort != before.ProxyPort {
		t.Errorf("serving ProxyPort = %d after a failed write, want %d", after.ProxyPort, before.ProxyPort)
	}
	if len(after.Exclusions) != len(before.Exclusions) {
		t.Errorf("serving exclusions = %v after a failed write, want %v", after.Exclusions, before.Exclusions)
	}
	if after.Revision != before.Revision {
		t.Errorf("revision advanced to %d on a failed write (was %d): the 2F-A token must only move when a mutation committed",
			after.Revision, before.Revision)
	}
	if !s.ModTime().Equal(beforeMod) {
		t.Errorf("modTime moved on a failed write (%v → %v): it is the Last-Modified source for /proxy.pac and the ArtifactCache key",
			beforeMod, s.ModTime())
	}

	// The compiled artifact is what clients actually execute.
	if js := s.Compile("").JS; strings.Contains(js, badHost) {
		t.Errorf("compiled PAC body names %q after a failed write: the unpersisted change reached the fleet", badHost)
	}
}

// TestChaos77_SuccessfulLegacyWriteStillCommits is the negative control: the
// persist-before-swap reordering must not make a healthy write a no-op.
func TestChaos77_SuccessfulLegacyWriteStillCommits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pac_config.json")
	s := &Store{}
	s.Restore(State{Cfg: Config{ProxyHost: "old.example", ProxyPort: 8080}, Path: path})
	before := s.Get()

	if err := s.Set(Config{ProxyHost: "new.example", ProxyPort: 3128, Exclusions: []string{"a.example"}}); err != nil {
		t.Fatalf("Set on a writable path: %v", err)
	}
	got := s.Get()
	if got.ProxyHost != "new.example" || got.ProxyPort != 3128 {
		t.Fatalf("committed config = %+v, want new.example:3128", got)
	}
	if got.Revision != before.Revision+1 {
		t.Errorf("revision = %d, want %d (exactly one advance per committed Set)", got.Revision, before.Revision+1)
	}
	if s.ModTime().IsZero() {
		t.Error("modTime not stamped on a committed Set")
	}
	// The durable copy must agree with the serving copy — the whole point of
	// making the write the commit point.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back store file: %v", err)
	}
	if !strings.Contains(string(raw), "new.example") {
		t.Errorf("store file does not carry the committed host: %s", raw)
	}

	reloaded := &Store{}
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rc := reloaded.Get(); rc.ProxyHost != got.ProxyHost || rc.ProxyPort != got.ProxyPort {
		t.Errorf("reloaded config = %+v, want %+v: serving and durable views disagree", rc, got)
	}
}

// TestChaos77_ModTimeNeverGoesBackwardsAcrossACommit covers the clock-rollback
// arm. modTime is stamped from the wall clock and is the Last-Modified source
// for /proxy.pac. pacNotModified honours If-Modified-Since for the
// WinHTTP/WinINET PAC clients that send no If-None-Match, so a modTime that
// moves BACKWARDS (an NTP step correction, a VM snapshot restore, a chrony
// makestep at boot) makes a genuinely changed PAC revalidate to 304: the
// client keeps executing the superseded PAC until the wall clock passes the
// stamp it already cached.
//
// A stored stamp that is ahead of time.Now() is exactly the state a rollback
// produces, so the gate restores one and requires the next commit to still
// advance the HTTP-visible (whole-second) stamp.
func TestChaos77_ModTimeNeverGoesBackwardsAcrossACommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pac_config.json")
	s := &Store{}
	stamped := time.Now().Add(90 * time.Minute) // clock has since stepped back
	s.Restore(State{Cfg: Config{ProxyHost: "old.example", ProxyPort: 8080}, Path: path, ModTime: stamped})

	if err := s.Set(Config{ProxyHost: "new.example", ProxyPort: 8080}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got := s.ModTime()
	if !got.After(stamped) {
		t.Errorf("modTime = %v after a commit, want strictly after the previously served stamp %v: a changed PAC that revalidates to 304 leaves the fleet on the superseded artifact",
			got, stamped)
	}
	// HTTP dates carry whole seconds, and pacNotModified truncates to a
	// second, so the advance has to survive truncation to be observable.
	if !got.Truncate(time.Second).After(stamped.Truncate(time.Second)) {
		t.Errorf("modTime second-granularity = %v, want strictly after %v: Last-Modified is sent truncated to the second",
			got.Truncate(time.Second), stamped.Truncate(time.Second))
	}

	// And it must keep advancing for every subsequent commit in the window.
	prev := got
	for i := 0; i < 3; i++ {
		if err := s.Set(Config{ProxyHost: "newer.example", ProxyPort: 8080 + i}); err != nil {
			t.Fatalf("Set %d: %v", i, err)
		}
		cur := s.ModTime()
		if !cur.Truncate(time.Second).After(prev.Truncate(time.Second)) {
			t.Fatalf("commit %d: modTime %v did not advance past %v", i, cur, prev)
		}
		prev = cur
	}
}

// TestChaos77_FailedWriteDoesNotStampModTimeForwardEither pins the other
// direction of the stamp rule: the monotonic bump must not fire on a write
// that never landed, or a failed save would invalidate every client's cached
// PAC (and the ArtifactCache) for a change that does not exist.
func TestChaos77_FailedWriteDoesNotStampModTimeForwardEither(t *testing.T) {
	s := &Store{}
	stamped := time.Now()
	s.Restore(State{Cfg: Config{ProxyHost: "old.example", ProxyPort: 8080}, Path: unwritableStorePath(t), ModTime: stamped})

	if err := s.Set(Config{ProxyHost: "new.example", ProxyPort: 8080}); err == nil {
		t.Fatal("Set on an unwritable path returned nil")
	}
	if !s.ModTime().Equal(stamped) {
		t.Errorf("modTime = %v after a failed write, want the unchanged %v", s.ModTime(), stamped)
	}
}

// TestChaos77_AnAdvancedStampIsNeverAReusedArtifactCacheKey pins the property
// the stamp rule must not cost us. ArtifactCache memoizes compiled artifacts
// keyed on Store.ModTime by EQUALITY (cache.go), so the stamp doubles as a
// cache key and has to stay unique per committed content. An advance derived
// purely from the previous stamp is reproducible: two commits made from the
// same previous stamp inside one wall-clock second mint the SAME key, and the
// cache then answers the second commit with the first one's artifact — a
// stale PAC served from a healthy store. This is a real regression that the
// first cut of the fix introduced and that `TestConfigRollback_JunkPACEntries
// StillApply` caught, so it is gated here rather than trusted to review.
func TestChaos77_AnAdvancedStampIsNeverAReusedArtifactCacheKey(t *testing.T) {
	cache := &ArtifactCache{} // one cache, as the process has one
	dir := t.TempDir()
	// The state both commits start from: the stamp rewind that makes the
	// advance collide (a restore, a reload, a backwards clock step).
	base := time.Now().Add(42 * time.Minute)

	serve := func(host string) string {
		s := &Store{}
		s.Restore(State{
			Cfg:     Config{ProxyHost: "placeholder.example", ProxyPort: 8080},
			Path:    filepath.Join(dir, "pac_config.json"),
			ModTime: base,
		})
		if err := s.Set(Config{ProxyHost: host, ProxyPort: 8080}); err != nil {
			t.Fatalf("Set %s: %v", host, err)
		}
		// An explicit ProxyHost keeps the artifact out of host-fallback mode,
		// which is deliberately never cached.
		return cache.Legacy(s, "ignored.example:9090").JS
	}

	first := serve("first.corp.example")
	if !strings.Contains(first, "first.corp.example") {
		t.Fatalf("precondition: first artifact does not name its proxy: %s", first)
	}
	second := serve("second.corp.example")
	if strings.Contains(second, "first.corp.example") || !strings.Contains(second, "second.corp.example") {
		t.Errorf("the artifact cache answered the second commit with the first one's artifact: the advanced stamp was reproducible and collided as a cache key")
	}
}
