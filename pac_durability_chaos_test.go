package main

// pac_durability_chaos_test.go — CHAOS-77 root gates: the consequences, at the
// boundaries main owns, of a legacy PAC write that does not land.
//
// internal/pac owns the persist-before-swap commit point (gated in
// internal/pac/store_durability_chaos_test.go). These are the cross-domain
// integration gates for what main does with it: the unauthenticated artifact
// the client fleet fetches, the audit trail, and the Data Plane's snapshot
// apply, whose three sibling PAC callers discard or merely log the error.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// chaos77UnwritablePath returns a path whose PARENT is a regular file, so
// every write beneath it fails with ENOTDIR for every uid — the suite can run
// as root, and root bypasses mode bits.
func chaos77UnwritablePath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	return filepath.Join(blocker, "pac_config.json")
}

// chaos77PinPACStore points the process-wide PAC store at cfg on an
// unwritable path and restores the previous state afterwards, so the suite
// stays hermetic under -shuffle. It also swaps in a fresh ArtifactCache:
// the cache is process-wide and keyed on Store.ModTime by equality, so a
// restored store must not be able to collide with an artifact some other
// test compiled — and these gates assert on what is actually SERVED, which
// has to be a fresh compile of the store rather than a neighbour's memo.
func chaos77PinPACStore(t *testing.T, cfg PACConfig) {
	t.Helper()
	chaos77FreshArtifactCache(t)
	prev := pacStore.Snapshot()
	t.Cleanup(func() { pacStore.Restore(prev) })
	pacStore.Restore(pac.State{
		Cfg:         cfg,
		Path:        chaos77UnwritablePath(t),
		DefaultPort: prev.DefaultPort,
		ModTime:     time.Now(),
	})
}

// chaos77FreshArtifactCache isolates this test from the process-wide
// compiled-artifact memo and restores it afterwards.
func chaos77FreshArtifactCache(t *testing.T) {
	t.Helper()
	prev := pacArtifactCache
	t.Cleanup(func() { pacArtifactCache = prev })
	pacArtifactCache = &pac.ArtifactCache{}
}

// servedPAC fetches /proxy.pac the way a client fleet member does —
// unauthenticated, no cache validators — and returns the artifact body.
func servedPAC(t *testing.T) string {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/proxy.pac", http.NoBody)
	req.Host = "gateway.corp.example:8080"
	rec := httptest.NewRecorder()
	servePACFile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /proxy.pac: got %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestChaos77_FailedPACSaveIsNotServedToTheFleet is the headline gate. An
// admin POST whose durable write cannot land must fail CLOSED: the operator
// gets the 500, and every PAC client keeps executing the configuration that
// is actually persisted. Before the fix the handler returned 500 while the
// unpersisted config was already live on /proxy.pac — and reverted on the
// next restart, with no audit record and no config version to explain it.
func TestChaos77_FailedPACSaveIsNotServedToTheFleet(t *testing.T) {
	const (
		goodHost = "proxy.corp.example"
		badHost  = "chaos77-never-persisted.example"
	)
	chaos77PinPACStore(t, PACConfig{ProxyHost: goodHost, ProxyPort: 8080})

	before := servedPAC(t)
	if !strings.Contains(before, goodHost) {
		t.Fatalf("precondition: served PAC does not name %q: %s", goodHost, before)
	}
	revBefore := pacStore.Get().Revision

	body, err := json.Marshal(PACConfig{ProxyHost: badHost, ProxyPort: 3128, Revision: revBefore})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/pac-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.77:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiPACConfig(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST with an unwritable store: got %d, want 500 (body=%s)", rec.Code, rec.Body.String())
	}

	// The fleet-visible artifact is the contract that matters.
	after := servedPAC(t)
	if strings.Contains(after, badHost) {
		t.Errorf("/proxy.pac names %q after a save the operator was told failed: the whole client fleet was repointed to an upstream that was never persisted and reverts on restart", badHost)
	}
	if !strings.Contains(after, goodHost) {
		t.Errorf("/proxy.pac no longer names the persisted proxy %q: %s", goodHost, after)
	}
	if got := pacStore.Get().ProxyHost; got != goodHost {
		t.Errorf("store ProxyHost = %q after a failed save, want %q", got, goodHost)
	}
	if got := pacStore.Get().Revision; got != revBefore {
		t.Errorf("revision advanced to %d on a failed save (was %d): a retry with the token the client still holds would be refused 409 for a mutation that never happened",
			got, revBefore)
	}

	// A change that never committed must leave no audit record claiming it
	// did. Asserted on unique entry content, never a ring length delta (the
	// audit ring is bounded and shuffled runs saturate it).
	// Index-based: AuditEntry is 136 bytes, over gocritic rangeValCopy's
	// threshold, and conventions.md asks for index-based range over a copy.
	entries := auditGet()
	for i := range entries {
		if strings.Contains(entries[i].Detail, badHost) || strings.Contains(entries[i].After, badHost) {
			t.Errorf("audit entry claims a PAC change that never committed: action=%q detail=%q",
				entries[i].Action, entries[i].Detail)
		}
	}
}

// TestChaos77_SnapshotApplyDefersAnUnpersistablePAC covers the Data Plane
// caller. applyConfigSnapshot logs this slice's error and continues — the
// deliberate per-slice degradation policy it shares with SSL bypass, URL
// categories and DPI patterns, and which the adjacent PAC *profiles* slice
// implements by DEFERRING ("PAC profiles not applied this sync (deferred)").
//
// fetchAndApply then persists last-good, marks the apply healthy and ratchets
// lastVersion, so the CP's "unchanged" reply suppresses every later poll. With
// a swap-before-persist Set the DP therefore converged onto exclusions that
// existed only in RAM, reported green, and silently reverted on restart with
// no further snapshot able to correct it. The slice must defer, like its
// neighbour, so memory and disk cannot disagree.
//
// The gate drives applySnapshotClusterRuntime, the slice group that holds the
// PAC-exclusions apply, rather than the whole applyConfigSnapshot. The full
// apply also replaces the shared blocklist, the admission owners and the
// external-auth settings for every slice this snapshot leaves empty, which a
// test would then have to restore one global at a time; this group touches
// nothing but the PAC stores for a snapshot carrying only PACExclusions.
func TestChaos77_SnapshotApplyDefersAnUnpersistablePAC(t *testing.T) {
	const keep = "persisted.corp.example"
	chaos77PinPACStore(t, PACConfig{ProxyHost: "dp.corp.example", ProxyPort: 8080, Exclusions: []string{keep}})

	applySnapshotClusterRuntime(ConfigSnapshot{
		Version:       1,
		PACExclusions: []string{"chaos77-ram-only.example"},
	})

	got := pacStore.Get().Exclusions
	if len(got) != 1 || got[0] != keep {
		t.Errorf("DP exclusions = %v after a snapshot whose PAC write could not land, want [%s]: the node converged onto a list that exists only in RAM, reports a healthy apply, ratchets lastVersion, and reverts on restart with no later snapshot able to correct it",
			got, keep)
	}
}

// TestChaos77_HealthySnapshotApplyStillAppliesPAC is the negative control for
// the gate above: the deferral must come from the write failing, not from the
// PAC slice having been disconnected.
func TestChaos77_HealthySnapshotApplyStillAppliesPAC(t *testing.T) {
	prev := pacStore.Snapshot()
	t.Cleanup(func() { pacStore.Restore(prev) })
	pacStore.Restore(pac.State{
		Cfg:  PACConfig{ProxyHost: "dp.corp.example", ProxyPort: 8080, Exclusions: []string{"old.example"}},
		Path: filepath.Join(t.TempDir(), "pac_config.json"),
	})

	applySnapshotClusterRuntime(ConfigSnapshot{
		Version:       2,
		PACExclusions: []string{"fresh.example"},
	})

	got := pacStore.Get().Exclusions
	if len(got) != 1 || got[0] != "fresh.example" {
		t.Fatalf("DP exclusions = %v after a healthy snapshot apply, want [fresh.example]", got)
	}
}

// TestChaos77_ClockRollbackCannotHoldTheFleetOnASupersededPAC ties the store's
// stamp rule to the HTTP behaviour it exists for. pacNotModified honours
// If-Modified-Since for PAC clients that send no If-None-Match (WinHTTP /
// WinINET, which is most of a Windows fleet). A modTime that does not advance
// past the stamp such a client already cached answers 304 for a PAC that
// genuinely changed, leaving it on the superseded artifact.
//
// Two causes, one gate: a wall clock that stepped backwards (the stamp on
// record is ahead of time.Now()), and two commits inside one wall-clock
// second, which an HTTP date cannot tell apart.
func TestChaos77_ClockRollbackCannotHoldTheFleetOnASupersededPAC(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ahead bool // stamp on record is ahead of the wall clock (clock stepped back)
	}{
		{name: "clock stepped backwards", ahead: true},
		{name: "two commits in one second", ahead: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chaos77FreshArtifactCache(t)
			prev := pacStore.Snapshot()
			t.Cleanup(func() { pacStore.Restore(prev) })
			st := pac.State{
				Cfg:  PACConfig{ProxyHost: "old.corp.example", ProxyPort: 8080},
				Path: filepath.Join(t.TempDir(), "pac_config.json"),
			}
			if tc.ahead {
				st.ModTime = time.Now().Add(90 * time.Minute)
			}
			pacStore.Restore(st)
			if !tc.ahead {
				// Establish a stamp from the wall clock, then change again
				// immediately: both commits land in the same second.
				if err := pacStore.Set(PACConfig{ProxyHost: "mid.corp.example", ProxyPort: 8080}); err != nil {
					t.Fatalf("seed commit: %v", err)
				}
			}

			// What the client cached: the stamp currently on record.
			cached := pacStore.ModTime()

			if err := pacStore.Set(PACConfig{ProxyHost: "new.corp.example", ProxyPort: 8080}); err != nil {
				t.Fatalf("commit: %v", err)
			}

			// That client revalidates with If-Modified-Since only.
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/proxy.pac", http.NoBody)
			req.Host = "gateway.corp.example:8080"
			req.Header.Set("If-Modified-Since", cached.UTC().Format(http.TimeFormat))
			rec := httptest.NewRecorder()
			servePACFile(rec, req)

			if rec.Code == http.StatusNotModified {
				t.Fatalf("GET /proxy.pac revalidated to 304 after the PAC changed (cached stamp %v, current %v): an If-Modified-Since client stays on the superseded artifact",
					cached.UTC().Format(http.TimeFormat), pacStore.ModTime().UTC().Format(http.TimeFormat))
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /proxy.pac: got %d, want 200", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, "new.corp.example") {
				t.Errorf("served PAC does not name the committed proxy: %s", body)
			}

			// Negative control: an UNCHANGED artifact must still revalidate
			// to 304, or the fix would have simply disabled PAC caching.
			req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/proxy.pac", http.NoBody)
			req2.Host = "gateway.corp.example:8080"
			req2.Header.Set("If-Modified-Since", pacStore.ModTime().UTC().Format(http.TimeFormat))
			rec2 := httptest.NewRecorder()
			servePACFile(rec2, req2)
			if rec2.Code != http.StatusNotModified {
				t.Errorf("unchanged PAC: got %d, want 304 — revalidation must still be free", rec2.Code)
			}
		})
	}
}
