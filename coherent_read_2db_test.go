package main

// coherent_read_2db_test.go — 2D-B final coherency correction (§1–§3).
//
// Every fenced list read must pair the returned rows with the revision (or
// fence version) that describes EXACTLY those rows. Assembling the response
// from independent store reads (All() then ContentFingerprint(); List() then
// Names() then Version(); a captured durable value then a fresh holder
// re-read) lets a writer land between the reads, handing a client superseded
// rows with the successor's fence token — its next edit then PASSES the
// optimistic fence against content it never saw.
//
// The expected fingerprint of a returned row set is computed through the
// ENGINE's own implementation (a scratch store over exactly the returned
// rows) — a server-side pure seam, never re-derived client logic (§3).
//
// Each proof drives a continuous mutator (channels for lifecycle — no
// sleeps) against the REAL handler and asserts that every observed response
// is internally consistent: old rows + old token or new rows + new token,
// never a mixed pair.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// fingerprintOfRows computes the semantic ContentFingerprint of an arbitrary
// row set via a scratch engine store holding exactly those rows — the
// server-owned identity function applied to the response body.
func fingerprintOfRows(rows []CategoryEntry) string {
	ptrs := make([]*urlcat.Entry, len(rows))
	for i := range rows {
		cp := rows[i]
		ptrs[i] = &cp
	}
	return urlcat.New(ptrs).ContentFingerprint()
}

// urlcatCoherencyState builds one of the two distinguishable taxonomy states
// the flip mutator alternates between. The states are large enough that the
// handler's read work and the mutator's install work genuinely interleave.
func urlcatCoherencyState(tag string) []CategoryEntry {
	out := make([]CategoryEntry, 30)
	for i := range out {
		hosts := make([]string, 60)
		for j := range hosts {
			hosts[j] = fmt.Sprintf("h%d-%d.%s.example", i, j, tag)
		}
		out[i] = CategoryEntry{Name: fmt.Sprintf("cat-%02d", i), Hosts: hosts}
	}
	return out
}

// TestCoherentRead_URLCatStateRevisionDescribesReturnedRows is the §22-A
// red-before proof: under a concurrent taxonomy writer, GET /api/urlcat/state
// must never return rows from one state paired with the revision of another.
func TestCoherentRead_URLCatStateRevisionDescribesReturnedRows(t *testing.T) {
	urlcatAPISetup(t)

	stateA := urlcatCoherencyState("a")
	stateB := urlcatCoherencyState("b")
	catStore.ReplaceAll(stateA)

	fpA := fingerprintOfRows(stateA)
	fpB := fingerprintOfRows(stateB)
	if fpA == fpB {
		t.Fatal("test states must have distinct fingerprints")
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		useA := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			if useA {
				catStore.ReplaceAll(stateA)
			} else {
				catStore.ReplaceAll(stateB)
			}
			useA = !useA
		}
	}()
	defer func() { close(stop); <-done }()

	const reads = 400
	for i := 0; i < reads; i++ {
		w := httptest.NewRecorder()
		apiURLCatState(w, getReq("/api/urlcat/state"))
		if w.Code != 200 {
			t.Fatalf("read %d: status %d: %s", i, w.Code, w.Body.String())
		}
		var resp struct {
			Categories []CategoryEntry `json:"categories"`
			Revision   string          `json:"revision"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("read %d: decode: %v", i, err)
		}
		if got := fingerprintOfRows(resp.Categories); got != resp.Revision {
			t.Fatalf("read %d: TORN STATE READ: response revision %q does not describe the returned rows (their fingerprint is %q) — a client editing from this pair passes the fence against content it never saw", i, resp.Revision, got)
		}
	}
}

// parseGenerationName extracts n from a "gen-<n>" marker name in a row list;
// -1 if absent.
func parseGenerationName(names []string) int64 {
	for _, n := range names {
		var g int64
		if _, err := fmt.Sscanf(n, "gen-%d", &g); err == nil {
			return g
		}
	}
	return -1
}

// TestCoherentRead_CategoryGroupsListNamesVersionAgree is the §2/§22-A proof
// for the 2D-A Category Groups list contract (POST-2D-A COHERENT-READ
// CORRECTION DISCOVERED DURING 2D-B REVIEW): groups, names, and the fence
// version in one GET response must all describe the same store state. The
// mutator installs generation-tagged full states via ReplaceAll (one version
// bump per install), so the content generation readable from the rows and the
// version delta must never diverge in the dangerous direction: a version
// AHEAD of the returned rows is exactly the stale-rows + successor-token pair
// that lets an edit pass the ifVersion fence against content the client never
// saw. (The engine applies content before bumping the version, so a version
// LAGGING the content by the single in-flight install is a benign — and
// permitted — observation; it only makes a client's edit conflict spuriously.)
func TestCoherentRead_CategoryGroupsListNamesVersionAgree(t *testing.T) {
	orig := globalCategoryGroups
	globalCategoryGroups = catgroup.New()
	t.Cleanup(func() { globalCategoryGroups = orig })

	state := func(n int64) []CategoryGroup {
		return []CategoryGroup{
			{Name: "alpha", Categories: []string{"news"}},
			{Name: fmt.Sprintf("gen-%d", n), Categories: []string{"social"}},
		}
	}
	globalCategoryGroups.ReplaceAll(state(0))
	base := globalCategoryGroups.Version() // corresponds to generation 0

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var n int64
		for {
			select {
			case <-stop:
				return
			default:
			}
			n++
			globalCategoryGroups.ReplaceAll(state(n))
		}
	}()
	defer func() { close(stop); <-done }()

	const reads = 400
	for i := 0; i < reads; i++ {
		w := httptest.NewRecorder()
		apiCategoryGroups(w, getReq("/api/category-groups"))
		if w.Code != 200 {
			t.Fatalf("read %d: status %d: %s", i, w.Code, w.Body.String())
		}
		var resp struct {
			Groups []struct {
				Name string `json:"name"`
			} `json:"groups"`
			Names   []string `json:"names"`
			Version int64    `json:"version"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("read %d: decode: %v", i, err)
		}
		if len(resp.Groups) != len(resp.Names) {
			t.Fatalf("read %d: TORN LIST READ: %d groups but %d names", i, len(resp.Groups), len(resp.Names))
		}
		rowNames := make([]string, len(resp.Groups))
		for j, g := range resp.Groups {
			if g.Name != resp.Names[j] {
				t.Fatalf("read %d: TORN LIST READ: groups[%d]=%q but names[%d]=%q", i, j, g.Name, j, resp.Names[j])
			}
			rowNames[j] = g.Name
		}
		g := parseGenerationName(rowNames)
		if g < 0 {
			t.Fatalf("read %d: no generation marker in rows %v", i, rowNames)
		}
		delta := resp.Version - base
		if delta > g {
			t.Fatalf("read %d: TORN VERSION READ: version %d (base %d, delta %d) is AHEAD of the returned rows (generation %d) — stale rows paired with a successor fence token", i, resp.Version, base, delta, g)
		}
	}
}

// TestCoherentRead_DecryptionProfilesListNamesVersionAgree — the same §2
// proof for the Decryption Profiles list contract (same directional
// invariant: the fence version must never be AHEAD of the returned rows).
func TestCoherentRead_DecryptionProfilesListNamesVersionAgree(t *testing.T) {
	orig := globalDecryptionProfiles
	globalDecryptionProfiles = decryptprofile.New()
	t.Cleanup(func() { globalDecryptionProfiles = orig })

	state := func(n int64) []DecryptionProfile {
		return []DecryptionProfile{
			{Name: "alpha"},
			{Name: fmt.Sprintf("gen-%d", n)},
		}
	}
	globalDecryptionProfiles.ReplaceAll(state(0))
	base := globalDecryptionProfiles.Version() // corresponds to generation 0

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var n int64
		for {
			select {
			case <-stop:
				return
			default:
			}
			n++
			globalDecryptionProfiles.ReplaceAll(state(n))
		}
	}()
	defer func() { close(stop); <-done }()

	const reads = 400
	for i := 0; i < reads; i++ {
		w := httptest.NewRecorder()
		apiDecryptionProfiles(w, getReq("/api/decryption-profiles"))
		if w.Code != 200 {
			t.Fatalf("read %d: status %d: %s", i, w.Code, w.Body.String())
		}
		var resp struct {
			Profiles []struct {
				Name string `json:"name"`
			} `json:"profiles"`
			Names   []string `json:"names"`
			Version int64    `json:"version"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("read %d: decode: %v", i, err)
		}
		if len(resp.Profiles) != len(resp.Names) {
			t.Fatalf("read %d: TORN LIST READ: %d profiles but %d names", i, len(resp.Profiles), len(resp.Names))
		}
		rowNames := make([]string, len(resp.Profiles))
		for j, p := range resp.Profiles {
			if p.Name != resp.Names[j] {
				t.Fatalf("read %d: TORN LIST READ: profiles[%d]=%q but names[%d]=%q", i, j, p.Name, j, resp.Names[j])
			}
			rowNames[j] = p.Name
		}
		g := parseGenerationName(rowNames)
		if g < 0 {
			t.Fatalf("read %d: no generation marker in rows %v", i, rowNames)
		}
		delta := resp.Version - base
		if delta > g {
			t.Fatalf("read %d: TORN VERSION READ: version %d (base %d, delta %d) is AHEAD of the returned rows (generation %d) — stale rows paired with a successor fence token", i, resp.Version, base, delta, g)
		}
	}
}

// TestCoherentRead_SaaSSettingsViewResolvedFromCapturedState — the §2 settings
// truth proof: the raw fields, the revision, and the RESOLVED block of one
// settings view must all derive from the same captured durable value. The
// mutator flips only Enabled; a view whose resolved block was re-read from
// the holder can pair enabled=true raw fields with a resolved.enabled=false
// block (or vice versa).
func TestCoherentRead_SaaSSettingsViewResolvedFromCapturedState(t *testing.T) {
	orig := getSaaSFeedDurable()
	t.Cleanup(func() { setSaaSFeedDurable(orig) })

	dOn := saasFeedDurable{Managed: true, Enabled: true, SchemaVersion: saasStoreSchemaVersion}
	dOff := saasFeedDurable{Managed: true, Enabled: false, SchemaVersion: saasStoreSchemaVersion}
	setSaaSFeedDurable(dOn)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		on := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			if on {
				setSaaSFeedDurable(dOn)
			} else {
				setSaaSFeedDurable(dOff)
			}
			on = !on
		}
	}()
	defer func() { close(stop); <-done }()

	revOn := saasFeedSettingsRevision(dOn)
	revOff := saasFeedSettingsRevision(dOff)
	if revOn == revOff {
		t.Fatal("test states must have distinct settings revisions")
	}

	const reads = 2000
	for i := 0; i < reads; i++ {
		view := saasFeedSettingsView()
		rawEnabled, ok := view["enabled"].(bool)
		if !ok {
			t.Fatalf("read %d: enabled missing/not bool", i)
		}
		resolved, ok := view["resolved"].(map[string]any)
		if !ok {
			t.Fatalf("read %d: resolved block missing (resolve_error=%v)", i, view["resolve_error"])
		}
		resolvedEnabled, ok := resolved["enabled"].(bool)
		if !ok {
			t.Fatalf("read %d: resolved.enabled missing/not bool", i)
		}
		if rawEnabled != resolvedEnabled {
			t.Fatalf("read %d: TORN SETTINGS VIEW: raw enabled=%t but resolved.enabled=%t — the resolved block was derived from a different holder state than the captured fields", i, rawEnabled, resolvedEnabled)
		}
		// The revision must also describe the same captured state.
		rev, ok := view["revision"].(string)
		if !ok {
			t.Fatalf("read %d: revision missing", i)
		}
		if rawEnabled && rev != revOn {
			t.Fatalf("read %d: TORN SETTINGS VIEW: raw enabled=true but revision %q is not the enabled-state revision", i, rev)
		}
		if !rawEnabled && rev != revOff {
			t.Fatalf("read %d: TORN SETTINGS VIEW: raw enabled=false but revision %q is not the disabled-state revision", i, rev)
		}
	}
}
