package main

// config_surfaces_test.go — parity wall for the config-surface registry
// (config_surfaces.go). Mirrors the uiRoutes/C1 pattern: the registry is only
// trustworthy because these tests make it impossible for it to drift from the
// structs and functions it describes.
//
//  1. ReflectionParity      — every exported field of the three surface
//                             structs is claimed by exactly one registry
//                             binding, and every binding resolves to a real
//                             field (forward + reverse).
//  2. SnapshotCapParity     — every slice/map field synced in ConfigSnapshot
//                             carries a validateConfigSnapshot cap (H5).
//  3. SensitiveInvariants   — secret-bearing rows are never on the rollback
//                             surface and only exported through redacting
//                             accessors.
//  4. DiffNilGuardMirrorsApply — diffConfigs' nil-guards match
//                             applyConfigBackup's nil-skip semantics, both in
//                             the registry and behaviorally (the
//                             ContentScanBypassHosts drift bug class).
//  5. DiffCoverage          — every rollback+diffed row actually produces a
//                             diffConfigs entry for a visible change.
//  6. RollbackRoundTrip     — seed → capture → mutate → apply → capture
//                             across the FULL rollback surface at once; a
//                             field that is captured but not applied (the
//                             historical RateLimitExempt half-migration
//                             class) fails here.

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// csrStructTypes maps registry Struct names to their reflect types.
func csrStructTypes() map[string]reflect.Type {
	return map[string]reflect.Type{
		"configBackup":   reflect.TypeOf(configBackup{}),
		"AdminSettings":  reflect.TypeOf(AdminSettings{}),
		"ConfigSnapshot": reflect.TypeOf(ConfigSnapshot{}),
	}
}

// ─── 1. Reflection parity (forward + reverse) ─────────────────────────

func TestConfigSurfaces_ReflectionParity(t *testing.T) {
	types := csrStructTypes()
	claimed := map[string]map[string]int{} // struct → field → claim count
	for name := range types {
		claimed[name] = map[string]int{}
	}

	seenIDs := map[string]bool{}
	for i := range configSurfaces {
		row := &configSurfaces[i]
		if seenIDs[row.ID] {
			t.Errorf("registry: duplicate row ID %q", row.ID)
		}
		seenIDs[row.ID] = true
		if len(row.Bindings) == 0 {
			t.Errorf("registry row %q has no bindings", row.ID)
		}
		for _, b := range row.Bindings {
			st, ok := types[b.Struct]
			if !ok {
				t.Errorf("row %q binds unknown struct %q", row.ID, b.Struct)
				continue
			}
			if _, ok := st.FieldByName(b.Field); !ok {
				t.Errorf("row %q binds %s.%s which does not exist — stale registry", row.ID, b.Struct, b.Field)
				continue
			}
			claimed[b.Struct][b.Field]++
		}
	}

	// Forward: no field claimed twice. Reverse: no struct field unclaimed.
	for name, st := range types {
		for i := 0; i < st.NumField(); i++ {
			field := st.Field(i).Name
			switch n := claimed[name][field]; n {
			case 0:
				t.Errorf("%s.%s has NO config-surface registry entry — add a row to configSurfaces (config_surfaces.go) declaring its surfaces", name, field)
			case 1: // exactly one owner — correct
			default:
				t.Errorf("%s.%s is claimed by %d registry bindings; must be exactly 1", name, field, n)
			}
		}
	}
}

// ─── 2. Snapshot cap parity (H5) ──────────────────────────────────────

func TestConfigSurfaces_SnapshotCapParity(t *testing.T) {
	snapType := csrStructTypes()["ConfigSnapshot"]
	capped := 0
	for i := range configSurfaces {
		row := &configSurfaces[i]
		for _, b := range row.Bindings {
			if b.Struct != "ConfigSnapshot" {
				continue
			}
			f, _ := snapType.FieldByName(b.Field)
			k := f.Type.Kind()
			if k != reflect.Slice && k != reflect.Map {
				continue
			}
			if row.SnapshotCap <= 0 {
				t.Errorf("ConfigSnapshot.%s (row %q) is a %s with no SnapshotCap — every synced slice/map needs a validateConfigSnapshot bound or a CP can memory-DoS every DP (H5)", b.Field, row.ID, k)
			}
			capped++
		}
	}
	// validateConfigSnapshot (controlplane.go) enforces exactly this many
	// per-slice caps. If you add a capped field there, register it here (and
	// vice versa) — the two tables must move in lockstep.
	if capped != 19 {
		t.Errorf("registry declares %d capped ConfigSnapshot fields; validateConfigSnapshot enforces 19 — the tables drifted", capped)
	}
}

// ─── 3. Sensitive invariants ──────────────────────────────────────────

func TestConfigSurfaces_SensitiveInvariants(t *testing.T) {
	for i := range configSurfaces {
		row := &configSurfaces[i]
		if !row.Sensitive {
			continue
		}
		// Secret material must never land in /data/config_versions/ (up to 50
		// plaintext copies, and rollback can't round-trip redacted values).
		if row.Rollback {
			t.Errorf("row %q is Sensitive AND Rollback — secrets must stay off the config-version rollback surface (Finding 10.3)", row.ID)
		}
		// Export is allowed only through a redacting accessor.
		if row.Export {
			for _, b := range row.Bindings {
				if b.Struct == "configBackup" && !b.Redacted {
					t.Errorf("row %q is Sensitive and exported via configBackup.%s without a redacting accessor", row.ID, b.Field)
				}
			}
		}
		// Sensitive + ClusterSynced / AdminDurable is deliberately permitted
		// (SessionHMAC, IdPProfiles, MetricsToken, UpstreamProxies): those
		// layers have their own protections (enrollment redaction, 0600 file).
	}
}

// ─── 4. Diff nil-guards mirror apply nil-skips ────────────────────────

// csrNilGuardCases builds, per DiffNilGuarded row, a populated live snapshot
// and the value that constitutes an explicit wipe. The set of keys here must
// exactly match the registry's DiffNilGuarded rows so neither can drift.
func csrNilGuardCases() map[string]struct {
	populate func(*configBackup)
	wipe     func(*configBackup)
} {
	return map[string]struct {
		populate func(*configBackup)
		wipe     func(*configBackup)
	}{
		"rate_limit_exempt": {
			populate: func(c *configBackup) { c.RateLimitExempt = []string{"203.0.113.7"} },
			wipe:     func(c *configBackup) { c.RateLimitExempt = []string{} },
		},
		"category_groups": {
			populate: func(c *configBackup) {
				c.CategoryGroups = []CategoryGroup{{Name: "csr-g", Categories: []string{"csr-c"}}}
			},
			wipe: func(c *configBackup) { c.CategoryGroups = []CategoryGroup{} },
		},
		"url_categories": {
			populate: func(c *configBackup) {
				c.URLCategories = []CategoryEntry{{Name: "csr-c", Hosts: []string{"csr.example.com"}}}
			},
			wipe: func(c *configBackup) { c.URLCategories = []CategoryEntry{} },
		},
		"content_scan_bypass_hosts": {
			populate: func(c *configBackup) { c.ContentScanBypassHosts = []string{"csr-bypass.example.com"} },
			wipe:     func(c *configBackup) { c.ContentScanBypassHosts = []string{} },
		},
	}
}

func csrDiffHasField(changes []configChange, field string) bool {
	for i := range changes {
		if changes[i].Field == field {
			return true
		}
	}
	return false
}

func TestConfigSurfaces_DiffNilGuardMirrorsApply(t *testing.T) {
	cases := csrNilGuardCases()

	for i := range configSurfaces {
		row := &configSurfaces[i]
		// Registry self-consistency: DiffNilGuarded ⇔ (diffed rollback row
		// whose rollback apply is nil-skip). A diff that reports what apply
		// skips lies to the operator during dry-run rollback.
		var rollbackSem emptySemantics
		for _, b := range row.Bindings {
			if b.Struct == "configBackup" && row.Rollback {
				rollbackSem = b.Apply
			}
		}
		wantGuard := row.Rollback && row.Diffed && rollbackSem == semNilSkipEmptyWipe
		if row.DiffNilGuarded != wantGuard {
			t.Errorf("row %q: DiffNilGuarded=%v but rollback apply semantics say %v — diff and apply must agree on nil handling", row.ID, row.DiffNilGuarded, wantGuard)
		}
		if wantGuard {
			if _, ok := cases[row.ID]; !ok {
				t.Errorf("row %q is DiffNilGuarded but has no case in csrNilGuardCases — extend the test table", row.ID)
			}
		}
	}

	// Behavioral: nil target → diff silent; explicit empty → diff reports.
	for id, tc := range cases {
		live := &configBackup{}
		tc.populate(live)

		nilTarget := &configBackup{} // pre-extension snapshot shape: field nil
		row := csrRowByID(t, id)
		if got := diffConfigs(live, nilTarget); csrDiffHasField(got, row.DiffKey) {
			t.Errorf("%s: diffConfigs reports %q for a NIL target that apply would skip — dry-run rollback lies to the operator", id, row.DiffKey)
		}

		wipeTarget := &configBackup{}
		tc.wipe(wipeTarget)
		if got := diffConfigs(live, wipeTarget); !csrDiffHasField(got, row.DiffKey) {
			t.Errorf("%s: diffConfigs is silent for an explicit-[] wipe that apply WILL perform", id)
		}
	}
}

func csrRowByID(t *testing.T, id string) *configSurfaceRow {
	t.Helper()
	for i := range configSurfaces {
		if configSurfaces[i].ID == id {
			return &configSurfaces[i]
		}
	}
	t.Fatalf("registry row %q not found", id)
	return nil
}

// ─── 5. Diff coverage ─────────────────────────────────────────────────

// csrDiffMutators makes one differ-visible change per rollback+diffed row.
// Add/remove deltas are used (not in-place edits) because diffPolicyRules
// keys on Priority comparing Name only and diffRewriteRules keys on Host —
// in-place edits are invisible by design.
func csrDiffMutators() map[string]func(a, b *configBackup) {
	return map[string]func(a, b *configBackup){
		"blocklist_mode":        func(a, b *configBackup) { a.BlocklistMode = "block"; b.BlocklistMode = "allow" },
		"blocklist":             func(_, b *configBackup) { b.Blocklist = []string{"csr-d.example.com"} },
		"policy_rules":          func(_, b *configBackup) { b.PolicyRules = []PolicyRule{{Priority: 42, Name: "csr-diff"}} },
		"default_action":        func(a, b *configBackup) { a.DefaultAction = "deny"; b.DefaultAction = "allow" },
		"rewrite_rules":         func(_, b *configBackup) { b.RewriteRules = []RewriteRule{{Host: "csr-diff.example.com"}} },
		"ssl_bypass":            func(_, b *configBackup) { b.SSLBypass = []string{"*.csr-diff.example.com"} },
		"content_scan_patterns": func(_, b *configBackup) { b.ContentScanPatterns = []string{"csr-diff-pattern"} },
		"content_scan_bypass_hosts": func(a, b *configBackup) {
			a.ContentScanBypassHosts = []string{}
			b.ContentScanBypassHosts = []string{"csr-diff-bypass.example.com"}
		},
		"file_block_extensions": func(_, b *configBackup) { b.FileBlockExtensions = []string{".csrd"} },
		"ip_filter_mode":        func(a, b *configBackup) { a.IPFilterMode = "off"; b.IPFilterMode = "block" },
		"ip_list":               func(_, b *configBackup) { b.IPList = []string{"203.0.113.42"} },
		"rate_limit_rpm":        func(a, b *configBackup) { a.RateLimitRPM = 60; b.RateLimitRPM = 120 },
		"rate_limit_exempt": func(a, b *configBackup) {
			a.RateLimitExempt = []string{}
			b.RateLimitExempt = []string{"198.51.100.0/24"}
		},
		"pac_proxy_host": func(a, b *configBackup) { b.PACProxyHost = "csr-pac.example.com" },
		"pac_proxy_port": func(a, b *configBackup) { b.PACProxyPort = 3128 },
		"pac_exclusions": func(_, b *configBackup) { b.PACExclusions = []string{"*.csr-pac.local"} },
		"category_groups": func(a, b *configBackup) {
			a.CategoryGroups = []CategoryGroup{}
			b.CategoryGroups = []CategoryGroup{{Name: "csr-diff-g"}}
		},
		"url_categories": func(a, b *configBackup) {
			a.URLCategories = []CategoryEntry{}
			b.URLCategories = []CategoryEntry{{Name: "csr-diff-c"}}
		},
	}
}

func TestConfigSurfaces_DiffCoverage(t *testing.T) {
	mutators := csrDiffMutators()
	for i := range configSurfaces {
		row := &configSurfaces[i]
		if !row.Rollback || !row.Diffed {
			continue
		}
		mutate, ok := mutators[row.ID]
		if !ok {
			t.Errorf("row %q is Rollback+Diffed but csrDiffMutators has no case — extend the test table", row.ID)
			continue
		}
		a, b := &configBackup{}, &configBackup{}
		mutate(a, b)
		if got := diffConfigs(a, b); !csrDiffHasField(got, row.DiffKey) {
			t.Errorf("row %q: diffConfigs produced no %q entry for a visible change — field is on the rollback surface but invisible in dry-run", row.ID, row.DiffKey)
		}
	}
	// Reverse: no mutator for a row that isn't Rollback+Diffed (stale table).
	for id := range mutators {
		row := csrRowByID(t, id)
		if !row.Rollback || !row.Diffed {
			t.Errorf("csrDiffMutators has case %q but the registry row is not Rollback+Diffed — stale test table", id)
		}
	}
}

// ─── 6. Behavioral rollback round-trip across the FULL surface ────────

// csrIsolateRollbackStores snapshots and restores every global the rollback
// surface touches, reusing the per-suite helpers where they exist
// (snapshotRateLimiter, snapshotCatStore, snapshotGlobalCategoryGroups,
// snapshotDPIScanner, snapshotPolicyStoreForTest) and adding the missing ones.
func csrIsolateRollbackStores(t *testing.T) {
	t.Helper()

	snapshotRateLimiter(t)          // rl: RPM + exemptions
	snapshotCatStore(t)             // catStore → TempDir
	snapshotGlobalCategoryGroups(t) // globalCategoryGroups → TempDir
	snapshotDPIScanner(t)           // dpiScanner → TempDir
	snapshotPolicyStoreForTest(t)   // policyStore, path="" (no persistence)

	origBL := bl
	bl = blocklist.New() // empty path → Save() is a no-op
	t.Cleanup(func() { bl = origBL })

	origIPF := ipf
	ipf = &IPFilter{single: map[string]bool{}}
	t.Cleanup(func() { ipf = origIPF })

	origRewrite := rewriter.List()
	t.Cleanup(func() { rewriter.SetRules(origRewrite) })

	origSSL := sslBypass.List()
	t.Cleanup(func() { _ = sslBypass.Set(origSSL) })

	origExts := fileBlocker.List()
	t.Cleanup(func() {
		for _, e := range fileBlocker.List() {
			fileBlocker.Remove(e)
		}
		for _, e := range origExts {
			fileBlocker.Add(e)
		}
	})

	origPAC := pacStore.Get()
	t.Cleanup(func() { _ = pacStore.Set(origPAC) })

	origAction := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(origAction) })
}

// csrSeedStateA drives every rollback-surface store to a known state A.
// Values are chosen to survive the apply-path validators (validatePolicyRule
// needs Name; dpiScanner.Set needs valid regexes; ipf.Add needs a real IP).
func csrSeedStateA() {
	bl.SetMode("block")
	bl.Add("csr-a.example.com")
	setDefaultPolicyAction("deny")
	// Action must be a canonical PolicyAction constant — applyConfigBackup
	// re-validates every rule and SILENTLY DROPS invalid ones, so a sloppy
	// seed here would read as a round-trip failure.
	policyStore.ReplaceAll([]PolicyRule{{Priority: 100, Name: "csr-rt-rule", Action: ActionAllow}})
	rewriter.SetRules([]RewriteRule{{Host: "csr-rt.example.com", ReqSet: map[string]string{"X-CSR": "1"}}})
	_ = sslBypass.Set([]string{"*.csr-rt.example.com"})
	_ = dpiScanner.Set([]string{"csr-rt-pattern"})
	dpiScanner.SetBypassHosts([]string{"csr-rt-bypass.example.com"})
	for _, e := range fileBlocker.List() {
		fileBlocker.Remove(e)
	}
	fileBlocker.Add(".csrx")
	ipf.SetMode("allow")
	_ = ipf.Add("203.0.113.7")
	rl.Configure(77, time.Minute)
	rl.ReplaceExemptions([]string{"198.51.100.0/24"})
	_ = pacStore.Set(PACConfig{ProxyHost: "csr-proxy.example.com", ProxyPort: 3128, Exclusions: []string{"*.csr.local"}})
	catStore.ReplaceAll([]CategoryEntry{{Name: "csr-cat", Hosts: []string{"csr.example.com"}}})
	globalCategoryGroups.ReplaceAll([]CategoryGroup{{Name: "csr-group", Categories: []string{"csr-cat"}}})
}

// csrMutateStateB moves every store somewhere else, so an apply-miss for any
// field leaves a B value behind for the comparison to catch.
func csrMutateStateB() {
	bl.SetMode("allow")
	bl.Remove("csr-a.example.com")
	bl.Add("csr-b.example.com")
	setDefaultPolicyAction("allow")
	policyStore.ReplaceAll([]PolicyRule{{Priority: 200, Name: "csr-rt-rule-b", Action: ActionDrop}})
	rewriter.SetRules([]RewriteRule{})
	_ = sslBypass.Set([]string{})
	_ = dpiScanner.Set([]string{"csr-other-pattern"})
	dpiScanner.SetBypassHosts([]string{})
	for _, e := range fileBlocker.List() {
		fileBlocker.Remove(e)
	}
	fileBlocker.Add(".csry")
	ipf.SetMode("block")
	_ = ipf.Add("192.0.2.9")
	rl.Configure(55, time.Minute)
	rl.ReplaceExemptions([]string{"192.0.2.0/24"})
	_ = pacStore.Set(PACConfig{})
	catStore.ReplaceAll([]CategoryEntry{})
	globalCategoryGroups.ReplaceAll([]CategoryGroup{})
}

// csrCanon renders a captured field value order-insensitively for slices
// (store iteration order is not part of the contract) and via plain JSON
// otherwise. stripID drops the "id" key from slice elements — RewriteRule IDs
// are runtime handles reassigned by SetRules on every restore, not config
// identity (rewrite.Rule doc: "assigned automatically when the rule is added
// at runtime").
func csrCanon(t *testing.T, v any, stripID bool) string {
	t.Helper()
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice {
		parts := make([]string, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			b, err := json.Marshal(rv.Index(i).Interface())
			if err != nil {
				t.Fatalf("marshal slice elem: %v", err)
			}
			if stripID {
				var m map[string]any
				if err := json.Unmarshal(b, &m); err != nil {
					t.Fatalf("unmarshal slice elem: %v", err)
				}
				delete(m, "id")
				if b, err = json.Marshal(m); err != nil {
					t.Fatalf("re-marshal slice elem: %v", err)
				}
			}
			parts = append(parts, string(b))
		}
		sort.Strings(parts)
		return strings.Join(parts, "\n")
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestConfigSurfaces_RollbackRoundTrip(t *testing.T) {
	csrIsolateRollbackStores(t)

	csrSeedStateA()
	capA := captureConfigBackup()

	csrMutateStateB()
	applyConfigBackup(capA)
	capA2 := captureConfigBackup()

	// Registry-driven comparison: every rollback-surface field must survive
	// capture → apply → capture. A mismatch means the field is captured but
	// not (fully) applied — the exact half-migration class the registry
	// exists to prevent.
	va, va2 := reflect.ValueOf(*capA), reflect.ValueOf(*capA2)
	compared := 0
	for i := range configSurfaces {
		row := &configSurfaces[i]
		if !row.Rollback {
			continue
		}
		for _, bnd := range row.Bindings {
			if bnd.Struct != "configBackup" {
				continue
			}
			stripID := row.ID == "rewrite_rules"
			got := csrCanon(t, va2.FieldByName(bnd.Field).Interface(), stripID)
			want := csrCanon(t, va.FieldByName(bnd.Field).Interface(), stripID)
			if got != want {
				t.Errorf("round-trip mismatch on %s (row %q):\n  captured: %s\n  after rollback: %s\n  → applyConfigBackup does not restore what captureConfigBackup records", bnd.Field, row.ID, want, got)
			}
			compared++
		}
	}
	if compared == 0 {
		t.Fatal("round-trip compared zero fields — registry has no rollback bindings?")
	}
}
