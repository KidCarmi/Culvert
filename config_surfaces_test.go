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
	"go/ast"
	"go/parser"
	"go/token"
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
	if rv.Kind() != reflect.Slice {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(b)
	}
	parts := make([]string, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		parts = append(parts, csrCanonElem(t, rv.Index(i).Interface(), stripID))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// csrCanonElem marshals one slice element, optionally dropping the "id" key.
func csrCanonElem(t *testing.T, v any, stripID bool) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal slice elem: %v", err)
	}
	if !stripID {
		return string(b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal slice elem: %v", err)
	}
	delete(m, "id")
	if b, err = json.Marshal(m); err != nil {
		t.Fatalf("re-marshal slice elem: %v", err)
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

// ─── 7. Snapshot capture parity (DEBT-006 PR-1) ───────────────────────
//
// Every ConfigSnapshot field must be ASSIGNED a value on the CP-side capture
// path, or a Data Plane silently receives that field's zero value for a
// setting the operator configured — the "captured-but-forgotten" drift the
// four-way DTO can hide (the field is in the struct + registered, so
// ReflectionParity passes, yet nothing puts a value on the wire).
//
// The capture "family" is CurrentConfigSnapshot (the bulk) PLUS
// ConfigStore.Update, which stamps Version + UpdatedAt AFTER capture
// (controlplane_snapshot.go). Both live in that one file, so the scan parses
// it and counts every write to a ConfigSnapshot-typed value. This is robust
// to a future gocognit split of CurrentConfigSnapshot: split helpers still
// assign `snap.Field` on a ConfigSnapshot(-pointer) named `snap`. See the
// DEBT-006 plan, Layer B.
func TestConfigSurfaces_SnapshotCaptureParity(t *testing.T) {
	captured := snapshotCapturedFields(t)
	st := reflect.TypeOf(ConfigSnapshot{})
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if !f.IsExported() {
			continue
		}
		if !captured[f.Name] {
			t.Errorf("ConfigSnapshot.%s is never assigned on the capture path "+
				"(CurrentConfigSnapshot / ConfigStore.Update in controlplane_snapshot.go): "+
				"a DP would receive its zero value. Wire the capture — or, if it is stamped "+
				"in a new function, extend the capture scan in snapshotCapturedFields.", f.Name)
		}
	}
}

// snapshotCapturedFields returns the set of ConfigSnapshot field names
// assigned anywhere in controlplane_snapshot.go, counting ONLY writes to a
// ConfigSnapshot-typed value:
//
//   - composite-literal keys in a `ConfigSnapshot{…}` literal, type-scoped so a
//     same-named key in an unrelated literal (e.g. FileExtProfile{}) is ignored;
//   - selector assignments `snap.Field = …` / `s.snap.Field = …` — the two
//     ConfigSnapshot value spellings in this file (the `snap` local/param and
//     the ConfigStore.snap field). Whole-struct writes like `s.snap = snap`
//     do not match (their LHS field is "snap", never a ConfigSnapshot field).
func snapshotCapturedFields(t *testing.T) map[string]bool {
	t.Helper()
	const file = "controlplane_snapshot.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	captured := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			id, ok := node.Type.(*ast.Ident)
			if !ok || id.Name != "ConfigSnapshot" {
				return true
			}
			for _, el := range node.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						captured[key.Name] = true
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && snapshotSelectorBase(sel.X) {
					captured[sel.Sel.Name] = true
				}
			}
		}
		return true
	})
	return captured
}

// snapshotSelectorBase reports whether expr denotes the ConfigSnapshot value
// in controlplane_snapshot.go: the ident `snap` (CurrentConfigSnapshot local,
// Update param, and any future capture-helper *ConfigSnapshot param
// conventionally named snap) or the selector `s.snap` (the ConfigStore.snap
// field).
func snapshotSelectorBase(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "snap"
	case *ast.SelectorExpr:
		return e.Sel.Name == "snap"
	}
	return false
}

// ─── 8. Snapshot apply parity (DEBT-006 PR-2) ─────────────────────────
//
// Every ConfigSnapshot field the Data Plane is supposed to CONSUME must be
// read in the apply family, or the DP silently ignores a setting the CP
// synced (it diverges with no error). "Supposed to consume" = the binding
// declares empty-value apply semantics (Apply != semNA) OR carries the
// AppliesOnDP marker. The marker exists so a field the DP acts on via a
// non-config side-effect — today only Epoch, the ADR-0005 fence ratchet read
// by dpObserveEpoch — is apply-verified even though it is kindMeta with no
// empty-value semantics. Keying on this (not on kindConfig) is deliberate:
// mislabeling a fence/rotation field kindMeta must NOT exempt it. See the
// DEBT-006 plan, Layer C.
func TestConfigSurfaces_SnapshotApplyParity(t *testing.T) {
	consumed := snapshotConsumedFields(t)
	checked := 0
	for _, row := range configSurfaces {
		for _, b := range row.Bindings {
			if b.Struct != "ConfigSnapshot" || (b.Apply == semNA && !b.AppliesOnDP) {
				continue
			}
			checked++
			if !consumed[b.Field] {
				t.Errorf("ConfigSnapshot.%s (row %q) declares a DP apply "+
					"(Apply=%d AppliesOnDP=%v) but is never read in the apply family "+
					"(%s) — the DP would silently ignore this synced setting. Wire the "+
					"apply, or if it moved to a new function extend snapshotApplyFuncs.",
					b.Field, row.ID, b.Apply, b.AppliesOnDP, snapshotApplyFuncNames())
			}
		}
	}
	if checked == 0 {
		t.Fatal("apply parity checked zero ConfigSnapshot bindings — registry wiring changed?")
	}
}

// snapshotApplyFuncs is the DP-side apply family: functions that CONSUME a
// received ConfigSnapshot. None of them WRITE snap.Field (verified), so every
// `snap.Field` selector inside them is a read = a consumed field. Enumerated
// here so the scan survives further gocognit splits (add the new function).
var snapshotApplyFuncs = map[string]bool{
	"applyConfigSnapshot":               true, // controlplane_snapshot.go
	"applySnapshotPolicyAndTraffic":     true,
	"applySnapshotClusterRuntime":       true,
	"applySnapshotSessionSecret":        true,
	"applySnapshotExtendedState":        true,
	"applyExternalAuthSnapshotSettings": true,
	"syncSnapshotIdPProfiles":           true,
	"fetchAndApply":                     true, // controlplane_client.go (DP poller)
}

func snapshotApplyFuncNames() string {
	names := make([]string, 0, len(snapshotApplyFuncs))
	for n := range snapshotApplyFuncs {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// snapshotConsumedFields returns the ConfigSnapshot field names read anywhere
// in the apply family (snap.Field selectors inside snapshotApplyFuncs bodies,
// across controlplane_snapshot.go + controlplane_client.go).
func snapshotConsumedFields(t *testing.T) map[string]bool {
	t.Helper()
	consumed := map[string]bool{}
	for _, file := range []string{"controlplane_snapshot.go", "controlplane_client.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !snapshotApplyFuncs[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "snap" {
						consumed[sel.Sel.Name] = true
					}
				}
				return true
			})
		}
	}
	return consumed
}

// ─── 9. Snapshot redaction parity (DEBT-006 PR-2, Layer D) ────────────
//
// The ConfigSnapshot DTO carries secrets (SessionHMAC, IdP client secrets) BY
// DESIGN. GetConfig zeroes them for non-enrolled callers
// (controlplane_server.go, the `if !callerIsEnrolledNode` block). Deleting
// that block would leak the session HMAC + OIDC secrets to any unenrolled TLS
// peer with NO other test firing — the highest-severity uncovered drift on
// this surface. Assert every Sensitive ConfigSnapshot binding is zeroed there.
func TestConfigSurfaces_SnapshotRedaction(t *testing.T) {
	redacted := snapshotRedactedFields(t)
	checked := 0
	for _, row := range configSurfaces {
		if !row.Sensitive {
			continue
		}
		for _, b := range row.Bindings {
			if b.Struct != "ConfigSnapshot" {
				continue
			}
			checked++
			if !redacted[b.Field] {
				t.Errorf("ConfigSnapshot.%s (Sensitive row %q) is synced CP→DP but is NOT "+
					"zeroed in the GetConfig redaction block (controlplane_server.go, "+
					"!callerIsEnrolledNode) — an unenrolled TLS peer could read this secret. "+
					"Add it to the redaction block.", b.Field, row.ID)
			}
		}
	}
	if checked == 0 {
		t.Fatal("redaction parity checked zero Sensitive ConfigSnapshot bindings — registry changed?")
	}
}

// ─── 10. Snapshot wire-wipe semantics (DEBT-006 PR-3) ─────────────────
//
// A ConfigSnapshot slice with semNilSkipEmptyWipe apply semantics has a real
// nil-vs-[] branch on the DP (nil → keep live state; [] → wipe). But Go's
// `omitempty` DROPS a non-nil EMPTY slice on the wire, so for any such field
// carrying `omitempty` the []-wipe is unreachable over JSON — an operator
// clearing the last entry sends [], it is omitted, the DP reads nil and SKIPS
// (keeps stale state). Only a field WITHOUT `omitempty` actually propagates
// the wipe.
//
// This is the RateLimitExempt bug class. The test pins BOTH postures so the
// tags cannot silently drift from intent:
//   - WireWipeCapable row  → its ConfigSnapshot field MUST omit `omitempty`
//     (clearing propagates). Adding omitempty to rate_limit_exempt — silently
//     breaking DP exemption clears — fails here.
//   - other semNilSkipEmptyWipe → MUST keep `omitempty` (the []-wipe is
//     intentionally wire-dead). Removing it is a deliberate wire-shape change
//     that must be accompanied by declaring the row WireWipeCapable.
//
// See the DEBT-006 plan, §4 (the corrected empty-semantics check).
func TestConfigSurfaces_SnapshotWireWipe(t *testing.T) {
	snapType := csrStructTypes()["ConfigSnapshot"]
	checked := 0
	for i := range configSurfaces {
		row := &configSurfaces[i]
		for _, b := range row.Bindings {
			if b.Struct != "ConfigSnapshot" || b.Apply != semNilSkipEmptyWipe {
				continue
			}
			checked++
			f, ok := snapType.FieldByName(b.Field)
			if !ok {
				t.Errorf("row %q binds ConfigSnapshot.%s which does not exist", row.ID, b.Field)
				continue
			}
			hasOmitempty := strings.Contains(f.Tag.Get("json"), ",omitempty")
			switch {
			case row.WireWipeCapable && hasOmitempty:
				t.Errorf("ConfigSnapshot.%s (row %q) is WireWipeCapable but its json tag has "+
					"`omitempty`: an empty slice is dropped on the wire, so clearing the last "+
					"entry never wipes the DP copy. Remove omitempty.", b.Field, row.ID)
			case !row.WireWipeCapable && !hasOmitempty:
				t.Errorf("ConfigSnapshot.%s (row %q) is semNilSkipEmptyWipe WITHOUT omitempty, "+
					"so an empty slice serializes as [] and the DP applies a wipe — but the row "+
					"is not marked WireWipeCapable. Either set WireWipeCapable (declare the wipe "+
					"intentional) or restore omitempty.", b.Field, row.ID)
			}
		}
	}
	if checked == 0 {
		t.Fatal("wire-wipe parity checked zero semNilSkipEmptyWipe ConfigSnapshot bindings — registry changed?")
	}
}

// snapshotRedactedFields returns the ConfigSnapshot field names zeroed inside
// the `if !callerIsEnrolledNode(…) { … }` block of controlplane_server.go
// (snap.Field = "" / nil assignments).
func snapshotRedactedFields(t *testing.T) map[string]bool {
	t.Helper()
	const file = "controlplane_server.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	redacted := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ifst, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		un, ok := ifst.Cond.(*ast.UnaryExpr)
		if !ok || un.Op != token.NOT {
			return true
		}
		call, ok := un.X.(*ast.CallExpr)
		if !ok {
			return true
		}
		if fnid, ok := call.Fun.(*ast.Ident); !ok || fnid.Name != "callerIsEnrolledNode" {
			return true
		}
		ast.Inspect(ifst.Body, func(m ast.Node) bool {
			if as, ok := m.(*ast.AssignStmt); ok {
				for _, lhs := range as.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "snap" {
							redacted[sel.Sel.Name] = true
						}
					}
				}
			}
			return true
		})
		return true
	})
	return redacted
}
