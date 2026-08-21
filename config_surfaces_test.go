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

	"github.com/KidCarmi/Culvert/internal/pac"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"github.com/KidCarmi/Culvert/internal/catoverride"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
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

// snapshotCapCeiling bounds any single ConfigSnapshot per-slice cap. The
// current maximum is 2M (blocked_hosts/ip_list/url_categories, raised for
// enterprise-scale threat feeds); 4M gives headroom without letting a cap grow
// so large the H5 memory-DoS bound stops meaning anything (DEBT-006 residual:
// magnitude, not just existence). The CP↔DP frame is independently bounded by
// maxClusterGRPCMsgSize, so the transport cannot be abused even at cap.
const snapshotCapCeiling = 4_000_000

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
			// Magnitude, not just existence (DEBT-006 residual): a cap set to
			// MaxInt or an absurd value passes the existence check but leaves
			// the H5 DoS bound toothless. The current max is 2M
			// (maxSnapBlockedHosts/IPList/URLCategories); ceiling gives 2×
			// headroom while still bounding a single field well under a
			// pathological allocation. A field that legitimately needs more is
			// a design smell that should be reviewed, not silently capped huge.
			if row.SnapshotCap > snapshotCapCeiling {
				t.Errorf("ConfigSnapshot.%s (row %q) SnapshotCap=%d exceeds the sanity ceiling %d — a cap this large defeats the H5 memory-DoS bound; if this is intentional, raise snapshotCapCeiling with justification", b.Field, row.ID, row.SnapshotCap, snapshotCapCeiling)
			}
			capped++
		}
	}
	// validateConfigSnapshot (controlplane.go) enforces exactly this many
	// per-slice caps. If you add a capped field there, register it here (and
	// vice versa) — the two tables must move in lockstep.
	if capped != 22 {
		t.Errorf("registry declares %d capped ConfigSnapshot fields; validateConfigSnapshot enforces 22 — the tables drifted", capped)
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
		"decryption_profiles": {
			populate: func(c *configBackup) {
				c.DecryptionProfiles = []DecryptionProfile{{Name: "csr-dp", MinTLSVersion: "1.3", OnInspectError: "fail-open"}}
			},
			wipe: func(c *configBackup) { c.DecryptionProfiles = []DecryptionProfile{} },
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
		"pac_profiles": {
			populate: func(c *configBackup) {
				c.PACProfiles = []pac.Profile{{ID: "csr-prof", Name: "CSR", Enabled: true, PoolID: "csr-pool",
					PrivateNetworks: pac.PrivateDirect, AvailabilityMode: pac.ModeBalanced}}
			},
			wipe: func(c *configBackup) { c.PACProfiles = []pac.Profile{} },
		},
		"pac_pools": {
			populate: func(c *configBackup) {
				c.PACPools = []pac.Pool{{ID: "csr-pool", Name: "CSR", Endpoints: []pac.PoolEndpoint{{Host: "csr.example", Port: 8080}}}}
			},
			wipe: func(c *configBackup) { c.PACPools = []pac.Pool{} },
		},
		// category_overrides is a pointer-to-struct on the rollback surface with
		// nil-skip / non-nil-replace semantics: nil target ⇒ apply skips (no diff);
		// a non-nil (even empty) set ⇒ apply replaces (diff reports the clear).
		"category_overrides": {
			populate: func(c *configBackup) {
				c.CategoryOverrides = &CategoryOverrides{Added: map[string]string{"csr.example.com": "csr-cat"}}
			},
			wipe: func(c *configBackup) { c.CategoryOverrides = &CategoryOverrides{} },
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
		"decryption_profiles": func(a, b *configBackup) {
			// Same NAME, different OnInspectError — exercises sameDecryptionProfile's
			// per-field comparison (a rollback that flips only fail-open must diff).
			a.DecryptionProfiles = []DecryptionProfile{{Name: "csr-diff-dp", OnInspectError: "fail-close"}}
			b.DecryptionProfiles = []DecryptionProfile{{Name: "csr-diff-dp", OnInspectError: "fail-open"}}
		},
		"url_categories": func(a, b *configBackup) {
			a.URLCategories = []CategoryEntry{}
			b.URLCategories = []CategoryEntry{{Name: "csr-diff-c"}}
		},
		"pac_profiles": func(a, b *configBackup) {
			a.PACProfiles = []pac.Profile{}
			b.PACProfiles = []pac.Profile{{ID: "csr-diff-prof", Name: "CSR"}}
		},
		"pac_pools": func(a, b *configBackup) {
			a.PACPools = []pac.Pool{}
			b.PACPools = []pac.Pool{{ID: "csr-diff-pool", Name: "CSR"}}
		},
		// SaaS feed scalars: the diff block is gated on b.SaaSFeedProtocol != ""
		// (mirroring applyConfigBackup), so every mutator sets protocol non-empty on
		// both sides, then diverges the target field on one side.
		"saas_feed_url": func(a, b *configBackup) {
			a.SaaSFeedProtocol, b.SaaSFeedProtocol = saasFeedProtocolV1, saasFeedProtocolV1
			a.SaaSFeedURL = builtinSaaSFeedURL
			b.SaaSFeedURL = ""
		},
		"saas_feed_managed": func(a, b *configBackup) {
			a.SaaSFeedProtocol, b.SaaSFeedProtocol = saasFeedProtocolV1, saasFeedProtocolV1
			a.SaaSFeedManaged, b.SaaSFeedManaged = false, true
		},
		"saas_feed_enabled": func(a, b *configBackup) {
			a.SaaSFeedProtocol, b.SaaSFeedProtocol = saasFeedProtocolV1, saasFeedProtocolV1
			a.SaaSFeedEnabled, b.SaaSFeedEnabled = false, true
		},
		"saas_feed_protocol": func(a, b *configBackup) {
			a.SaaSFeedProtocol = "signed_manifest_v0"
			b.SaaSFeedProtocol = saasFeedProtocolV1
		},
		"saas_feed_refresh_seconds": func(a, b *configBackup) {
			a.SaaSFeedProtocol, b.SaaSFeedProtocol = saasFeedProtocolV1, saasFeedProtocolV1
			a.SaaSFeedRefreshSeconds, b.SaaSFeedRefreshSeconds = 3600, 7200
		},
		"category_overrides": func(a, b *configBackup) {
			a.CategoryOverrides = &CategoryOverrides{Added: map[string]string{"csr.example.com": "csr-cat"}}
			b.CategoryOverrides = &CategoryOverrides{}
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

	// globalDecryptionProfiles: swap for a fresh in-memory store (path="" → Save
	// is a no-op) and restore, so the round-trip actually diverges the profile
	// store + never leaks profile state across tests.
	origDP := globalDecryptionProfiles
	globalDecryptionProfiles = decryptprofile.New()
	t.Cleanup(func() { globalDecryptionProfiles = origDP })

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

	// SaaS feed durable holder (F3a-2): snapshot + restore the whole struct.
	origFeed := getSaaSFeedDurable()
	t.Cleanup(func() { setSaaSFeedDurable(origFeed) })

	// globalCategoryOverrides (F3a-2): swap for a fresh in-memory store (path="" →
	// Save is a no-op) and restore, so the round-trip diverges it without leaking.
	origOv := globalCategoryOverrides
	globalCategoryOverrides = catoverride.New()
	t.Cleanup(func() { globalCategoryOverrides = origOv })
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
	globalDecryptionProfiles.ReplaceAll([]DecryptionProfile{{Name: "csr-dp-a", MinTLSVersion: "1.2", OnInspectError: "fail-open"}})
	// SaaS feed config (F3a-2): a fully-set managed state so capture (resolved
	// url/protocol non-empty) applies on rollback and round-trips.
	setSaaSFeedDurable(saasFeedDurable{
		Managed: true, Enabled: true, URL: builtinSaaSFeedURL,
		Protocol: saasFeedProtocolV1, RefreshSeconds: 3600, SchemaVersion: saasStoreSchemaVersion,
	})
	_ = globalCategoryOverrides.ReplaceAll(CategoryOverrides{Added: map[string]string{"csr-a.example.com": "csr-cat"}})
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
	globalDecryptionProfiles.ReplaceAll([]DecryptionProfile{})
	// SaaS feed config (F3a-2): diverge every field so an apply-miss is caught.
	setSaaSFeedDurable(saasFeedDurable{
		Managed: false, Enabled: false, URL: "", Protocol: "", RefreshSeconds: 0,
		SchemaVersion: saasStoreSchemaVersion,
	})
	_ = globalCategoryOverrides.ReplaceAll(CategoryOverrides{Tombstones: []string{"csr-b.example.com"}})
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

// ─── 7b. Snapshot wrong-owner capture guard (DEBT-006 residual) ───────
//
// The registry's Owner column names the global a field is captured FROM. A
// presence scan (capture parity) can't catch `snap.NodeGroups =
// globalBandwidth.List()` — a paste-o that captures the right field from the
// WRONG store. This walls the DIRECT-receiver captures (`snap.Field =
// owner.Method(...)`): the receiver ident must equal the row's Owner. Captures
// that read through an intermediate local (`cats := catStore.All(); snap.X =
// cats`) or a helper (`buildCPAddressList()`) can't be bound by a receiver
// scan and are intentionally out of scope — they simply don't appear in the
// direct-capture map. A coverage floor keeps the guard from silently decaying
// to zero if the capture style changes wholesale.
func TestConfigSurfaces_SnapshotCaptureOwner(t *testing.T) {
	direct := snapshotDirectCaptureOwners(t) // field → receiver ident
	ownerByField := map[string]string{}
	knownOwner := map[string]bool{}
	for i := range configSurfaces {
		row := &configSurfaces[i]
		if row.Owner == "" {
			continue
		}
		knownOwner[row.Owner] = true
		for _, b := range row.Bindings {
			if b.Struct == "ConfigSnapshot" {
				ownerByField[b.Field] = row.Owner
			}
		}
	}
	checked := 0
	for field, recv := range direct {
		owner, ok := ownerByField[field]
		if !ok {
			continue // meta field with no Owner (e.g. captured from a ConfigStore field)
		}
		// Only receivers that are themselves a known store Owner are direct
		// store captures. A receiver like `hex` (SessionHMAC =
		// hex.EncodeToString(session.SigningKey())) is a stdlib wrapper over
		// the real owner and is out of scope — same as an intermediate local.
		if !knownOwner[recv] {
			continue
		}
		checked++
		if recv != owner {
			t.Errorf("CurrentConfigSnapshot captures ConfigSnapshot.%s from %q but the registry "+
				"Owner is %q — wrong-owner capture (the field would carry another store's data). "+
				"Fix the capture receiver or the registry Owner.", field, recv, owner)
		}
	}
	if checked < 10 {
		t.Fatalf("wrong-owner guard bound only %d direct captures (want >=10) — the capture style "+
			"changed and the scan no longer sees receivers; revisit snapshotDirectCaptureOwners", checked)
	}
}

// snapshotDirectCaptureOwners scans CurrentConfigSnapshot for direct-receiver
// captures `snap.Field = <ident>.Method(...)` and returns field → receiver
// ident. Intermediate-local and helper-call captures are not matched (no
// single receiver ident) and are excluded by construction.
func snapshotDirectCaptureOwners(t *testing.T) map[string]string {
	t.Helper()
	const file = "controlplane_snapshot.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string]string{}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "CurrentConfigSnapshot" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("CurrentConfigSnapshot not found in controlplane_snapshot.go")
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		lhs, ok := as.Lhs[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if base, ok := lhs.X.(*ast.Ident); !ok || base.Name != "snap" {
			return true
		}
		// RHS must be <ident>.Method(...): a call on a selector with an ident receiver.
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if recv, ok := sel.X.(*ast.Ident); ok {
			out[lhs.Sel.Name] = recv.Name
		}
		return true
	})
	return out
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
	"applyConfigSnapshot":                 true, // controlplane_snapshot.go
	"applySnapshotPolicyAndTraffic":       true,
	"applySnapshotBlocklist":              true, // T3 P1: blocklist step, split out of applySnapshotPolicyAndTraffic
	"applySnapshotTrafficExceptBlocklist": true, // T3 P1: the rest, shared by the full + delta apply paths
	"applySnapshotClusterRuntime":         true,
	"applySnapshotSessionSecret":          true,
	"applySnapshotExtendedState":          true,
	"applySnapshotSaaSFeed":               true, // F3a-2: SaaS feed config + category overrides
	"applyExternalAuthSnapshotSettings":   true,
	"syncSnapshotIdPProfiles":             true,
	"fetchAndApply":                       true, // controlplane_client.go (DP poller)
	"applyBlocklistDeltaSnapshot":         true, // T3 P1: DP-side delta apply (controlplane_delta.go)
	"applySnapshotMCP":                    true, // PR-10: optional signed MCP CP→DP snapshots (mcp_distribution.go)
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
	for _, file := range []string{"controlplane_snapshot.go", "controlplane_client.go", "mcp_distribution.go"} {
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

// snapshotRedactedFields returns the ConfigSnapshot field names zeroed inside the
// shared redactUnenrolledSnapshot helper (snap.Field = "" / nil assignments on the
// pointer parameter). Redaction moved OUT of the GetConfig if-block into this
// single helper so BOTH unenrolled-reachable surfaces (GetConfig and
// GetConfigDelta) route through one pinned place — the AST scan follows it there.
// snapshotRedactionCallers additionally asserts every such surface calls it.
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
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "redactUnenrolledSnapshot" || fn.Body == nil {
			return true
		}
		// The pointer param is named "snap"; collect its zeroed fields.
		ast.Inspect(fn.Body, func(m ast.Node) bool {
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
		return false
	})
	if len(redacted) == 0 {
		t.Fatal("redactUnenrolledSnapshot not found or zeroes no fields — the redaction wall lost its anchor")
	}
	return redacted
}

// snapshotRedactionCallers asserts that every unenrolled-reachable snapshot
// surface routes through redactUnenrolledSnapshot, so the wall (which pins the
// helper's fields) actually covers each door. Sec-F2: GetConfigDelta added a
// SECOND secret-bearing surface in a different file; without this the parity test
// would give false assurance for it.
func TestConfigSurfaces_RedactionCallers(t *testing.T) {
	for _, file := range []string{"controlplane_server.go", "controlplane_delta.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "redactUnenrolledSnapshot" {
				found = true
			}
			return true
		})
		if !found {
			t.Errorf("%s serves ConfigSnapshot to unenrolled callers but never calls "+
				"redactUnenrolledSnapshot — a secret-bearing surface outside the redaction wall", file)
		}
	}
}
