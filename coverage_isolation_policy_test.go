package main

// coverage_isolation_policy_test.go — isolated fixtures for code paths whose
// coverage previously depended on test ORDER or on TIMING (roadmap/CI-REDESIGN.md
// stage 5B).
//
// When the root suite runs as one process, some blocks are reached only because
// an EARLIER test happened to leave process-global state behind — a request-log
// ring already holding >50 entries, a policy version some other test moved, a
// crash record never cleared, a cluster CA never loaded — or because a map
// iteration order or a goroutine interleaving happened to fall one way. Once the
// suite is split across shards those blocks flip between covered and uncovered
// depending on which tests share a process. Every test below sets up (and
// restores via t.Cleanup) all the global state its path needs, never depends on
// a preceding test, drives the path deterministically (no sleeps, no network),
// and asserts the path's observable behaviour — not merely that a line ran.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/reqlog"
	"github.com/KidCarmi/Culvert/internal/support"
)

// ─── request-log ring (logstore.go, ui_config.go /api/logs) ─────────────────

// Pins logstore.go avgLogEntryBytes `if n > 50 { n = 50 }`. Previously covered
// only when earlier tests had already filled the shared in-memory request-log
// ring past 50 entries. The ring is swapped for an empty one and seeded with
// 10 OLD entries that are huge and 50 NEW entries that are small: the estimate
// must sample only the 50 newest (newest-first ring), so it equals the size of
// one small entry — a missing cap would average in the huge ones.
func TestCovIsoPolicy_AvgLogEntryBytesSamplesNewestFifty(t *testing.T) {
	isolateLogRing(t)
	big := LogEntry{TS: 1, Method: "GET", Host: strings.Repeat("h", 4096) + ".example", Status: "OK", Level: "INFO"}
	small := LogEntry{TS: 2, Method: "GET", Host: "s.example", Status: "OK", Level: "INFO"}
	for i := 0; i < 10; i++ {
		reqlog.Add(big)
	}
	for i := 0; i < 50; i++ {
		reqlog.Add(small)
	}
	if n := len(logGet()); n != 60 {
		t.Fatalf("seeded ring holds %d entries, want 60", n)
	}
	b, err := json.Marshal(small)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := int64(len(b)) + 1
	if got := avgLogEntryBytes(); got != want {
		t.Fatalf("avgLogEntryBytes = %d, want %d (only the 50 newest entries may be sampled)", got, want)
	}
}

type covIsoLogsResp struct {
	Logs  []LogEntry `json:"logs"`
	Total int        `json:"total"`
}

func covIsoGetLogs(t *testing.T, query string) (resp covIsoLogsResp, raw string) {
	t.Helper()
	w := httptest.NewRecorder()
	apiLogs(w, getReq("/api/logs?"+query))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/logs?%s = %d: %s", query, w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	return resp, w.Body.String()
}

// Pins ui_config.go buildLogFilterPredicate `if filterMethod != "" &&
// e.Method != filterMethod { return false }`. Reached before only when the
// shared ring happened to contain entries of a method other than the one some
// method-filter test asked for. The ring is seeded with GET and POST entries;
// ?method=post (case-folded) must return exactly the POST ones.
func TestCovIsoPolicy_LogsMethodFilterExcludesOtherMethods(t *testing.T) {
	isolateLogRing(t)
	reqlog.Add(LogEntry{TS: 1, Method: "GET", Host: "get-a.example", Status: "OK", Level: "INFO"})
	reqlog.Add(LogEntry{TS: 2, Method: "POST", Host: "post-a.example", Status: "OK", Level: "INFO"})
	reqlog.Add(LogEntry{TS: 3, Method: "GET", Host: "get-b.example", Status: "OK", Level: "INFO"})

	resp, raw := covIsoGetLogs(t, "method=post")
	if resp.Total != 1 || len(resp.Logs) != 1 {
		t.Fatalf("method=post returned total=%d logs=%d, want 1/1: %s", resp.Total, len(resp.Logs), raw)
	}
	if resp.Logs[0].Method != "POST" || resp.Logs[0].Host != "post-a.example" {
		t.Fatalf("method=post returned %+v, want the POST entry", resp.Logs[0])
	}
}

// Pins ui_config.go apiLogs `if offsetVal >= total { filtered = nil }`.
// Reached before only when a pagination test's offset happened to exceed
// whatever the shared ring held at that moment. With exactly 3 entries and
// ?offset=10 the page must be empty (JSON null) while total still reports 3.
func TestCovIsoPolicy_LogsOffsetPastEndReturnsEmptyPage(t *testing.T) {
	isolateLogRing(t)
	for i := 0; i < 3; i++ {
		reqlog.Add(LogEntry{TS: int64(i + 1), Method: "GET", Host: fmt.Sprintf("off-%d.example", i), Status: "OK", Level: "INFO"})
	}
	resp, raw := covIsoGetLogs(t, "offset=10")
	if resp.Total != 3 {
		t.Fatalf("total = %d, want 3: %s", resp.Total, raw)
	}
	if resp.Logs != nil {
		t.Fatalf("logs = %+v, want null past the end", resp.Logs)
	}
	if !strings.Contains(raw, `"logs":null`) {
		t.Fatalf("body %s must carry logs:null", raw)
	}
}

// ─── Stage-2 evaluator trace (policy.go) ───────────────────────────────────

// Pins policy.go evalAccessRules `if trace != nil { trace(rule,
// accessSkipSource) }`. Reached before only via the Policy Tester when some
// test's rulebase happened to contain a source-scoped rule the probe did not
// match. The evaluator is driven directly with a non-nil trace: a rule scoped
// to identity "alice" must be traced as a source mismatch for "bob", and the
// following unscoped rule must match and be traced with the empty reason.
func TestCovIsoPolicy_EvalAccessRulesTracesSourceMismatch(t *testing.T) {
	scoped := &PolicyRule{Priority: 1, Name: "alice-only", SourceIdentity: "alice", Action: ActionDrop}
	open := &PolicyRule{Priority: 2, Name: "anyone", Action: ActionAllow}
	in := accessEvalInput{clientIP: "192.0.2.10", identity: "bob", host: "dest.example", normHost: normalizeHost("dest.example")}

	type step struct{ name, skip string }
	var got []step
	matched := evalAccessRules([]*PolicyRule{scoped, open}, &in, time.Now, func(r *PolicyRule, skip string) {
		got = append(got, step{r.Name, skip})
	})
	if matched != open {
		t.Fatalf("matched %+v, want the unscoped rule", matched)
	}
	want := []step{{"alice-only", accessSkipSource}, {"anyone", ""}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("trace = %+v, want %+v", got, want)
	}
}

// ─── optimistic-concurrency fences (ui_authpolicy.go, ui_policy.go) ──────────

type covIsoConflictBody struct {
	Error          string `json:"error"`
	CurrentVersion int64  `json:"currentVersion"`
	YourVersion    int64  `json:"yourVersion"`
}

func covIsoAssertConflict(t *testing.T, w *httptest.ResponseRecorder, wantCur, wantYours int64) {
	t.Helper()
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	var body covIsoConflictBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 409: %v (%s)", err, w.Body.String())
	}
	if body.Error == "" || body.CurrentVersion != wantCur || body.YourVersion != wantYours {
		t.Fatalf("409 body = %+v, want currentVersion=%d yourVersion=%d", body, wantCur, wantYours)
	}
}

// covIsoBumpRunningVersion advances the running policy generation without
// changing content — exactly what a competing writer's commit does to the fence.
func covIsoBumpRunningVersion() {
	policyStore.mu.Lock()
	policyStore.bumpVersion()
	policyStore.mu.Unlock()
}

// covIsoRaceAtFence installs the policyWriteStateDecision seam so that the
// request carrying the hold header has the running generation advanced at the
// "fence" stage — AFTER its early version check passed and BEFORE the
// coordinator's in-lock re-check. Deterministic: the seam runs synchronously on
// the handler goroutine, no scheduling involved.
func covIsoRaceAtFence(t *testing.T) {
	t.Helper()
	prev := policyWriteStateDecisionHook
	policyWriteStateDecisionHook = func(r *http.Request, stage string) {
		if stage == "fence" && r.Header.Get(holdHeader) == "covIso" {
			covIsoBumpRunningVersion()
		}
	}
	t.Cleanup(func() { policyWriteStateDecisionHook = prev })
}

// Pins ui_authpolicy.go apiAuthPolicyCreate `if runningPolicyVersionConflict
// { return }`. Previously covered only when an earlier test left the running
// version somewhere a later create's ?ifVersion= no longer matched. A stale
// ?ifVersion= must be refused 409 with the current version, and no rule created.
func TestCovIsoPolicy_AuthPolicyCreateStaleVersion409(t *testing.T) {
	draftTestSetup(t)
	cur, _ := policyStore.policyVersion()
	stale := cur + 7
	w := createAuthRuleViaAPI(t, "covIso-stale-create", fmt.Sprintf("%d", stale))
	covIsoAssertConflict(t, w, cur, stale)
	if ruleByName("covIso-stale-create") != nil {
		t.Fatal("a stale create must not add the rule")
	}
	if now, _ := policyStore.policyVersion(); now != cur {
		t.Fatalf("running version moved %d → %d on a refused create", cur, now)
	}
}

// Pins ui_authpolicy.go apiAuthPolicyDelete's early
// `if runningPolicyVersionConflict { return }`. Same order dependence as the
// create case. A stale ?ifVersion= delete must 409 and leave the rule in place.
func TestCovIsoPolicy_AuthPolicyDeleteStaleVersion409(t *testing.T) {
	draftTestSetup(t)
	rule := seedAuthRule(t, "covIso-del-stale")
	cur, _ := policyStore.policyVersion()
	w := deleteAuthRuleReq(rule.ID, cur+3)
	covIsoAssertConflict(t, w, cur, cur+3)
	if ruleByName("covIso-del-stale") == nil {
		t.Fatal("a stale delete must not remove the rule")
	}
}

// Pins ui_authpolicy.go apiAuthPolicyDelete `if res.conflict != nil {
// writePolicyVersionConflictError }` — the in-fence re-check. Previously hit
// only when a concurrent-pair race test happened to interleave so the version
// moved between the early check and the coordinator lock. Here the seam moves
// it at exactly that point: the early check passes, the fence refuses 409
// with the NEW current version, and the rule survives.
func TestCovIsoPolicy_AuthPolicyDeleteFencedConflict409(t *testing.T) {
	draftTestSetup(t)
	rule := seedAuthRule(t, "covIso-del-fenced")
	cur, _ := policyStore.policyVersion()
	covIsoRaceAtFence(t)

	w := httptest.NewRecorder()
	r := jsonReq("DELETE", fmt.Sprintf("/api/authpolicy?id=%s&ifVersion=%d", rule.ID, cur), nil)
	r.Header.Set(holdHeader, "covIso")
	apiAuthPolicyDelete(w, r)

	covIsoAssertConflict(t, w, cur+1, cur)
	if ruleByName("covIso-del-fenced") == nil {
		t.Fatal("a fenced-out delete must not remove the rule")
	}
}

// Pins ui_policy.go apiPolicyUpdate `if policyVersionConflict { return }`.
// Previously order-dependent like the auth cases: a stale ?ifVersion= must be
// refused 409 before the body is even read, leaving the rule untouched.
func TestCovIsoPolicy_PolicyUpdateStaleVersion409(t *testing.T) {
	draftTestSetup(t)
	added := policyStore.Add(PolicyRule{Priority: 1, Name: "covIso-upd", Action: ActionAllow})
	cur, _ := policyStore.policyVersion()

	w := httptest.NewRecorder()
	apiPolicyUpdate(w, jsonReq("PUT", fmt.Sprintf("/api/policy?id=%s&ifVersion=%d", added.ID, cur+5),
		map[string]any{"name": "covIso-upd-renamed", "action": "Drop"}))
	covIsoAssertConflict(t, w, cur, cur+5)
	if got := ruleByName("covIso-upd"); got == nil || got.Action != ActionAllow {
		t.Fatalf("stale update mutated the rule: %+v", got)
	}
}

// covIsoSeedTwoAccessRules seeds two access rules at priorities 1 and 2.
func covIsoSeedTwoAccessRules() {
	policyStore.Add(PolicyRule{Priority: 1, Name: "covIso-first", Action: ActionAllow})
	policyStore.Add(PolicyRule{Priority: 2, Name: "covIso-second", Action: ActionDrop})
}

func covIsoAssertOrderUnchanged(t *testing.T) {
	t.Helper()
	if a, b := ruleByName("covIso-first"), ruleByName("covIso-second"); a == nil || b == nil || a.Priority != 1 || b.Priority != 2 {
		t.Fatalf("refused reorder changed the rulebase: first=%+v second=%+v", a, b)
	}
}

// Pins ui_policy.go apiPolicyReorder `if policyVersionConflict { return }`.
// Order-dependent for the same reason: a stale ?ifVersion= must 409 and the
// priorities must be unchanged.
func TestCovIsoPolicy_PolicyReorderStaleVersion409(t *testing.T) {
	draftTestSetup(t)
	covIsoSeedTwoAccessRules()
	cur, _ := policyStore.policyVersion()

	w := httptest.NewRecorder()
	apiPolicyReorder(w, jsonReq("POST", fmt.Sprintf("/api/policy/reorder?ifVersion=%d", cur+9),
		map[string]any{"priorities": []int{2, 1}}))
	covIsoAssertConflict(t, w, cur, cur+9)
	covIsoAssertOrderUnchanged(t)
}

// Pins ui_policy.go apiPolicyReorder `if res.conflict != nil {
// writePolicyVersionConflictError }` — the in-fence re-check, previously hit
// only by a lucky concurrent interleaving. The seam advances the version
// between the early check and the coordinator lock: 409 with the new version,
// order untouched.
func TestCovIsoPolicy_PolicyReorderFencedConflict409(t *testing.T) {
	draftTestSetup(t)
	covIsoSeedTwoAccessRules()
	cur, _ := policyStore.policyVersion()
	covIsoRaceAtFence(t)

	w := httptest.NewRecorder()
	r := jsonReq("POST", fmt.Sprintf("/api/policy/reorder?ifVersion=%d", cur), map[string]any{"priorities": []int{2, 1}})
	r.Header.Set(holdHeader, "covIso")
	apiPolicyReorder(w, r)

	covIsoAssertConflict(t, w, cur+1, cur)
	covIsoAssertOrderUnchanged(t)
}

// ─── config import / preview (ui_config.go) ─────────────────────────────────

// Pins ui_config.go buildImportSettingsPreview `if b.ConnLimitEnabled {
// state = "enabled" }`. Reached before only through an import-preview test
// whose backup happened to carry an ENABLED connection limit. The preview is
// a pure function of the backup: it must report "5 per IP (enabled)", and the
// disabled twin must report "(disabled)".
func TestCovIsoPolicy_ImportPreviewReportsEnabledConnLimit(t *testing.T) {
	find := func(settings []importPreviewSetting) string {
		for _, s := range settings {
			if s.Setting == "Connection Limit" {
				return s.Value
			}
		}
		return ""
	}
	if got := find(buildImportSettingsPreview(&configBackup{ConnLimitMaxPerIP: 5, ConnLimitEnabled: true})); got != "5 per IP (enabled)" {
		t.Fatalf("enabled preview = %q, want %q", got, "5 per IP (enabled)")
	}
	if got := find(buildImportSettingsPreview(&configBackup{ConnLimitMaxPerIP: 5})); got != "5 per IP (disabled)" {
		t.Fatalf("disabled preview = %q, want %q", got, "5 per IP (disabled)")
	}
}

// covIsoImportEnv isolates every process-global the config-import handler
// writes for the backups used below: the data dir, the admin-settings file
// (unset ⇒ in-memory save), the config-version store, the cluster snapshot
// store, the running policy (persistence disabled), and fresh SSL-bypass,
// content-scanner and connection-limiter singletons. The import spawns an
// asynchronous admin-settings save that READS these singletons, so the save
// group is drained before any of them is restored (registered last ⇒ runs
// first).
func covIsoImportEnv(t *testing.T) {
	t.Helper()
	withTempDataDir(t)
	snapshotConfigVersionsDir(t)
	snapshotPolicyStoreForTest(t)

	adminSettingsMu.Lock()
	prevPath := adminSettingsPath
	adminSettingsPath = ""
	adminSettingsMu.Unlock()

	prevCfgStore := globalConfigStore
	globalConfigStore = &ConfigStore{}
	prevBypass, prevDPI, prevConn := sslBypass, dpiScanner, connLimiter
	sslBypass = &SSLBypassMatcher{}
	dpiScanner = newContentScanner(1 << 20)
	connLimiter = newConnLimiter()

	t.Cleanup(func() {
		sslBypass, dpiScanner, connLimiter = prevBypass, prevDPI, prevConn
		globalConfigStore = prevCfgStore
		adminSettingsMu.Lock()
		adminSettingsPath = prevPath
		adminSettingsMu.Unlock()
	})
	t.Cleanup(adminSettingsSaveWG.Wait)
}

func covIsoImport(t *testing.T, path string, backup map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", path, backup))
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", path, w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp["ok"] != true {
		t.Fatalf("import response %s (err %v), want ok:true", w.Body.String(), err)
	}
}

// Pins ui_config.go apiConfigImport `if replaceMode && len(b.SSLBypass) > 0 {
// sslBypass.Set(...) }`. Previously covered only by whichever replace-mode
// import test happened to carry bypass patterns while sharing a process with
// the one that seeded them. A replace import must REPLACE the live list
// wholesale (the pre-existing pattern is gone).
func TestCovIsoPolicy_ImportReplaceSetsSSLBypass(t *testing.T) {
	covIsoImportEnv(t)
	if err := sslBypass.Add("old-bypass.example"); err != nil {
		t.Fatalf("seed bypass: %v", err)
	}
	covIsoImport(t, "/api/config/import?mode=replace", map[string]any{
		"version":   1,
		"sslBypass": []string{"new-a.example", "new-b.example"},
	})
	got := sslBypass.List()
	if len(got) != 2 || !sslBypass.Matches("new-a.example") || !sslBypass.Matches("new-b.example") {
		t.Fatalf("bypass list after replace import = %v, want exactly the two imported patterns", got)
	}
	if sslBypass.Matches("old-bypass.example") {
		t.Fatalf("replace import kept the pre-existing pattern: %v", got)
	}
}

// Pins ui_config.go apiConfigImport's merge-mode `for _, p := range
// b.ContentScanPatterns { dpiScanner.Add(p) }` loop. Order-dependent before
// because only some merge-import tests carried patterns. A merge import must
// ADD the patterns alongside the existing one.
func TestCovIsoPolicy_ImportMergeAddsContentScanPatterns(t *testing.T) {
	covIsoImportEnv(t)
	if err := dpiScanner.Add(`covIsoExisting[0-9]+`); err != nil {
		t.Fatalf("seed pattern: %v", err)
	}
	covIsoImport(t, "/api/config/import", map[string]any{
		"version":             1,
		"contentScanPatterns": []string{`covIsoMergedA[0-9]+`, `covIsoMergedB[a-z]+`},
	})
	got := strings.Join(dpiScanner.List(), "\n")
	for _, want := range []string{`covIsoExisting[0-9]+`, `covIsoMergedA[0-9]+`, `covIsoMergedB[a-z]+`} {
		if !strings.Contains(got, want) {
			t.Fatalf("patterns after merge import = %q, missing %q", got, want)
		}
	}
	if len(dpiScanner.List()) != 3 {
		t.Fatalf("patterns after merge import = %v, want 3", dpiScanner.List())
	}
}

// Pins ui_config.go apiConfigImport `if b.ConnLimitEnabled { … } else {
// connLimiter.Disable() }` — the else arm. Reached before only when an import
// carrying a DISABLED limit happened to follow a test that had left the
// process-global limiter enabled. Starting from an enabled limiter, importing
// maxPerIP>0 with enabled=false must switch it off.
func TestCovIsoPolicy_ImportDisablesConnLimit(t *testing.T) {
	covIsoImportEnv(t)
	connLimiter.Enable(9)
	if !connLimiter.Enabled() {
		t.Fatal("precondition: limiter must start enabled")
	}
	covIsoImport(t, "/api/config/import", map[string]any{
		"version":           1,
		"connLimitMaxPerIP": 4,
		"connLimitEnabled":  false,
	})
	if connLimiter.Enabled() {
		t.Fatal("import with connLimitEnabled=false must disable the connection limiter")
	}
}

// Pins the other arm, `connLimiter.Enable(b.ConnLimitMaxPerIP)`. No test
// imports an enabled limit directly: before, the arm was reached only by an
// export→import round trip that happened to run after an earlier test left the
// process-global limiter enabled, so the export carried enabled=true. The
// qualification audit caught it the first time the shards separated those two
// tests (qa-gate run 35834009198). Starting from a disabled limiter, importing
// maxPerIP>0 with enabled=true must switch it on AT the imported cap.
func TestCovIsoPolicy_ImportEnablesConnLimit(t *testing.T) {
	covIsoImportEnv(t)
	connLimiter.Disable()
	if connLimiter.Enabled() {
		t.Fatal("precondition: limiter must start disabled")
	}
	covIsoImport(t, "/api/config/import", map[string]any{
		"version":           1,
		"connLimitMaxPerIP": 7,
		"connLimitEnabled":  true,
	})
	if !connLimiter.Enabled() {
		t.Fatal("import with connLimitEnabled=true must enable the connection limiter")
	}
	if got := connLimiter.MaxPerIP(); got != 7 {
		t.Fatalf("imported cap not applied: MaxPerIP=%d, want 7", got)
	}
}

// ─── top-hosts insert race (store.go) ───────────────────────────────────────

// covIsoWaitBlockedInRecord polls every goroutine's stack until one that was
// started by fnMarker is parked inside (*hostCounter).Record on the mutex —
// i.e. it has already missed the lock-free fast path. No sleeps: runtime.Stack
// is re-read after runtime.Gosched until the state is observed.
func covIsoWaitBlockedInRecord(t *testing.T, fnMarker string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, fnMarker) && strings.Contains(g, "(*hostCounter).Record") &&
				strings.Contains(g, "(*Mutex).Lock") {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("Record goroutine never blocked on hc.mu")
}

// Pins store.go hostCounter.Record's double-checked insert branch
// `raced with another inserter — count, don't reset`. Previously reachable only
// when two goroutines inserting the same new host happened to interleave.
// Here the interleaving is forced: hc.mu is held, a Record for an untracked host
// is started and observed (via its stack) parked on the mutex AFTER missing the
// fast path; still holding the lock the host is inserted with count 5 exactly as
// the slow path would; on release the parked Record must find it and INCREMENT
// it to 6 — not reset it to 1 and not insert a second entry.
func TestCovIsoPolicy_TopHostsRecordRacedInserterCounts(t *testing.T) {
	hc := freshHostCounter()
	const host = "raced-insert.example"

	hc.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		covIsoRecordRacer(hc, host)
	}()
	covIsoWaitBlockedInRecord(t, "covIsoRecordRacer")

	five := int64(5)
	hc.hosts.Store(host, &five)
	hc.n.Add(1)
	hc.mu.Unlock()
	<-done

	c, ok := hc.count(host)
	if !ok || c != 6 {
		t.Fatalf("count after raced insert = %d (tracked=%v), want 6 — the loser must count, not reset", c, ok)
	}
	if hc.size() != 1 {
		t.Fatalf("size = %d, want 1 (no duplicate insert)", hc.size())
	}
}

// covIsoRecordRacer is a named frame so the stack poll can identify the
// racing goroutine unambiguously.
//
//go:noinline
func covIsoRecordRacer(hc *hostCounter, host string) { hc.Record(host) }

// ─── release catalog comparator (release_catalog_resolve.go) ────────────────

// Pins release_catalog_resolve.go catalogCompareSemver `case apre == "":
// return 1` AND `case bpre == "": return -1`, plus catalogCmpInt's `a > b`
// arm. Which arm a sort reaches depends on the argument order it happens to
// pass — driven by map iteration — so both orders are exercised directly.
func TestCovIsoPolicy_CatalogCompareSemverPrereleaseBothOrders(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.4.0", "1.4.0-rc.1", 1},  // a has no prerelease ⇒ higher
		{"1.4.0-rc.1", "1.4.0", -1}, // b has no prerelease ⇒ a lower
		{"2.0.0", "1.9.9", 1},       // catalogCmpInt a > b
		{"1.4.0", "1.4.0", 0},
	}
	for _, c := range cases {
		if got := catalogCompareSemver(c.a, c.b); got != c.want {
			t.Errorf("catalogCompareSemver(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if got := catalogCmpInt(7, 3); got != 1 {
		t.Errorf("catalogCmpInt(7, 3) = %d, want 1", got)
	}
}

// ─── agent op polling (release_dispatch_exec.go) ────────────────────────────

type covIsoCancelOnPoll struct {
	cancel context.CancelFunc
	calls  int
}

func (rt *covIsoCancelOnPoll) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.calls++
	rt.cancel() // the operator gives up while the op is still running
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"state":"running"}`)),
		Request:    r,
	}, nil
}

// Pins release_dispatch_exec.go httpAgentClient.WaitOp `case <-ctx.Done():
// return "", ctx.Err()`. Previously a race between the context deadline and
// the poll ticker. Here a transport (no network) answers one successful
// non-terminal poll and cancels the context while doing so, and the poll
// interval is an hour, so ctx.Done is the ONLY ready select case: WaitOp must
// return context.Canceled after exactly one poll.
func TestCovIsoPolicy_WaitOpReturnsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &covIsoCancelOnPoll{cancel: cancel}
	c, err := NewHTTPAgentClient("http://agent.invalid", &http.Client{Transport: rt})
	if err != nil {
		t.Fatalf("NewHTTPAgentClient: %v", err)
	}
	c.pollInterval = time.Hour

	state, err := c.WaitOp(ctx, "op-cov-iso")
	if state != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitOp = (%q, %v), want (\"\", context.Canceled)", state, err)
	}
	if rt.calls != 1 {
		t.Fatalf("agent polled %d times, want 1", rt.calls)
	}
}

// ─── SaaS feed migration classifier (saas_feed_migrate.go) ──────────────────

// Pins saas_feed_migrate.go classifyFeedURL `if validateOfficialManifestURL(p)
// == nil { return "official" }`. Previously reached only when a migration test
// happened to persist the official URL. The canonical manifest URL (with
// surrounding whitespace, which the classifier trims) is "official"; the other
// three classes are asserted alongside as controls.
func TestCovIsoPolicy_ClassifyFeedURLOfficial(t *testing.T) {
	if got := classifyFeedURL("  " + builtinSaaSFeedURL + " "); got != "official" {
		t.Fatalf("classifyFeedURL(official) = %q, want official", got)
	}
	if got := classifyFeedURL(""); got != "unset" {
		t.Fatalf("classifyFeedURL(\"\") = %q, want unset", got)
	}
	if got := classifyFeedURL(historicalSaaSFeedURLs[0]); got != "historical" {
		t.Fatalf("classifyFeedURL(historical) = %q, want historical", got)
	}
	if got := classifyFeedURL("https://example.com/feed.json"); got != "unsupported" {
		t.Fatalf("classifyFeedURL(other) = %q, want unsupported", got)
	}
}

// ─── cluster CA rotation (enrollment.go) ────────────────────────────────────

// Pins enrollment.go clusterCA.RotateIfNeeded `if ca.cert == nil { RUnlock;
// return }`. Previously reached only when the shared rotation loop ran while
// the process-global cluster CA happened to be unloaded. A CA with no
// certificate must be a no-op: nothing is minted and no rotation failure is
// recorded in the health plane.
func TestCovIsoPolicy_ClusterCARotateIfNeededWithoutCertIsNoop(t *testing.T) {
	clusterCAHealth.mu.Lock()
	before := clusterCAHealth.rotationFailures
	clusterCAHealth.mu.Unlock()

	ca := &clusterCA{}
	ca.RotateIfNeeded()

	ca.mu.RLock()
	cert, lastErr := ca.cert, ca.lastRotationErr
	ca.mu.RUnlock()
	if cert != nil || lastErr != "" {
		t.Fatalf("RotateIfNeeded on an empty CA changed it: cert=%v lastErr=%q", cert, lastErr)
	}
	clusterCAHealth.mu.Lock()
	after := clusterCAHealth.rotationFailures
	clusterCAHealth.mu.Unlock()
	if after != before {
		t.Fatalf("rotation failures %d → %d; an absent CA is not a rotation failure", before, after)
	}
}

// ─── support-bundle crash section (support_collectors.go) ───────────────────

type covIsoSink struct{ got []any }

func (s *covIsoSink) WriteJSON(v any) error { s.got = append(s.got, v); return nil }

// Pins support_collectors.go crashCollector.Collect's `if !ok { WriteJSON
// {"last_crash": nil} … return StatusOK/ClassPublic }` branch. Previously
// covered only when no earlier test in the process had recorded a crash. The
// process-global crash record is cleared (and restored): the section must be
// exactly {"last_crash": null}, status ok, class public.
func TestCovIsoPolicy_CrashCollectorWithNoCrashRecorded(t *testing.T) {
	lastCrashMu.Lock()
	prev := lastCrash
	lastCrash = nil
	lastCrashMu.Unlock()
	t.Cleanup(func() {
		lastCrashMu.Lock()
		lastCrash = prev
		lastCrashMu.Unlock()
	})

	sink := &covIsoSink{}
	res := crashCollector{}.Collect(context.Background(), support.CollectInput{Redactor: redaction.New()}, sink)
	if res.Status != support.StatusOK || res.ClassMax != redaction.ClassPublic {
		t.Fatalf("result = %+v, want status ok / class public", res)
	}
	if len(sink.got) != 1 {
		t.Fatalf("section writes = %d, want 1", len(sink.got))
	}
	m, ok := sink.got[0].(map[string]any)
	if !ok {
		t.Fatalf("section = %T, want map", sink.got[0])
	}
	if v, present := m["last_crash"]; !present || v != nil || len(m) != 1 {
		t.Fatalf("section = %v, want exactly {last_crash: nil}", m)
	}
}
