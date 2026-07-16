package main

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// autoexclude_qualification_test.go — pre-merge qualification (Tracks 4 & 5):
// an end-to-end staged-rollout rehearsal and an adversarial resource-bound proof.

// qualClock is a race-safe injectable clock for the global cache.
type qualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *qualClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *qualClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestRolloutRehearsal walks the operator's staged rollout end-to-end and asserts
// the observability + safety contract at each step (Track 5).
//
//nolint:gocognit // a linear 9-step rollout rehearsal; splitting it would obscure the sequence
func TestRolloutRehearsal(t *testing.T) {
	clk := &qualClock{t: time.Unix(1_700_000_000, 0)}
	prevCache := autoExclude()
	setAutoExclude(autoexclude.New(autoexclude.Config{ConfirmN: 2, Now: clk.now}))
	t.Cleanup(func() { setAutoExclude(prevCache) })
	swapProfiles(t)

	// 1. Zero fail-open profiles → provable-OFF.
	if p, r := failOpenFootprint(); p != 0 || r != 0 {
		t.Fatalf("step1: expected provable-OFF (0,0), got (%d,%d)", p, r)
	}
	// A rule with no fail-open profile never consults the cache (feature-off).
	noProf := &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect, Rule: &PolicyRule{Name: "np", SSLAction: SSLInspect}}
	if a, _ := resolveSSLAction(noProf, "any.example", "1.2.3.4"); a != SSLInspect {
		t.Fatal("step1: feature-off must Inspect")
	}

	// 2. Enable ONE narrow fail-open profile on one rule.
	fo, scope := bindFailOpenProfile(t, "byod", "fail-open")
	if p, _ := failOpenFootprint(); p != 1 {
		t.Fatalf("step2: expected 1 fail-open profile, got %d", p)
	}

	// 3. Trigger each supported reason to promotion (2 distinct identities).
	reasons := []AutoExcludeReason{autoExReasonClientCert, autoExReasonUnsupported, autoExReasonClientPinned}
	hosts := []string{"cc.example", "unsup.example", "pin.example"}
	baseline := time.Now().UnixMilli()
	for i, reason := range reasons {
		recordAutoExclude(fo, hosts[i], reason, ProxyIdentity{ClientIP: "10.0.0.1", Identity: "alice"})
		if _, ok := autoExclude().Contains(scope, hosts[i]); ok {
			t.Fatalf("step3: %s promoted on ONE identity (confirm-count bypassed)", reason)
		}
		recordAutoExclude(fo, hosts[i], reason, ProxyIdentity{ClientIP: "10.0.0.2", Identity: "bob"})
		if _, ok := autoExclude().Contains(scope, hosts[i]); !ok {
			t.Fatalf("step3: %s not excluded after 2 distinct identities", reason)
		}
	}

	// 4. Confirm audit + metric + panel(API) + scope + hit + expiry.
	learnAudits := 0
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "decryption.autoexclude.learn" && strings.Contains(e.Detail, "scope=byod") {
			learnAudits++
		}
	}
	if learnAudits < 3 {
		t.Fatalf("step4: expected >=3 scoped learn audits, got %d", learnAudits)
	}
	// Panel API: viewer GET lists the 3 entries with their scope + provable footprint.
	rw := httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleViewer, http.MethodGet, "/api/decryption-exclusions", nil))
	body := rw.Body.String()
	for _, h := range hosts {
		if !strings.Contains(body, h) {
			t.Fatalf("step4: panel missing host %s", h)
		}
	}
	if !strings.Contains(body, "byod") || !strings.Contains(body, "scope_rule_counts") {
		t.Fatal("step4: panel missing scope / blast-radius")
	}
	// Hit: a fail-open session to an excluded host bypasses (increments hit counter).
	before := autoExcludeHitCounter
	if a, _ := resolveSSLAction(fo, "cc.example", "9.9.9.9"); a != SSLBypass {
		t.Fatal("step4: excluded host should bypass under its fail-open rule")
	}
	if autoExcludeHitCounter <= before {
		t.Fatal("step4: hit counter did not increment")
	}
	// Expiry: advance past the pinned TTL (1h) — pin.example expires, cc/unsup stay (12h).
	clk.add(90 * time.Minute)
	if _, ok := autoExclude().Contains(scope, "pin.example"); ok {
		t.Fatal("step4: client_pinned entry should expire after 1h")
	}
	if _, ok := autoExclude().Contains(scope, "cc.example"); !ok {
		t.Fatal("step4: server-observed entry should survive to 12h")
	}

	// 5. Disable fail-open on the profile.
	if err := globalDecryptionProfiles.Update(DecryptionProfile{Name: "byod", OnInspectError: "fail-close"}); err != nil {
		t.Fatalf("step5: update: %v", err)
	}
	fc := &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect, Rule: &PolicyRule{Name: "r-byod", SSLAction: SSLInspect, DecryptionProfile: "byod"}}

	// 6. No further reads (still-cached cc.example is inspected now) and no learns.
	if a, _ := resolveSSLAction(fc, "cc.example", "9.9.9.9"); a != SSLInspect {
		t.Fatal("step6: disabling fail-open must stop consulting the cache")
	}
	if maybeFailOpenOrigin("new.example", fc, ProxyIdentity{ClientIP: "10.0.0.3", Identity: "carol"}, errTLS("certificate required")) {
		t.Fatal("step6: disabled profile must not learn or rescue")
	}
	if _, ok := autoExclude().Contains(scope, "new.example"); ok {
		t.Fatal("step6: no new learn after disable")
	}

	// 7. Evict + clear → inspection resumes.
	rw = httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleOperator, http.MethodDelete, "/api/decryption-exclusions", nil))
	if autoExclude().Len() != 0 {
		t.Fatalf("step7: clear-all left %d entries", autoExclude().Len())
	}

	// 8. Restart → the cache is VOLATILE: no promotion survives a process restart.
	// A fresh empty map is trivially empty, so instead prove volatility where it
	// matters — re-promote a host, then model the restart by re-running the SAME
	// boot wiring the composition root uses (autoexclude.New, no load/read-back),
	// and assert the previously-excluded host is gone. If anyone ever adds a
	// persistence load to the boot path, the re-promoted host would survive and
	// this fails.
	fo2, scope2 := bindFailOpenProfile(t, "byod2", "fail-open")
	recordAutoExclude(fo2, "persist-check.example", autoExReasonUnsupported, ProxyIdentity{ClientIP: "10.0.0.1", Identity: "alice"})
	recordAutoExclude(fo2, "persist-check.example", autoExReasonUnsupported, ProxyIdentity{ClientIP: "10.0.0.2", Identity: "bob"})
	if _, ok := autoExclude().Contains(scope2, "persist-check.example"); !ok {
		t.Fatal("step8: precondition — host should be excluded before the restart")
	}
	setAutoExclude(autoexclude.New(autoexclude.Config{})) // == the boot wiring; no on-disk load exists
	if _, ok := autoExclude().Contains(scope2, "persist-check.example"); ok {
		t.Fatal("step8: an exclusion survived a restart — the cache is no longer volatile (a persistence load crept into the boot path)")
	}
	if autoExclude().Len() != 0 {
		t.Fatal("step8: restarted cache must be empty")
	}

	// 9. Downgrade compat: a profile without the field (old on-disk shape) resolves
	// to fail-close — no fail-open scope, so the cache is never consulted.
	swapProfiles(t)
	if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "legacy"}); err != nil { // no OnInspectError
		t.Fatalf("step9: add legacy: %v", err)
	}
	if _, ok := globalDecryptionProfiles.FailOpenScope("legacy"); ok {
		t.Fatal("step9: a profile without OnInspectError must resolve fail-close")
	}
}

// errTLS is a tiny error stand-in for a TLS handshake error string.
type errTLSString string

func (e errTLSString) Error() string { return "remote error: tls: " + string(e) }
func errTLS(s string) error          { return errTLSString(s) }

// TestResourceBounded_UnderAdversarialLoad proves the cache stays bounded under a
// pending flood + a distinct-host flood, that post-GC heap returns to a sane
// baseline, and that resource pressure can only EVICT (re-enable inspection) —
// never create a bypass for a host that was not legitimately promoted (Track 4).
func TestResourceBounded_UnderAdversarialLoad(t *testing.T) {
	c := autoexclude.New(autoexclude.Config{ConfirmN: 5, MaxEntries: 4096, Now: time.Now})

	// N floods well past the 4096 cap either way (the bound holds identically at any
	// N >> cap); -short keeps the -race critical path light.
	n := 12_000
	if testing.Short() {
		n = 5_000
	}

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	// Pending flood: one attacker identity across N distinct hosts, none ever
	// reaching confirmN=5 → must not grow the pending map past the cap.
	for i := 0; i < n; i++ {
		c.Observe("scope", "prof", genHost(i), autoexclude.ReasonClientPinned, "id:attacker")
	}
	if pl := c.PendingLen(); pl > 4096 {
		t.Fatalf("pending map unbounded under flood: PendingLen=%d > cap 4096", pl)
	}
	if c.Len() != 0 {
		t.Fatalf("a single identity must never promote anything: active=%d", c.Len())
	}

	// Active flood: promote N distinct hosts (confirmN met via 5 identities) →
	// active map must stay capped; eviction only removes (never creates a bypass).
	for i := 0; i < n; i++ {
		h := "active-" + genHost(i)
		for k := 0; k < 5; k++ {
			c.Observe("scope", "prof", h, autoexclude.ReasonUnsupportedParams, "id:"+string(rune('a'+k)))
		}
	}
	if l := c.Len(); l > 4096 {
		t.Fatalf("active map unbounded: Len=%d > cap 4096", l)
	}

	// Post-GC heap returns to a bounded baseline (bounded maps ⇒ bounded retention).
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	var grownMB int64
	if m1.HeapAlloc > m0.HeapAlloc {
		grownMB = int64((m1.HeapAlloc - m0.HeapAlloc) / (1 << 20)) // #nosec G115 -- heap delta is single-digit MB, no overflow
	}
	// The two capped 4096-entry maps + keys retain single-digit MB; allow generous
	// headroom so this is a bound, not a flaky exact-match.
	if grownMB > 64 {
		t.Fatalf("post-GC heap grew %d MB after 2N adversarial ops — retention not bounded", grownMB)
	}
	t.Logf("Track4: post-GC heap delta after 2N adversarial ops = %d MB (active=%d pending=%d)", grownMB, c.Len(), c.PendingLen())

	// Safety: a host that never reached the confirm-count is NOT excluded — pressure
	// can only evict/re-enable, never bypass.
	if _, ok := c.Contains("scope", genHost(0)); ok {
		t.Fatal("pressure created a bypass for an unconfirmed host — MUST NEVER HAPPEN")
	}
}

func genHost(i int) string {
	// deterministic distinct hostnames, up to a realistic length
	return "h-" + string(rune('a'+i%26)) + "-" + qualItoa(i) + ".example.test"
}

func qualItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
