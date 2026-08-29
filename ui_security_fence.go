package main

// ui_security_fence.go — 2E-A Content Security stale-writer fences + shared
// helpers (Batch-2 structured-conflict doctrine applied to the security-scan
// configuration surfaces).
//
// CONTRACT: the whole-set/config-style writes (threat-feed domain allowlist,
// YARA engine settings, scan exclusions, DPI bypass) and the per-file YARA
// rule writes accept an OPTIONAL `ifRevision` assertion. When present it must
// equal the surface's current content-derived revision or the write is the
// ONE structured 409 {error, currentRevision, yourRevision} with no mutation.
// When absent, the pre-fence last-writer-wins contract is preserved verbatim
// (legacy compat — the v2 frontend always asserts). GET responses carry the
// current `revision`. Revisions are DERIVED from canonical content (no new
// persisted state, no schema change), so they are identical across restarts
// for identical content and never need migration.
//
// SERIALIZATION: contentSecMu serializes every fenced read-compare-apply-save
// section, so two racing fenced writers cannot both pass the compare. The
// YARA-settings surface fences inside saveAdminSettingsWithOverrides'
// precondition instead (adminSettingsMu is that surface's writer domain).
// Bulk doors (config import/rollback, CP→DP snapshot apply, startup seeds)
// deliberately bypass the fence — they install validated whole candidates
// under their own established domains, matching the 2D convention.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
)

// contentSecMu serializes the fenced admin writes on the content-security
// surfaces (admin-rate; never taken on a request-path read).
var contentSecMu sync.Mutex

// contentSecGETPauseHook, when non-nil, is invoked by the content-security GET
// handlers after assembling the response state and before writing it — a
// deterministic interleaving seam so tests can land a concurrent writer at the
// exact read boundary without sleeps. nil in production (the call is a nil
// check and nothing else); never set outside tests.
var contentSecGETPauseHook func(surface string)

// contentSecGETPause fires the test-only GET interleaving seam.
func contentSecGETPause(surface string) {
	if h := contentSecGETPauseHook; h != nil {
		h(surface)
	}
}

// contentSecRevision derives a deterministic revision string from canonical
// content parts. Length-framed so ("ab","c") never collides with ("a","bc").
func contentSecRevision(parts ...string) string {
	h := sha256.New()
	var frame [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(frame[:], uint64(len(p)))
		h.Write(frame[:])
		h.Write([]byte(p))
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// COHERENT {state, revision(state)} PAIRS (2E-A-2 §1): every fenced GET (and
// every fenced PUT's success response) derives its revision from the SAME
// single committed store snapshot it returns — never from a second store read,
// which could interleave with a writer and emit data=A with revision(B) (a
// token that lets a stale A-based write pass the fence against state B). The
// three list stores each return a coherent copy under one lock
// (threatfeed.DomainAllowlist, scanexcl.Lists, scanner.BypassHosts), so the
// pure *RevisionOf derivations below fingerprint exactly that copy; the YARA
// settings snapshot is taken under adminSettingsMu, the surface's writer
// domain (yaraSettingsSnapshot).

// domainAllowlistRevisionOf derives the threat-feed domain-allowlist revision
// from one returned snapshot (DomainAllowlist() copies are normalized+sorted).
func domainAllowlistRevisionOf(domains []string) string {
	return contentSecRevision(append([]string{"allowlist"}, domains...)...)
}

// domainAllowlistRevision reads the current committed allowlist and derives
// its revision (fence-compare sites; response sites derive from the snapshot
// they return instead).
func domainAllowlistRevision() string {
	return domainAllowlistRevisionOf(globalThreatFeed.DomainAllowlist())
}

// scanExclusionsRevisionOf derives the scan-exclusion revision from one
// returned snapshot pair (Lists() copies are normalized + sorted; the section
// markers keep the two lists unambiguous).
func scanExclusionsRevisionOf(hashes, hosts []string) string {
	parts := append([]string{"hashes"}, hashes...)
	parts = append(parts, "hosts")
	parts = append(parts, hosts...)
	return contentSecRevision(parts...)
}

// scanExclusionsRevision reads the current committed lists and derives their
// revision (fence-compare sites).
func scanExclusionsRevision() string {
	hashes, hosts := globalScanExclusions.Lists()
	return scanExclusionsRevisionOf(hashes, hosts)
}

// dpiBypassRevisionOf derives the DPI bypass-host revision from one returned
// snapshot (BypassHosts() copies are normalized, sorted).
func dpiBypassRevisionOf(hosts []string) string {
	return contentSecRevision(append([]string{"dpi-bypass"}, hosts...)...)
}

// dpiBypassRevision reads the current committed bypass list and derives its
// revision (fence-compare sites).
func dpiBypassRevision() string {
	return dpiBypassRevisionOf(dpiScanner.BypassHosts())
}

// yaraSettingsSnapshot reads the six YARA engine values as ONE coherent
// posture under adminSettingsMu — the surface's writer domain (the settings
// PUT's applyOnSuccess installs all six while holding that mutex, so a
// lock-free reader could observe a torn mix of old and new values).
func yaraSettingsSnapshot() yaraSettingsTarget {
	adminSettingsMu.Lock()
	defer adminSettingsMu.Unlock()
	return yaraSettingsTarget{
		Enabled:       yaraGetEnabled(),
		TimeoutSecs:   yaraGetTimeoutSecs(),
		MaxInflight:   yaraGetMaxInflight(),
		OnTimeout:     yaraGetOnTimeout(),
		OnSaturation:  yaraGetOnSaturation(),
		AlertDegraded: yaraGetAlertDegraded(),
	}
}

// yaraSettingsRevisionOf derives the engine-settings revision from one
// coherent posture snapshot.
func yaraSettingsRevisionOf(s yaraSettingsTarget) string {
	return contentSecRevision("yara-settings",
		fmt.Sprintf("%t", s.Enabled),
		fmt.Sprintf("%d", s.TimeoutSecs),
		fmt.Sprintf("%d", s.MaxInflight),
		s.OnTimeout,
		s.OnSaturation,
		fmt.Sprintf("%t", s.AlertDegraded),
	)
}

// yaraSettingsMapOf renders one coherent posture snapshot for JSON responses
// and audit diffs.
func yaraSettingsMapOf(s yaraSettingsTarget) map[string]any {
	return map[string]any{
		"enabled":        s.Enabled,
		"timeout_secs":   s.TimeoutSecs,
		"max_inflight":   s.MaxInflight,
		"on_timeout":     s.OnTimeout,
		"on_saturation":  s.OnSaturation,
		"alert_degraded": s.AlertDegraded,
	}
}

// yaraSettingsRevision derives the engine-settings revision from the live
// values. ONLY safe where the caller already holds adminSettingsMu (the
// settings PUT precondition) — everywhere else use yaraSettingsSnapshot +
// yaraSettingsRevisionOf so the read is serialized with the writer domain.
func yaraSettingsRevision() string {
	return yaraSettingsRevisionOf(yaraSettingsTarget{
		Enabled:       yaraGetEnabled(),
		TimeoutSecs:   yaraGetTimeoutSecs(),
		MaxInflight:   yaraGetMaxInflight(),
		OnTimeout:     yaraGetOnTimeout(),
		OnSaturation:  yaraGetOnSaturation(),
		AlertDegraded: yaraGetAlertDegraded(),
	})
}

// yaraRuleRevision derives a rule FILE's revision from its raw source. The
// create sentinel is the literal "new": a fenced create refuses when the file
// already exists.
func yaraRuleRevision(source string) string {
	return contentSecRevision("yara-rule", source)
}

// yaraRuleCreateSentinel is the ifRevision value a fenced CREATE asserts.
const yaraRuleCreateSentinel = "new"

// writeContentSecRevisionConflict renders the shared structured 409 ({error,
// currentRevision, yourRevision} — one dialect across every fenced surface).
func writeContentSecRevisionConflict(w http.ResponseWriter, surface, current, asserted string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":           surface + " changed since you loaded it — refresh and retry",
		"currentRevision": current,
		"yourRevision":    asserted,
	})
}

// errContentSecRevisionConflict carries a fence conflict out of a
// saveAdminSettingsWithOverrides precondition so the handler can render the
// structured 409 (the YARA-settings surface fences inside that domain).
type errContentSecRevisionConflict struct{ current, asserted string }

func (e errContentSecRevisionConflict) Error() string {
	return "revision conflict: current " + e.current + ", asserted " + e.asserted
}

// redactURLUserinfo strips embedded credentials (userinfo) from a URL before
// it reaches a read surface — a scan-service URL configured as
// http://user:secret@host must never echo the secret to viewers. Unparseable
// input is returned verbatim (it cannot carry parseable userinfo).
func redactURLUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}
