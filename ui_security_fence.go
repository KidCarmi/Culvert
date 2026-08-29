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

// domainAllowlistRevision derives the threat-feed domain-allowlist revision
// (DomainAllowlist() returns the normalized, sorted entries).
func domainAllowlistRevision() string {
	return contentSecRevision(append([]string{"allowlist"}, globalThreatFeed.DomainAllowlist()...)...)
}

// scanExclusionsRevision derives the scan-exclusion revision (Lists() returns
// both lists normalized + sorted; the section markers keep them unambiguous).
func scanExclusionsRevision() string {
	hashes, hosts := globalScanExclusions.Lists()
	parts := append([]string{"hashes"}, hashes...)
	parts = append(parts, "hosts")
	parts = append(parts, hosts...)
	return contentSecRevision(parts...)
}

// dpiBypassRevision derives the DPI bypass-host revision (BypassHosts()
// returns the normalized, sorted entries).
func dpiBypassRevision() string {
	return contentSecRevision(append([]string{"dpi-bypass"}, dpiScanner.BypassHosts()...)...)
}

// yaraSettingsRevision derives the YARA engine-settings revision from the six
// live values in canonical order.
func yaraSettingsRevision() string {
	return contentSecRevision("yara-settings",
		fmt.Sprintf("%t", yaraGetEnabled()),
		fmt.Sprintf("%d", yaraGetTimeoutSecs()),
		fmt.Sprintf("%d", yaraGetMaxInflight()),
		yaraGetOnTimeout(),
		yaraGetOnSaturation(),
		fmt.Sprintf("%t", yaraGetAlertDegraded()),
	)
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
