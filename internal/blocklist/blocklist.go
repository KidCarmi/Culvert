// Package blocklist is the host blocklist engine: O(labels) exact/wildcard
// matching with a never-block exceptions list, block/allow modes, sidecar
// persistence (.mode/.manual/.exceptions/.sources), per-feed attribution, and
// hosts-format line normalization. Extracted from package main's store.go per
// ADR-0002 (store.go decomposition, Phase A). The matcher (IsBlocked) sits on
// the proxy/SOCKS5 per-request hot path and moved VERBATIM — same RWMutex,
// same probe sequence. package main keeps the process-wide `bl` singleton and
// every admin/cluster surface behind type aliases.
//
// The probe SEQUENCE is still that original one, verdict for verdict; what has
// changed since the extraction is how each probe's lookup key is built. See
// probePrefixed for why the concatenated keys had to go, and
// blocklist_bench_test.go for the differential test that pins the new bodies
// against the pre-fix ones.
package blocklist

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// New returns an empty Store with initialized maps and the default "block"
// mode — the same shape as the pre-extraction package-main literal.
func New() *Store {
	return &Store{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
}

// Entry is a single blocklist host with its origin.
type Entry struct {
	Host   string `json:"host"`
	Source string `json:"source"`         // "manual" or "feed"
	Feed   string `json:"feed,omitempty"` // feed URL that imported this entry, when known
}

// Store holds two separate maps for O(1) host lookups:
//   - exact:     e.g. "ads.example.com"
//   - wildcards: keyed by dot-prefix, e.g. ".example.com" (from "*.example.com")
//
// IsBlocked walks the host's own dot-labels to probe the wildcards map, so
// lookup cost is O(labels) ≈ O(1) for real-world domain names, regardless of
// how many wildcard rules are loaded. All methods are safe for concurrent use.
type Store struct {
	// mu is a sharded RWMutex: readers on the per-request path take one of 64
	// cache-line-isolated shards, writers take all of them. Mutual exclusion is
	// identical to the sync.RWMutex it replaces — see hotread.go for why the
	// contention had to go and why an atomic.Pointer read view was the wrong
	// instrument for THIS store.
	mu         hotRW
	exact      map[string]bool   // exact hostnames
	wildcards  map[string]bool   // dot-prefixes: ".example.com"
	manual     map[string]bool   // subset added by an admin (not the feed)
	exceptions map[string]bool   // hosts that are NEVER blocked, even if listed
	feedSrc    map[string]string // host → feed URL attribution (lazily initialized)
	path       string
	mode       string // "block" (default) or "allow"

	// syncedFP is the 256-bit XOR-of-SHA256 fingerprint of the
	// CP-AUTHORITATIVE host set the cluster delta-sync path last applied
	// (T3 P1). It is fed ONLY by CP-supplied data (ReplaceFeedEntries /
	// ApplyDelta) and is deliberately DECOUPLED from DP-local manual blocks
	// and from the enforcement maps, so a DP with its own manual blocks still
	// converges to the exact fingerprint the CP advertises. See delta.go.
	syncedFP [32]byte
}

// Mode returns the current list mode: "block" (default) or "allow".
func (b *Store) Mode() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.mode == "allow" {
		return "allow"
	}
	return "block"
}

// SetMode sets the list mode ("allow"; anything else means "block") and
// persists it to the .mode sidecar.
func (b *Store) SetMode(mode string) {
	if mode != "allow" {
		mode = "block"
	}
	b.mu.Lock()
	b.mode = mode
	b.mu.Unlock()
	b.saveMode()
}

// saveMode persists the mode to a sidecar file (<blocklist>.mode).
func (b *Store) saveMode() {
	if b.path == "" {
		return
	}
	_ = fileutil.AtomicWrite(b.path+".mode", []byte(b.mode), 0o600)
}

// loadHostSidecar reads a one-host-per-line sidecar (".manual" /
// ".exceptions"), warning on lines that don't look like hostnames
// (D1.2-flag-F4) but accepting them anyway. lower controls whether
// lines are lowercased (exceptions yes, manual no — preserving the
// pre-extraction byte-for-byte behavior of each loop).
func loadHostSidecar(path, kind string, lower bool) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if lower {
			line = strings.ToLower(line)
		}
		if line == "" {
			continue
		}
		if !looksLikeHostname(line) {
			obs.Printf("Loader: blocklist.%s: line %d at %q does not look like a hostname: %q — accepting anyway (D1.2-flag-F4)", kind, i+1, obs.Sanitize(path), obs.Sanitize(line))
		}
		out[line] = true
	}
	return out
}

// loadFeedSources reads the ".sources" attribution sidecar (host → feed URL).
func loadFeedSources(path string) map[string]string {
	feedSrc := map[string]string{}
	if data, err := os.ReadFile(path); err == nil {
		if jerr := json.Unmarshal(data, &feedSrc); jerr != nil {
			obs.Printf("Loader: blocklist.sources: unparseable %q: %v — attribution reset", obs.Sanitize(path), jerr)
			feedSrc = map[string]string{}
		}
	}
	return feedSrc
}

// scanBlocklistEntries reads the main blocklist file, normalizing every line
// (see NormalizeLine). Entries stored verbatim by pre-normalization
// feed imports ("0.0.0.0 ads.example") are repaired into blockable hostnames;
// unblockable junk rows are dropped, with one summary log line.
func scanBlocklistEntries(f io.Reader, path string) (exact, wildcards map[string]bool, err error) {
	exact = map[string]bool{}
	wildcards = map[string]bool{}
	repaired := 0
	dropped := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Text()
		line, ok := NormalizeLine(raw)
		if !ok {
			if t := strings.TrimSpace(raw); t != "" && !strings.HasPrefix(t, "#") {
				dropped++ // junk entry from a pre-normalization feed import
			}
			continue
		}
		if line != strings.ToLower(strings.TrimSpace(raw)) {
			repaired++ // e.g. "0.0.0.0 ads.example" stored verbatim by old imports
		}
		if strings.HasPrefix(line, "*.") {
			wildcards[line[1:]] = true
		} else {
			exact[line] = true
		}
	}
	if repaired > 0 || dropped > 0 {
		obs.Printf("Blocklist: normalized %d hosts-format entries and dropped %d unblockable entries from %q (pre-normalization feed import); file rewritten on next save", repaired, dropped, obs.Sanitize(path))
	}
	return exact, wildcards, sc.Err()
}

// Load reads the main blocklist file and its sidecars (.mode, .manual,
// .exceptions, .sources) from path, which becomes the persistence path.
func (b *Store) Load(path string) error {
	b.path = path
	// Load mode sidecar.
	if data, err := os.ReadFile(path + ".mode"); err == nil {
		m := strings.TrimSpace(string(data))
		switch {
		case m == "allow":
			b.mode = "allow"
		case m != "":
			// D1.1h: anything other than "allow" silently keeps the
			// default ("block"). Surface it so operators can see typos
			// or case mistakes; behavior unchanged.
			obs.Printf("Loader: blocklist.mode: unrecognized value %q at %q, mode left at default (D1.2-flag-F3)", obs.Sanitize(m), obs.Sanitize(path+".mode"))
		}
	}
	// Sidecars: admin attribution, never-block exceptions, feed attribution.
	manual := loadHostSidecar(path+".manual", "manual", false)
	exceptions := loadHostSidecar(path+".exceptions", "exceptions", true)
	feedSrc := loadFeedSources(path + ".sources")

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	exact, wildcards, scanErr := scanBlocklistEntries(f, path)

	b.mu.Lock()
	b.exact = exact
	b.wildcards = wildcards
	b.manual = manual
	b.exceptions = exceptions
	b.feedSrc = feedSrc
	b.mu.Unlock()
	return scanErr
}

// Save persists the main blocklist file and the pruned .sources attribution
// sidecar (fsynced atomic writes). No-op when no path is set.
func (b *Store) Save() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	var buf strings.Builder
	for h := range b.exact {
		buf.WriteString(h)
		buf.WriteByte('\n')
	}
	for suffix := range b.wildcards {
		// ".example.com" → "*.example.com"
		buf.WriteByte('*')
		buf.WriteString(suffix)
		buf.WriteByte('\n')
	}
	// Feed-source attribution sidecar, pruned to currently-listed,
	// non-manual entries so removed hosts don't accumulate stale rows.
	sources := map[string]string{}
	for h, src := range b.feedSrc {
		if b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if !b.wildcards[h[1:]] {
				continue
			}
		} else if !b.exact[h] {
			continue
		}
		sources[h] = src
	}
	path := b.path
	b.mu.RUnlock()
	// CL-1 / Bucket-4 durability hardening: atomicWriteFile gives
	// unique tmp + chmod + fsync(file) + rename + best-effort
	// fsync(parent dir) — replaces the previous os.OpenFile+os.Rename
	// path which was atomic-via-rename but NOT fsynced.
	_ = fileutil.AtomicWrite(path, []byte(buf.String()), 0o600)
	if data, err := json.Marshal(sources); err == nil {
		_ = fileutil.AtomicWrite(path+".sources", data, 0o600)
	}
}

// hostKeyProbeMax bounds the stack scratch buffer probePrefixed uses to build
// a prefixed lookup key. A DNS name is at most 253 bytes (RFC 1035 §2.3.4), so
// this covers every legitimate host plus the two-byte "*." prefix with room to
// spare; a longer host falls back to the plain concatenation, which is equally
// correct and simply allocates as it always did.
const hostKeyProbeMax = 255

// probePrefixed reports whether m contains the key prefix+host, WITHOUT
// building that key on the heap.
//
// The probes it replaces sit on the per-request proxy hot path (IsBlocked runs
// on every HTTP, CONNECT, WebSocket and SOCKS5 destination) and each one built
// a throwaway string only to index a map with it. Go's compiler hands a
// non-escaping concatenation a 32-byte stack buffer, so the cost was invisible
// on a short hostname and a heap allocation on a long one — and long is the
// ordinary shape in real traffic (regional cloud and CDN endpoints such as
// "very-long-subdomain.assets.cdn.example-corporation.com" run well past 30
// bytes). Measured on that host with NO exceptions configured at all — the
// default posture, where every probe misses an EMPTY map:
//
//	before   415 ns/op   176 B/op   3 allocs/op
//	after    181 ns/op     0 B/op   0 allocs/op
//
// The full before/after table across host shapes and both postures lives in
// blocklist_bench_test.go, whose baseline benchmark runs these exact pre-fix
// bodies in the same binary.
//
// Two mechanisms, both behaviour-preserving:
//
//   - len(m) == 0 short-circuits. Indexing an empty map always misses, so the
//     answer is unchanged; this is what erases the whole exception walk on a
//     store with no exceptions.
//   - m[string(buf[:n])] is the compiler's no-copy map-index form: the string
//     conversion of a byte slice used directly as a map key does not allocate,
//     so the key lives on the stack for the length of the lookup and nowhere
//     else. The map itself never sees the buffer — only the bytes are compared.
func probePrefixed(m map[string]bool, prefix, host string) bool {
	if len(m) == 0 {
		return false
	}
	n := len(prefix) + len(host)
	if n > hostKeyProbeMax {
		return m[prefix+host]
	}
	var buf [hostKeyProbeMax]byte
	copy(buf[:], prefix)
	copy(buf[len(prefix):], host)
	return m[string(buf[:n])]
}

// isListed reports whether host matches any entry in the list (mode-agnostic).
//
// The label walk indexes bytes rather than ranging over runes. '.' (0x2E) is
// ASCII, and no byte of a multi-byte UTF-8 sequence can equal it, so the two
// forms visit exactly the same dot positions — the byte form just skips the
// rune decoding on the way.
func (b *Store) isListed(host string) bool {
	if b.exact[host] {
		return true
	}
	if len(b.wildcards) == 0 {
		return false
	}
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && b.wildcards[host[i:]] {
			return true
		}
	}
	return probePrefixed(b.wildcards, ".", host)
}

// isExcepted returns true when host or any of its parent domains is in the
// exceptions list. Supports exact hosts, parent-domain inheritance, and
// wildcard entries (stored as "*.example.com").
// Must be called with b.mu held (at least RLock).
func (b *Store) isExcepted(host string) bool {
	// No exceptions configured — the default posture — so every probe below
	// would miss an empty map. Answer without walking the labels at all.
	if len(b.exceptions) == 0 {
		return false
	}
	if b.exceptions[host] {
		return true
	}
	// Check if a wildcard exception covers this exact host
	// e.g. "*.raw.githubusercontent.com" should match "raw.githubusercontent.com"
	if probePrefixed(b.exceptions, "*.", host) {
		return true
	}
	// Walk parent domains: sub.example.com → example.com → com
	// Each dot boundary is also checked as a wildcard pattern *.parent.
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			parent := host[i+1:]
			if b.exceptions[parent] {
				return true
			}
			// e.g. "*.example.com" stored literally in exceptions
			if probePrefixed(b.exceptions, "*.", parent) {
				return true
			}
		}
	}
	return false
}

// AddException marks host as permanently exempt from blocking.
// Feed syncs will still add the host to the blocklist, but IsBlocked will
// always return false for it.
func (b *Store) AddException(host string) {
	host = hostutil.NormalizeHost(strings.TrimSpace(host))
	if host == "" {
		return
	}
	// Warn on overly broad exceptions that may exempt many domains.
	bare := strings.TrimPrefix(host, "*.")
	parts := strings.Split(bare, ".")
	if len(parts) <= 1 || (len(parts) == 2 && strings.HasPrefix(host, "*.")) {
		obs.Warnf("Blocklist: broad exception added: %q — may exempt many domains", obs.Sanitize(host))
	}
	b.mu.Lock()
	b.exceptions[host] = true
	b.mu.Unlock()
	b.saveExceptions()
}

// RemoveException removes an exception, allowing the host to be blocked again.
func (b *Store) RemoveException(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	delete(b.exceptions, host)
	b.mu.Unlock()
	b.saveExceptions()
}

// ListExceptions returns a sorted list of all exception hosts.
func (b *Store) ListExceptions() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.exceptions))
	for h := range b.exceptions {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// saveExceptions persists the exceptions set to a sidecar file.
func (b *Store) saveExceptions() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	var sb strings.Builder
	for h := range b.exceptions {
		fmt.Fprintln(&sb, h)
	}
	_ = fileutil.AtomicWrite(b.path+".exceptions", []byte(sb.String()), 0o600)
}

// looksLikeHostname returns true if s plausibly resembles a hostname.
// Used only by Blocklist.Load for D1.1h observability logging — the
// loader still accepts arbitrary lines regardless. The check is
// intentionally loose: just enough to flag obviously-not-a-host
// content (whitespace, special chars, control bytes).
func looksLikeHostname(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '*':
		default:
			return false
		}
	}
	return true
}

// IsBlocked reports whether a request to host should be blocked.
// In "block" mode (default): listed hosts are blocked.
// In "allow" mode:           only listed hosts are allowed; all others blocked.
// Exceptions always pass through regardless of mode or list membership.
func (b *Store) IsBlocked(host string) bool {
	host = hostutil.NormalizeHost(host)
	// The per-request hot path: one sharded read lock instead of the single
	// process-wide one every proxied destination used to serialise on. The
	// probe sequence below is unchanged, verdict for verdict. See hotread.go.
	sh := b.mu.rlockHot()
	defer sh.RUnlock()
	if b.isExcepted(host) {
		return false
	}
	listed := b.isListed(host)
	if b.mode == "allow" {
		return !listed
	}
	return listed
}

// Add inserts host ("*.example.com" → wildcard, otherwise exact) without
// persisting — the feed-sync path batches its own Save.
func (b *Store) Add(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	if strings.HasPrefix(host, "*.") {
		b.wildcards[host[1:]] = true
	} else {
		b.exact[host] = true
	}
	b.mu.Unlock()
}

// ReplaceFeedEntries replaces the feed-pushed entries (exact +
// wildcards) in place, leaving DP-local state (path, mode, manual,
// exceptions) intact. Used by applyConfigSnapshot to avoid the
// wholesale-replacement pattern that previously zeroed those
// local fields and orphaned the persistence path. Per-host parsing
// mirrors Add: "*.example.com" → wildcard, otherwise → exact.
//
// IMPORTANT: AddManual (below) writes admin-added hosts
// to BOTH the metadata map (b.manual) AND the enforcement maps
// (b.exact / b.wildcards). The enforcement maps are what IsBlocked
// consults; b.manual is just the attribution set. We therefore
// re-inject every b.manual host into the new enforcement maps
// before the swap so admin-added blocks survive every cluster
// sync. Without this re-injection (pre-fix and my first-pass
// ReplaceFeedEntries had the same defect; flagged by Codex on
// PR #249), admin manual blocks would silently disappear from
// enforcement on every snapshot apply.
func (b *Store) ReplaceFeedEntries(hosts []string) {
	newExact := map[string]bool{}
	newWildcards := map[string]bool{}
	// Recompute the CP-authoritative synced fingerprint over the incoming set
	// (T3 P1). A full apply is the ground-truth reset for syncedFP — it heals
	// any drift a malformed delta stream could have introduced. Computed here,
	// before the lock, so the O(N) hashing never stalls IsBlocked. The
	// fingerprint is over the CP list ONLY (no manual re-injection) because the
	// synced set the CP advertises does not include DP-local manual blocks.
	fp := feedSetFingerprint(hosts)
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			newWildcards[h[1:]] = true
		} else {
			newExact[h] = true
		}
	}
	b.mu.Lock()
	b.syncedFP = fp
	// Re-inject admin-added manual entries into the enforcement
	// maps. b.manual is the attribution set; the entries are also
	// normalised at AddManual time so no further trim/lowercase is
	// needed here.
	for h := range b.manual {
		if strings.HasPrefix(h, "*.") {
			newWildcards[h[1:]] = true
		} else {
			newExact[h] = true
		}
	}
	b.exact = newExact
	b.wildcards = newWildcards
	b.mu.Unlock()
}

// AddManual adds a host and marks it as manually managed by an admin.
// Unlike Add (used by the feed syncer), this persists both the source
// attribution (the .manual sidecar via saveManual) AND the enforcement
// state (the main blocklist file via Save). The dual save makes the call
// self-durable so a caller path that bails before its own deferred Save
// (e.g. the apiBlocklist POST handler returning early on an invalid
// wildcard mid-loop, ui_policy.go) cannot leave manual entries in
// memory + sidecar but missing from the main file — which would not
// survive restart, because Load reads the main file into b.exact /
// b.wildcards (the maps IsBlocked consults) and the .manual sidecar
// only restores attribution metadata.
//
// For bulk admin requests, prefer AddManualBulk: it does one save for
// N hosts instead of N saves, avoiding the O(hosts × blocklist-size)
// rewrite when the main file is large (e.g. a feed-backed blocklist
// with hundreds of thousands of entries). Codex P2 review on PR #283.
func (b *Store) AddManual(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	if strings.HasPrefix(host, "*.") {
		b.wildcards[host[1:]] = true
	} else {
		b.exact[host] = true
	}
	b.manual[host] = true
	b.mu.Unlock()
	b.saveManual()
	b.Save()
}

// AddManualBulk adds multiple hosts as manually-managed admin entries
// under a single write lock with a single saveManual + single Save call,
// instead of one save per host. Use this for bulk admin requests; the
// per-host normalization and dedupe match AddManual exactly (lowercase
// + trim, empty hosts skipped, "*." → wildcard, otherwise exact). The
// caller is responsible for any validation (length cap, wildcard
// format) before invoking this method — invalid entries reaching here
// are silently accepted, mirroring AddManual.
//
// Returns the number of unique normalized entries actually stored by
// THIS call — i.e. hosts whose admin attribution (b.manual) went from
// false to true. Within-batch duplicates count once; cross-call repeats
// of an already-attributed host count as 0. This matches the caller's
// expectation that "added: N" in the API response and audit line
// reflects net new admin entries, not raw non-empty input count. A
// zero return means no on-disk write happens, so calling with an empty
// or all-blank slice (or an all-duplicates slice) is a cheap no-op.
//
// Added per the Codex P2 review on PR #283: with per-call Save() inside
// AddManual, a bulk POST of N hosts to a feed-backed blocklist rewrote
// the entire main file N times (O(hosts × blocklist-size) disk work).
// This save-once path preserves the durability guarantee while keeping
// bulk cost O(blocklist-size).
func (b *Store) AddManualBulk(hosts []string) int {
	if len(hosts) == 0 {
		return 0
	}
	added := 0
	// dirty tracks whether ANY map (b.exact, b.wildcards, b.manual)
	// flipped a key from false to true during this call. Save() must
	// run on any flip — not only on a b.manual flip — so that recovery
	// paths (e.g. a pre-fix-era stale main file where b.manual still
	// has an entry but b.exact lost it) re-persist the now-corrected
	// enforcement state. added is kept separate because it only counts
	// net new admin attributions (b.manual false→true), which is the
	// honest "stored by this call" number the API response and audit
	// line should report.
	dirty := false
	b.mu.Lock()
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			if !b.wildcards[host[1:]] {
				b.wildcards[host[1:]] = true
				dirty = true
			}
		} else {
			if !b.exact[host] {
				b.exact[host] = true
				dirty = true
			}
		}
		if !b.manual[host] {
			b.manual[host] = true
			dirty = true
			added++
		}
	}
	b.mu.Unlock()
	if dirty {
		b.saveManual()
		b.Save()
	}
	return added
}

// saveManual persists the set of manually-added hosts to a sidecar file.
func (b *Store) saveManual() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	var sb strings.Builder
	for h := range b.manual {
		fmt.Fprintln(&sb, h)
	}
	_ = fileutil.AtomicWrite(b.path+".manual", []byte(sb.String()), 0o600)
}

// Remove deletes host from the enforcement maps, the manual set, and the
// feed attribution, persisting the .manual sidecar.
func (b *Store) Remove(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	if strings.HasPrefix(host, "*.") {
		delete(b.wildcards, host[1:])
	} else {
		delete(b.exact, host)
	}
	delete(b.manual, host)
	delete(b.feedSrc, host)
	b.mu.Unlock()
	b.saveManual()
}

// List returns all entries; wildcards are rendered as "*.example.com".
func (b *Store) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.exact)+len(b.wildcards))
	for h := range b.exact {
		out = append(out, h)
	}
	for suffix := range b.wildcards {
		out = append(out, "*"+suffix)
	}
	return out
}

// FeedList returns the CP-authoritative (non-manual) entries — the synced set —
// with wildcards rendered as "*.example.com". The delta path persists this as the
// last-good BlockedHosts so a cold restart reconstructs a fingerprint-consistent
// synced set: List() would fold in DP-local manual blocks the CP set never had,
// which on reload would poison syncedFP relative to the CP's feed-only target.
// (Enforcement of manual blocks is unaffected — ReplaceFeedEntries re-injects
// b.manual on every apply.)
func (b *Store) FeedList() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.exact)+len(b.wildcards))
	for h := range b.exact {
		if !b.manual[h] {
			out = append(out, h)
		}
	}
	for suffix := range b.wildcards {
		if h := "*" + suffix; !b.manual[h] {
			out = append(out, h)
		}
	}
	return out
}

// ListWithSource returns all blocklist entries annotated with their origin:
// "manual" if added by an admin via the UI/API, "feed" if imported from a feed.
func (b *Store) ListWithSource() []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Entry, 0, len(b.exact)+len(b.wildcards))
	for h := range b.exact {
		src, feed := "feed", b.feedSrc[h]
		if b.manual[h] {
			src, feed = "manual", ""
		}
		out = append(out, Entry{Host: h, Source: src, Feed: feed})
	}
	for suffix := range b.wildcards {
		h := "*" + suffix
		src, feed := "feed", b.feedSrc[h]
		if b.manual[h] {
			src, feed = "manual", ""
		}
		out = append(out, Entry{Host: h, Source: src, Feed: feed})
	}
	return out
}

// Count returns the number of entries (exact + wildcard).
func (b *Store) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.exact) + len(b.wildcards)
}

// ClearAll removes all blocklist entries (exact, wildcard, manual) but preserves
// exceptions and mode. Used by config import "replace" mode.
func (b *Store) ClearAll() {
	b.mu.Lock()
	b.exact = map[string]bool{}
	b.wildcards = map[string]bool{}
	b.manual = map[string]bool{}
	b.feedSrc = map[string]string{}
	b.mu.Unlock()
}

// RemoveByFeedSource removes every entry attributed to feedURL (cascade
// delete when the admin removes a feed AND opts to purge its imports).
// Admin-added (manual) entries always survive. Returns the removed count.
func (b *Store) RemoveByFeedSource(feedURL string) int {
	b.mu.Lock()
	removed := 0
	for h, src := range b.feedSrc {
		if src != feedURL || b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if b.wildcards[h[1:]] {
				delete(b.wildcards, h[1:])
				removed++
			}
		} else if b.exact[h] {
			delete(b.exact, h)
			removed++
		}
		delete(b.feedSrc, h)
	}
	b.mu.Unlock()
	if removed > 0 {
		b.Save()
	}
	return removed
}

// CountByFeedSource reports how many currently-listed, non-manual entries
// are attributed to feedURL (the number a cascade delete would remove).
func (b *Store) CountByFeedSource(feedURL string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := 0
	for h, src := range b.feedSrc {
		if src != feedURL || b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if b.wildcards[h[1:]] {
				n++
			}
		} else if b.exact[h] {
			n++
		}
	}
	return n
}

// SnapshotFeedSources returns a copy of the per-entry feed attribution map.
// Taken before a wholesale rebuild (config rollback / import-replace) so
// RestoreFeedSources can re-stamp surviving entries afterwards.
func (b *Store) SnapshotFeedSources() map[string]string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	snap := make(map[string]string, len(b.feedSrc))
	for h, src := range b.feedSrc {
		snap[h] = src
	}
	return snap
}

// RestoreFeedSources re-stamps feed attribution onto currently-listed,
// non-manual entries after a wholesale rebuild. Config rollback and
// import-replace go through Remove/ClearAll + Add, which would otherwise
// strand every feed entry as "unknown origin" — making them prey for the
// unattributed-cleanup operation (Codex P1, PR #447). Attribution already
// present (e.g. re-stamped by a sync mid-rebuild) is not overwritten.
func (b *Store) RestoreFeedSources(snap map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.feedSrc == nil {
		b.feedSrc = map[string]string{}
	}
	for h, src := range snap {
		if b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if !b.wildcards[h[1:]] {
				continue
			}
		} else if !b.exact[h] {
			continue
		}
		if _, exists := b.feedSrc[h]; !exists {
			b.feedSrc[h] = src
		}
	}
}

// RemoveUnattributedFeedEntries removes every feed-owned entry with no
// recorded source — the legacy cohort imported before per-feed attribution
// existed and no longer present in any current feed (a host still carried
// by a configured feed is re-stamped on every sync, so it never stays
// unattributed for long). Admin-added entries always survive. Returns the
// removed count.
func (b *Store) RemoveUnattributedFeedEntries() int {
	b.mu.Lock()
	removed := 0
	for h := range b.exact {
		if b.manual[h] || b.feedSrc[h] != "" {
			continue
		}
		delete(b.exact, h)
		removed++
	}
	for suffix := range b.wildcards {
		h := "*" + suffix
		if b.manual[h] || b.feedSrc[h] != "" {
			continue
		}
		delete(b.wildcards, suffix)
		removed++
	}
	b.mu.Unlock()
	if removed > 0 {
		b.Save()
	}
	return removed
}

// hostsFileBoilerplate lists names that appear in the standard header of
// /etc/hosts-format feeds (e.g. StevenBlack). They are never legitimately
// blockable upstream hosts, so hosts-format lines naming them are skipped.
var hostsFileBoilerplate = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true,
}

// NormalizeLine extracts the blockable host from one feed or
// blocklist-file line. It handles plain domain lists, /etc/hosts format
// ("0.0.0.0 domain" / "127.0.0.1 domain"), inline comments, accidental
// schemes, and trailing paths/ports. Returns ok=false for lines that carry
// no blockable host (comments, hosts-file boilerplate, unspecified/loopback
// IPs). Wildcard entries ("*.example.com") pass through untouched.
func NormalizeLine(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	// Inline comment: "0.0.0.0 ads.example # comment".
	if i := strings.Index(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	// /etc/hosts format: "<ip> <host> [aliases…]" — take the first host.
	hostsFormat := false
	if fields := strings.Fields(line); len(fields) == 0 {
		return "", false
	} else if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
		line = fields[1]
		hostsFormat = true
	} else {
		line = fields[0]
	}
	// Strip scheme if someone accidentally includes it.
	if i := strings.Index(line, "://"); i >= 0 {
		line = line[i+3:]
	}
	// Strip path/query/port.
	if i := strings.IndexAny(line, "/:?"); i >= 0 {
		line = line[:i]
	}
	line = strings.ToLower(line)
	// Canonicalize FQDN trailing dot ("example.com." ≡ "example.com") so
	// both spellings can't coexist as near-duplicate entries.
	line = strings.TrimSuffix(line, ".")
	if line == "" {
		return "", false
	}
	// "0.0.0.0 0.0.0.0" and friends: an unspecified/loopback IP is not a
	// blockable upstream host.
	if ip := net.ParseIP(line); ip != nil && (ip.IsUnspecified() || ip.IsLoopback()) {
		return "", false
	}
	if hostsFormat && hostsFileBoilerplate[line] {
		return "", false
	}
	return line, true
}

// MergeFromLines adds all valid host entries from lines to the blocklist and
// saves it. Existing entries are NOT removed — safe to call on a live
// blocklist. Lines starting with '#' or empty are skipped; /etc/hosts-format
// lines are normalized to their hostname (see NormalizeLine). source is the
// feed URL recorded as per-entry attribution ("" = none). Returns the number
// of newly-added entries.
func (b *Store) MergeFromLines(lines []string, source string) int {
	added := 0
	attributed := false
	b.mu.Lock()
	for _, raw := range lines {
		line, ok := NormalizeLine(raw)
		if !ok {
			continue
		}
		if strings.HasPrefix(line, "*.") {
			key := line[1:] // ".example.com"
			if !b.wildcards[key] {
				b.wildcards[key] = true
				added++
			}
		} else if !b.exact[line] {
			b.exact[line] = true
			added++
		}
		// Stamp attribution on feed-owned entries (also retroactively on
		// re-sync, so pre-attribution entries converge). Admin-added
		// entries keep their "manual" badge — ListWithSource checks
		// b.manual first. attributed only flips on an actual change so
		// steady-state re-syncs (already attributed, nothing new) don't
		// trigger a full-file rewrite.
		if source != "" && !b.manual[line] {
			if b.feedSrc == nil {
				b.feedSrc = map[string]string{}
			}
			if b.feedSrc[line] != source {
				b.feedSrc[line] = source
				attributed = true
			}
		}
	}
	b.mu.Unlock()
	// attributed alone must also save: a re-sync that only stamps
	// attribution on already-listed hosts (e.g. entries repaired by Load
	// or imported before the .sources sidecar existed) would otherwise
	// hold the attribution in memory only and lose it on restart
	// (Codex P2, PR #438).
	if added > 0 || attributed {
		b.Save()
	}
	return added
}
