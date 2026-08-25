// Package fileblock is the file-type blocking engine: an extension/MIME/
// Content-Disposition blocklist (FileBlocker) and named file-type profiles
// (FileProfileStore, in fileprofile.go). It depends only on the shared seam
// (internal/obs for logging, internal/fileutil for atomic persistence) and the
// standard library — no dependency on the rest of Culvert (ADR-0002 leaf,
// unblocked by the ADR-0003 seam).
package fileblock

import (
	"encoding/json"
	"fmt"
	"mime"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// FileBlocker holds the set of file extensions to block.
// Extensions are normalised to lowercase with a leading dot (e.g. ".exe").
// All operations are safe for concurrent use. Persists to a JSON file when
// a path is configured via SetPath().
//
// ── The per-transaction gate is LOCK-FREE ─────────────────────────────────────
//
// CheckPath runs on every plain-HTTP request (proxy.go preDispatchBlocked) and
// every SSL-inspected inner request; CheckContentType and
// CheckContentDisposition run on every plain-HTTP response (proxy_http.go
// blockedByResponseHeaders) and every inspected response (proxy_tunnel.go
// inspectFileBlocked). So one inspected transaction reached this store up to
// THREE times, and each probe took mu.RLock — an atomic read-modify-write on
// ONE process-wide word — purely to read a set that in steady state never
// changes (the shipped default is ten extensions seeded once at startup).
//
// That is not a constant cost but a THROUGHPUT CEILING, the same shape already
// recorded for internal/threatfeed, security.go's IP filter, internal/connlimit
// and metrics.go's latency histogram. Measured on this machine (4-core Xeon,
// Go 1.26, CheckPath against "/static/app.js", medians of n=6):
//
//	       │ 1 core  │ 4x parallel │ what four cores bought
//	before │ 27.6 ns │   135.5 ns  │ 0.82x of ONE core — cores SUBTRACTED throughput
//	after  │ 19.4 ns │    25.8 ns  │ 3.0x, i.e. 5.3x the old four-core ceiling
//
// The absolute numbers are load-sensitive by construction (a contended lock
// degrades further the busier the box is); quote the SHAPE, not the constants.
//
// Reads now go through an immutable view published via atomic.Pointer. THE
// CONTRACT IS ONE LINE AND IT IS LOAD-BEARING: a map reachable from a published
// view is never mutated in place. The mu-guarded fields stay the AUTHORITATIVE
// write-side state — every mutator keeps its exact prior semantics and calls
// publishLocked() before releasing the lock. Adding a mutator without that call
// is a silent SECURITY failure, not a performance one (a newly-blocked
// extension that never blocks, a removed one that keeps blocking), so it is
// pinned per mutator by TestBlockerView_EveryMutatorRepublishes.
//
// publishLocked COPIES rather than aliasing, so an Add loop is O(N) per call.
// That introduces no new complexity class: Add already calls save(), which
// marshals the WHOLE set and rewrites the file on every single call, so the
// bulk paths were quadratic in bytes-to-disk before this change and the map
// copy is strictly cheaper than the marshal it sits beside. ReplaceAll remains
// the batch entry point for bulk loads (CL-13).
type FileBlocker struct {
	mu         sync.RWMutex
	extensions map[string]bool
	path       string // persistence file (e.g. /data/fileblock.json); "" = no persistence

	// view is the immutable read side, rebuilt by publishLocked on every
	// mutation. Nil until the first publish, which is indistinguishable from an
	// empty set — the shape a zero-valued FileBlocker already had.
	view atomic.Pointer[blockerView]
}

// blockerView is the immutable snapshot the per-transaction checks read. Its
// map is never mutated after publication (see FileBlocker's contract note).
type blockerView struct {
	extensions map[string]bool
}

// blockedExt reports whether ext (already normalised) is in the published
// block set. Lock-free and allocation-free; safe on a never-published view.
func (fb *FileBlocker) blockedExt(ext string) bool {
	v := fb.view.Load()
	return v != nil && v.extensions[ext]
}

// publishLocked rebuilds the immutable read view from the authoritative map.
// Callers MUST hold fb.mu for writing.
func (fb *FileBlocker) publishLocked() {
	cp := make(map[string]bool, len(fb.extensions))
	for ext, on := range fb.extensions {
		cp[ext] = on
	}
	fb.view.Store(&blockerView{extensions: cp})
}

// NewBlocker returns an empty, ready-to-use FileBlocker. package main holds the
// process-wide singleton (var fileBlocker = fileblock.NewBlocker()).
func NewBlocker() *FileBlocker {
	fb := &FileBlocker{extensions: map[string]bool{}}
	fb.view.Store(&blockerView{extensions: map[string]bool{}})
	return fb
}

// SetPath configures the persistence file and loads any previously saved
// extensions from it. If the file doesn't exist, the current in-memory
// state is kept (caller should load defaults before calling SetPath).
func (fb *FileBlocker) SetPath(p string) {
	fb.mu.Lock()
	fb.path = p
	fb.mu.Unlock()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p) // #nosec G304 -- operator-configured persistence path
	if err != nil {
		return // file doesn't exist yet — keep current state
	}
	var exts []string
	if json.Unmarshal(data, &exts) != nil {
		return
	}
	fb.mu.Lock()
	fb.extensions = map[string]bool{}
	for _, ext := range exts {
		fb.extensions[fb.norm(ext)] = true
	}
	fb.publishLocked()
	fb.mu.Unlock()
}

// save persists the current extension list to the configured file.
// Called internally after Add/Remove/ClearAll — no-op if no path is set.
func (fb *FileBlocker) save() {
	if fb.path == "" {
		return
	}
	exts := make([]string, 0, len(fb.extensions))
	for ext := range fb.extensions {
		exts = append(exts, ext)
	}
	data, _ := json.Marshal(exts)
	_ = fileutil.AtomicWrite(fb.path, data, 0o600)
}

// DefaultBlockedExts is loaded at startup when no config override is provided.
// Covers common Windows malware/script delivery formats.
var DefaultBlockedExts = []string{
	".exe", ".dll", ".bat", ".cmd", ".ps1",
	".vbs", ".scr", ".msi", ".pif", ".com",
}

func (fb *FileBlocker) norm(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	if ext != "" && !strings.HasPrefix(ext, ".") {
		return "." + ext
	}
	return ext
}

// Add inserts a normalised extension into the block list and persists.
func (fb *FileBlocker) Add(ext string) {
	ext = fb.norm(ext)
	if ext == "" || ext == "." {
		return
	}
	fb.mu.Lock()
	fb.extensions[ext] = true
	fb.publishLocked()
	fb.save()
	fb.mu.Unlock()
}

// ReplaceAll atomically replaces the in-memory extension set with
// the normalised contents of exts and persists once. Per-element
// semantics mirror Add exactly: lowercase + trim, leading-dot
// inserted if missing, empty / bare-dot entries skipped,
// duplicates collapsed by the set.
//
// CL-13: used by applyConfigSnapshot's FileBlockExtensions branch
// to replace the prior ClearAll + per-extension Add loop, which
// triggered N+1 atomicWriteFile syscalls per snapshot apply
// (cap 10_000 extensions per maxSnapFileBlockExtensions). ReplaceAll
// triggers exactly one save() call regardless of N.
//
// Save is invoked unconditionally — including when the new set is
// equal to the existing set. Skipping save on equal content would
// require deep-comparing maps under the lock and add a fast-path
// that could deviate from the long-term durability guarantee, which
// is out of CL-13 scope per the user brief.
func (fb *FileBlocker) ReplaceAll(exts []string) {
	newSet := make(map[string]bool, len(exts))
	for _, e := range exts {
		e = fb.norm(e)
		if e == "" || e == "." {
			continue
		}
		newSet[e] = true
	}
	fb.mu.Lock()
	fb.extensions = newSet
	fb.publishLocked()
	fb.save()
	fb.mu.Unlock()
}

// Remove deletes an extension from the block list and persists.
func (fb *FileBlocker) Remove(ext string) {
	ext = fb.norm(ext)
	fb.mu.Lock()
	delete(fb.extensions, ext)
	fb.publishLocked()
	fb.save()
	fb.mu.Unlock()
}

// List returns a snapshot of the blocked extensions.
func (fb *FileBlocker) List() []string {
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	out := make([]string, 0, len(fb.extensions))
	for ext := range fb.extensions {
		out = append(out, ext)
	}
	return out
}

// ClearAll removes all blocked extensions. Used by config import "replace" mode.
func (fb *FileBlocker) ClearAll() {
	fb.mu.Lock()
	fb.extensions = map[string]bool{}
	fb.publishLocked()
	fb.save()
	fb.mu.Unlock()
}

// Count returns the number of blocked extensions.
func (fb *FileBlocker) Count() int {
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	return len(fb.extensions)
}

// CheckPath returns the blocked extension if urlPath ends with a blocked file
// extension, or empty string if the request is allowed.
// Pass r.URL.Path (not the full URL) to avoid matching query-string artefacts.
func (fb *FileBlocker) CheckPath(urlPath string) string {
	ext := strings.ToLower(path.Ext(urlPath))
	if ext == "" {
		return ""
	}
	if fb.blockedExt(ext) {
		return ext
	}
	return ""
}

// CheckExt checks if a specific extension is in the block list.
// Extension should include the dot (e.g., ".exe").
func (fb *FileBlocker) CheckExt(ext string) string {
	ext = fb.norm(ext)
	if ext == "" {
		return ""
	}
	if fb.blockedExt(ext) {
		return ext
	}
	return ""
}

// blockedMIMETypes maps dangerous Content-Type MIME types to their canonical
// file extension. Used by CheckContentType to detect renamed executables
// (e.g. malware.exe renamed to malware.txt still served as application/x-msdownload).
var blockedMIMETypes = map[string]string{
	"application/x-msdownload":                      ".exe",
	"application/x-msdos-program":                   ".exe",
	"application/x-dosexec":                         ".exe",
	"application/x-executable":                      ".exe",
	"application/vnd.microsoft.portable-executable": ".exe",
	"application/x-msi":                             ".msi",
	"application/x-ms-installer":                    ".msi",
	"application/x-bat":                             ".bat",
	"application/x-powershell":                      ".ps1",
	"application/x-vbs":                             ".vbs",
}

// CheckContentType returns the blocked extension if the response Content-Type
// header matches a dangerous MIME type whose associated extension is in the
// block list. This prevents bypass by renaming files (e.g. malware.exe → malware.txt).
// The contentType parameter should be the raw Content-Type header value
// (e.g. "application/x-msdownload; charset=utf-8").
//
// ── Why the media type is decided before the header is parsed ─────────────────
//
// This runs on EVERY proxied response that carries a Content-Type — the
// plain-HTTP forward path (proxy_http.go blockedByResponseHeaders) and the
// SSL-inspect path (proxy_tunnel.go inspectFileBlocked) alike. It consumed the
// full mime.ParseMediaType, which allocates a map[string]string for the header
// PARAMETERS and then walks the header to fill it — and this function discards
// that map. Every response paid it so that a ten-entry lookup could miss.
//
// Measured on this machine (4-core Xeon, Go 1.26, "text/html; charset=utf-8" —
// the shape almost all web traffic carries; medians of n=6):
//
//	before   283.7 ns/op   336 B/op   2 allocs/op
//	after     35.9 ns/op     0 B/op   0 allocs/op
//
// The trade-off is stated rather than papered over: the ten dangerous media
// types now pay the cheap split AND the parse, 341.2 -> 374.8 ns (+10%). They
// are the arm that is about to serve a block page and write two log lines, and
// ordinary traffic never reaches it, so the exchange is accepted deliberately.
// BenchmarkCheckContentType_Dangerous keeps it measurable.
//
// The parse is now reached ONLY for a header whose media type is one of the ten
// dangerous types, i.e. never on ordinary traffic. The pre-filter is a pure
// NEGATIVE one: it can only return the empty (allow) answer early, and every
// BLOCK is still decided by the original body, unchanged, parse included. So
// the malformed-parameter case still declines to block exactly as before —
// ParseMediaType reports ErrInvalidMediaParameter for "application/x-msdownload;
// bogus" and this returns "", which a naive prefix split would have turned into
// a block. That would have been a tightening, but a tightening is still a
// behaviour change in a cost fix, so it is deliberately not taken here.
//
// The equivalence is exact, not approximate. ParseMediaType computes its
// returned mediatype as strings.TrimSpace(strings.ToLower(base)) over
// base, _, _ := strings.Cut(v, ";") — reproduced verbatim below — and returns a
// non-nil error otherwise, in which case the pre-fix body returned "" as well.
// So "candidate is not a blocked MIME type" implies the pre-fix body returned
// "" for every input, including the malformed ones. Pinned against a verbatim
// copy of the pre-fix body by TestCheckContentType_MatchesPreFilterBehaviour
// and FuzzCheckContentType, so an upstream mime behaviour change fails CI
// rather than silently diverging.
func (fb *FileBlocker) CheckContentType(contentType string) string {
	if contentType == "" {
		return ""
	}
	ext, ok := blockedMIMETypes[mediaTypeOf(contentType)]
	if !ok {
		return ""
	}
	// Candidate is a dangerous MIME type: re-decide through the original,
	// unchanged path so parameter validation is preserved byte-for-byte.
	if _, _, err := mime.ParseMediaType(contentType); err != nil {
		return ""
	}
	if fb.blockedExt(ext) {
		return ext
	}
	return ""
}

// mediaTypeOf returns the media type mime.ParseMediaType would report for v,
// without parsing its parameters. It reproduces the stdlib's first two lines
// verbatim (order included — ToLower before TrimSpace), and allocates nothing
// for an already-lowercase header value, which is what real traffic sends.
//
// It is only ever used to decide that a header CANNOT be blocked; a value
// ParseMediaType would reject still reaches ParseMediaType above.
func mediaTypeOf(v string) string {
	base, _, _ := strings.Cut(v, ";")
	return strings.TrimSpace(strings.ToLower(base))
}

// ExtractCDFilename extracts the filename from a Content-Disposition header.
// Returns "" if no filename is found. Used by per-rule file profile checking
// when the download URL doesn't contain the file extension (e.g. SourceForge's
// /files/latest/download pattern).
func ExtractCDFilename(cd string) string {
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	return params["filename"]
}

// CheckContentDisposition returns the blocked extension if the
// Content-Disposition response header carries a filename with a blocked
// extension (catches downloads that use a generic URL but declare the real
// file name in the header).
func (fb *FileBlocker) CheckContentDisposition(cd string) string {
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	filename := params["filename"]
	if filename == "" {
		return ""
	}
	ext := strings.ToLower(path.Ext(filename))
	if ext == "" {
		return ""
	}
	if fb.blockedExt(ext) {
		return ext
	}
	return ""
}

// BlockMessage returns the plain-text body of a file-block 403 for the given
// extension and source label. Exposed so the SSL-inspect path can emit the block
// through its protocol-neutral responder (HTTP/1.1 or HTTP/2) without this
// package owning HTTP framing; the legacy raw-conn BlockConn uses it too.
func BlockMessage(ext, source string) string {
	return fmt.Sprintf("Blocked: file type %s is not allowed (%s)\r\n", ext, source)
}

// LogBlock emits the FILE_BLOCKED tunnel observability line. Split out of
// BlockConn so the SSL-inspect path can log identically while emitting the wire
// block through its own responder (keeping this package framing-free).
func LogBlock(host, urlPath, ext, source string) {
	obs.Printf("FILE_BLOCKED (tunnel %s) -> %q%q (ext=%q)", source, obs.Sanitize(host), obs.Sanitize(urlPath), obs.Sanitize(ext))
}

// BlockConn writes a synthetic HTTP/1.1 403 response to a raw connection and
// closes it. Retained for the raw-conn callers and its own test; the SSL-inspect
// path no longer uses it (it emits via the protocol-neutral blockResponder so the
// same detector serves HTTP/2, where closing the shared conn on a per-stream
// block would kill sibling streams and Connection: close is illegal per RFC 9113
// §8.2.2). The force-close here prevents HTTP/1.1 pipelined-request bypass.
func BlockConn(dst interface {
	Write([]byte) (int, error)
	Close() error
}, host, urlPath, ext, source string) {
	LogBlock(host, urlPath, ext, source)
	body := BlockMessage(ext, source)
	fmt.Fprintf(dst, //nolint:errcheck // best-effort write of the 403 block response
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		len(body), body,
	)
	dst.Close() //nolint:errcheck // force-close prevents pipelined-request bypass
}
