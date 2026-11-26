package main

// CHAOS-129 — the two content-shape blocks are not gated on a scanner.
//
// Archive magic bytes (F4) and Content-Type/magic polyglots (F5) decide from
// the first bytes of a response alone. Before this round both legs reached them
// only from inside the scanner's buffering branch, so in the default posture —
// no ClamAV address, no YARA rules, no sidecar — neither block was evaluated at
// all, and deleting the last YARA rule through the admin API took them away at
// runtime on a YARA-only node. See content_shape.go for the full account.
//
// Every positive assertion below carries a negative control, because a change
// that blocked all traffic, or that corrupted every body it passed, would
// satisfy the positive half on its own.

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/filemagic"
)

// chaos129Zip is a body whose magic bytes say ZIP. Served as text/plain it is
// the polyglot F5 exists to catch; the bytes after the signature are padding,
// since no detection reads them.
func chaos129Zip() []byte {
	return append([]byte("PK\x03\x04"), bytes.Repeat([]byte("A"), 2048)...)
}

// chaos129ISO is a body whose ISO9660 signature sits at sector 16 (0x8001) —
// the one signature outside filemagic.PrefixWindow(). It is the fixture for the
// recorded residue, not for a claim of coverage.
func chaos129ISO() []byte {
	b := make([]byte, 0x8001+len("CD001")+16)
	copy(b[0x8001:], "CD001")
	return b
}

// chaos129HTTPResp builds a plain-HTTP response fixture. Each caller defers a
// close that re-reads resp.Body at close time rather than capturing the handle
// here: the pipeline REPLACES that field on every clean pass, so the body the
// test leaves behind is not always the one it was constructed with.
func chaos129HTTPResp(t *testing.T, body []byte, header http.Header) *http.Response {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        header,
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
}

func chaos129Req() *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://files.example.com/notes.txt", http.NoBody)
	r.RemoteAddr = "198.51.100.9:5555"
	return r
}

// ── The finding, on the plain-HTTP leg ───────────────────────────────────────

// With NO scanner configured — the default posture — a ZIP served as
// text/plain was forwarded with status 200. The same bytes were 403
// POLYGLOT_BLOCKED as soon as an unrelated ClamAV client was configured, which
// is what made the gating a defect rather than a design.
func TestCHAOS129_PlainHTTP_PolyglotBlockedWithNoScannerConfigured(t *testing.T) {
	if globalSecScanner.BodyScanEnabled() || globalRemoteScanner.Enabled() {
		t.Fatal("fixture precondition: this gate must run with no scanner active")
	}
	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, chaos129Zip(), http.Header{"Content-Type": {"text/plain"}})
	defer func() { _ = resp.Body.Close() }()

	handled, readErr := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})

	if !handled {
		t.Fatalf("a ZIP served as text/plain was forwarded with no scanner configured (status %d) — "+
			"the polyglot block was gated on a scanner it does not use", w.Code)
	}
	if readErr != nil {
		t.Errorf("upstreamReadErr = %v, want nil: the origin read succeeded; only the shape verdict blocked", readErr)
	}
	if w.Code == http.StatusOK {
		t.Errorf("status = 200 on a blocked response")
	}
}

// Negative control for the gate above: an ordinary text/plain body must still
// pass, and must arrive BYTE-IDENTICAL. The shape stage reads a prefix off the
// body and reassembles it, so a reassembly bug would silently truncate or
// reorder every plain-HTTP response in the default posture.
func TestCHAOS129_PlainHTTP_CleanBodyPassesIntact(t *testing.T) {
	payload := []byte("the quick brown fox jumps over the lazy dog\n" + strings.Repeat("x", 9000))
	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, payload, http.Header{"Content-Type": {"text/plain"}})
	defer func() { _ = resp.Body.Close() }()

	handled, readErr := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})

	if handled || readErr != nil {
		t.Fatalf("ordinary text was blocked: handled=%v err=%v status=%d", handled, readErr, w.Code)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the reassembled body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled body differs from the origin's: got %d bytes, want %d (first divergence matters more than the count)",
			len(got), len(payload))
	}
	if _, ok := resp.Body.(shapeReassembledBody); !ok {
		t.Errorf("reassembled body is %T, not the wrapper that preserves the origin's Close — "+
			"an io.NopCloser here leaks the upstream body on every clean pass", resp.Body)
	}
}

// A body shorter than the prefix window must not be mistaken for a short read
// or lose bytes. One byte is below every signature length in the table.
func TestCHAOS129_PlainHTTP_BodyShorterThanTheWindowSurvives(t *testing.T) {
	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, []byte("x"), http.Header{"Content-Type": {"text/plain"}})
	defer func() { _ = resp.Body.Close() }()

	handled, _ := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
	if handled {
		t.Fatalf("a one-byte text body was blocked (status %d)", w.Code)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "x" {
		t.Fatalf("body = %q, want %q", got, "x")
	}
}

// An empty body is the degenerate case of the one above: nothing to inspect,
// nothing to reassemble, and it must not be blocked or turned into an error.
func TestCHAOS129_PlainHTTP_EmptyBodySurvives(t *testing.T) {
	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, nil, http.Header{"Content-Type": {"text/plain"}})
	defer func() { _ = resp.Body.Close() }()

	handled, readErr := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
	if handled || readErr != nil {
		t.Fatalf("an empty body was handled: handled=%v err=%v status=%d", handled, readErr, w.Code)
	}
	got, _ := io.ReadAll(resp.Body)
	if len(got) != 0 {
		t.Fatalf("body = %q, want empty", got)
	}
}

// F4 is the half an operator EXPLICITLY turns on, and it was silent too. The
// archive block fires only when the detected extension — or ".zip", which
// blanket-blocks every archive — is in the file blocker (IsBlockedArchive,
// filemagic.go), so in the stock profile it could not have fired anyway and the
// gate above measures F5. This one measures F4: an operator who has blocked
// archive downloads, on a node with no scanner, got nothing.
func TestCHAOS129_PlainHTTP_ConfiguredArchiveBlockWasAlsoSilent(t *testing.T) {
	snapshotFileBlocker(t)
	fileBlocker.ReplaceAll([]string{".zip"})
	zip := chaos129Zip()
	if IsBlockedArchive(zip) == "" {
		t.Fatal("fixture: the file blocker must consider this archive blocked, or the gate proves nothing")
	}
	// application/zip is an HONEST Content-Type for these bytes, so F5 has
	// nothing to say and only F4 can block — which is what isolates the two.
	if reason := CheckMagicVsContentType(zip, "application/zip"); reason != "" {
		t.Fatalf("fixture: the polyglot check must stay silent here, got %q", reason)
	}
	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, zip, http.Header{"Content-Type": {"application/zip"}})
	defer func() { _ = resp.Body.Close() }()

	handled, _ := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
	if !handled {
		t.Fatalf("an archive the operator blocked was forwarded because no scanner was configured (status %d)", w.Code)
	}
}

// ── The arm that was silent WITH a scanner configured ────────────────────────

// A declared Content-Length past the scan window also returned before the
// shape stage, so an origin could place a body outside both content-shape
// blocks by declaring it large — with scanning fully configured. The shape
// stage needs six bytes, so the declaration cannot buy that any more.
func TestCHAOS129_PlainHTTP_OversizedDeclarationStillShapeChecked(t *testing.T) {
	withScanLimit(t, 1024)
	if !globalSecScanner.BodyScanEnabled() {
		t.Fatal("fixture precondition: withScanLimit must leave a scanner active")
	}
	body := chaos129Zip()
	resp := chaos129HTTPResp(t, body, http.Header{"Content-Type": {"text/plain"}})
	defer func() { _ = resp.Body.Close() }()
	resp.ContentLength = int64(len(body)) // 2052 bytes, past the 1024 window
	if resp.ContentLength <= globalSecScanner.MaxBytes() {
		t.Fatalf("fixture: declared length %d must exceed the scan window %d",
			resp.ContentLength, globalSecScanner.MaxBytes())
	}
	w := httptest.NewRecorder()

	handled, _ := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
	if !handled {
		t.Fatalf("an over-declared ZIP served as text/plain was forwarded unshaped (status %d) — "+
			"the declaration still bought a pass on the content-shape blocks", w.Code)
	}
}

// ── The deliberate exemptions this round must not widen ──────────────────────

// The admin-managed host allowlist (Tier 3.3) is the ONE case that leaves the
// response without a shape verdict, on both legs. It has to keep working now
// that the shape stage is reached with no scanner active, or an operator's
// "do not touch this mirror" would have quietly stopped meaning that.
func TestCHAOS129_PlainHTTP_ExcludedHostIsStillExempt(t *testing.T) {
	origHashes, origHosts := globalScanExclusions.Lists()
	t.Cleanup(func() { globalScanExclusions.Replace(origHashes, origHosts) })
	globalScanExclusions.Replace(origHashes, []string{"files.example.com"})

	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, chaos129Zip(), http.Header{"Content-Type": {"text/plain"}})
	defer func() { _ = resp.Body.Close() }()

	handled, _ := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
	if handled {
		t.Fatalf("an excluded host was shape-blocked (status %d) — the allowlist stopped covering this stage", w.Code)
	}
}

// A declared Content-Encoding is deferred to the full-window path, which
// decompresses before deciding. Testing the COMPRESSED bytes instead would
// block a gzip-encoded PDF as "GZIP disguised as application/pdf": the raw
// prefix is gzip magic, and application/pdf is neither an accepted
// content-type for GZIP nor web content exempted as HTTP-compressed. This is
// the false positive the deferral exists to prevent, so it is pinned here.
func TestCHAOS129_PlainHTTP_EncodedBodyIsNotAFalsePositive(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte("%PDF-1.7\n" + strings.Repeat("p", 4096))); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	// Sanity: the raw bytes really do carry gzip magic, so the assertion below
	// is about the deferral and not about a fixture that never triggers.
	if reason := CheckMagicVsContentType(buf.Bytes(), "application/pdf"); reason == "" {
		t.Fatal("fixture: the compressed prefix must look like a polyglot to the checker, or this gate proves nothing")
	}
	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, buf.Bytes(), http.Header{
		"Content-Type":     {"application/pdf"},
		"Content-Encoding": {"gzip"},
	})
	defer func() { _ = resp.Body.Close() }()

	handled, _ := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
	if handled {
		t.Fatalf("a gzip-encoded PDF was blocked as a polyglot (status %d) — the shape stage judged compressed bytes", w.Code)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("encoded body was altered: got %d bytes, want %d", len(got), buf.Len())
	}
}

// ── The recorded residue ─────────────────────────────────────────────────────

// ISO9660 is outside the prefix window by construction, so the shape-only path
// does NOT detect it. That is a deliberate cost decision — reaching it would
// retain filemagic.MaxWindow() bytes per in-flight response to add one type —
// and it is asserted here so the gap stays a recorded residue rather than
// becoming an unnoticed claim. The second half proves the coverage is not lost
// outright: with a scanner configured, the full window still catches it.
func TestCHAOS129_ISO9660_IsTheRecordedResidueOfThePrefixWindow(t *testing.T) {
	if filemagic.PrefixWindow() >= filemagic.MaxWindow() {
		t.Skip("every signature now fits the prefix window; the residue is closed")
	}
	iso := chaos129ISO()
	if filemagic.Detect(iso) == nil {
		t.Fatal("fixture: the ISO body must be detectable when the whole window is available")
	}

	t.Run("no scanner: outside the prefix window", func(t *testing.T) {
		w := httptest.NewRecorder()
		resp := chaos129HTTPResp(t, iso, http.Header{"Content-Type": {"text/plain"}})
		defer func() { _ = resp.Body.Close() }()
		handled, _ := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
		if handled {
			t.Fatalf("ISO9660 was blocked on the prefix window (status %d) — "+
				"update the residue in content_shape.go and the review; this is now coverage, not a gap", w.Code)
		}
	})

	t.Run("scanner configured: the full window still sees it", func(t *testing.T) {
		withScanLimit(t, int64(filemagic.MaxWindow())*2)
		w := httptest.NewRecorder()
		resp := chaos129HTTPResp(t, iso, http.Header{"Content-Type": {"text/plain"}})
		defer func() { _ = resp.Body.Close() }()
		handled, _ := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
		if !handled {
			t.Fatalf("ISO9660 served as text/plain passed the FULL window too (status %d) — "+
				"this is not a window residue, the detection is unreachable", w.Code)
		}
	})
}

// ── Fail-closed on a read error, narrowed to this window ─────────────────────

// The shape stage reads from the origin, so it inherits CHAOS-17's contract:
// an origin that fails inside the first bytes of its own body must not have a
// truncated response forwarded as a success, and the error must reach the
// caller so the upstream breaker is charged (CHAOS-11).
func TestCHAOS129_PlainHTTP_ShapeReadErrorFailsClosed(t *testing.T) {
	w := httptest.NewRecorder()
	resp := chaos129HTTPResp(t, nil, http.Header{"Content-Type": {"text/plain"}})
	defer func() { _ = resp.Body.Close() }()
	resp.ContentLength = -1
	resp.Body = &erroringBody{
		prefix: strings.NewReader(""),
		err:    errors.New("read tcp: connection reset by peer"),
	}

	handled, readErr := scanHTTPResponseBody(w, chaos129Req(), resp, ProxyIdentity{})
	if !handled {
		t.Fatal("a read error inside the shape window was not handled — a truncated body would be forwarded as a success")
	}
	if readErr == nil {
		t.Error("upstreamReadErr = nil: the breaker attribution (CHAOS-11) would credit a parent that failed")
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
}

// ── The same finding, on the SSL-inspect leg ─────────────────────────────────

// bodyNeedsBuffering is false for every content type unless a scanner is
// active, so the inspect leg returned scanClean before inspectMagicStage in
// exactly the same posture. Fixing only the plain-HTTP leg would have left a
// differential between the two legs of one gateway.
func TestCHAOS129_Inspect_PolyglotBlockedWithNoScannerConfigured(t *testing.T) {
	if bodyNeedsBuffering("text/plain") {
		t.Fatal("fixture precondition: this gate must run with no scanner active")
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://files.example.com/notes.txt", http.NoBody)
	body := chaos129Zip()
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		ContentLength: int64(len(body)),
		Body:          &closeSpyBody{Reader: bytes.NewReader(body)},
	}
	br := &spyResponder{}

	out := scanInspectBody(req, req, resp, br, nil, ProxyIdentity{ClientIP: "198.51.100.9"}, "files.example.com", nil)

	if out != scanBlocked {
		t.Fatalf("outcome = %v, want scanBlocked — the inspect leg forwarded a ZIP served as text/plain "+
			"because no scanner was configured", out)
	}
	if br.calls != 1 {
		t.Errorf("block emissions = %d, want exactly 1 through the responder choke point", br.calls)
	}
}

// Negative control for the inspect gate, including body integrity: the inspect
// leg previously left resp.Body untouched in this branch, so the reassembly is
// new there and a bug in it would corrupt every inspected response in the
// default posture. The origin body must also be CLOSED by nobody but the
// caller on a clean pass — a leaked upstream body holds a connection.
func TestCHAOS129_Inspect_CleanBodyPassesIntact(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://files.example.com/notes.txt", http.NoBody)
	payload := []byte("ordinary inspected content " + strings.Repeat("y", 7000))
	spy := &closeSpyBody{Reader: bytes.NewReader(payload)}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		ContentLength: int64(len(payload)),
		Body:          spy,
	}
	br := &spyResponder{}

	out := scanInspectBody(req, req, resp, br, nil, ProxyIdentity{ClientIP: "198.51.100.9"}, "files.example.com", nil)

	if out != scanClean {
		t.Fatalf("outcome = %v, want scanClean for ordinary content", out)
	}
	if br.calls != 0 {
		t.Errorf("block emissions = %d, want 0", br.calls)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the reassembled inspected body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled inspected body differs: got %d bytes, want %d", len(got), len(payload))
	}
	if spy.closed.Load() {
		t.Error("the origin body was closed on a clean pass; the caller owns that close")
	}
	// ...and the caller must still be ABLE to close it. Replacing resp.Body
	// with an io.NopCloser strands the origin handle, so the upstream body and
	// its connection leak on every clean pass — the regression
	// TestRunInspectExchange_BodyClose caught when this stage was first wired
	// in, since the exchange seam closes exactly the handle it is left with.
	if err := resp.Body.Close(); err != nil {
		t.Errorf("closing the reassembled body: %v", err)
	}
	if !spy.closed.Load() {
		t.Error("closing the reassembled body did not close the ORIGIN body — the upstream connection leaks")
	}
}
