package supportupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// mockGateway is an in-memory TAC upload gateway implementing the §4 protocol:
// init → offset-idempotent chunk PUT → complete (hash re-verify) + a status GET.
type mockGateway struct {
	received []byte // bytes assembled so far for the single active session
	uploadID string
	// corruptReceiptHash makes :complete return a receipt whose hash does NOT
	// match, to exercise the client's defense-in-depth receipt re-check.
	corruptReceiptHash bool
	// chunkSize advertised at init (0 → client default).
	chunkSize int64
}

func (g *mockGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/v1/uploads:init":
		var m Meta
		_ = json.NewDecoder(r.Body).Decode(&m)
		g.uploadID = "up_test_1"
		g.received = nil
		writeJSON(w, map[string]any{"upload_id": g.uploadID, "chunk_size": g.chunkSize, "accepted": true})

	case r.Method == http.MethodGet && strings.HasPrefix(p, "/v1/uploads/") && !strings.Contains(p, "/chunks/"):
		writeJSON(w, map[string]any{"received_offset": len(g.received), "state": "uploading"})

	case r.Method == http.MethodPut && strings.Contains(p, "/chunks/"):
		offset, _ := strconv.Atoi(p[strings.LastIndex(p, "/")+1:])
		body, _ := io.ReadAll(r.Body)
		switch {
		case offset == len(g.received):
			g.received = append(g.received, body...)
		case offset < len(g.received):
			// idempotent re-send of an already-received prefix: no-op.
		default:
			http.Error(w, "gap", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"received_offset": len(g.received)})

	case r.Method == http.MethodPost && strings.HasSuffix(p, ":complete"):
		var body struct {
			BundleSHA256 string `json:"bundle_sha256"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got := sha256hex(g.received)
		if got != body.BundleSHA256 {
			http.Error(w, "hash mismatch", http.StatusConflict)
			return
		}
		receiptHash := got
		if g.corruptReceiptHash {
			receiptHash = strings.Repeat("0", 64)
		}
		writeJSON(w, Receipt{BundleSHA256: receiptHash, ReceivedAt: "2026-07-19T00:00:00Z", Sig: "mock-sig"})

	default:
		http.Error(w, "not found: "+r.Method+" "+p, http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// testClient builds a Client bound to an httptest server, bypassing NewClient's
// https requirement and the SSRF dial guard (the server is loopback). The
// protocol logic is what these tests exercise; the SSRF transport is covered by
// TestUpload_SSRFGuarded / TestCheckRedirect_* against the real NewClient path.
func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse srv url: %v", err)
	}
	return &Client{base: u, http: srv.Client()}
}

func TestUpload_FullTransferReceiptHashMatch(t *testing.T) {
	g := &mockGateway{chunkSize: 8} // tiny chunks to force multiple PUTs
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(t, srv)

	data := []byte("culvert-encrypted-bundle-payload-abcdefghij") // 43 bytes → 6 chunks of 8
	m := Meta{CaseID: "CASE-1", BundleID: "csb_x", BundleSHA256: sha256hex(data), KeyID: "tac-2026"}
	rec, err := c.Upload(context.Background(), m, newReaderAt(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !bytes.Equal(g.received, data) {
		t.Fatalf("gateway assembled %q, want %q", g.received, data)
	}
	if rec.BundleSHA256 != m.BundleSHA256 {
		t.Fatalf("receipt hash %q != bundle hash %q", rec.BundleSHA256, m.BundleSHA256)
	}
	if rec.Sig == "" {
		t.Error("receipt missing signature")
	}
}

func TestUpload_Resumable(t *testing.T) {
	g := &mockGateway{chunkSize: 16}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(t, srv)
	ctx := context.Background()

	data := []byte("resumable-upload-across-a-simulated-connection-drop!!")
	m := Meta{CaseID: "CASE-2", BundleID: "csb_y", BundleSHA256: sha256hex(data), Size: int64(len(data))}

	// Attempt 1: init + send the first chunk only, then "drop".
	uploadID, chunkSize, err := c.Init(ctx, m)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := c.PutChunk(ctx, uploadID, 0, data[0:chunkSize]); err != nil {
		t.Fatalf("PutChunk#0: %v", err)
	}

	// Attempt 2 (after a "restart"): a fresh client resumes from the gateway's
	// received offset using only the persisted uploadID.
	c2 := testClient(t, srv)
	off, err := c2.Status(ctx, uploadID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if off != chunkSize {
		t.Fatalf("resume offset = %d, want %d", off, chunkSize)
	}
	for off < int64(len(data)) {
		end := off + chunkSize
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		newOff, err := c2.PutChunk(ctx, uploadID, off, data[off:end])
		if err != nil {
			t.Fatalf("resume PutChunk@%d: %v", off, err)
		}
		off = newOff
	}
	rec, err := c2.Complete(ctx, uploadID, m.BundleSHA256)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if rec.BundleSHA256 != m.BundleSHA256 {
		t.Fatalf("resumed receipt hash mismatch")
	}
	if !bytes.Equal(g.received, data) {
		t.Fatalf("resumed transfer assembled wrong bytes")
	}
}

func TestUpload_ReceiptHashMismatchRejected(t *testing.T) {
	g := &mockGateway{chunkSize: 32, corruptReceiptHash: true}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(t, srv)

	data := []byte("bytes-transfer-fine-but-receipt-hash-is-wrong")
	m := Meta{CaseID: "CASE-3", BundleID: "csb_z", BundleSHA256: sha256hex(data)}
	_, err := c.Upload(context.Background(), m, newReaderAt(data), int64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "receipt hash") {
		t.Fatalf("expected a receipt-hash mismatch error, got %v", err)
	}
}

func TestUpload_SSRFGuarded(t *testing.T) {
	// A real client against a private origin: the dial-time SSRF guard must
	// refuse the connection (no bytes leave for an internal address).
	c, err := NewClient(Config{Origin: "https://10.0.0.5"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	data := []byte("should-never-leave")
	_, err = c.Upload(context.Background(), Meta{CaseID: "x", BundleID: "y", BundleSHA256: sha256hex(data)}, newReaderAt(data), int64(len(data)))
	if err == nil {
		t.Fatal("upload to a private origin must be refused")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Fatalf("error should name the private-address refusal, got: %v", err)
	}
}

func TestCheckRedirect_GuardsPrivateAndCapsHops(t *testing.T) {
	c, err := NewClient(Config{Origin: "https://tac.example.com"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Redirect to a private host is refused.
	req := &http.Request{URL: mustURL(t, "https://10.0.0.9/evil")}
	if err := c.checkRedirect(req, nil); err == nil {
		t.Error("redirect to a private host must be refused")
	}
	// A downgrade to http is refused (would leak the bearer credential + body).
	downgrade := &http.Request{URL: mustURL(t, "http://tac.example.com/downgrade")}
	if err := c.checkRedirect(downgrade, nil); err == nil {
		t.Error("non-https redirect must be refused")
	}
	// Too many hops is refused.
	pub := &http.Request{URL: mustURL(t, "https://tac.example.com/next")}
	via := make([]*http.Request, maxRedirects)
	if err := c.checkRedirect(pub, via); err == nil {
		t.Error("too many redirects must be refused")
	}
}

// TestComplete_RejectsMismatchedReceipt proves the receipt-hash check lives in
// Complete, so the queue's direct Init/PutChunk/Complete resume path rejects a
// corrupted/mis-issued receipt identically to the Upload wrapper.
func TestComplete_RejectsMismatchedReceipt(t *testing.T) {
	g := &mockGateway{chunkSize: 64, corruptReceiptHash: true}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(t, srv)
	ctx := context.Background()

	data := []byte("resume-path-completion-must-verify-the-receipt-hash")
	m := Meta{CaseID: "CASE-4", BundleID: "csb_r", BundleSHA256: sha256hex(data)}
	uploadID, _, err := c.Init(ctx, m)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := c.PutChunk(ctx, uploadID, 0, data); err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if _, err := c.Complete(ctx, uploadID, m.BundleSHA256); err == nil || !strings.Contains(err.Error(), "receipt hash") {
		t.Fatalf("Complete must reject a mismatched receipt hash, got %v", err)
	}
}

func TestNewClient_RejectsNonHTTPS(t *testing.T) {
	if _, err := NewClient(Config{Origin: "http://tac.example.com"}); err == nil {
		t.Error("non-https origin must be rejected")
	}
	if _, err := NewClient(Config{Origin: "https://"}); err == nil {
		t.Error("origin with no host must be rejected")
	}
	if _, err := NewClient(Config{Origin: "https://tac.example.com"}); err != nil {
		t.Errorf("valid https origin should construct: %v", err)
	}
}

// ── small test helpers ──────────────────────────────────────────────────────

type readerAt struct{ b []byte }

func newReaderAt(b []byte) *readerAt { return &readerAt{b: b} }

func (r *readerAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}
