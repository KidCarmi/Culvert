package main

// ADR-FE-002 Monitor cursor-contract tests for GET /api/logs?source=store:
// compatibility (offset mode untouched), cursor paging with no exact total,
// query-fingerprint binding, window escape prevention, malformed-cursor 400s,
// and the conservative page-size clamp.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/logstore"
)

type cursorPageResp struct {
	Logs        []LogEntry `json:"logs"`
	NextCursor  string     `json:"next_cursor"`
	HasMore     bool       `json:"has_more"`
	ScanLimited bool       `json:"scan_limited"`
	History     bool       `json:"history"`
	SnapshotAt  string     `json:"snapshot_at"`
	Limit       int        `json:"limit"`
	Total       *int       `json:"total"` // must stay ABSENT in cursor mode
}

func cursorStoreFixture(t *testing.T, n int) {
	t.Helper()
	// Direct engine open (no encryption, no janitor) — the handler under test
	// only needs a published store; lifecycle plumbing is covered elsewhere.
	s, err := logstore.OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	old := globalLogStore.Swap(s)
	t.Cleanup(func() {
		globalLogStore.Store(old)
		_ = s.Close()
	})
	base := time.Now().Add(-30 * time.Minute).UnixMilli()
	for i := 0; i < n; i++ {
		status := "OK"
		if i%5 == 0 {
			status = "BLOCKED"
		}
		s.Add(LogEntry{TS: base + int64(i), IP: "10.0.0.9", Method: "GET",
			Host: "cursor.example.com", Status: status, Level: "INFO"})
	}
	drainLogStore(t, s, n)
}

func getCursorPage(t *testing.T, query string) (resp cursorPageResp, code int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/logs?"+query, http.NoBody)
	rec := httptest.NewRecorder()
	apiLogs(rec, req)
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
	}
	return resp, rec.Code
}

func TestApiLogsCursor_PagesWithoutExactTotal(t *testing.T) {
	cursorStoreFixture(t, 250)

	page1, code := getCursorPage(t, "source=store&cursor=")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if !page1.History {
		t.Fatal("history should be true")
	}
	if len(page1.Logs) != apiLogsCursorDefaultLimit {
		t.Fatalf("default page = %d, want %d", len(page1.Logs), apiLogsCursorDefaultLimit)
	}
	if !page1.HasMore || page1.NextCursor == "" {
		t.Fatalf("expected has_more + next_cursor, got %+v", page1)
	}
	if page1.Total != nil {
		t.Fatal("cursor mode must NOT report an exact total")
	}
	if page1.SnapshotAt == "" {
		t.Fatal("snapshot_at missing")
	}

	page2, code := getCursorPage(t, "source=store&cursor="+url.QueryEscape(page1.NextCursor))
	if code != http.StatusOK {
		t.Fatalf("page2 status %d", code)
	}
	if len(page2.Logs) != 100 {
		t.Fatalf("page2 = %d, want 100", len(page2.Logs))
	}
	// Continuation without duplication.
	if page2.Logs[0].TS >= page1.Logs[len(page1.Logs)-1].TS {
		t.Fatalf("page2 does not continue below page1")
	}

	page3, _ := getCursorPage(t, "source=store&cursor="+url.QueryEscape(page2.NextCursor))
	if len(page3.Logs) != 50 || page3.HasMore || page3.NextCursor != "" {
		t.Fatalf("final page wrong: len=%d has_more=%v", len(page3.Logs), page3.HasMore)
	}
}

func TestApiLogsCursor_OffsetModeUnchanged(t *testing.T) {
	cursorStoreFixture(t, 30)
	req := httptest.NewRequest(http.MethodGet, "/api/logs?source=store&offset=0&limit=10", http.NoBody)
	rec := httptest.NewRecorder()
	apiLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Logs    []LogEntry `json:"logs"`
		Total   *int       `json:"total"`
		History bool       `json:"history"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The legacy contract is byte-compatible: total present, history true.
	if resp.Total == nil || *resp.Total != 30 || !resp.History || len(resp.Logs) != 10 {
		t.Fatalf("legacy offset contract changed: %+v", resp)
	}
}

func TestApiLogsCursor_FingerprintBindsQuery(t *testing.T) {
	cursorStoreFixture(t, 120)
	page1, _ := getCursorPage(t, "source=store&status=BLOCKED&cursor=")
	if len(page1.Logs) == 0 || page1.NextCursor == "" {
		// 24 BLOCKED entries; default limit 100 → all fit, no cursor. Use a
		// smaller page to force one.
		page1, _ = getCursorPage(t, "source=store&status=BLOCKED&limit=10&cursor=")
	}
	if page1.NextCursor == "" {
		t.Fatal("fixture should produce a next_cursor")
	}
	// The SAME cursor presented with a DIFFERENT filter → 400.
	_, code := getCursorPage(t, "source=store&status=OK&limit=10&cursor="+url.QueryEscape(page1.NextCursor))
	if code != http.StatusBadRequest {
		t.Fatalf("cross-query cursor accepted: status %d", code)
	}
	// And with the filter dropped entirely → 400.
	_, code = getCursorPage(t, "source=store&limit=10&cursor="+url.QueryEscape(page1.NextCursor))
	if code != http.StatusBadRequest {
		t.Fatalf("filterless reuse accepted: status %d", code)
	}
	// Same query → accepted.
	_, code = getCursorPage(t, "source=store&status=BLOCKED&limit=10&cursor="+url.QueryEscape(page1.NextCursor))
	if code != http.StatusOK {
		t.Fatalf("legitimate continuation refused: %d", code)
	}
}

func TestApiLogsCursor_MalformedAndEscapeRejected(t *testing.T) {
	cursorStoreFixture(t, 10)
	bad := []string{
		"not-base64!!!",
		base64.RawURLEncoding.EncodeToString([]byte("not json")),
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":9,"ts":1,"seq":0,"fp":"x"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"ts":-5,"seq":0,"fp":"x"}`)),
		string(make([]byte, apiLogsCursorMaxLen+1)),
	}
	for _, c := range bad {
		_, code := getCursorPage(t, "source=store&cursor="+url.QueryEscape(c))
		if code != http.StatusBadRequest {
			t.Fatalf("malformed cursor %q accepted: status %d", c[:16], code)
		}
	}
	// A syntactically valid cursor whose ts sits OUTSIDE the request window
	// (correct fingerprint for that window) must be refused.
	from := time.Now().Add(-10 * time.Minute).Unix()
	to := time.Now().Unix()
	q := url.Values{}
	q.Set("from", fmt.Sprintf("%d", from))
	q.Set("to", fmt.Sprintf("%d", to))
	fp := logsQueryFingerprint(q)
	escape := encodeLogsCursor(logsCursor{V: 1, TS: (from - 3600) * 1000, Seq: 0, FP: fp})
	_, code := getCursorPage(t,
		fmt.Sprintf("source=store&from=%d&to=%d&cursor=%s", from, to, url.QueryEscape(escape)))
	if code != http.StatusBadRequest {
		t.Fatalf("window-escaping cursor accepted: status %d", code)
	}
}

func TestApiLogsCursor_LimitClampConservative(t *testing.T) {
	cursorStoreFixture(t, 5)
	page, code := getCursorPage(t, "source=store&limit=99999&cursor=")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if page.Limit != apiLogsCursorMaxLimit {
		t.Fatalf("limit clamp = %d, want %d (never the 5000 offset ceiling)", page.Limit, apiLogsCursorMaxLimit)
	}
}

func TestApiLogsCursor_HistoryDisabledTruthful(t *testing.T) {
	old := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(old) })
	page, code := getCursorPage(t, "source=store&cursor=")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if page.History || page.HasMore || len(page.Logs) != 0 {
		t.Fatalf("disabled history must be truthful: %+v", page)
	}
}
