package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var backupListLineRE = regexp.MustCompile(`BACKUP_LIST corr=([0-9a-f]{16}) start=\S+ conn_ms=(\S+) reused=(true|false) first_byte_ms=(\S+) total_ms=(\S+) status=(\d+) entries=(\d+) outcome=(\S+)`)

// One fresh listing: the correlation id the agent received is the one the
// proxy logged, with connection, first byte, total, status and outcome.
func TestBackupListTrace_CorrelatesWithTheAgent(t *testing.T) {
	resetBackupsCache(t)
	seen := make(chan string, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(headerMaintCorrelation)
		_, _ = w.Write([]byte(`[{"filename":"a.tar.gz","path":"/backup/a.tar.gz","size_bytes":1,"modified_at":"2026-08-20T01:00:00Z"}]`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	out := captureLogger(t, func() { callAPIBackups(t) })
	m := backupListLineRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no BACKUP_LIST line:\n%s", out)
	}
	if got := <-seen; got != m[1] {
		t.Fatalf("agent received correlation %q, proxy logged %q", got, m[1])
	}
	if m[2] == "-" || m[4] == "-" || m[5] == "-" || m[6] != "200" || m[7] != "1" || m[8] != "ok" {
		t.Fatalf("incomplete trace: %v", m[1:])
	}
}

// Outcomes are bounded classes that tell a timeout from an agent error.
func TestBackupListTrace_OutcomeClasses(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"list_backups_failed","detail":"/secret/path"}`, http.StatusInternalServerError)
	}))
	defer failing.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer garbage.Close()

	for _, c := range []struct {
		url, want string
		budget    time.Duration
	}{
		{slow.URL, "timeout", 150 * time.Millisecond},
		{failing.URL, "agent_http_error", 5 * time.Second},
		{garbage.URL, "parse_error", 5 * time.Second},
		{"http://127.0.0.1:1", "unreachable", 5 * time.Second},
	} {
		ep, ok := localAgentEndpoint(c.url)
		if !ok {
			t.Fatalf("endpoint %s", c.url)
		}
		out := captureLogger(t, func() {
			ctx, cancel := context.WithTimeout(context.Background(), c.budget)
			defer cancel()
			_, _ = fetchAgentBackups(ctx, ep)
		})
		m := backupListLineRE.FindStringSubmatch(out)
		if len(m) < 9 || m[8] != c.want {
			t.Errorf("%s: want outcome=%s, got %q", c.url, c.want, out)
		}
		if strings.Contains(out, "secret") {
			t.Errorf("agent error text leaked into the trace: %s", out)
		}
	}
}

// A cached available=false served to a later caller names the fetch that
// produced it and its age, so "fresh timeout" and "reused negative" are
// distinguishable; repeats inside the window are suppressed.
func TestBackupListTrace_CachedNegativeIsAttributed(t *testing.T) {
	resetBackupsCache(t)
	lastCachedNegativeLog.Store(0)
	t.Setenv(envMaintAgentURL, "http://127.0.0.1:1")
	var first, second string
	out := captureLogger(t, func() {
		callAPIBackups(t) // fresh fetch → unreachable → cached negative
		callAPIBackups(t) // served from cache
		callAPIBackups(t) // suppressed (rate limit)
	})
	for _, l := range strings.Split(out, "\n") {
		if m := backupListLineRE.FindStringSubmatch(l); m != nil {
			first = m[1]
		}
		if strings.Contains(l, "served cached available=false") {
			if second != "" {
				t.Fatalf("cached-negative line not rate-limited:\n%s", out)
			}
			second = l
		}
	}
	if first == "" || !strings.Contains(second, "from corr="+first+" age_ms=") {
		t.Fatalf("cached negative not attributed to fetch %q:\n%s", first, out)
	}
}

// The cli's stderr timing line and the agent's parser share one marker and
// field set across two Go modules; pin them so neither side drifts alone.
func TestBackupListTrace_MarkerMatchesAgentParser(t *testing.T) {
	src, err := os.ReadFile("cmd/culvert-maint/internal/server/backup_list_timing.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`listTimingMarker     = "` + listBackupsTimingMarker + `"`,
		`case "start_unix_ns":`, `case "enumerate_us":`, `case "entries":`, `case "ok":`,
		`headerCorrelation    = "` + headerMaintCorrelation + `"`,
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("agent parser lacks %q", want)
		}
	}
	var stdout, diag strings.Builder
	if err := runListBackupsTimed(t.TempDir(), &stdout, &diag); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^` + listBackupsTimingMarker + ` start_unix_ns=\d+ enumerate_us=\d+ entries=0 ok=true\n$`).MatchString(diag.String()) {
		t.Fatalf("timing line %q", diag.String())
	}
	if strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("stdout must stay the bare JSON array, got %q", stdout.String())
	}
}
