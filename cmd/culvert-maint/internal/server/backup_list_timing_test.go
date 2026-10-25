package server

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseListTiming(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		found  bool
		enumUS int64
	}{
		{"interleaved with compose output", " Container x Creating\n" + listTimingMarker + " start_unix_ns=1700000000000000000 enumerate_us=1500 entries=3 ok=true\n Container x Removed\n", true, 1500},
		{"failed scan still reports", listTimingMarker + " start_unix_ns=1700000000000000000 enumerate_us=20 entries=0 ok=false", true, 20},
		{"no marker", "List backups error: boom\n", false, 0},
		{"missing field", listTimingMarker + " start_unix_ns=1700000000000000000 enumerate_us=20 ok=true", false, 0},
		{"non-numeric field", listTimingMarker + " start_unix_ns=x enumerate_us=20 entries=0 ok=true", false, 0},
		{"marker not at line start", "foo " + listTimingMarker + " start_unix_ns=1 enumerate_us=2 entries=0 ok=true", false, 0},
	}
	for _, c := range cases {
		got := parseListTiming([]byte(c.stderr))
		if got.found != c.found || (c.found && got.enumerateUS != c.enumUS) {
			t.Errorf("%s: got %+v, want found=%v enumerate_us=%d", c.name, got, c.found, c.enumUS)
		}
	}
}

func TestCorrelationOf_OnlyTheProxyShapeIsLogged(t *testing.T) {
	for in, want := range map[string]string{
		"0123456789abcdef":                  "0123456789abcdef",
		"":                                  "-",
		"0123456789ABCDEF":                  "-",
		"0123456789abcde":                   "-",
		"0123456789abcdef0":                 "-",
		"0123456789abcdef\nforged log line": "-",
	} {
		if got := correlationOf(in); got != want {
			t.Errorf("correlationOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// captureLog swaps the standard logger's output for the test.
func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	b := &syncBuf{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return b
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func (r *d16bTestRig) getWithHeader(t *testing.T, path, k, v string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix"+path, http.NoBody)
	req.Header.Set(k, v)
	resp, err := udsClient(r.sockPath).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// The listing logs one line carrying the proxy's correlation id and every
// phase: accept, handler, compose, cli start, enumeration, outcome.
func TestBackupList_LogsCorrelatedPhases(t *testing.T) {
	logs := captureLog(t)
	rig := startD16bRig(t)
	defer rig.stop()
	if st := rig.getWithHeader(t, "/v1/backups", headerCorrelation, "00112233aabbccdd"); st != http.StatusOK {
		t.Fatalf("status %d", st)
	}
	var line string
	deadline := time.Now().Add(2 * time.Second)
	for line == "" && time.Now().Before(deadline) {
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, "backup_list corr=00112233aabbccdd") {
				line = l
			}
		}
		if line == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if line == "" {
		t.Fatalf("no correlated backup_list line; log:\n%s", logs.String())
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`conn_accepted=\d{4}-\d\d-\d\dT`),
		regexp.MustCompile(`accept_to_handler_ms=\d+\.\d`),
		regexp.MustCompile(`compose_ms=\d+\.\d`),
		regexp.MustCompile(`cli_start_ms=-?\d+\.\d`),
		regexp.MustCompile(`enumerate_ms=1\.2 `),
		regexp.MustCompile(`handler_ms=\d+\.\d`),
		regexp.MustCompile(`entries=1 outcome=ok$`),
	} {
		if !want.MatchString(line) {
			t.Errorf("line lacks %s: %s", want, line)
		}
	}
}

// A runner failure still logs exactly one line, with a bounded outcome and
// no error text (the cli's stderr can carry paths and compose output).
func TestBackupList_FailureLogsBoundedOutcome(t *testing.T) {
	logs := captureLog(t)
	rig := startD16bRig(t)
	defer rig.stop()
	rig.addFailMatch("--list-backups")
	if st := rig.getWithHeader(t, "/v1/backups", headerCorrelation, "ffeeddccbbaa9988"); st != http.StatusInternalServerError {
		t.Fatalf("status %d", st)
	}
	var line string
	deadline := time.Now().Add(2 * time.Second)
	for line == "" && time.Now().Before(deadline) {
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, "backup_list corr=ffeeddccbbaa9988") {
				line = l
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.HasSuffix(line, "outcome=runner_error") {
		t.Fatalf("want outcome=runner_error, got %q", line)
	}
	if strings.Contains(line, "simulated") {
		t.Fatalf("error text leaked into the timing line: %s", line)
	}
}
