package server

// backup_list_timing.go — the agent half of the correlated backup-listing
// timing (the proxy half is backups_list_trace.go in the root package).
//
// One line per GET /v1/backups, keyed by the proxy's correlation id:
// connection accept, handler entry, compose invocation, the cli process
// start reported by --list-backups on stderr (so container start-up is
// separable from the directory scan), the scan itself, and a bounded
// outcome. Timestamps, durations, counts and classes only — the runner's
// error text and the cli's stderr are never logged from here.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// connAcceptedKey carries the time the UDS connection was accepted
// (http.Server.ConnContext). On a kept-alive connection it predates the
// request, which is why the handler-entry time is logged separately.
type connAcceptedKey struct{}

const (
	headerCorrelation    = "X-Culvert-Correlation"
	listTimingMarker     = "CULVERT_LIST_BACKUPS_TIMING"
	backupListOutcomeOK  = "ok"
	backupListRunnerFail = "runner_error"
)

var correlationRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// correlationOf returns the request's correlation id, or "-" when absent or
// not the exact shape the proxy sends (the header is never echoed raw).
func correlationOf(h string) string {
	if correlationRe.MatchString(h) {
		return h
	}
	return "-"
}

type listCLITiming struct {
	startUnixNS int64
	enumerateUS int64
	entries     int
	ok          bool
	found       bool
}

// parseListTiming extracts the --list-backups timing line from the cli's
// stderr (compose interleaves its own progress lines there). Strict: every
// field must parse, or the line is ignored.
func parseListTiming(stderr []byte) listCLITiming {
	sc := bufio.NewScanner(bytes.NewReader(stderr))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, listTimingMarker+" ") {
			continue
		}
		var t listCLITiming
		fields := strings.Fields(strings.TrimPrefix(line, listTimingMarker+" "))
		seen := 0
		for _, f := range fields {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			var err error
			switch k {
			case "start_unix_ns":
				t.startUnixNS, err = strconv.ParseInt(v, 10, 64)
			case "enumerate_us":
				t.enumerateUS, err = strconv.ParseInt(v, 10, 64)
			case "entries":
				t.entries, err = strconv.Atoi(v)
			case "ok":
				t.ok, err = strconv.ParseBool(v)
			default:
				continue
			}
			if err != nil {
				return listCLITiming{}
			}
			seen++
		}
		if seen == 4 && t.startUnixNS > 0 && t.enumerateUS >= 0 && t.entries >= 0 {
			t.found = true
			return t
		}
	}
	return listCLITiming{}
}

type backupListTiming struct {
	corr       string
	handlerAt  time.Time
	composeAt  time.Time
	composeDur time.Duration
	stderr     []byte
	entries    int
	outcome    string
}

func newBackupListTiming(corrHeader string) *backupListTiming {
	return &backupListTiming{corr: correlationOf(corrHeader), handlerAt: time.Now(), outcome: backupListRunnerFail}
}

func msBetween(a, b time.Time) string {
	if a.IsZero() || b.IsZero() {
		return "-"
	}
	return fmt.Sprintf("%.1f", float64(b.Sub(a).Microseconds())/1000)
}

// line renders the log line; accepted is the connection accept time (zero
// when unknown).
func (t *backupListTiming) line(accepted time.Time, end time.Time) string {
	cli := parseListTiming(t.stderr)
	cliStart, enumerate := "-", "-"
	if cli.found {
		cliStart = msBetween(t.composeAt, time.Unix(0, cli.startUnixNS))
		enumerate = fmt.Sprintf("%.1f", float64(cli.enumerateUS)/1000)
	}
	compose := "-"
	if t.composeDur > 0 {
		compose = fmt.Sprintf("%.1f", float64(t.composeDur.Microseconds())/1000)
	}
	acc := "-"
	if !accepted.IsZero() {
		acc = accepted.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("culvert-maint: backup_list corr=%s conn_accepted=%s handler_at=%s accept_to_handler_ms=%s compose_ms=%s cli_start_ms=%s enumerate_ms=%s handler_ms=%s entries=%d outcome=%s",
		t.corr, acc, t.handlerAt.UTC().Format(time.RFC3339Nano), msBetween(accepted, t.handlerAt),
		compose, cliStart, enumerate, msBetween(t.handlerAt, end), t.entries, t.outcome)
}

func (t *backupListTiming) log(ctx context.Context) {
	accepted, _ := ctx.Value(connAcceptedKey{}).(time.Time)
	log.Print(t.line(accepted, time.Now()))
}
