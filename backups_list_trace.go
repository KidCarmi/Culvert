package main

// backups_list_trace.go — correlated, secret-free timing for the backup
// listing path (GET /api/backups → agent GET /v1/backups → `docker compose
// run cli --list-backups` → the directory scan).
//
// A historical ESXi run saw the first post-reboot listing answer
// available=false after the 10 s agent deadline, and the evidence could not
// say WHERE the time went or whether that answer was a fresh timeout or a
// cached negative. Each fresh fetch now carries a random correlation id to
// the agent, the agent logs its own phases under the same id (accept →
// handler → compose → CLI start → enumeration), and the proxy logs its
// side: connection, first response byte, total, outcome. A cached negative
// served to a later caller is logged too, with its age and the id of the
// fetch that produced it.
//
// Nothing here is secret: a random id, timestamps, durations, counts and
// BOUNDED outcome classes. Raw error text is never logged from this path.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

// headerMaintCorrelation carries the fetch's correlation id to the agent.
// The agent accepts only 16 lowercase hex characters and logs "-" otherwise.
const headerMaintCorrelation = "X-Culvert-Correlation"

type backupListTrace struct {
	corr  string
	start time.Time
	// Written from transport callbacks, which can fire on another goroutine
	// after a timed-out Do has already returned, so they are atomics.
	connAt      atomic.Int64 // unix nanos, 0 = never
	reused      atomic.Bool
	firstByteAt atomic.Int64
	end         time.Time
	status      int
	entries     int
	outcome     string
}

func newBackupListTrace() *backupListTrace {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return &backupListTrace{corr: "-", start: time.Now()}
	}
	return &backupListTrace{corr: hex.EncodeToString(b[:]), start: time.Now()}
}

func (t *backupListTrace) withClientTrace(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			t.reused.Store(info.Reused)
			t.connAt.Store(time.Now().UnixNano())
		},
		GotFirstResponseByte: func() { t.firstByteAt.Store(time.Now().UnixNano()) },
	})
}

// classifyAgentFetchError maps a fetch error to a bounded outcome class.
func classifyAgentFetchError(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "unreachable"
	}
}

// msSince renders a phase stamp relative to the fetch start, "-" when the
// phase never happened (no connection, no response byte).
func (t *backupListTrace) msSince(at time.Time) string {
	if at.IsZero() {
		return "-"
	}
	return fmt.Sprintf("%.1f", float64(at.Sub(t.start).Microseconds())/1000)
}

func stampOf(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (t *backupListTrace) log() {
	if t.end.IsZero() {
		t.end = time.Now()
	}
	logger.Printf("BACKUP_LIST corr=%s start=%s conn_ms=%s reused=%t first_byte_ms=%s total_ms=%s status=%d entries=%d outcome=%s",
		t.corr, t.start.UTC().Format(time.RFC3339Nano), t.msSince(stampOf(t.connAt.Load())), t.reused.Load(),
		t.msSince(stampOf(t.firstByteAt.Load())), t.msSince(t.end), t.status, t.entries, t.outcome)
}

// lastCachedNegativeLog rate-limits the cached-negative line: GET is not
// rate-limited, so a polling viewer must not turn it into log volume.
var lastCachedNegativeLog atomic.Int64

const cachedNegativeLogEvery = 5 * time.Second

func logCachedBackupsNegative(corr string, at time.Time) {
	now := time.Now()
	prev := lastCachedNegativeLog.Load()
	if now.UnixNano()-prev < int64(cachedNegativeLogEvery) || !lastCachedNegativeLog.CompareAndSwap(prev, now.UnixNano()) {
		return
	}
	logger.Printf("BACKUP_LIST served cached available=false from corr=%s age_ms=%d", corr, now.Sub(at).Milliseconds())
}
