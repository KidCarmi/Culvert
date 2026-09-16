package main

// syslog.go — package-main bootstrap for SIEM syslog forwarding. The Writer
// engine moved to internal/syslog (ADR-0002); this file keeps the ACTIVE
// WRITER'S OWNERSHIP, the shim alias + constructor, and InitSyslog (URL parsing
// + startup logging) where the logger/sanitizeLog coupling belongs.
//
// CHAOS-66 — why the active writer has an owner rather than a plain global.
//
// `globalSyslog` used to be an ordinary package-level `*syslogWriter`, written
// by InitSyslog and read directly by the request path. Three things were wrong
// with that, and the first two were reproduced against the real binary:
//
//  1. It was a DATA RACE. The pointer is read on the per-request path
//     (`recordRequest` → WriteRequest, and the audit SIEM closure in store.go)
//     and written by the admin API (`POST /api/syslog`) and by both startup
//     paths, with nothing between them. `-race` reports it on both the pointer
//     itself and, worse, on `Writer.queue` — which `NewWriter` writes and
//     `send()` reads. Without a happens-before edge a request goroutine may
//     observe a published Writer whose queue field is still nil, and `send()`
//     then takes the SYNCHRONOUS path: the collector write happens on the
//     REQUEST goroutine, under the Writer's connection mutex. That is precisely
//     the contract the async design exists to enforce ("a slow SIEM must cost
//     drops, not proxy latency" — internal/syslog's package doc), defeated by a
//     reordering rather than by a code change.
//
//  2. It LEAKED the writer it replaced. Nothing closed the predecessor, so each
//     reconfigure stranded a drain goroutine and an open TCP connection to the
//     old collector for the life of the process. That is not a rare path: the
//     boot sequence itself re-inits when a syslog target is present in BOTH the
//     YAML/flag config and the persisted admin settings (loadObservability runs
//     first, applyAdminServices runs after), so an ordinary appliance leaked one
//     on EVERY boot, and an admin changing collectors leaked one per change.
//     FD exhaustion is the recorded terminal state of PX-6/WK-11.
//
//  3. It had no single point at which a change of active writer could be
//     OBSERVED, which is what the health plane (syslog_health.go) needs.
//
// The fix is ownership, not locking: publication goes through
// `publishSyslogWriter`, the pointer is an `atomic.Pointer` so the per-request
// read stays lock-free (a mutex here would add an acquisition to the request
// path — the throughput ceiling this repo has found repeatedly in
// internal/threatfeed, internal/connlimit, internal/rewrite and hostCounter),
// and the atomic store/load pair supplies the happens-before edge that makes
// every field the Writer was constructed with safely visible to the reader.
//
// **Read the active writer only through `activeSyslog()` and publish only
// through `publishSyslogWriter`/`clearSyslogWriter`.** A reintroduced plain
// global would restore all three defects at once and is walled by
// `TestChaos66_NoPlainGlobalSyslogPointer`.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// syslogWriter is the package-main alias for the relocated engine so existing
// unqualified references (the coverage test's constructor) stay unchanged.
type syslogWriter = syslog.Writer

// newSyslogWriter constructs a syslog Writer. Thin wrapper over syslog.NewWriter
// kept for InitSyslog and the integration test that builds a writer directly.
// Wires the panic observer here (the internal/syslog package is a stdlib-only
// leaf and cannot log for itself) so every Writer this process constructs —
// startup and runtime reconfigure alike — reports a recovered delivery panic
// to the process log, which is what the SIEM-forwarding admin panel's warning
// tells the operator to check. The delivery observer is wired for the same
// leaf-package-can't-report reason: it is what drives the SIEM health plane.
func newSyslogWriter(network, addr, format string) (*syslogWriter, error) {
	sw, err := syslog.NewWriter(network, addr, format)
	if err != nil {
		return nil, err
	}
	sw.SetPanicObserver(func(recovered any) {
		logger.Printf("ERROR syslog: recovered panic in delivery goroutine (line dropped): %q", sanitizeLog(fmt.Sprintf("%v", recovered)))
	})
	sw.SetDeliveryObserver(noteSyslogDelivery)
	return sw, nil
}

// syslogOwner holds the active syslog writer; nil when syslog is not
// configured. Never referenced directly outside this file — see the header.
var syslogOwner atomic.Pointer[syslogWriter]

// syslogPublishMu serialises PUBLICATION (never reads). Two concurrent
// publishes would otherwise be able to each load the same predecessor, publish
// over each other, and close it twice while leaking the loser — the swap and
// the handover of the old writer have to be one step.
var syslogPublishMu sync.Mutex

// syslogGeneration counts publications, including disables. The reconnect
// campaign (syslog_recovery.go) fences on it so a retry that finally connects
// can never install itself over a target the operator has since changed or
// switched off.
var syslogGeneration atomic.Uint64

// activeSyslog returns the writer currently forwarding to the collector, or nil
// when SIEM forwarding is not configured. One atomic load — this is on the
// per-request path (store.go).
func activeSyslog() *syslogWriter { return syslogOwner.Load() }

// publishSyslogWriter installs sw as the active writer and RELEASES the one it
// replaces. Passing nil disables forwarding.
//
// The predecessor is closed on its own goroutine, never inline: Close waits up
// to the engine's closeWait (~7 s) for the drain goroutine to finish flushing
// against a wedged collector, and neither an admin request nor the boot
// sequence may block for that. The goroutine is bounded by that same wait and
// always terminates.
func publishSyslogWriter(sw *syslogWriter) {
	syslogPublishMu.Lock()
	prev := syslogOwner.Swap(sw)
	syslogGeneration.Add(1)
	syslogPublishMu.Unlock()

	if prev != nil && prev != sw {
		go func() { _ = prev.Close() }()
	}
}

// clearSyslogWriter disables forwarding and releases the active writer.
func clearSyslogWriter() { publishSyslogWriter(nil) }

// InitSyslog parses addr and initialises the global syslog writer.
// Supported addr formats:
//
//	udp://10.0.0.1:514       (default protocol when scheme is omitted)
//	tcp://logs.corp.com:601
//
// syslogFmt selects the message format: "rfc3164" (default) or "rfc5424".
func InitSyslog(addr, syslogFmt string) error {
	if addr == "" {
		return nil
	}
	network, target := parseSyslogTarget(addr)
	sw, err := newSyslogWriter(network, target, syslogFmt)
	if err != nil {
		return err
	}
	publishSyslogWriter(sw)
	noteSyslogConnected()
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}

// parseSyslogTarget splits an operator-supplied syslog address into its network
// and host:port halves. UDP is the default when no scheme is given.
func parseSyslogTarget(addr string) (network, target string) {
	network, target = "udp", addr
	switch {
	case strings.HasPrefix(addr, "tcp://"):
		network = "tcp"
		target = strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "udp://"):
		target = strings.TrimPrefix(addr, "udp://")
	}
	return network, target
}
