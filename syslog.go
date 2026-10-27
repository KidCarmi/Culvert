package main

// syslog.go — package-main bootstrap for SIEM syslog forwarding. The Writer
// engine moved to internal/syslog (ADR-0002); this file keeps the global, the
// shim alias + constructor, and InitSyslog (URL parsing + startup logging) where
// the logger/sanitizeLog coupling belongs.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// syslogWriter is the package-main alias for the relocated engine so existing
// unqualified references (the globalSyslogHandle declaration, the coverage test's
// constructor) stay unchanged.
type syslogWriter = syslog.Writer

// syslogStats is the package-main alias for the engine's delivery snapshot,
// so the health record can hold one without importing the package by name at
// every use site.
type syslogStats = syslog.Stats

// newSyslogWriter constructs a syslog Writer. Thin wrapper over syslog.NewWriter
// kept for InitSyslog and the integration test that builds a writer directly.
// Wires the panic observer here (the internal/syslog package is a stdlib-only
// leaf and cannot log for itself) so every Writer this process constructs —
// startup and runtime reconfigure alike — reports a recovered delivery panic
// to the process log, which is what the SIEM-forwarding admin panel's warning
// tells the operator to check.
func newSyslogWriter(network, addr, format string) (*syslogWriter, error) {
	sw, err := syslog.NewWriter(network, addr, format)
	if err != nil {
		return nil, err
	}
	sw.SetPanicObserver(func(recovered any) {
		logger.Printf("ERROR syslog: recovered panic in delivery goroutine (line dropped): %q", sanitizeLog(fmt.Sprintf("%v", recovered)))
	})
	return sw, nil
}

// globalSyslogHandle holds the active syslog writer; nil when syslog is not
// configured. It is an atomic.Pointer, not a plain variable, for two reasons
// that the plain variable got wrong (CHAOS-78, closing §42 OBS-1).
//
// It is WRITTEN at runtime from the admin handler goroutine (InitSyslog below,
// via the apiSyslogConfig POST; the disable branch stores nil) and READ on the
// proxy request path at every request-log record (store.go's persistLogEntry
// chokepoint) and on the audit SIEM hook (store.go's audit.SetSIEM closure).
// As a plain variable the nil check and the dereference were two separate
// unsynchronized loads of the same global, so a request goroutine could pass
// the check and then dereference the nil the disable branch had just stored —
// a data race whose crash the proxy crash guard contains per request, but
// which still aborts an in-flight request or tunnel over a routine
// "disable SIEM forwarding" click.
//
// The second reason is the one a nil guard would NOT have fixed. The engine
// sets its queue in startAsync, AFTER the struct literal (internal/syslog), and
// treats a nil queue as "deliver synchronously" — a path that holds the
// writer's mutex across three serialized network ops (write, dial, write),
// which deliverLine's own comment puts at ~15 s worst case. A plain
// pointer write carries no release edge, so on a weakly ordered target (this
// appliance ships linux/arm64) a request goroutine could observe a non-nil
// writer whose queue was still zero, fall into that synchronous path, and pay
// ~15 s on the data path with every other logging caller queued behind it —
// precisely the proxy-wide stall the async design and the engine's own
// TestAsync_WedgedCollectorNeverBlocksCaller exist to prevent, reached not
// through the engine but through the pointer holding it.
//
// atomic.Pointer's Store/Load is the release/acquire edge that closes both, and
// it is what this codebase already does for every other hot-path-read,
// runtime-reconfigured global: globalLogStore (logstore.go), logSink
// (logger.go), obs.sink (internal/obs) and the syslog engine's own
// panicObserver. The pointer holding the engine was the one left plain.
//
// Access it through syslogHandle/setSyslogHandle, never directly: a caller that
// needs both a nil check and a method call must hold ONE loaded value in a
// local, which is what those helpers make the natural thing to write.
// TestChaos78_Wall_SyslogHandleIsAtomic pins the declaration.
var globalSyslogHandle atomic.Pointer[syslogWriter]

// syslogHandle loads the active syslog writer, or nil when forwarding is off.
//
// Read it ONCE into a local and use that local for both the nil test and every
// subsequent call. Two syslogHandle() calls in one expression are two separate
// loads and reintroduce exactly the window this type exists to close.
func syslogHandle() *syslogWriter { return globalSyslogHandle.Load() }

// setSyslogHandle publishes sw as the active writer and returns the writer it
// displaced, or nil if there was none. The caller owns closing the returned
// writer: the engine's drainLoop exits ONLY via Close, so a displaced writer
// that is never closed leaks its delivery goroutine and its collector socket
// for the life of the process (CHAOS-78).
func setSyslogHandle(sw *syslogWriter) (displaced *syslogWriter) {
	return globalSyslogHandle.Swap(sw)
}

// syslogPublishMu makes "publish the active writer" and "install the health
// record that describes it" ONE transition. They used to be two steps, so two
// overlapping admin re-points could interleave as publish(B), publish(C),
// install(C), install(B): the active writer is C while target, installedAt and
// the alert latch describe B — misclassifying TCP-vs-UDP delivery evidence and
// the feed age until the next configuration change (Codex review, PR #1494).
// Only the publication is serialized; the dial happens before the lock.
var syslogPublishMu sync.Mutex

// syslogLateDrops is the engine's process-lifetime count of losses charged to
// a Writer whose totals had already been retired — see internal/syslog's
// lateDrops. Wrapped here so the health plane has one local name for the
// three terms of its drop total.
func syslogLateDrops() uint64 { return syslog.LateDrops() }

// syslogConfiguredSnapshot reads the config metadata under the same lock that
// publishes it. Read through this, never off the variables directly.
//
// The pair was a plain read/write pair on package variables, written by the
// admin plane and read from handler goroutines, which this file's own header
// recorded as a follow-up to close. Moving the writes inside the publication
// transaction (Codex P2, PR #1494) made that follow-up load-bearing rather
// than latent: InitSyslog is reached concurrently, so the write is now on a
// concurrent path and the unsynchronised read is a confirmed race under
// -race. A new writer is a new concurrency context — the same lesson this
// sweep recorded when its own observer joined the drain goroutine.
//
// connected is the target a Writer was actually installed for; intended is
// what an operator asked for, which is recorded even when the dial fails; sw
// is the Writer serving them. All three are read in ONE critical section.
//
// A caller that needs more than one of these must take them from here. Pairing
// a target from a config-metadata read with a separately-loaded
// syslogHandle() is a read that does not participate in the publication
// transition: a disable landing between the two yields the old address beside
// no writer (so an omnibus settings save persists a target the operator has
// just switched off, and the next restart re-enables it), and a re-point
// yields target A beside writer B (so the same save persists A with B's wire
// format, and the restart then restarts A speaking the wrong one) — Codex P2,
// PR #1494. This is the SAME defect the health snapshot closed one reader
// earlier: a snapshot must read the generation it describes.
func syslogConfiguredSnapshot() (connected, intended string, sw *syslogWriter) {
	syslogPublishMu.Lock()
	defer syslogPublishMu.Unlock()
	return syslogConfigured, syslogConfiguredAddr, globalSyslogHandle.Load()
}

// noteSyslogConfiguredIntent records the target an operator asked for, before
// any dial is attempted, so a failed connect is still reported as a
// configured-but-down feed rather than as no feed at all.
func noteSyslogConfiguredIntent(addr string) {
	syslogPublishMu.Lock()
	syslogConfiguredAddr = addr
	syslogPublishMu.Unlock()
}

// disableActiveSyslog clears the active writer and the health record as one
// serialized transition, releasing the writer it displaced.
func disableActiveSyslog() {
	syslogPublishMu.Lock()
	old := setSyslogHandle(nil)
	noteSyslogForwardingDisabled()
	// The config metadata is part of the SAME transition as the writer.
	// It used to be cleared by the admin handler after this call returned,
	// so an enable that had already published its writer could resume in the
	// gap and re-set these strings: the process then had no active writer
	// while GET /api/syslog and admin_settings.json both said forwarding was
	// on, and the next restart re-enabled a target nobody had asked for
	// (Codex P2, PR #1494).
	syslogConfigured = ""
	syslogConfiguredAddr = ""
	syslogPublishMu.Unlock()
	if old != nil {
		old.SetDeliveryObserver(nil)
		_ = old.Close() //nolint:errcheck // best-effort release; the handle is being cleared either way
	}
}

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
	network := "udp"
	target := addr
	switch {
	case strings.HasPrefix(addr, "tcp://"):
		network = "tcp"
		target = strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "udp://"):
		target = strings.TrimPrefix(addr, "udp://")
	}
	sw, err := newSyslogWriter(network, target, syslogFmt)
	if err != nil {
		return err
	}
	// Swap, not load-then-store: two concurrent admin re-points would
	// otherwise both read the same predecessor (one of them closing a writer
	// the other is about to leak) or clobber each other's publication. The
	// swap makes "publish the new one and hand me exactly the one I displaced"
	// a single step, so every displaced writer is released exactly once.
	syslogPublishMu.Lock()
	releaseReplacedSyslogWriter(setSyslogHandle(sw), sw)
	noteSyslogWriterInstalled(sw, addr)
	// Published with the writer, not by the caller afterwards — see
	// disableActiveSyslog for the interleaving that made the two disagree.
	// Callers must NOT assign these on success; they may still record the
	// INTENT (syslogConfiguredAddr) before calling, which is what survives a
	// dial that never produces a writer.
	syslogConfigured = addr
	syslogConfiguredAddr = addr
	syslogPublishMu.Unlock()
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}

// releaseReplacedSyslogWriter closes the Writer that InitSyslog is about to
// replace (CHAOS-81).
//
// Overwriting the published handle used to be the whole handover, which
// stranded the old Writer's drain goroutine parked forever on a queue nobody
// can reach any more, holding its collector socket OPEN. Measured against the pre-fix tree:
// +1 goroutine and +1 file descriptor per re-init, with the connection to the
// abandoned collector still ESTABLISHED (no EOF at the far end) — a phantom
// session that many SIEMs count against a per-source connection licence.
//
// This is NOT only an admin-triggered path. main.go runs initObservability
// (YAML/flags) at step 206 and initPersistentAdminState → LoadAdminSettings →
// applyAdminServices at step 240, and snapshotAdminEndpoints persists
// syslogConfigured into admin_settings.json — so once an operator saves any
// admin setting, EVERY SUBSEQUENT BOOT calls InitSyslog twice and leaks the
// first Writer. FD exhaustion is the recorded terminal state of WK-11/PX-6.
//
// The close is ASYNCHRONOUS on purpose. Writer.Close is self-bounded (it waits
// at most closeWait for the drain to flush) but that bound is ~7s against a
// wedged collector, and the collector being replaced is — by the nature of the
// operation — the one the operator has decided is broken. Paying that
// synchronously would let a dead SIEM stall the boot (before the proxy
// listener is up) or the admin request that is fixing it. Close is idempotent
// and releases the socket itself when its write deadline fires, so nothing
// here needs to wait for it.
//
// The displaced writer is HANDED OFF to its successor before it is closed. A
// caller on the request or admin path may have loaded the old handle just
// before the swap and call WriteAudit/WriteRequest on it after it is closed;
// without the handoff that security event was dropped against a writer no
// health surface reads any more — lost AND invisible. With it, such a late
// line (and anything still queued on the old writer) is re-routed to the live
// writer, whose counters every surface reads (Codex review, PR #1494).
func releaseReplacedSyslogWriter(old, successor *syslogWriter) {
	if old == nil {
		return
	}
	// Retired before anything can close it: the health plane folds this
	// Writer's totals moments from now, and a loss landing after its drain
	// seals but before it is marked would be counted in neither place.
	old.MarkRetired()
	old.HandOffTo(successor)
	// Detach the delivery observer FIRST. This is HYGIENE, not a fix for an
	// observed defect: the plane reads its counters from whichever writer is
	// live, so a displaced writer's final-flush drops land on its own Stats and
	// cannot move the successor's (pinned as a control, which passes with and
	// without this line). What it stops is an abandoned writer doing pointless
	// work through a stale callback while it drains — and it removes the one
	// path by which a future change to syslogFeedState could start attributing
	// a dead writer's outcomes to a live one.
	old.SetDeliveryObserver(nil)
	go func() { _ = old.Close() }()
}
