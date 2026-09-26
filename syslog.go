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
// unqualified references (the globalSyslog declaration, the coverage test's
// constructor) stay unchanged.
type syslogWriter = syslog.Writer

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

// globalSyslog holds the active syslog writer; nil when syslog is not
// configured. Read through activeSyslog, written through setActiveSyslog —
// never touched directly.
//
// It is an atomic.Pointer because this handle is MUTATED AT RUNTIME by the
// admin plane (POST /api/syslog re-points or disables forwarding) while it is
// READ ON THE REQUEST PATH: store.go's recordRequest fan-out reaches
// `WriteRequest` for every proxied request and the audit fan-out reaches
// `WriteAudit` for every admin action, and the diagnostics row, the /metrics
// scrape and the /healthz probe read it from their own handler goroutines.
// As a bare `*syslogWriter` that was an unsynchronised concurrent
// read/write of a pointer, confirmed under `-race` against the real
// `apiSyslogConfig` and `recordRequest` shapes. Nothing in the suite happened
// to exercise both at once, which is the only reason it had not been reported.
//
// A pointer swap is all that is required: the Writer it points at is already
// internally synchronised, and every reader wants the generation that was live
// when it looked. Callers therefore load ONCE into a local and use that —
// `activeSyslog() != nil` followed by a second `activeSyslog()` call is a
// check-then-act against a handle the admin plane can clear in between.
var globalSyslog atomic.Pointer[syslogWriter]

// activeSyslog returns the live writer, or nil when forwarding is off.
func activeSyslog() *syslogWriter { return globalSyslog.Load() }

// setActiveSyslog publishes a writer (or nil to disable forwarding).
func setActiveSyslog(sw *syslogWriter) { globalSyslog.Store(sw) }

// syslogPublishMu makes "publish the active writer" and "install the health
// record that describes it" ONE transition. They used to be two steps, so two
// overlapping admin re-points could interleave as publish(B), publish(C),
// install(C), install(B): the active writer is C while target, installedAt and
// the alert latch describe B — misclassifying TCP-vs-UDP delivery evidence and
// the feed age until the next configuration change (Codex review, PR #1494).
// Only the publication is serialized; the dial happens before the lock.
var syslogPublishMu sync.Mutex

// disableActiveSyslog clears the active writer and the health record as one
// serialized transition, releasing the writer it displaced.
func disableActiveSyslog() {
	syslogPublishMu.Lock()
	old := globalSyslog.Swap(nil)
	noteSyslogForwardingDisabled()
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
	releaseReplacedSyslogWriter(globalSyslog.Swap(sw), sw)
	noteSyslogWriterInstalled(sw, addr)
	syslogPublishMu.Unlock()
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}

// releaseReplacedSyslogWriter closes the Writer that InitSyslog is about to
// replace (CHAOS-72).
//
// Overwriting globalSyslog used to be the whole handover, which stranded the
// old Writer's drain goroutine parked forever on a queue nobody can reach any
// more, holding its collector socket OPEN. Measured against the pre-fix tree:
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
