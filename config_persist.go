package main

// config_persist.go — CHAOS-27 / F-12: durable-write failures on the config
// state files are never silent.
//
// The stores that hold enforcement state (policy rules, blocklist + mode,
// category groups, URL categories, decryption profiles, SSL-bypass set,
// content-scan envelope, file-block extensions) all persist through
// fileutil.AtomicWrite, and all of them discarded its error. On a full,
// read-only, or permission-broken data directory that produced the worst
// failure class an appliance can have: the admin's change is accepted (HTTP
// 200), enforced in memory, shown in the UI — and silently reverted by the next
// restart. Nothing logged, nothing counted, nothing alerted.
//
// The write sites now go through fileutil.AtomicWriteTracked, which records the
// outcome per logical store and calls the reporter installed here. This file is
// the main-side response, and it deliberately mirrors the CHAOS-05/07
// state-corruption model in state_corruption.go:
//
//  1. a loud, sanitised log line on the failure edge and on recovery;
//  2. a config_persist_failed alert on the TRANSITION into failing (via
//     deferStartupAlert, so a failure during an early startup slice is not
//     swallowed by an empty webhook list — the CHAOS-06 lesson), plus one
//     config_persist_recovered on the way back;
//  3. a report-only /readyz row per failing store, carrying a FIXED,
//     non-path detail because /readyz is served unauthenticated on the proxy
//     port (same disclosure posture as appendStateFileChecks);
//  4. Prometheus series (see metrics.go) so the condition is graphable and
//     alertable outside the webhook path.
//
// Posture: report, do not refuse. A failed config write means the RUNNING
// enforcement is still correct and strictly newer than disk; halting the proxy
// would convert a durability problem into an availability outage. What must not
// happen — and no longer does — is the operator not knowing.

import (
	"fmt"
	"io"
	"sort"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// configPersistAlert is the alert seam (tests swap it for a synchronous
// recorder rather than listening on the process-global alerts sink — the
// determinism lesson from the CHAOS-11 run).
var configPersistAlert = deferStartupAlert

func init() { fileutil.SetPersistFailureReporter(reportConfigPersist) }

// reportConfigPersist logs and alerts a durable-write state change. Called from
// inside the store's Save path — possibly with that store's lock held — so it
// only logs and enqueues; it never re-enters a store and never blocks.
func reportConfigPersist(ev fileutil.PersistEvent) {
	if ev.Recovered {
		logger.Printf("ConfigPersist: store %q recovered — %q is durable again (%d prior failure(s))",
			sanitizeLog(ev.Store), sanitizeLog(ev.Path), ev.Total)
		configPersistAlert("config_persist_recovered", AlertPayload{
			Detail: fmt.Sprintf("config store %s persisted successfully again after %d failed write(s)",
				sanitizeLog(ev.Store), ev.Total),
			Source: "storage",
		})
		return
	}

	logWarnf("ConfigPersist: store %q FAILED to persist to %q (%q) — the running config is NOT on disk and will be lost on restart (consecutive=%d total=%d)",
		sanitizeLog(ev.Store), sanitizeLog(ev.Path), sanitizeLog(errString(ev.Err)), ev.Consecutive, ev.Total)

	// Transition edge only. A store that keeps failing on every save would
	// otherwise emit one webhook per dedup window for as long as the disk is
	// broken; the /readyz row and the Prometheus gauge carry the ongoing state.
	if ev.Consecutive != 1 {
		return
	}
	configPersistAlert("config_persist_failed", AlertPayload{
		Detail: fmt.Sprintf("config store %s could not be written to disk (%s) — the change is live in memory but will be LOST on restart; check the data directory for a full, read-only, or permission-broken filesystem",
			sanitizeLog(ev.Store), sanitizeLog(errString(ev.Err))),
		Source: "storage",
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// appendConfigPersistChecks adds one report-only /readyz row per config store
// whose last durable write failed. Report-only matches the CHAOS-06 posture:
// the node keeps serving (its in-memory config is correct), but the condition
// must be visible to a probe, not just to a log reader.
//
// The detail is FIXED and path-free on purpose: /readyz is unauthenticated on
// the proxy port, and the absolute state-file path plus the raw syscall error
// would fingerprint a degraded node and disclose the filesystem layout. The row
// KEY names the store, so the operator signal survives; the full detail stays in
// the logs, the alert, and the authenticated diagnostics.
func appendConfigPersistChecks(checks map[string]*readinessCheck) {
	for _, f := range fileutil.PersistFailures() {
		checks["config_persist_"+f.Store] = &readinessCheck{
			Status: "fail",
			Detail: "config store could not be written to disk; running config is newer than disk and will be lost on restart — see server logs",
		}
	}
}

// writeConfigPersistMetrics emits the CHAOS-27 Prometheus series. The
// _failing_stores gauge is emitted unconditionally (0 when healthy) so an
// alerting rule never depends on a metric that only appears once things are
// already broken; the labelled series appear per store that has failed at least
// once this process lifetime. Store names are compile-time constants at the
// write sites, so the label values are not attacker-influenced.
func writeConfigPersistMetrics(w io.Writer) {
	failing := map[string]bool{}
	for _, f := range fileutil.PersistFailures() {
		failing[f.Store] = true
	}
	totals := fileutil.PersistFailureTotals()
	stores := make([]string, 0, len(totals))
	for s := range totals {
		stores = append(stores, s)
	}
	sort.Strings(stores)

	_, _ = fmt.Fprintf(w, `# HELP culvert_config_persist_failing_stores Config state files whose most recent durable write failed (running config is newer than disk)
# TYPE culvert_config_persist_failing_stores gauge
culvert_config_persist_failing_stores %d
`, len(failing))

	if len(stores) == 0 {
		return
	}
	_, _ = fmt.Fprint(w, `
# HELP culvert_config_persist_failures_total Failed durable writes of a config state file, by store
# TYPE culvert_config_persist_failures_total counter
`)
	for _, s := range stores {
		_, _ = fmt.Fprintf(w, "culvert_config_persist_failures_total{store=%q} %d\n", s, totals[s])
	}
	_, _ = fmt.Fprint(w, `
# HELP culvert_config_persist_failing 1 when this config state file's most recent durable write failed
# TYPE culvert_config_persist_failing gauge
`)
	for _, s := range stores {
		v := 0
		if failing[s] {
			v = 1
		}
		_, _ = fmt.Fprintf(w, "culvert_config_persist_failing{store=%q} %d\n", s, v)
	}
}
