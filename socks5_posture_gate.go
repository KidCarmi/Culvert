package main

// socks5_posture_gate.go — CHAOS-102: the pre-posture accept window.
//
// Why this file exists.
//
// `main()` binds the optional SOCKS5 listener at `initSOCKS5` and restores the
// operator's GUI-persisted admission posture one line later, at
// `initPersistentAdminState` → `LoadAdminSettings` → `applyAdminSecurity`.
// `startSOCKS5` deliberately blocks until the first `bind(2)` resolves and then
// returns (socks5_bind.go), so for the whole of that next line **the socket is
// bound and the accept loop is serving** while the posture it is supposed to
// enforce has not been installed.
//
// `handleSOCKS5` consults exactly three globals that `applyAdminSecurity`
// writes — `connLimiter`, `ipf`, `rl` — and with no `-ip-filter-mode` and no
// YAML `ip_filter_mode`, which is the normal case when the operator built the
// allowlist in the GUI, `applyAdminSecurity` is the ONLY thing that ever sets
// them. Until it runs, `IPFilter.Allowed` returns true for every address
// (internal/admission: an empty mode is "unconfigured", and unconfigured
// allows), `rl` has no limit and `connLimiter` is disabled. A SOCKS5 client
// that connects in that window is admitted from ANY source IP, unrate-limited
// and uncapped, and relayed to an arbitrary TCP destination.
//
// The window is not nothing. `loadPersistentAdminState` runs
// `probeStorageWritability` (create + write + fsync + unlink of a probe file),
// `initConfigVersioning`, three store constructions, `globalAlertStore.Init`,
// `loadHitCounters` + `RestoreHitCounts` and a `saveHitCounters` fsync BEFORE
// it reaches `LoadAdminSettings` — milliseconds on a healthy volume, far
// longer on a slow, contended or failing `/data`. Every item on that list is
// an I/O operation on exactly the volume whose failure the SIMULATE list names
// four separate ways ("disk full", "disk read-only", "slow filesystem",
// "permission denied"), so the worst case for THIS defect is reached by the
// faults the register already tracks elsewhere: the slower the volume, the
// longer the gateway relays unfiltered.
//
// The HTTP/HTTPS plane has no such window — `buildAndStartProxyServer` only
// CONSTRUCTS the server and the listener is opened by
// `runProxyUntilShutdown`'s `ListenAndServe`, the last statement in `main` —
// and neither does the admin UI, the MCP gateway or policy learning, all of
// which start after `initPersistentAdminState`. The asymmetry is what makes
// this a defect rather than a posture: the primary data path already has the
// property, and the optional one was simply wired earlier.
//
// Why a gate and not a reorder.
//
// The remedy the 2026-10-18 sweep described — move `initSOCKS5` down beside
// `startAdminUI` — is the obvious fix and the wrong one. It changes WHEN the
// SOCKS5 listener's bind is attempted and therefore when its health is first
// reported, and AGENTS.md is explicit that "optional-listener failure must not
// become a new primary data-plane termination path". That sweep declined it
// for exactly that reason and left the row open.
//
// A gate separates the two concerns. The bind still happens where it happens,
// `socks5ListenerState` still reports it at the same point in boot, and the
// one thing that changes is that a connection arriving before the posture is
// installed is REFUSED instead of relayed. Startup ownership is untouched.
//
// Why "armed", and why the zero value is open.
//
// The gate is ARMED by `initSOCKS5` immediately before `startSOCKS5` and
// RELEASED by `loadPersistentAdminState` immediately after `LoadAdminSettings`
// returns. It is therefore armed strictly before the socket exists and
// released strictly after the posture restore has run: there is no ordering in
// which the listener is accepting and the gate is not armed, which is the
// property that matters.
//
// The zero value is deliberately "not armed" ⇒ open, and that is NOT a
// fail-open posture, because an unarmed gate means "no boot ever opened this
// window" rather than "the posture is unknown". The two populations with an
// unarmed gate are the ordinary appliance (`socks5_port: 0` — no listener at
// all, nothing to refuse) and this package's tests, which construct admission
// owners directly through `bindFreshAdmissionOwners` / `setupProxyTest` and
// never run `main`'s boot sequence. Defaulting to CLOSED would make the gate's
// correctness depend on ~1,500 test files remembering to release it, and a
// gate that everything has to opt out of is a gate that gets opted out of in
// production too. The arm is one line, next to the only statement in the tree
// that creates the window.
//
// Why the release is unconditional.
//
// `releaseSOCKS5PostureGate` runs after `LoadAdminSettings` whatever that
// returned. `LoadAdminSettings` has three early returns that never reach
// `applyAdminSecurity` — file absent (first run), file unreadable
// (EACCES/EIO), file present but corrupt (quarantined) — and in all three the
// admission posture stays at its compiled default for the life of the process.
// That outcome is pre-existing, deliberate and LOUDLY surfaced (an explicit
// "every GUI-saved admin setting is using its default until the file is
// readable and the node is restarted" log line, the `state_file_corrupt`
// alert, and a /readyz fail row — the CHAOS-05/07 quarantine posture), and
// turning it into a permanent SOCKS5 outage would be a posture change for a
// condition the operator has already been told about by three surfaces. This
// gate closes "the restore has not run YET", which is a race; it deliberately
// does not take on "the restore ran and failed", which is a decision. See the
// CHAOS-102 review's residual-risk section.

import (
	"sync/atomic"
)

// socks5PostureGate holds the pre-posture accept window's state.
//
// `armed` is the gate itself. `refused` is the magnitude an operator can
// scrape after the fact — the window is milliseconds on a healthy volume, so
// the counter, not the log, is what survives to be read. `logged` keeps the
// refusal line to ONE per boot: the window can cover a reconnect storm (every
// client in the fleet redialling a restarted gateway), and the one accept loop
// this file guards is the same one CHAOS-54 recorded flooding 40 MB/s of log
// into a 50 MB rotating file and destroying the evidence of its own fault.
// Same rule as scan_svc.go's oversize line: the counter carries the magnitude,
// the line carries the news.
var socks5PostureGate struct {
	armed   atomic.Bool
	refused atomic.Int64
	logged  atomic.Bool
}

// armSOCKS5PostureGate closes the gate. Called by initSOCKS5 immediately
// before startSOCKS5, so the gate is armed before the socket exists.
// Idempotent.
func armSOCKS5PostureGate() {
	socks5PostureGate.armed.Store(true)
}

// releaseSOCKS5PostureGate opens the gate for the rest of the process's life.
// Called by loadPersistentAdminState immediately after LoadAdminSettings
// returns. Idempotent, and safe to call when the gate was never armed (the
// socks5_port: 0 appliance), in which case it is a no-op with nothing to
// report.
//
// The summary line is emitted only when the window actually refused something,
// and it is the only place the TOTAL is logged: the first refusal logs that the
// window is open, this logs how much it cost. A boot that refused nothing says
// nothing, because "the window closed with no connections in it" is the
// expected outcome on every healthy boot and an operator should not have to
// read past it.
func releaseSOCKS5PostureGate() {
	if !socks5PostureGate.armed.Swap(false) {
		return
	}
	if n := socks5PostureGate.refused.Load(); n > 0 {
		logger.Printf("SOCKS5: admission posture installed; %d connection(s) were refused while it was pending", n)
	}
}

// socks5PostureHeld reports whether the SOCKS5 listener is bound but the
// operator's persisted admission posture has not been installed yet.
func socks5PostureHeld() bool {
	return socks5PostureGate.armed.Load()
}

// noteSOCKS5PostureRefusal records one refused pre-posture connection and logs
// the first one of the boot.
func noteSOCKS5PostureRefusal(clientIP string) {
	socks5PostureGate.refused.Add(1)
	if !socks5PostureGate.logged.Swap(true) {
		logger.Printf("SOCKS5 NOT_READY %q — refused: the persisted admission posture (IP filter, rate limit, "+
			"connection cap) is not installed yet, so admitting this connection would relay it unfiltered. "+
			"Further refusals in this window are counted in culvert_socks5_posture_refused_total, not logged",
			sanitizeLog(clientIP))
	}
}

// socks5PosturePendingGauge renders socks5PostureHeld as the 0/1 Prometheus
// gauge. The branch lives here rather than in handleMetrics deliberately: that
// function is already over the configured gocognit threshold, and the
// conventions ask that a change not make a function the linter attributes to
// its declaration line measurably worse. An accessor that returns the rendered
// value keeps the scrape site a plain format argument.
func socks5PosturePendingGauge() int {
	if socks5PostureHeld() {
		return 1
	}
	return 0
}

// socks5PostureRefusedTotal is the /metrics accessor for the refusal count.
func socks5PostureRefusedTotal() int64 {
	return socks5PostureGate.refused.Load()
}

// resetSOCKS5PostureGateForTest clears the gate. Test isolation only, matching
// resetSOCKS5HealthForTest's contract in socks5_health.go.
func resetSOCKS5PostureGateForTest() {
	socks5PostureGate.armed.Store(false)
	socks5PostureGate.refused.Store(0)
	socks5PostureGate.logged.Store(false)
}
