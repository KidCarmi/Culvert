package secscan

// avposture.go — the av_unavailable posture: what a body scan does when the AV
// engine cannot render a verdict because it is FAULTED (daemon stopped,
// crashed, restarting, unreachable, or a sidecar that is down or answering
// nonsense).
//
// This is deliberately ONE posture for BOTH scanning back ends (the in-process
// ClamAV leg and the remote sidecar), CHAOS-53's rule: one budget, one
// posture. Which back end a node happens to run must never decide whether
// unscanned content is admitted.
//
//	open   — the historical behaviour (register rows WK-1b / WK-2b): the
//	         content is forwarded UNSCANNED for that request, counted and
//	         alerted. The default, byte-identical when nothing is configured.
//	closed — the content is REFUSED (Result Source "av_unavailable"), counted
//	         by its own counter and logged at a rate limit. The appliance ships
//	         this posture.
//
// It governs the FAULT branch only. A scan that ran out of budget, or could
// not get a ClamAV slot inside it, is already refused in both postures by the
// fail-closed timeout path (Source "timeout") and is untouched here.
//
// A refusal under this posture is an INFRASTRUCTURE verdict, never a verdict
// about the content, so it is never cached: the next request for the same
// object rescans, and the moment the engine recovers the object is judged on
// its merits again.

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// AV-unavailable posture values. The wire, the settings file and the
// CULVERT_AV_UNAVAILABLE env var all use these exact strings.
const (
	AVUnavailableOpen   = "open"
	AVUnavailableClosed = "closed"
)

// SourceAVUnavailable is the Result.Source of a refusal under the closed
// posture. Reason is AVUnavailableReason.
const (
	SourceAVUnavailable = "av_unavailable"
	AVUnavailableReason = "AV scan unavailable"
)

// avUnavailableClosed is the live posture. Read once per FAULTED scan only
// (never on the healthy path), so an atomic is plenty.
var avUnavailableClosed atomic.Bool

// statAVUnavailableRefused counts bodies refused because the AV engine could
// not render a verdict while the posture was closed (both back ends).
var statAVUnavailableRefused int64

var lastAVRefusalLog atomic.Int64

// NormalizeAVUnavailable canonicalises a posture string (case- and
// space-tolerant). ok is false for anything but open/closed.
func NormalizeAVUnavailable(s string) (posture string, ok bool) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case AVUnavailableOpen, AVUnavailableClosed:
		return v, true
	default:
		return "", false
	}
}

// SetAVUnavailablePosture installs the posture. An unrecognised value is
// refused and the live posture is left unchanged.
func SetAVUnavailablePosture(p string) error {
	v, ok := NormalizeAVUnavailable(p)
	if !ok {
		return fmt.Errorf("av_unavailable must be %q or %q", AVUnavailableOpen, AVUnavailableClosed)
	}
	avUnavailableClosed.Store(v == AVUnavailableClosed)
	return nil
}

// AVUnavailablePosture reports the live posture ("open" or "closed").
func AVUnavailablePosture() string {
	if avUnavailableClosed.Load() {
		return AVUnavailableClosed
	}
	return AVUnavailableOpen
}

// AVUnavailableRefusedTotal reports refusals under the closed posture so far.
func AVUnavailableRefusedTotal() int64 { return atomic.LoadInt64(&statAVUnavailableRefused) }

// avUnavailableRefusal records one refusal and returns the blocked Result.
// backend names which leg faulted ("clamav" / "remote sidecar"); class is the
// BOUNDED reason class already used by that leg's alert. cause is the full
// error text for the (rate-limited) log line only — "" when the leg already
// logs it (the ClamAV leg does, in clamScanError) — and is sanitised because
// it can carry a daemon- or sidecar-supplied string (CWE-117).
func avUnavailableRefusal(hash, backend, class, cause string) *Result {
	total := atomic.AddInt64(&statAVUnavailableRefused, 1)
	if degradedLogAllowed(&lastAVRefusalLog) {
		detail := strings.ReplaceAll(class, "\n", " ")
		if cause != "" {
			detail += ": " + obs.Sanitize(cause)
		}
		obs.Warnf("SecurityScan: AV scan unavailable (%s: %s) — content REFUSED (av_unavailable=closed) for hash %s; total %d",
			backend, detail, hash, total)
	}
	return &Result{Blocked: true, Reason: AVUnavailableReason, Source: SourceAVUnavailable, Hash: hash}
}

// avFaultOutcome is the clause a fault log line uses to say what happened to
// the content, so the line never claims "forwarding UNSCANNED" while the
// closed posture is refusing it.
func avFaultOutcome() string {
	if avUnavailableClosed.Load() {
		return "content REFUSED (av_unavailable=closed)"
	}
	return "forwarding UNSCANNED (fail-open)"
}
