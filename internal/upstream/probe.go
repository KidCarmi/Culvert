package upstream

// probe.go — the single health classifier for periodic and manual probes
// (2F contract C11). Only the bounded reason enum is stored; response bodies
// are drained unread (≤1 KiB) and discarded; a transport error is never
// rendered anywhere (binding clarification 2).

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// Probe statuses.
const (
	ProbeUnprobed  = "unprobed"
	ProbeHealthy   = "healthy"
	ProbeUnhealthy = "unhealthy"
)

// Probe reasons.
const (
	ReasonNone            = "none"
	ReasonConnectFailed   = "connect_failed"
	ReasonTimeout         = "timeout"
	ReasonProxyAuthFailed = "proxy_auth_failed"
	ReasonProbeHTTPError  = "probe_http_error"
)

// ProbeState is an entry's last probe outcome.
type ProbeState struct {
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	CheckedAt string `json:"checkedAt,omitempty"`
	// Source distinguishes a periodic health-loop verdict from an operator
	// triggered manual check (empty while unprobed).
	Source string `json:"source,omitempty"`
}

// Probe sources.
const (
	ProbePeriodic = "periodic"
	ProbeManual   = "manual"
)

// Health is the contracted per-entry health shape on the read model.
type Health struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	LastProbeAt string `json:"lastProbeAt,omitempty"`
	Source      string `json:"source,omitempty"`
}

// HealthOf projects a probe state onto the contracted health shape.
func HealthOf(st ProbeState) Health {
	return Health{Status: st.Status, Reason: st.Reason, LastProbeAt: st.CheckedAt, Source: st.Source}
}

// probeDrainLimit bounds how much of a probe response body is read (and
// discarded) before the connection is released.
const probeDrainLimit = 1 << 10

// ClassifyProbe maps a probe outcome to (status, reason). It is the ONE
// classifier: dial/TLS error → connect_failed, deadline → timeout, HTTP 407
// → proxy_auth_failed, 2xx/3xx → healthy, any other status →
// probe_http_error.
func ClassifyProbe(resp *http.Response, err error) (status, reason string) {
	if err != nil {
		return ProbeUnhealthy, classifyTransportError(err)
	}
	if resp == nil {
		return ProbeUnhealthy, ReasonConnectFailed
	}
	switch {
	case resp.StatusCode == http.StatusProxyAuthRequired:
		return ProbeUnhealthy, ReasonProxyAuthFailed
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		return ProbeHealthy, ReasonNone
	default:
		return ProbeUnhealthy, ReasonProbeHTTPError
	}
}

// classifyTransportError maps a transport error to a bounded reason without
// ever rendering it (it may embed a credential-bearing proxy URL).
func classifyTransportError(err error) string {
	if errors.Is(err, ErrCredentialMismatch) || errors.Is(err, ErrKeyMissing) || errors.Is(err, errProbeIneligible) {
		return ReasonProxyAuthFailed
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReasonTimeout
	}
	return ReasonConnectFailed
}

// errProbeIneligible is returned by the probe's proxy selector when the
// entry stopped being credential-eligible between selection and dial.
var errProbeIneligible = errors.New("upstream probe: entry not credential-eligible")

// drainAndClose reads at most probeDrainLimit bytes of a response body and
// discards them, then closes it.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, resp.Body, probeDrainLimit)
	_ = resp.Body.Close()
}

// nowRFC3339 is the probe clock (a var so tests can pin it).
var nowRFC3339 = func() string { return time.Now().UTC().Format(time.RFC3339) }
