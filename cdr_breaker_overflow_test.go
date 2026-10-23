package main

// cdr_breaker_overflow_test.go — cdr.timeout_sec has a lower bound only
// (validCDRTimeoutSec), so every conversion of it and every addition to the
// derived deadline must saturate instead of wrapping (PR #1611, Codex P2 on
// b1b128c). timeout_sec 9223372036 is the reviewer's value: the deadline
// itself fits, but deadline+grace wrapped negative and the probe timeout fell
// to the 90s floor. One more second and the deadline conversion itself
// wrapped.

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

// cdrHugeTimeoutSecs are accepted by validCDRTimeoutSec and sit at or past the
// point where seconds→Duration or deadline+grace overflows.
var cdrHugeTimeoutSecs = []int{
	9223372036 - 29, // deadline+grace lands exactly past the maximum
	9223372036,      // the reviewer's value: deadline fits, +30s grace wraps
	9223372037,      // the conversion itself wraps
	math.MaxInt,
}

func TestCDRTimeoutSec_HugeValuesSaturateNotWrap(t *testing.T) {
	for _, secs := range cdrHugeTimeoutSecs {
		if msg := validCDRTimeoutSec(secs); msg != "" {
			t.Fatalf("premise: validCDRTimeoutSec(%d) rejected it (%s); the overflow is no longer reachable", secs, msg)
		}
		cfg := CDRConfig{TimeoutSec: secs}

		deadline := cdrConfigPerFileDeadline(cfg)
		if deadline < 9223372036*time.Second-29*time.Second {
			t.Errorf("timeout_sec=%d: per-file deadline %s wrapped (want >= ~292 years, saturated)", secs, deadline)
		}

		probe := cdrHalfOpenProbeTimeout(30*time.Second, deadline)
		if probe < deadline {
			t.Errorf("REGRESSION: timeout_sec=%d: HalfOpenProbeTimeout %s is below the %s per-file "+
				"deadline it must exceed — the deadline+grace addition overflowed", secs, probe, deadline)
		}

		b := newCDRCircuitBreaker(cdrBreakerConfig{PerFileDeadline: deadline})
		if b.cfg.HalfOpenProbeTimeout < deadline {
			t.Errorf("timeout_sec=%d: breaker HalfOpenProbeTimeout %s < deadline %s", secs, b.cfg.HalfOpenProbeTimeout, deadline)
		}

		ctx, cancel := cdrCallContext(context.Background(), cfg)
		dl, ok := ctx.Deadline()
		cancel()
		if !ok || !dl.After(time.Now().Add(24*time.Hour)) {
			t.Errorf("REGRESSION: timeout_sec=%d: call context deadline %v (set=%v) is not far in the "+
				"future — the conversion wrapped and every Sanitize would expire at once", secs, dl, ok)
		}
	}
}

// TestCDRHalfOpenProbeTimeout_HugeResetSaturates covers the other operand:
// 2×ResetTimeout must saturate too.
func TestCDRHalfOpenProbeTimeout_HugeResetSaturates(t *testing.T) {
	reset := cdrMaxDuration/2 + time.Second
	if got := cdrHalfOpenProbeTimeout(reset, cdrDefaultTimeout); got < reset {
		t.Fatalf("REGRESSION: cdrHalfOpenProbeTimeout(reset=%s) = %s; 2×reset wrapped", reset, got)
	}
}

// TestCDRDialSingle_HugeTimeoutSeedsAPositiveDeadline drives the production
// construction path: the client deadline and the breaker seed come from the
// same saturating conversion, so the breaker still outlasts the client.
func TestCDRDialSingle_HugeTimeoutSeedsAPositiveDeadline(t *testing.T) {
	for _, secs := range cdrHugeTimeoutSecs {
		pc, err := dialSingleFromConfig(CDRConfig{
			Endpoint: "127.0.0.1:1", ServerFingerprint: strings.Repeat("ab", 32), TimeoutSec: secs,
		})
		if err != nil {
			t.Fatalf("dialSingleFromConfig(timeout_sec=%d): %v", secs, err)
		}
		clientTimeout := pc.Client.cfg.Timeout
		probe := pc.Breaker.cfg.HalfOpenProbeTimeout
		_ = pc.Client.Close()
		if clientTimeout <= 0 {
			t.Errorf("REGRESSION: timeout_sec=%d: client deadline %s is not positive", secs, clientTimeout)
		}
		if probe < clientTimeout {
			t.Errorf("timeout_sec=%d: breaker HalfOpenProbeTimeout %s < client deadline %s", secs, probe, clientTimeout)
		}
	}
}
