package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

func upstreamEgressRow(t *testing.T) *OperatorContractCheck {
	t.Helper()
	rows := checkUpstreamEgress()
	if len(rows) > 1 {
		t.Fatalf("want at most one upstream_egress row, got %+v", rows)
	}
	if len(rows) == 0 {
		return nil
	}
	return &rows[0]
}

func TestCheckUpstreamEgress(t *testing.T) {
	upEnv(t)
	upstream.FallbackAlertHook = func(string) {}

	// No pool configured: direct egress is the intended posture, no row.
	if r := upstreamEgressRow(t); r != nil {
		t.Fatalf("no pool: want no row, got %+v", r)
	}

	if rec := upV1Post(t, `[{"url":"http://parent-egress.test:3128"}]`); rec.Code != 200 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	upProbe(0, errors.New("dial tcp 192.0.2.1:3128: connect: connection refused"))
	upstreamPool.HealthCheck(upstream.ProbeManual)

	// Zero eligible, no request fell back yet.
	r := upstreamEgressRow(t)
	if r == nil || r.Code != "upstream_egress" || r.Status != diagWarn || r.OperatorAction == "" {
		t.Fatalf("no eligible parent: want upstream_egress WARN, got %+v", r)
	}
	if !strings.Contains(r.Message, "no_eligible_parent") || !strings.Contains(r.Message, "0 of 1") {
		t.Errorf("message should name no_eligible_parent and counts, got %q", r.Message)
	}

	// A request falls back: the row names the active direct fallback.
	if u := upProxyURL(t); u != nil {
		t.Fatal("the request must fall back to direct")
	}
	r = upstreamEgressRow(t)
	if r == nil || !strings.Contains(r.Message, "direct_fallback") || !strings.Contains(r.Message, "egressing DIRECT") {
		t.Fatalf("active fallback: want direct_fallback row, got %+v", r)
	}
	if strings.Contains(r.Message+r.OperatorAction, "parent-egress.test") {
		t.Error("row must not carry the parent authority")
	}

	// The row reaches the operator contract.
	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "upstream_egress" {
			found = true
		}
	}
	if !found {
		t.Error("upstream_egress row missing from the operator contract")
	}

	// A healthy parent clears the row.
	upProbe(200, nil)
	upstreamPool.HealthCheck(upstream.ProbeManual)
	if r := upstreamEgressRow(t); r != nil {
		t.Fatalf("eligible parent: want no row, got %+v", r)
	}
}
