package main

import (
	"strings"
	"testing"
	"time"
)

func TestClusterRateLimitFreshnessDiagnostics(t *testing.T) {
	r := withClusterRateLimiter(t, 10, time.Minute)
	useProductionRateLimiter(t, r)

	r.SetClusterEnabled(false)
	if rows := checkClusterRateLimitFreshness(r); len(rows) != 0 {
		t.Fatalf("unarmed node must add no row, got %+v", rows)
	}

	r.SetClusterEnabled(true)
	rows := checkClusterRateLimitFreshness(r)
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "no Control Plane broadcast") {
		t.Fatalf("armed node that never received a broadcast must warn, got %+v", rows)
	}
	if rows[0].Code != "cluster_ratelimit_freshness" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
		t.Fatalf("unexpected row %+v", rows[0])
	}
	found := false
	for _, c := range buildOperatorContract().Checks {
		found = found || c.Code == "cluster_ratelimit_freshness"
	}
	if !found {
		t.Fatal("row missing from the assembled contract")
	}

	r.ApplyRemoteCounts(map[string]int{})
	if rows := checkClusterRateLimitFreshness(r); len(rows) != 0 {
		t.Fatalf("a fresh broadcast must clear the row, got %+v", rows)
	}
}
