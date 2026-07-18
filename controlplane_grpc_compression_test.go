package main

// controlplane_grpc_compression_test.go — P0 rollout-safety coverage.
//
// The DP client's gzip compression is opt-in and default-off
// (CULVERT_CLUSTER_GRPC_COMPRESSION). An unconditional client-side compressor
// would make a new DP fail EVERY RPC (Unimplemented) against an un-upgraded or
// rolled-back CP that has not registered the gzip codec — a fleet-wide
// config-sync blackout. readClusterGRPCCompression must therefore fail SAFE:
// only an explicit true-ish value enables compression.

import (
	"testing"
)

func TestReadClusterGRPCCompression_FailsSafe(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		// Explicit opt-in — the only values that enable compression.
		{"true", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"TRUE", true},
		{"  On  ", true},
		// Everything else must leave compression OFF (fail-safe default).
		{"", false},        // unset
		{"false", false},   // explicit off
		{"0", false},       // explicit off
		{"no", false},      // explicit off
		{"off", false},     // explicit off
		{"gzip", false},    // typo / unknown must not silently enable
		{"enabled", false}, // near-miss must not enable
		{"2", false},       // non-1 numeric
	}
	for _, c := range cases {
		t.Setenv(clusterGRPCCompressionEnvVar, c.val)
		if got := readClusterGRPCCompression(); got != c.want {
			t.Errorf("readClusterGRPCCompression(%q) = %v, want %v", c.val, got, c.want)
		}
	}
}

// TestClusterGRPCCompression_DefaultOff pins the package-level default: with no
// env override at startup, compression must be disabled so a mixed-version
// cluster cannot go dark.
func TestClusterGRPCCompression_DefaultOff(t *testing.T) {
	t.Setenv(clusterGRPCCompressionEnvVar, "")
	if readClusterGRPCCompression() {
		t.Fatal("compression must default OFF when the env var is unset — a DP-first rollout would otherwise blackout every RPC against an un-upgraded CP")
	}
}
