package main

// cluster_startup_test.go — per-slice tests for the cluster startup slice:
// resolver precedence, the mode predicates, and the 3-priority DP wiring
// (resolveDPWiring is loader-side but pure-ish enough to test directly with a
// temp working dir so the saved-enrollment read misses). The CP/HA boot flow
// itself is covered by the ha_* suites and the evidence tests.

import "testing"

func TestResolveClusterStartupConfig_PrecedenceAndDefaults(t *testing.T) {
	fc := &FileConfig{}
	fc.Cluster.StateDB = "/data/cluster-from-config.json"
	fc.Cluster.GRPCAddr = ":50051"
	fc.Cluster.CertFile = "/certs/config.crt"

	got := resolveClusterStartupConfig(fc, clusterCLIFlags{ClusterDB: "/data/cli.json"})
	if got.ClusterDBPath != "/data/cli.json" {
		t.Errorf("ClusterDBPath = %q, want the CLI value", got.ClusterDBPath)
	}
	if got.CPAddr != ":50051" || got.CPCert != "/certs/config.crt" {
		t.Errorf("CP wiring = (%q, %q), want config fallbacks", got.CPAddr, got.CPCert)
	}
	// Default DB path when nothing is set.
	if got := resolveClusterStartupConfig(&FileConfig{}, clusterCLIFlags{}); got.ClusterDBPath != "cluster.json" {
		t.Errorf("default ClusterDBPath = %q, want cluster.json", got.ClusterDBPath)
	}
}

func TestClusterStartupConfig_ModePredicates(t *testing.T) {
	// haJoinMode needs BOTH join addr and token.
	c := clusterStartupConfig{HAJoinAddr: "cp1:50051"}
	if c.haJoinMode() {
		t.Error("join addr without token must not enter HA-join mode")
	}
	c.HAToken = "tok"
	if !c.haJoinMode() {
		t.Error("join addr + token must enter HA-join mode")
	}

	// cpMode via listen addr OR pinned YAML role.
	if (clusterStartupConfig{}).cpMode() {
		t.Error("zero config must not be CP mode")
	}
	if !(clusterStartupConfig{CPAddr: ":50051"}).cpMode() {
		t.Error("a gRPC listen addr must select CP mode")
	}
	if !(clusterStartupConfig{ConfigRoleIsCP: true}).cpMode() {
		t.Error("cluster.role=control-plane must select CP mode")
	}
	fc := &FileConfig{}
	fc.Cluster.Role = "control-plane"
	if !resolveClusterStartupConfig(fc, clusterCLIFlags{}).ConfigRoleIsCP {
		t.Error("resolver must map cluster.role=control-plane")
	}
}

func TestResolveDPWiring_ThreePriorities(t *testing.T) {
	// Run from a temp dir so the priority-2 saved-enrollment read misses.
	t.Chdir(t.TempDir())

	// Priority 0: CLI flags win outright.
	cfg := clusterStartupConfig{DPAddr: "cp:50051", DPNodeID: "cli-node"}
	enrolled := &dpEnrollmentConfig{CPAddr: "enrolled:50051", NodeID: "enrolled-node"}
	if dp := resolveDPWiring(cfg, enrolled); dp.addr != "cp:50051" || dp.nodeID != "cli-node" {
		t.Errorf("CLI must win: %+v", dp)
	}

	// Priority 1: fresh enrollment fills in when no CLI addr (ALL fields
	// replaced together — verbatim pre-slice semantics).
	cfg = clusterStartupConfig{DPNodeID: "cli-node-only"}
	if dp := resolveDPWiring(cfg, enrolled); dp.addr != "enrolled:50051" || dp.nodeID != "enrolled-node" {
		t.Errorf("fresh enrollment must replace all fields: %+v", dp)
	}

	// Priority 3 (nothing anywhere): empty addr = not a Data Plane.
	if dp := resolveDPWiring(clusterStartupConfig{}, nil); dp.addr != "" {
		t.Errorf("no source must yield empty wiring, got %+v", dp)
	}
}
