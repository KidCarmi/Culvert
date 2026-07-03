package main

// cluster_startup_test.go — per-slice tests for the cluster startup slice:
// resolver precedence, the mode predicates, and the 3-priority DP wiring
// (resolveDPWiring is loader-side but pure-ish enough to test directly with a
// temp working dir so the saved-enrollment read misses). The CP/HA boot flow
// itself is covered by the ha_* suites and the evidence tests.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestResolveClusterStartupConfig_LeaseFields(t *testing.T) {
	fc := &FileConfig{}
	fc.Cluster.EtcdEndpoints = "https://yaml-etcd:2379"
	fc.Cluster.EtcdCA = "/yaml/ca.pem"
	fc.Cluster.LeaseTTLSeconds = 30

	// CLI wins per field.
	got := resolveClusterStartupConfig(fc, clusterCLIFlags{
		HAEtcdEndpoints: "https://cli-etcd:2379", HALeaseTTLSec: 5,
	})
	if got.HAEtcdEndpoints != "https://cli-etcd:2379" || got.HALeaseTTLSec != 5 {
		t.Errorf("CLI must win: endpoints=%q ttl=%d", got.HAEtcdEndpoints, got.HALeaseTTLSec)
	}
	if got.HAEtcdCA != "/yaml/ca.pem" {
		t.Errorf("HAEtcdCA = %q, want the yaml fallback", got.HAEtcdCA)
	}

	// YAML fallback + TTL default.
	got = resolveClusterStartupConfig(fc, clusterCLIFlags{})
	if got.HAEtcdEndpoints != "https://yaml-etcd:2379" || got.HALeaseTTLSec != 30 {
		t.Errorf("yaml fallback: endpoints=%q ttl=%d", got.HAEtcdEndpoints, got.HALeaseTTLSec)
	}
	if got := resolveClusterStartupConfig(&FileConfig{}, clusterCLIFlags{}); got.HALeaseTTLSec != 10 {
		t.Errorf("default lease TTL = %d, want 10", got.HALeaseTTLSec)
	}
}

// armHALease error paths must be loud (the loader Fatals on them): a fence
// the operator asked for that cannot be built is never silently downgraded
// to legacy mode. Only MALFORMED config errors — an unreachable etcd does
// not (client construction is lazy; leadership is simply denied later).
func TestArmHALease_MalformedConfigErrors(t *testing.T) {
	dir := t.TempDir()

	// Client cert requested but unreadable.
	err := armHALease(clusterStartupConfig{
		HAEtcdEndpoints: "https://etcd:2379",
		HAEtcdCert:      filepath.Join(dir, "missing.crt"),
		HAEtcdKey:       filepath.Join(dir, "missing.key"),
		HALeaseTTLSec:   10,
	})
	if err == nil || !strings.Contains(err.Error(), "etcd client cert") {
		t.Errorf("missing client cert: err = %v, want etcd client cert error", err)
	}

	// CA file unreadable.
	err = armHALease(clusterStartupConfig{
		HAEtcdEndpoints: "https://etcd:2379",
		HAEtcdCA:        filepath.Join(dir, "missing-ca.pem"),
		HALeaseTTLSec:   10,
	})
	if err == nil || !strings.Contains(err.Error(), "etcd CA") {
		t.Errorf("missing CA: err = %v, want etcd CA error", err)
	}

	// CA file present but not PEM.
	garbage := filepath.Join(dir, "garbage-ca.pem")
	if werr := os.WriteFile(garbage, []byte("not a certificate"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	err = armHALease(clusterStartupConfig{
		HAEtcdEndpoints: "https://etcd:2379",
		HAEtcdCA:        garbage,
		HALeaseTTLSec:   10,
	})
	if err == nil || !strings.Contains(err.Error(), "no certificates parsed") {
		t.Errorf("garbage CA: err = %v, want no-certificates-parsed error", err)
	}
}

// armHALease with an UNREACHABLE (but well-formed) endpoint must succeed and
// install the provider: the etcd client connects lazily, so an etcd outage at
// boot surfaces as denied leadership (fail-closed), never a boot failure.
func TestArmHALease_UnreachableEndpointStillArms(t *testing.T) {
	installGlobalHA(t, &HAState{})
	if err := armHALease(clusterStartupConfig{
		HAEtcdEndpoints: "127.0.0.1:1, 127.0.0.1:2", // reserved ports; nothing listens
		HALeaseTTLSec:   1,
	}); err != nil {
		t.Fatalf("armHALease with unreachable endpoints must not error (lazy client): %v", err)
	}
	if !globalHA.leaseConfigured() {
		t.Fatal("provider must be installed on globalHA")
	}
	// Fail-closed proof: leadership is denied while etcd is unreachable.
	if globalHA.acquireLeaseForLeadership("test") {
		t.Fatal("acquire against an unreachable etcd must be denied (fail-closed)")
	}
	globalHA.mu.RLock()
	p := globalHA.lease
	globalHA.mu.RUnlock()
	_ = p.Close()
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
