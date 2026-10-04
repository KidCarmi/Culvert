package main

// cluster_startup_config.go — resolved config for the cluster slice (Control
// Plane / Data Plane gRPC + the HA boot flow). Pure DTO + a single
// side-effect-free resolver invoked from the initCluster shim. CLI flag
// values are passed IN as a value struct so the resolver stays pure (slice
// convention pinned by startup_slice_contract_test.go). Runtime inputs the
// resolver deliberately does NOT touch: the hostname, the persisted HA config
// (ha_config.json), the saved enrollment config, and the fresh-enrollment
// result — all loader-side.

// clusterCLIFlags carries the cluster CLI flag values (read in the shim).
// Empty values mean "flag not set" — config file values win.
type clusterCLIFlags struct {
	ClusterDB      string
	CPGRPCAddr     string
	CPGRPCCert     string
	CPGRPCKey      string
	CPGRPCCA       string
	HAJoin         string
	HAToken        string
	HAAutoFailover bool
	// ADR-0005 S5: etcd fencing-lease wiring.
	HAEtcdEndpoints string
	HAEtcdCert      string
	HAEtcdKey       string
	HAEtcdCA        string
	HALeaseTTLSec   int
	DPCPAddr        string
	DPNodeID        string
	DPCert          string
	DPKey           string
	DPCA            string
}

// clusterStartupConfig carries the resolved cluster init inputs.
type clusterStartupConfig struct {
	// ClusterDBPath is the cluster state persistence file
	// (CLI > config > "cluster.json").
	ClusterDBPath string

	// CP gRPC listen address + mTLS material (CLI wins per field).
	CPAddr, CPCert, CPKey, CPCA string

	// HA standby-join inputs (--ha-join/--ha-token from the leader's deploy
	// command) + the opt-in auto-failover preference (ADR-0004; legacy mode
	// only — in lease mode the fence arbitrates).
	HAJoinAddr, HAToken string
	HAAutoFailover      bool

	// ADR-0005 S5: etcd fencing lease (empty endpoints = legacy manual
	// mode). CLI wins per field; TTL defaults to 10s.
	HAEtcdEndpoints                 string
	HAEtcdCert, HAEtcdKey, HAEtcdCA string
	HALeaseTTLSec                   int

	// ConfigRoleIsCP is true when the YAML pins cluster.role=control-plane.
	ConfigRoleIsCP bool

	// DP CLI-layer wiring (priority 0 of 3 — fresh enrollment and the saved
	// enrollment config are runtime inputs resolved by the loader).
	DPAddr, DPNodeID, DPCert, DPKey, DPCA string
}

// haJoinMode reports whether this boot was invoked as an HA standby joining a
// leader (both --ha-join and --ha-token present).
func (c clusterStartupConfig) haJoinMode() bool {
	return c.HAJoinAddr != "" && c.HAToken != ""
}

// cpMode reports whether this node should start as a Control Plane (a gRPC
// listen address is configured, or the YAML pins the role).
func (c clusterStartupConfig) cpMode() bool {
	return c.CPAddr != "" || c.ConfigRoleIsCP
}

// resolveClusterStartupConfig is the single startup-time reader of fc.Cluster
// for this slice. Pure and deterministic; safe on a zero-value *FileConfig.
// cpGRPCAddrFrom resolves the Control Plane gRPC listen address this node will
// actually bind: the CLI flag wins, else `cluster.grpc_addr` from config.yaml.
//
// It exists because TWO places need that answer and they must not be able to
// disagree about it — `validatePortCollisions` (main.go), which refuses a
// pre-boot collision with the proxy/UI/SOCKS5 ports, and this resolver, which
// is what `initCluster` actually binds. CHAOS-71 shipped the validator reading
// only the CLI flag, so with `-cp-grpc-addr` unset and `cluster.grpc_addr`
// equal to the proxy port the validator saw an EMPTY address, passed, and the
// Control Plane then took the port before the proxy reached it. Reproduced
// against the real binary (Codex review P1, PR #1546):
//
//	ControlPlane: enabled (gRPC :18090)
//	Proxy: http://localhost:18090
//	Proxy error: listen tcp :18090: bind: address already in use   → exit 1
//
// i.e. exactly the unattended crash loop that validation exists to prevent,
// surviving through the YAML path. This is the divergence class CHAOS-69
// recorded for lockout's `Check`/`RecordFailure` pair and for its own
// measure-vs-use round: two call sites deriving ONE value separately will
// drift, and the drift lands where a hostile or merely unlucky input wants it.
// `TestChaos71_PortValidatorResolvesTheAddressTheClusterSliceBinds` pins the
// AGREEMENT rather than either spelling, so a future change to the precedence
// fails the build unless both move together.
func cpGRPCAddrFrom(cliAddr string, fc *FileConfig) string {
	if fc == nil {
		return cliAddr
	}
	return firstStr(cliAddr, fc.Cluster.GRPCAddr)
}

func resolveClusterStartupConfig(fc *FileConfig, flags clusterCLIFlags) clusterStartupConfig {
	return clusterStartupConfig{
		ClusterDBPath:   firstStr(flags.ClusterDB, fc.Cluster.StateDB, "cluster.json"),
		CPAddr:          cpGRPCAddrFrom(flags.CPGRPCAddr, fc),
		CPCert:          firstStr(flags.CPGRPCCert, fc.Cluster.CertFile),
		CPKey:           firstStr(flags.CPGRPCKey, fc.Cluster.KeyFile),
		CPCA:            firstStr(flags.CPGRPCCA, fc.Cluster.CAFile),
		HAJoinAddr:      flags.HAJoin,
		HAToken:         flags.HAToken,
		HAAutoFailover:  flags.HAAutoFailover,
		HAEtcdEndpoints: firstStr(flags.HAEtcdEndpoints, fc.Cluster.EtcdEndpoints),
		HAEtcdCert:      firstStr(flags.HAEtcdCert, fc.Cluster.EtcdCert),
		HAEtcdKey:       firstStr(flags.HAEtcdKey, fc.Cluster.EtcdKey),
		HAEtcdCA:        firstStr(flags.HAEtcdCA, fc.Cluster.EtcdCA),
		HALeaseTTLSec:   firstNonZero(flags.HALeaseTTLSec, fc.Cluster.LeaseTTLSeconds, 10),
		ConfigRoleIsCP:  fc.Cluster.Role == "control-plane",
		DPAddr:          flags.DPCPAddr,
		DPNodeID:        flags.DPNodeID,
		DPCert:          flags.DPCert,
		DPKey:           flags.DPKey,
		DPCA:            flags.DPCA,
	}
}
