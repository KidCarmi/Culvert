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
	DPCPAddr       string
	DPNodeID       string
	DPCert         string
	DPKey          string
	DPCA           string
}

// clusterStartupConfig carries the resolved cluster init inputs.
type clusterStartupConfig struct {
	// ClusterDBPath is the cluster state persistence file
	// (CLI > config > "cluster.json").
	ClusterDBPath string

	// CP gRPC listen address + mTLS material (CLI wins per field).
	CPAddr, CPCert, CPKey, CPCA string

	// HA standby-join inputs (--ha-join/--ha-token from the leader's deploy
	// command) + the opt-in auto-failover preference (ADR-0004).
	HAJoinAddr, HAToken string
	HAAutoFailover      bool

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
func resolveClusterStartupConfig(fc *FileConfig, flags clusterCLIFlags) clusterStartupConfig {
	return clusterStartupConfig{
		ClusterDBPath:  firstStr(flags.ClusterDB, fc.Cluster.StateDB, "cluster.json"),
		CPAddr:         firstStr(flags.CPGRPCAddr, fc.Cluster.GRPCAddr),
		CPCert:         firstStr(flags.CPGRPCCert, fc.Cluster.CertFile),
		CPKey:          firstStr(flags.CPGRPCKey, fc.Cluster.KeyFile),
		CPCA:           firstStr(flags.CPGRPCCA, fc.Cluster.CAFile),
		HAJoinAddr:     flags.HAJoin,
		HAToken:        flags.HAToken,
		HAAutoFailover: flags.HAAutoFailover,
		ConfigRoleIsCP: fc.Cluster.Role == "control-plane",
		DPAddr:         flags.DPCPAddr,
		DPNodeID:       flags.DPNodeID,
		DPCert:         flags.DPCert,
		DPKey:          flags.DPKey,
		DPCA:           flags.DPCA,
	}
}
