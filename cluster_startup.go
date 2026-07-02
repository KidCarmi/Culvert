package main

// cluster_startup.go — loader for the cluster slice. Owns the side effects:
// node identity, cluster-state DB load, the CP/HA-standby/HA-resume boot flow
// (ADR-0004), and the 3-priority Data-Plane wiring. The resolver + DTO live
// in cluster_startup_config.go; the initCluster shim in main.go wires them.

import (
	"context"
	"os"
)

// loadCluster applies the resolved cluster config. enrolled is the
// fresh-enrollment result from THIS run (nil when no enrollment happened) —
// a runtime input, deliberately not part of the resolved config.
func loadCluster(cfg clusterStartupConfig, ctx context.Context, enrolled *dpEnrollmentConfig) {
	// Node identity: standalone until a CP/DP/HA path below claims a role.
	clusterRole.role = "standalone"
	if h, err := os.Hostname(); err == nil {
		clusterRole.nodeID = h
	}

	// Cluster state persistence.
	clusterDBPathGlobal = cfg.ClusterDBPath
	if err := globalClusterStore.Load(cfg.ClusterDBPath); err != nil {
		logger.Printf("ClusterDB: load error: %v — starting fresh", err)
	} else if nodes := globalClusterStore.ListNodes(); len(nodes) > 0 {
		logger.Printf("ClusterDB: loaded %d enrolled node(s) from %s", len(nodes), cfg.ClusterDBPath)
	}

	switch {
	case cfg.haJoinMode():
		// Fresh HA standby joining a leader (--ha-join from the deploy command).
		startHAStandby(cfg, ctx, cfg.HAJoinAddr, cfg.HAToken, cfg.HAAutoFailover)
	case cfg.cpMode():
		startControlPlaneWithHAResume(cfg, ctx)
	}

	// Data Plane wiring (independent of the CP/HA paths above).
	dp := resolveDPWiring(cfg, enrolled)
	if dp.addr != "" {
		startDataPlane(ctx, dp.addr, dp.nodeID, dp.certFile, dp.keyFile, dp.caFile)
	}
}

// startHAStandby enters standby mode against leaderAddr. Shared by the fresh
// --ha-join path and the ADR-0004 restart-as-standby path (identical apart
// from where the address/token/preference come from). onPromote enables the
// CP gRPC server when this standby is later promoted.
func startHAStandby(cfg clusterStartupConfig, ctx context.Context, leaderAddr, token string, autoFailover bool) {
	initClusterCA(cfg.ClusterDBPath)
	globalHA.StartAsStandby(ctx, leaderAddr, token,
		cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, autoFailover,
		func() error {
			return enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath)
		},
	)
}

// startControlPlaneWithHAResume is the normal CP boot path. Per ADR-0004 the
// persisted HA role is resolved BEFORE asserting leadership: a node persisted
// as standby re-enters standby (never a silent second leader); a persisted
// leader (or a legacy config with no role) resumes leadership — with a
// split-brain-risk warning when auto-failover is enabled, because a restarted
// leader cannot probe its peer (ADR-0004 scope note).
func startControlPlaneWithHAResume(cfg clusterStartupConfig, ctx context.Context) {
	haCfg, haErr := loadHAConfig()
	if haRestartAction(haCfg, haErr) == "standby" {
		startHAStandby(cfg, ctx, haCfg.PeerAddr, haCfg.Token, haCfg.AutoFailover)
		logger.Printf("HA: restarted as standby from %s (leader=%s) — not self-asserting leader (ADR-0004)",
			haConfigFile, sanitizeLog(haCfg.PeerAddr))
		return
	}

	if err := enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath); err != nil {
		logger.Fatalf("ControlPlane gRPC: %v", err)
	}
	// Persisted leader (or legacy config with no role) resumes leadership.
	if haErr == nil && haCfg.Enabled {
		globalHA.ResumeAsLeader(haCfg) // restores role+token+term+auto_failover (no term bump)
		if haCfg.AutoFailover {
			logger.Printf("HA: resumed as leader from %s after restart. WARNING: automatic failover is "+
				"enabled — if the standby promoted while this node was down, BOTH may now lead. Verify via "+
				"/healthz or the HA panel and reconcile (ADR-0004/RISK-001).", haConfigFile)
		} else {
			logger.Printf("HA: resumed as leader from %s after restart (peer=%s)", haConfigFile, haCfg.PeerAddr)
		}
	}
}

// dpWiring is the resolved Data-Plane connection material.
type dpWiring struct {
	addr, nodeID, certFile, keyFile, caFile string
}

// resolveDPWiring applies the 3-priority DP config resolution (verbatim from
// the pre-slice init): CLI flags win; then a fresh enrollment from THIS run;
// then the saved enrollment config from a previous run. An empty addr means
// "not a Data Plane".
func resolveDPWiring(cfg clusterStartupConfig, enrolled *dpEnrollmentConfig) dpWiring {
	dp := dpWiring{addr: cfg.DPAddr, nodeID: cfg.DPNodeID, certFile: cfg.DPCert, keyFile: cfg.DPKey, caFile: cfg.DPCA}
	// Priority 1: fresh enrollment from this run.
	if enrolled != nil && dp.addr == "" {
		dp = dpWiring{addr: enrolled.CPAddr, nodeID: enrolled.NodeID, certFile: enrolled.CertFile, keyFile: enrolled.KeyFile, caFile: enrolled.CAFile}
	}
	// Priority 2: saved enrollment config from a previous run.
	if dp.addr == "" {
		if ec, err := loadEnrollmentConfig(); err == nil {
			dp = dpWiring{addr: ec.CPAddr, nodeID: ec.NodeID, certFile: ec.CertFile, keyFile: ec.KeyFile, caFile: ec.CAFile}
			logger.Printf("DataPlane: loaded enrollment config from %s", enrollmentConfigFile)
		}
	}
	return dp
}
