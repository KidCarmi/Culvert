package main

// cluster_startup.go — loader for the cluster slice. Owns the side effects:
// node identity, cluster-state DB load, the CP/HA-standby/HA-resume boot flow
// (ADR-0004), and the 3-priority Data-Plane wiring. The resolver + DTO live
// in cluster_startup_config.go; the initCluster shim in main.go wires them.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
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

	// ADR-0005 S5: arm the etcd fencing lease BEFORE any role branch so
	// every path to leadership below is lease-arbitrated. A requested fence
	// that cannot be built is FATAL — silently running legacy when the
	// operator asked for fencing would be an invisible safety downgrade.
	if cfg.HAEtcdEndpoints != "" {
		if err := armHALease(cfg); err != nil {
			logFatalf("HA lease: %v", err)
		}
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
	// ADR-0005 S4: record the material a later demotion needs to resync
	// (a promoted standby that self-fences re-enters standby mode).
	globalHA.SetResyncMaterial(ctx, cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA)
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

	// CHAOS-73: a CP gRPC listener that cannot come up must NOT terminate the
	// proxy data plane, SOCKS5, the admin UI and every health endpoint with it.
	// This line was `logFatalf("ControlPlane gRPC: %v", err)` and initCluster
	// runs BEFORE startAdminUI and buildAndStartProxyServer, so an occupied
	// :50051 or a half-written certificate pair was an unattended crash loop
	// with nothing left serving — reproduced against the real binary (exit 1,
	// proxy/adminui/health all http_code=000). Process death is not "fail
	// closed": it delegates the posture to the topology (§33).
	//
	// noteCPGRPCConfigured/noteCPGRPCRequested run BEFORE the first attempt —
	// the CHAOS-54/66 ordering rule — so a listener that never binds is
	// reported against a CONFIGURED Control Plane rather than as "no cluster",
	// which on a standalone proxy is the healthy steady state and would make
	// the two indistinguishable on exactly the node being debugged.
	noteCPGRPCConfigured(cfg.CPAddr)
	noteCPGRPCRequested(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA)
	if err := enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath); err != nil {
		reason := classifyCPGRPCListenError(err)
		wait := jitterDuration(cpGRPCListenBackoffInitial, cpGRPCListenJitter)
		noteCPGRPCListenFailure(reason, cpGRPCListenBackoffInitial, time.Now())
		logErrorf("ControlPlane gRPC listener on %s could not start (%s): %v — retrying in %s; "+
			"this node continues to serve proxy traffic and its admin UI, but no Data Plane can "+
			"fetch config, enroll or renew certificates until the listener recovers",
			cfg.CPAddr, reason, err, wait.Round(time.Millisecond))
		// LEADERSHIP FOLLOWS THE LISTENER. The resume below is deferred, NOT
		// dropped. Two wrong answers were considered and rejected:
		//
		//   - returning here and leaving it undone makes a restarted leader
		//     that hit a port conflict never resume leadership even after the
		//     port frees, so with auto-failover off (the default) the pair has
		//     no leader at all — a silent ADR-0004 divergence;
		//   - resuming it anyway asserts leadership, the fencing epoch and the
		//     persisted role on a node NO Data Plane can reach, which is the
		//     leader-nobody-can-reach hazard this file argues against for
		//     promote(), and in a lease deployment it holds the fence that
		//     stops anyone else leading.
		//
		// Deferring it is also the closest thing to the pre-change semantics:
		// before this change a failed bind exited, so leadership was only ever
		// asserted after a listener was actually up. It still is.
		cpGRPCOnRecovered(func() { resumeCPLeadership(ctx, cfg, haCfg, haErr) })
		armCPGRPCRecovery()
		return
	}
	// enableControlPlane records the serving state itself (it is the one place
	// all three callers pass through — see the note there). Calling it again
	// here would count two binds for one listener.
	resumeCPLeadership(ctx, cfg, haCfg, haErr)
}

// resumeCPLeadership is the ADR-0004/ADR-0005 leadership resume, reached once a
// CP gRPC listener is actually serving — on the boot path directly, or from the
// recovery loop after a listener that failed its first attempt came up.
// ctx is first per revive's context-as-argument rule. The neighbouring
// startControlPlaneWithHAResume takes (cfg, ctx) — a pre-existing order in this
// file, left alone rather than churned by a sweep about listener fatality.
func resumeCPLeadership(ctx context.Context, cfg clusterStartupConfig, haCfg *haConfig, haErr error) {
	// ADR-0005 S4: record resync material BEFORE any leadership assertion —
	// an unfenced resume (or a later self-fence) re-enters standby with it.
	globalHA.SetResyncMaterial(ctx, cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA)
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

// haLeaseMinTTLSec is the smallest accepted lease TTL. WriteAllowed trusts
// the confirmed validity window MINUS haLeaseWriteMargin (1s), so a TTL at
// or below the margin would grant a lease that never confers write
// authority; 3s leaves a ≥2s trusted window plus renew headroom
// (keepalive tick = TTL/3).
const haLeaseMinTTLSec = 3

// armHALease builds the etcd-backed fencing lease from the resolved config
// and installs it on globalHA (ADR-0005 S5). The candidate ID is this
// node's cluster identity. etcd client construction is lazy (no connection
// until the first lease operation), so an unreachable etcd surfaces as
// denied leadership (fail-closed) rather than a boot failure — only
// MALFORMED config (bad TLS material, unusable TTL) errors here.
func armHALease(cfg clusterStartupConfig) error {
	if cfg.HALeaseTTLSec < haLeaseMinTTLSec {
		return fmt.Errorf("lease TTL %ds too short: minimum %ds (the %s write margin would leave no trusted write window)",
			cfg.HALeaseTTLSec, haLeaseMinTTLSec, haLeaseWriteMargin)
	}
	endpoints := strings.Split(cfg.HAEtcdEndpoints, ",")
	for i := range endpoints {
		endpoints[i] = strings.TrimSpace(endpoints[i])
	}

	tlsCfg, err := buildEtcdTLSConfig(cfg)
	if err != nil {
		return err
	}

	provider, err := halease.NewEtcd(halease.Config{
		Endpoints: endpoints,
		TLS:       tlsCfg,
		TTL:       time.Duration(cfg.HALeaseTTLSec) * time.Second,
	})
	if err != nil {
		return err
	}
	globalHA.SetLeaseProvider(provider, clusterRole.nodeID)
	// CHAOS-55: the recovery loop must look at the fence more often than a
	// holder's key can appear and expire, or a peer's whole tenure can pass
	// between two observations. That bound is the TTL.
	globalHA.SetLeaseTTL(time.Duration(cfg.HALeaseTTLSec) * time.Second)
	logger.Printf("HA: etcd fencing lease ARMED (endpoints=%s, ttl=%ds, candidate=%s) — leadership is lease-arbitrated (ADR-0005)",
		sanitizeLog(cfg.HAEtcdEndpoints), cfg.HALeaseTTLSec, sanitizeLog(clusterRole.nodeID))
	return nil
}

// buildEtcdTLSConfig assembles the etcd client TLS material from the resolved
// config. nil when neither cert nor CA is configured (plaintext — operator's
// call, the compose lab profile uses it).
func buildEtcdTLSConfig(cfg clusterStartupConfig) (*tls.Config, error) {
	if cfg.HAEtcdCert == "" && cfg.HAEtcdCA == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.HAEtcdCert != "" {
		pair, err := tls.LoadX509KeyPair(cfg.HAEtcdCert, cfg.HAEtcdKey)
		if err != nil {
			return nil, fmt.Errorf("etcd client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	if cfg.HAEtcdCA != "" {
		caPEM, err := os.ReadFile(cfg.HAEtcdCA) // #nosec G304 -- operator-configured path
		if err != nil {
			return nil, fmt.Errorf("etcd CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("etcd CA: no certificates parsed from %s", cfg.HAEtcdCA)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}
