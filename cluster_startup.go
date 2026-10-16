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
	host, _ := os.Hostname()
	initStandaloneClusterRole(host)

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

	// ADR-0005 S4: record resync material BEFORE any leadership assertion —
	// an unfenced resume (or a later self-fence) re-enters standby with it.
	// Unconditional, and deliberately ahead of the listener: it only RECORDS
	// where a later demotion would resync from, so a node whose listener is
	// still coming up is better off having it than not.
	globalHA.SetResyncMaterial(ctx, cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA)

	// CHAOS-71 — this used to be:
	//
	//	if err := enableControlPlane(...); err != nil {
	//	        logFatalf("ControlPlane gRPC: %v", err)   // ← os.Exit(1)
	//	}
	//
	// which terminated the whole appliance — proxy, SOCKS5, admin UI, health
	// endpoints, none of which have started yet at this point in main.go — for
	// any reason the CLUSTER plane's listener could not bind. See
	// cp_grpc_bind.go for the finding, the reproduction and why process death
	// is not "fail closed" here.
	//
	// The leadership resume is the onActivated callback rather than a statement
	// after this call, so this node never asserts a term it cannot exercise: a
	// "leader" no Data Plane can reach cannot serve HASync. On the happy path
	// (the listener binds on its first attempt, i.e. every healthy boot) the
	// callback runs synchronously inside this call and the ordering is
	// byte-identical to the code above.
	//
	// The callback deliberately does NOT close over the boot-time haCfg: with
	// the retrying supervisor it can run minutes after boot, and resuming from
	// a config the operator has since disabled or flipped to standby would
	// restore and re-persist a stale leader (CodeRabbit review of #1556).
	resumeLeadership := func() { resumeLeadershipIfStillPersisted() }
	if err := enableControlPlaneResilient(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath, resumeLeadership); err != nil {
		// Reached only for a refusal that no retry can fix (an empty address, or
		// a listener already starting) — never for a bind or TLS fault, which
		// the supervisor owns. Still not fatal: a misconfigured cluster plane
		// must not cost this node's traffic.
		logErrorf("ControlPlane: not enabled: %v — this node continues as a standalone gateway", err)
	}
}

// haBootResumeAsLeader is the boot path's leadership-resume action. A seam so
// the gate for resumeLeadershipIfStillPersisted can observe the decision
// without mutating the process-global HA state.
//
// It resumes through ResumeAsLeaderIfUnclaimed: the lease acquisition can take
// seconds, during which an admin HA enable may claim the node, so the resume
// revalidates the persisted config and applies only while no HA role is held
// (atomic with every HA transition under HAState.mu). Reports whether it was
// applied.
var haBootResumeAsLeader = func(cfg *haConfig) bool {
	// restores role+token+term+auto_failover (no term bump)
	return globalHA.ResumeAsLeaderIfUnclaimed(cfg, func() bool { return haConfigStillResumable(cfg) })
}

// haConfigStillResumable reports whether the persisted HA config still says
// this node leads with the same peer and token as cfg — the config a resume
// started from.
func haConfigStillResumable(cfg *haConfig) bool {
	now, err := loadHAConfig()
	if haRestartAction(now, err) != "leader" {
		return false
	}
	return now.PeerAddr == cfg.PeerAddr && now.Token == cfg.Token && now.Term == cfg.Term
}

// resumeLeadershipIfStillPersisted is the boot path's onActivated callback: it
// resumes HA leadership on the first OBSERVED bind, from the HA config as it is
// persisted NOW.
//
// It re-reads the config rather than using the one loaded at boot because the
// callback runs on the first successful bind, which with the retrying
// supervisor can be long after boot. It resumes only if the CURRENT config
// still says this node leads (haRestartAction == "leader": readable, enabled,
// not standby), and never when this process already holds an HA role — an
// operator acting through the live HA API in the meantime has already decided
// it, and ResumeAsLeader would overwrite that and persist the stale leader.
func resumeLeadershipIfStillPersisted() {
	haCfg, haErr := loadHAConfig()
	if action := haRestartAction(haCfg, haErr); action != "leader" {
		if action == "standby" {
			logger.Printf("HA: %s now records this node as standby — not resuming leadership on the "+
				"Control Plane listener's first bind", haConfigFile)
		}
		return
	}
	if role := globalHA.Status().Role; role != "" {
		logger.Printf("HA: this node already holds HA role %q — not resuming leadership from %s on the "+
			"Control Plane listener's first bind", role, haConfigFile)
		return
	}
	if !haBootResumeAsLeader(haCfg) {
		return // revalidation lost to a live HA transition; it logged why
	}
	if haCfg.AutoFailover {
		logger.Printf("HA: resumed as leader from %s after restart. WARNING: automatic failover is "+
			"enabled — if the standby promoted while this node was down, BOTH may now lead. Verify via "+
			"/healthz or the HA panel and reconcile (ADR-0004/RISK-001).", haConfigFile)
	} else {
		logger.Printf("HA: resumed as leader from %s after restart (peer=%q)", haConfigFile, sanitizeLog(haCfg.PeerAddr))
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
	nodeID := clusterRoleSnapshot().nodeID
	globalHA.SetLeaseProvider(provider, nodeID)
	// CHAOS-55: the recovery loop must look at the fence more often than a
	// holder's key can appear and expire, or a peer's whole tenure can pass
	// between two observations. That bound is the TTL.
	globalHA.SetLeaseTTL(time.Duration(cfg.HALeaseTTLSec) * time.Second)
	logger.Printf("HA: etcd fencing lease ARMED (endpoints=%s, ttl=%ds, candidate=%s) — leadership is lease-arbitrated (ADR-0005)",
		sanitizeLog(cfg.HAEtcdEndpoints), cfg.HALeaseTTLSec, sanitizeLog(nodeID))
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
