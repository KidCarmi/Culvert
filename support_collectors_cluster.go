package main

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// M5 cluster-posture collector. Captures the SAME secret-free cluster/HA posture
// the `diagnose cluster` verb reports (diagnoseCluster → clusterDiagnosis), so a
// support bundle records "what did the cluster look like at collection time"
// without a live admin round-trip. It reuses the vetted diagnose path rather than
// re-deriving the snapshot, so the no-secret guarantee (peer/standby CP addresses,
// tokens, and cert material are never surfaced — pinned by
// TestDiagnoseCluster_NoSecrets) holds identically here. Fields are Internal at
// most (operational posture), so this is an L1 collector on the standard bundle
// and a member of the `cluster` incident scope.

// clusterSection is the purpose-built, fully redact:-tagged copy of the non-secret
// cluster posture. Every field is Public or Internal — there is no secret or
// infrastructure-address field to leak.
type clusterSection struct {
	Role           string `json:"role" redact:"internal"`
	OK             bool   `json:"ok" redact:"public"`
	HAEnabled      bool   `json:"ha_enabled" redact:"internal"`
	Term           uint64 `json:"term,omitempty" redact:"internal"`
	AutoFailover   bool   `json:"auto_failover" redact:"internal"`
	LeaseMode      string `json:"lease_mode" redact:"internal"`
	LeaseValid     bool   `json:"lease_valid,omitempty" redact:"internal"`
	Epoch          int64  `json:"epoch,omitempty" redact:"internal"`
	WriteAuthority bool   `json:"write_authority" redact:"internal"`
	NodesTotal     int    `json:"nodes_total" redact:"public"`
	NodesConnected int    `json:"nodes_connected" redact:"public"`
	SyncFailCount  int    `json:"sync_fail_count,omitempty" redact:"internal"`
	LastSyncOK     string `json:"last_sync_ok,omitempty" redact:"internal"`
	Detail         string `json:"detail,omitempty" redact:"internal"`
}

type clusterCollector struct{}

func (clusterCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "cluster", Path: "sections/cluster.json", Owner: "core", SchemaVersion: 1,
		Description: "Cluster/HA posture (role, fencing lease, node counts, write authority; no peer addresses or secrets)",
		Timeout:     2 * time.Second, ByteBudget: 8 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (clusterCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	d := diagnoseCluster(time.Now()) // secret-free posture over in-memory state; no network
	sec := clusterSection{
		Role: d.Role, OK: d.OK, HAEnabled: d.HAEnabled, Term: d.Term,
		AutoFailover: d.AutoFailover, LeaseMode: d.LeaseMode, LeaseValid: d.LeaseValid,
		Epoch: d.Epoch, WriteAuthority: d.WriteAuthority, NodesTotal: d.NodesTotal,
		NodesConnected: d.NodesConnected, SyncFailCount: d.SyncFailCount,
		LastSyncOK: d.LastSyncOK, Detail: d.Detail,
	}
	return classifyAndWriteSection(in, sink, sec)
}

func init() {
	support.Register(clusterCollector{})
}
