package main

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// M5 local-health collector. Captures the secret-free verdicts of the no-network
// diagnose verbs — cluster/HA posture and upstream egress posture — INTO the bundle
// at collection time, so an offline reader (TAC) can see "was this appliance
// locally healthy when the bundle was taken?" without the live diagnose API. It is
// the bundle-side of `diagnose all`, reusing the same vetted, secret-free builders
// (no peer addresses, tokens, or values are surfaced — pinned by the diagnose tests
// and TestNoSecretInBundle).
//
// Both members are CHEAP pure reads (HA status + node counts; the redacted upstream
// List). config/dns/tls/storage are deliberately excluded: config's diagnoseConfig
// builds the FULL synced ConfigSnapshot (copying the entire threat-feed URL/domain
// maps) which is too heavy to run in every standard L1 bundle; dns/tls need a target
// host + network; and storage runs a writability probe (a collector side effect).
// Those stay live-only via the diagnose API.

// localHealthSection is the purpose-built, fully redact:-tagged posture snapshot.
// Every field is Public or Internal — there is no secret/address field.
type localHealthSection struct {
	ClusterRole    string `json:"cluster_role" redact:"internal"`
	ClusterOK      bool   `json:"cluster_ok" redact:"public"`
	HAEnabled      bool   `json:"ha_enabled" redact:"internal"`
	LeaseMode      string `json:"lease_mode" redact:"internal"`
	WriteAuthority bool   `json:"write_authority" redact:"internal"`
	NodesTotal     int    `json:"nodes_total" redact:"public"`
	NodesConnected int    `json:"nodes_connected" redact:"public"`

	UpstreamEnabled bool `json:"upstream_enabled" redact:"internal"`
	UpstreamOK      bool `json:"upstream_ok" redact:"public"`
	UpstreamCount   int  `json:"upstream_count" redact:"public"`
	UpstreamUsable  int  `json:"upstream_usable" redact:"public"`
}

type localHealthCollector struct{}

func (localHealthCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "local_health", Path: "sections/local_health.json", Owner: "core", SchemaVersion: 1,
		Description: "Local health posture at collection time (cluster + upstream diagnose verdicts; cheap pure reads, no network, no secrets)",
		Timeout:     2 * time.Second, ByteBudget: 8 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (localHealthCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	cl := diagnoseCluster(time.Now()) // secret-free posture; cheap pure reads, no network
	up := diagnoseUpstream(time.Now())
	sec := localHealthSection{
		ClusterRole: cl.Role, ClusterOK: cl.OK, HAEnabled: cl.HAEnabled, LeaseMode: cl.LeaseMode,
		WriteAuthority: cl.WriteAuthority, NodesTotal: cl.NodesTotal, NodesConnected: cl.NodesConnected,
		UpstreamEnabled: up.Enabled, UpstreamOK: up.OK, UpstreamCount: up.Count, UpstreamUsable: up.UsableCount,
	}
	return classifyAndWriteSection(in, sink, sec)
}

func init() {
	support.Register(localHealthCollector{})
}
