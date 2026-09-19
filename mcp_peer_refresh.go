package main

import (
	"context"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Governed authenticated peer refresh (blocker 11, §7).
//
// This file is the SMALLEST production path that turns an operator action into an authenticated
// observation of a registered MCP peer. It exists because `execution.Discovery.Discover` — the
// only code that can refresh the catalog FROM a live server — had no non-test caller, so the
// catalog only ever held what `seedTools` re-encoded from operator-declared JSON and
// `ToolStillCurrent` validated that unchanged local record indefinitely.
//
// WHAT IT IS NOT, and this is the load-bearing part. Observation is not authority. A refresh
// supplies TRUTH about what the peer currently advertises; it confers nothing else:
//
//   - it never arms the live tier, begins a Canary generation, or changes rollout mode;
//   - it never issues an approval, promotes a tool, or reserves Canary budget;
//   - it is invokable while the node is Observe/Shadow/composed-but-unarmed, precisely because
//     an operator must be able to learn what the peer offers BEFORE deciding anything.
//
// Everything a refresh does downstream is the catalog's existing drift/quarantine classification
// and the existing tool-trust reconcile hook, both of which can only ever WITHDRAW or re-affirm
// trust. A tool that comes back changed lands Quarantined exactly as a first sighting would.
//
// LOCK DISCIPLINE. No network I/O happens under an activation, rollout or durable-state lock.
// The single-flight registration below is taken and RELEASED before the dial; the only lock the
// dial's result meets is the ingest guard's derive lock, which serializes the catalog PUBLISH
// after the response has already arrived (execution.Discovery.IngestGuard, ADR-0034). That
// ordering is the existing design and is what keeps a slow or hung peer from stalling an
// in-flight approval or a rollout transition.

const (
	// mcpPeerRefreshBudget bounds ONE refresh end to end. The upstream client carries its own
	// dial/TLS/read limits; this is the envelope over all of them, so a peer that is slow at
	// every individual step still cannot hold the operator's request open indefinitely.
	mcpPeerRefreshBudget = 30 * time.Second
	// mcpPeerRefreshMaxConcurrent bounds refreshes across ALL servers. Per-server single-flight
	// already stops one peer being stampeded; this stops a fleet-wide fan-out from turning an
	// admin surface into an outbound amplifier.
	mcpPeerRefreshMaxConcurrent = 4
)

// Bounded refusal reasons. They are a closed vocabulary because they reach an operator surface
// and an audit record: a raw upstream error would carry the endpoint and the ephemeral local
// port, which is the WK-12/RS-5 defect (an unbounded reason defeats dedup and leaks topology).
const (
	mcpPeerRefreshReasonNotConfigured = "inventory_not_configured"
	mcpPeerRefreshReasonInProgress    = "refresh_in_progress"
	mcpPeerRefreshReasonBusy          = "refresh_capacity_reached"
	mcpPeerRefreshReasonNoServerID    = "server_id_required"
	mcpPeerRefreshReasonUnregistered  = "server_not_registered"
	mcpPeerRefreshReasonUnusable      = "server_not_usable"
	mcpPeerRefreshReasonTransport     = "upstream_client_unavailable"
	mcpPeerRefreshReasonFailed        = "discovery_failed"
)

// mcpPeerRefreshOutcome is the bounded, operator-safe result of one refresh. It deliberately
// carries no tool names, schemas, endpoint or peer payload — a count and a revision are enough to
// tell an operator the refresh landed and to correlate it with the catalog.
type mcpPeerRefreshOutcome struct {
	ServerID     string
	Revision     uint64
	Observations int
}

// mcpPeerRefreshInflight tracks one in-flight refresh per server plus the global cap.
var mcpPeerRefreshInflight = struct {
	mu     sync.Mutex
	byID   map[string]struct{}
	active int
}{byID: map[string]struct{}{}}

// acquire registers an in-flight refresh for serverID. A second concurrent request for the SAME
// server is REFUSED rather than queued or coalesced: refusing is deterministic and observable,
// where queueing would let an operator's repeated clicks become a backlog of dials at a peer that
// is by hypothesis already slow. The caller retries; nothing is lost.
func mcpPeerRefreshAcquire(serverID string) (release func(), reason string) {
	mcpPeerRefreshInflight.mu.Lock()
	defer mcpPeerRefreshInflight.mu.Unlock()
	if _, busy := mcpPeerRefreshInflight.byID[serverID]; busy {
		return nil, mcpPeerRefreshReasonInProgress
	}
	if mcpPeerRefreshInflight.active >= mcpPeerRefreshMaxConcurrent {
		return nil, mcpPeerRefreshReasonBusy
	}
	mcpPeerRefreshInflight.byID[serverID] = struct{}{}
	mcpPeerRefreshInflight.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			mcpPeerRefreshInflight.mu.Lock()
			defer mcpPeerRefreshInflight.mu.Unlock()
			delete(mcpPeerRefreshInflight.byID, serverID)
			mcpPeerRefreshInflight.active--
		})
	}, ""
}

// mcpPeerRefreshUpstream supplies the caller for a refresh dial. It is a seam ONLY so a unit test
// can drive the sequencing without a socket; production resolves it to the same constructor the
// live-execution tier uses, so a refresh carries identical transport guarantees — destination
// policy, pinned-destination behaviour, TLS ≥ 1.2, SPKI verification and the retry-free envelope.
// A freshness claim produced over a weaker transport would not be a freshness claim.
var mcpPeerRefreshUpstream = func() (execution.UpstreamCaller, error) {
	return newProductionUpstreamClient()
}

// mcpRefreshPeerObservation performs ONE authenticated discovery against ONE registered server
// and returns the bounded outcome, or a bounded refusal reason.
//
// The ONLY caller-supplied value is serverID. Endpoint, pinned identity, tenant, expected
// fingerprint, tool set, provenance and the observation timestamp all come from authoritative
// state or from the authenticated peer itself — never from the request. That is what makes this
// an observation rather than an assertion: there is no field an operator could fill in to make
// the catalog say something the peer did not.
func mcpRefreshPeerObservation(ctx context.Context, serverID string) (mcpPeerRefreshOutcome, string, error) {
	if serverID == "" {
		return mcpPeerRefreshOutcome{}, mcpPeerRefreshReasonNoServerID, nil
	}
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		return mcpPeerRefreshOutcome{}, mcpPeerRefreshReasonNotConfigured, nil
	}
	release, reason := mcpPeerRefreshAcquire(serverID)
	if reason != "" {
		return mcpPeerRefreshOutcome{}, reason, nil
	}
	defer release()

	up, err := mcpPeerRefreshUpstream()
	if err != nil {
		return mcpPeerRefreshOutcome{}, mcpPeerRefreshReasonTransport, err
	}
	// NewDiscovery installs the startup-wired reconcile hook and ingest guard, so a successful
	// refresh re-materializes matching approvals and serializes its publish with in-flight ones
	// without this caller having to know either exists.
	d, err := execution.NewDiscovery(reg, cat, up)
	if err != nil {
		return mcpPeerRefreshOutcome{}, mcpPeerRefreshReasonTransport, err
	}

	ctx, cancel := context.WithTimeout(ctx, mcpPeerRefreshBudget)
	defer cancel()
	report, derr := d.Discover(ctx, serverID)
	if derr != nil {
		// A FAILED discovery changes nothing. It does not stamp an observation, does not
		// advance freshness, and — critically — does not erase the last good one: the peer
		// having been unreachable is not evidence about what it advertises, in either
		// direction. The existing record keeps aging on its own clock, so an outage expires
		// freshness by the passage of time rather than by a fabricated verdict.
		return mcpPeerRefreshOutcome{}, mcpPeerRefreshFailureReason(derr), derr
	}
	out := mcpPeerRefreshOutcome{ServerID: serverID}
	if report != nil {
		out.Revision = report.Revision
		out.Observations = len(report.Observations)
	}
	return out, "", nil
}

// mcpPeerRefreshFailureReason maps a discovery error onto the closed reason vocabulary. Anything
// unrecognised is reported as a generic discovery failure rather than passed through, so the
// operator surface and the audit record can never carry an unbounded upstream string.
func mcpPeerRefreshFailureReason(err error) string {
	switch mcperr.ReasonOf(err) {
	case mcperr.ReasonUnregisteredServer:
		return mcpPeerRefreshReasonUnregistered
	case mcperr.ReasonUpstreamServerUnusable:
		return mcpPeerRefreshReasonUnusable
	default:
		return mcpPeerRefreshReasonFailed
	}
}
