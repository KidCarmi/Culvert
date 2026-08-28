package execution

import (
	"context"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// Discovery performs a real upstream tools/list against a registered server and
// feeds the result through the PR-2 catalog ingestion path (fingerprints → drift
// classification → quarantine of unknown/expanded tools). It reuses the PR-1
// kernel on the upstream leg (via the upstream client's strict decode) and never
// auto-approves a new or changed fingerprint. A discovery failure returns a
// classified error and leaves the previous known-good catalog snapshot UNCHANGED.
type Discovery struct {
	Registry *registry.Registry
	Catalog  *catalog.Catalog
	Upstream UpstreamCaller
	// OnIngest, when set, is invoked after a SUCCESSFUL catalog ingest (a new snapshot was
	// published). Ingestion can only ever land a tool Quarantined/ReviewRequired — it never
	// produces catalog.Usable — so a re-discovered tool that exactly matches an active trust
	// approval would otherwise stay non-Usable until the next inventory read, Shadow
	// preflight, or the periodic 30s reconcile tick, contaminating an in-flight Shadow
	// experiment. The composition root wires this to the tool-trust reconcile hook so the
	// approval's projection is re-materialized immediately. Optional and nil-safe; it must
	// only WITHDRAW-or-re-affirm trust (it can never widen usability), so calling it here is
	// safe even though this package holds no trust authority.
	OnIngest func()
}

// discoveryReconcileHook is the default OnIngest callback installed on every Discovery built
// by NewDiscovery. The composition root sets it (SetReconcileHook) to the tool-trust reconcile
// hook so a successful discovery ingest re-materializes matching approvals immediately, rather
// than requiring each caller to remember to wire it. Nil (tests, or tool trust not composed) ⇒
// no default (a no-op ingest). It is set once at startup before any Discovery is constructed,
// so no synchronization is required — the same convention as the other startup-wired MCP seams.
var discoveryReconcileHook func()

// SetReconcileHook installs the default post-ingest reconcile callback used by NewDiscovery.
// The composition root calls it once at startup; nil clears it (tests). It keeps this package
// decoupled from tool trust — it only ever invokes the func it is handed, and that func can
// only withdraw-or-re-affirm trust, never widen usability.
func SetReconcileHook(fn func()) { discoveryReconcileHook = fn }

// NewDiscovery constructs a Discovery. It fails closed on missing collaborators and installs
// the default post-ingest reconcile hook (SetReconcileHook) so the ingest path reconciles
// trust without the caller having to wire OnIngest itself.
func NewDiscovery(reg *registry.Registry, cat *catalog.Catalog, up UpstreamCaller) (*Discovery, error) {
	if reg == nil || cat == nil || up == nil {
		return nil, mcperr.New(mcperr.ReasonListenerConfigInvalid, "execution.discovery", "incomplete discovery config")
	}
	return &Discovery{Registry: reg, Catalog: cat, Upstream: up, OnIngest: discoveryReconcileHook}, nil
}

// Discover runs the ordered discovery sequence for one registered server:
//  1. resolve + validate the server registration + trusted identity;
//  2. fetch a bounded tools/list via the upstream client (strict shared-kernel
//     decode of the response);
//  3. feed the exact result bytes into the PR-2 catalog ingestion path;
//  4. drift classification + quarantine happen inside Ingest (unknown/expanded
//     fingerprints land Quarantined and never auto-clear);
//  5. on ANY failure, the previous catalog snapshot is retained unchanged.
//
// It returns the ingestion Report (safe drift/quarantine evidence) on success.
func (d *Discovery) Discover(ctx context.Context, serverID string) (*catalog.Report, error) {
	rec, ok := d.Registry.Current().Get(registry.ServerID(serverID))
	if !ok {
		return nil, mcperr.New(mcperr.ReasonUnregisteredServer, "execution.discovery", "server not registered")
	}
	if !rec.Usable() {
		// A disabled or identity-mismatched server is never discovered against.
		return nil, mcperr.New(mcperr.ReasonUpstreamServerUnusable, "execution.discovery", "server not usable")
	}
	target := upstreamclient.Target{
		ServerID:       string(rec.ID),
		Endpoint:       string(rec.Endpoint),
		PinnedIdentity: string(rec.PinnedIdentity),
	}
	resp, err := d.Upstream.Call(ctx, target, "tools/list", nil, upstreamclient.CallOptions{Idempotent: true, WireID: "disc-" + string(rec.ID)})
	if err != nil {
		// Discovery failure — the previous known-good catalog is retained unchanged.
		return nil, mcperr.Wrap(mcperr.ReasonUpstreamDiscoveryFailed, "execution.discovery", "tools/list", err)
	}
	if resp == nil || resp.Error != nil {
		return nil, mcperr.New(mcperr.ReasonUpstreamDiscoveryFailed, "execution.discovery", "upstream returned no tools/list result")
	}
	// Feed the EXACT received result bytes into the catalog ingestion path (a second
	// strict decode with a member allowlist, per-tool fingerprinting, drift
	// classification, sticky quarantine, all-or-nothing publish). The previous
	// snapshot is retained on any ingestion error.
	_, report, err := d.Catalog.Ingest(d.Registry, catalog.DiscoveryInput{
		ServerID: rec.ID,
		Identity: rec.PinnedIdentity,
		Raw:      []byte(resp.Result),
	})
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonUpstreamDiscoveryFailed, "execution.discovery", "catalog ingest", err)
	}
	// A new snapshot was published. Reconcile trust NOW so a re-discovered tool that matches
	// an active approval is re-promoted immediately rather than after the next reconcile tick.
	if d.OnIngest != nil {
		d.OnIngest()
	}
	return report, nil
}
