package execution

import (
	"context"
	"time"

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
	// IngestGuard, when set, runs the catalog ingest (its snapshot PUBLISH) inside the
	// tool-trust reconcile critical section so a catalog revision advance is MUTUALLY
	// EXCLUSIVE with an in-flight trust approval. Without it, ingestion advances the live
	// catalog revision without holding the coordinator's derive lock, so an approval that
	// captured the pre-advance revision between its target load and its durable commit would
	// validate a stale copy — an identical rediscovery (same fingerprint, bumped revision) or
	// an F1→F2→F1 flap in that window would be approved instead of returning the required
	// stale-target conflict (ADR-0034 optimistic concurrency, PR round-15). Optional and
	// nil-safe; when nil the ingest runs directly. Like OnIngest it only ever gates WHEN a
	// publish lands, never what a publish produces, so carrying it grants this package no
	// trust authority.
	IngestGuard func(ingest func() error) error
	// Now supplies the observation clock. It is a field so a test can drive freshness
	// deterministically; NewDiscovery defaults it to time.Now. A nil value falls back to
	// time.Now rather than producing a zero timestamp, because a zero timestamp is exactly what
	// PeerObservation treats as "no observation" and a silently un-stamped discovery would be a
	// freshness hole rather than a visible failure.
	Now func() time.Time
}

// now reads the observation clock, defaulting to the wall clock.
func (d *Discovery) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
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

// discoveryIngestGuard is the default IngestGuard installed on every Discovery built by
// NewDiscovery. The composition root sets it (SetIngestGuard) to run the ingest publish under
// the tool-trust derive lock, so a catalog revision advance cannot slip under an in-flight
// approval's target-load→commit window. Nil (tests, or tool trust not composed) ⇒ no guard
// (the ingest runs directly). Set once at startup before any Discovery is constructed, so no
// synchronization is required — the same convention as the other startup-wired MCP seams.
var discoveryIngestGuard func(ingest func() error) error

// SetIngestGuard installs the default ingest-serialization guard used by NewDiscovery. The
// composition root calls it once at startup; nil clears it (tests). It keeps this package
// decoupled from tool trust — it only ever runs the ingest it is handed inside whatever
// critical section the composition root wraps it in, and that gating can never widen usability.
func SetIngestGuard(fn func(ingest func() error) error) { discoveryIngestGuard = fn }

// NewDiscovery constructs a Discovery. It fails closed on missing collaborators and installs
// the default post-ingest reconcile hook (SetReconcileHook) plus the ingest-serialization
// guard (SetIngestGuard) so the ingest path reconciles trust and serializes its publish with
// in-flight approvals without the caller having to wire OnIngest / IngestGuard itself.
func NewDiscovery(reg *registry.Registry, cat *catalog.Catalog, up UpstreamCaller) (*Discovery, error) {
	if reg == nil || cat == nil || up == nil {
		return nil, mcperr.New(mcperr.ReasonListenerConfigInvalid, "execution.discovery", "incomplete discovery config")
	}
	return &Discovery{
		Registry:    reg,
		Catalog:     cat,
		Upstream:    up,
		OnIngest:    discoveryReconcileHook,
		IngestGuard: discoveryIngestGuard,
		Now:         time.Now,
	}, nil
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
	// A DISCOVERY WITHOUT A PINNED IDENTITY IS NOT FRESHNESS EVIDENCE, so it is refused here
	// rather than performed and then filed as something weaker.
	//
	// With a pin configured the transport replaces standard chain verification with an EXACT
	// check of the leaf's SPKI against it (upstreamclient.tlsConfig → VerifyConnection), so a
	// call that SUCCEEDS proves the peer holds that identity. That proof is the whole reason
	// this function may stamp a peer observation at all. With no pin the transport still does
	// standard chain + hostname verification — genuine authentication — but it binds no
	// identity this catalog can name, and an observation that cannot say WHO was observed
	// cannot support a per-server freshness claim.
	//
	// Refusing early also keeps the failure legible: without it the empty identity would flow
	// into IngestObserved and surface as an incomplete-observation error AFTER the peer had
	// already been contacted.
	if rec.PinnedIdentity == "" {
		return nil, mcperr.New(mcperr.ReasonUpstreamServerUnusable, "execution.discovery", "server has no pinned identity to observe against")
	}
	target := upstreamclient.Target{
		ServerID:       string(rec.ID),
		Endpoint:       string(rec.Endpoint),
		PinnedIdentity: string(rec.PinnedIdentity),
	}
	// Stamped BEFORE the call, deliberately. The peer advertised its tools at some instant
	// between this send and the response, and taking the EARLIER end is the conservative
	// choice: an observation can then only ever read as older than it truly is, so a slow or
	// long-stalled call that eventually succeeds is never credited with freshness it did not
	// earn. Stamping on receipt would do the opposite.
	observedAt := d.now()
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
	var report *catalog.Report
	ingest := func() error {
		// IngestObserved, never Ingest: this result came off an authenticated transport, and
		// the entrypoint is what records that. The identity stamped is the PIN THE TRANSPORT
		// VERIFIED — never a value read out of the MCP payload, which the peer writes and
		// could therefore choose.
		_, r, ierr := d.Catalog.IngestObserved(d.Registry, catalog.DiscoveryInput{
			ServerID: rec.ID,
			Identity: rec.PinnedIdentity,
			Raw:      []byte(resp.Result),
		}, catalog.PeerObservation{At: observedAt, Identity: rec.PinnedIdentity})
		report = r
		return ierr
	}
	// Serialize the publish with in-flight approvals when a guard is installed, so the catalog
	// revision an approval verifies for its durable decision cannot advance underneath it.
	run := ingest
	if d.IngestGuard != nil {
		run = func() error { return d.IngestGuard(ingest) }
	}
	if ierr := run(); ierr != nil {
		return nil, mcperr.Wrap(mcperr.ReasonUpstreamDiscoveryFailed, "execution.discovery", "catalog ingest", ierr)
	}
	// A new snapshot was published. Reconcile trust NOW so a re-discovered tool that matches
	// an active approval is re-promoted immediately rather than after the next reconcile tick.
	if d.OnIngest != nil {
		d.OnIngest()
	}
	return report, nil
}
