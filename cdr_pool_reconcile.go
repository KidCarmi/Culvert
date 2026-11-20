package main

// cdr_pool_reconcile.go — re-dial an enrolled Sluice instance that is missing
// from the live CDR pool.
//
// grpc.NewClient is lazy, so an unreachable Sluice never keeps an instance out
// of the pool. What does is a LOCAL failure while the pool is built: the
// instance's credential bundle (ca.pem / client.pem / client.key) could not be
// read or opened — the data volume was not mounted yet, ownership was wrong,
// the at-rest key could not be opened. buildCDRPoolFromRegistry logs
// `CDR: pool: skipping "<name>"` and leaves the instance out, and before this
// file nothing ever tried it again: probeCDRHealth only probes members that
// are already in the pool (and returns early on an empty one), and the only
// rebuilds are an admin action, a rotation promotion or a renewal. The
// operator runbook therefore said to RESTART the process to rebuild the pool,
// because the runtime disable/enable toggle zeroes fail_mode and the other
// cdr.* settings. Meanwhile every inspected document was refused
// (fail_mode closed) or delivered unsanitized (fail_mode open) on an empty
// pool, or scanned with reduced capacity on a partial one.
//
// reconcileCDRPool does what that restart would have done for the missing
// members only:
//
//   - WHAT is dialled: exactly the set a pool build dials — every ENABLED
//     registry instance that is not in the live pool, through the same
//     dialEnrolledInstance (or, with an empty registry, the same
//     dialSingleFromConfig bootstrap, only when the last pool build was that
//     bootstrap and it failed, and only with a certs dir configured: a
//     bootstrap with no files to read cannot fail transiently, and a registry
//     emptied by an admin delete must not switch the bootstrap client on).
//   - HOW it is published: the live members are kept as they are (same
//     clients, same breakers, no connection closed) and the newly dialled
//     ones are appended. Nothing is removed and nothing else is rebuilt.
//   - WHAT it never touches: cdrActiveCfg (fail_mode, profile, timeouts), the
//     registry, credential lineage, the runtime enable sentinel and every
//     file on disk except the existing opt-in key-at-rest migration that any
//     bundle load performs. No configuration version is written (CDR is not
//     on the versioning surface, and this is not a configuration change).
//
// Refusal: CDR disabled in the ACTIVE config (an admin disable and the
// graceful-shutdown hook both clear it), a cancelled lifecycle context, or no
// missing member. All of it runs under cdrPoolLifecycleMu, the lock that
// initCDRClient and shutdownCDRClient also hold, and every newly dialled
// member is re-validated against the registry both before AND after it is
// published, so an instance deleted or revoked concurrently is never left in
// the pool (see dropInvalidRedialed).
//
// Cadence: driven by the existing 15s health poller round (runGuarded, so a
// panic is contained there), gated by auditOpenRetryDelay (10s doubling to a
// 2m cap, 25% jitter, no attempt limit). A missing member that stays broken
// costs one bundle read per instance per ~2.5 minutes, logged on the first
// failed attempt and every 10th.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

const cdrRedialLogEvery = 10

// cdrRedialDelay is the backoff between re-dial attempts that left a member
// missing. Package-level seam so tests drive the gate without wall-clock
// waits.
var cdrRedialDelay = auditOpenRetryDelay

// cdrRedialWithdrawHook runs after the post-publish re-validation has DECIDED
// which published members to withdraw and before cdrPool.replace unpublishes
// them. Production leaves it nil.
//
// It exists because the ordering it brackets is the whole invariant: a
// withdrawn member must be unpublished BEFORE its connection is closed, and
// that window is not observable from the end state (both orders end with the
// member closed and out of the pool). This is the only point at which a test
// can catch the inversion. See
// TestCDRRedial_WithdrawnMemberIsUnpublishedBeforeItIsClosed.
var cdrRedialWithdrawHook func(withdrawn []string)

// cdrRedialGate is the poller-side backoff state. Only the health-poller
// goroutine calls maybeRedialMissingCDRMembers in production; the mutex keeps
// tests (and a second poller from a repeated startCDRHealthPoller) race-free.
var cdrRedialGate struct {
	mu     sync.Mutex
	failed int
	nextAt time.Time
}

// cdrRedialResult reports one reconcile pass.
type cdrRedialResult struct {
	attempted bool     // at least one missing member was dialled
	added     []string // members published into the pool
	missing   []string // members still missing afterwards
	err       error    // first dial error, if any
}

// maybeRedialMissingCDRMembers runs one gated reconcile pass from the health
// poller round.
func maybeRedialMissingCDRMembers(ctx context.Context) {
	now := time.Now()
	cdrRedialGate.mu.Lock()
	if now.Before(cdrRedialGate.nextAt) {
		cdrRedialGate.mu.Unlock()
		return
	}
	cdrRedialGate.mu.Unlock()

	res := reconcileCDRPool(ctx)

	cdrRedialGate.mu.Lock()
	defer cdrRedialGate.mu.Unlock()
	if !res.attempted {
		cdrRedialGate.failed = 0
		cdrRedialGate.nextAt = time.Time{}
		return
	}
	attempt := cdrRedialGate.failed + 1
	if len(res.added) > 0 {
		names := strings.Join(res.added, ",")
		logger.Printf("CDR: re-dialled %q into the pool automatically after %d attempt(s); %d member(s) still missing",
			sanitizeLog(names), attempt, len(res.missing))
		for _, n := range res.added {
			// Attributed to "system": no human asked for this re-dial now.
			auditSystem("cdr.pool.auto_redial", n,
				"enrolled Sluice instance missing from the CDR pool (credential bundle unreadable at the last pool build) was dialled into the pool automatically; configuration unchanged")
		}
	}
	if len(res.missing) == 0 {
		cdrRedialGate.failed = 0
		cdrRedialGate.nextAt = time.Time{}
		return
	}
	if len(res.added) == 0 {
		cdrRedialGate.failed++
		if cdrRedialGate.failed == 1 || cdrRedialGate.failed%cdrRedialLogEvery == 0 {
			errText := ""
			if res.err != nil {
				errText = res.err.Error()
			}
			logger.Printf("CDR: %d enrolled instance(s) still missing from the pool (%q), retrying automatically (attempt %d): %q",
				len(res.missing), sanitizeLog(strings.Join(res.missing, ",")), cdrRedialGate.failed, sanitizeLog(errText))
		}
	}
	cdrRedialGate.nextAt = time.Now().Add(cdrRedialDelay(cdrRedialGate.failed))
}

// reconcileCDRPool dials the enabled registry instances that are missing
// from the live pool and appends the ones that dial. See the file header for
// the contract.
func reconcileCDRPool(ctx context.Context) cdrRedialResult {
	cdrPoolLifecycleMu.Lock()
	defer cdrPoolLifecycleMu.Unlock()

	if ctx.Err() != nil {
		return cdrRedialResult{}
	}
	cfg := cdrActiveConfig()
	if !cfg.Enabled {
		return cdrRedialResult{}
	}
	live := cdrPool.List()
	targets, bootstrap := cdrMissingPoolMembers(cfg, live)
	if len(targets) == 0 && !bootstrap {
		return cdrRedialResult{}
	}

	res := cdrRedialResult{attempted: true}
	var dialed []*cdrPooledClient
	if bootstrap {
		pc, err := dialSingleFromConfig(cfg)
		if err != nil {
			res.err = fmt.Errorf("bootstrap: %w", err)
			res.missing = append(res.missing, "default")
		} else {
			dialed = append(dialed, pc)
		}
	}
	for i := range targets {
		pc, err := dialEnrolledInstance(targets[i], cfg, live)
		if err != nil {
			if res.err == nil {
				res.err = fmt.Errorf("instance %q: %w", targets[i].Name, err)
			}
			res.missing = append(res.missing, targets[i].Name)
			continue
		}
		dialed = append(dialed, pc)
	}
	if len(dialed) == 0 {
		return res
	}

	// Re-validate immediately before publishing: CDR still enabled, the
	// lifecycle still running, each instance still enrolled as dialled.
	// Nothing here is published yet, so this pass owns the teardown of what it
	// drops (closeDropped=true).
	dialed, dropped := dropInvalidRedialed(ctx, dialed, targets, bootstrap, true)
	res.missing = append(res.missing, dropped...)
	if len(dialed) == 0 {
		return res
	}
	next := make([]*cdrPooledClient, 0, len(live)+len(dialed))
	next = append(next, live...)
	next = append(next, dialed...)
	cdrPool.replace(next) // every live client is carried over: none is closed
	if bootstrap {
		cdrBootstrapRedialArmed = false
	}

	// And once more AFTER publishing. A delete/revoke handler removes the
	// registry entry and THEN asks cdrActiveClient() whether a pool exists to
	// tear down. Either that check saw the member just published (and its
	// shutdownCDRClient, waiting on cdrPoolLifecycleMu, tears it down after
	// this returns), or the removal happened before this re-check and the
	// member is withdrawn here. No interleaving leaves it in the pool.
	// closeDropped=false: these clients are PUBLISHED now, and cdrPool.pick
	// filters only on breaker state — CDRClient.closedAt is written by Close
	// and read by nothing — so a client closed while still in the pool is
	// still selectable, and the sanitize RPC that drew it fails. Under
	// fail_mode: open that one document passes CDR UNSANITIZED. So decide
	// here, unpublish first, and let cdrPool.replace do the closing: it
	// already closes exactly the clients not carried over, after the swap.
	kept, withdrawn := dropInvalidRedialed(ctx, dialed, targets, bootstrap, false)
	if cdrRedialWithdrawHook != nil {
		cdrRedialWithdrawHook(withdrawn)
	}
	if len(withdrawn) > 0 {
		// A fresh slice: next is now the pool's published backing array.
		trimmed := make([]*cdrPooledClient, 0, len(live)+len(kept))
		trimmed = append(trimmed, live...)
		trimmed = append(trimmed, kept...)
		cdrPool.replace(trimmed) // closes exactly the withdrawn clients
		res.missing = append(res.missing, withdrawn...)
	}
	for _, pc := range kept {
		res.added = append(res.added, pc.Name)
	}
	return res
}

// cdrMissingPoolMembers lists the enabled registry instances absent from the
// live pool, and reports whether the empty-registry bootstrap client is
// missing instead.
func cdrMissingPoolMembers(cfg CDRConfig, live []*cdrPooledClient) ([]CDREnrolledInstance, bool) {
	instances := cdrInstances.SnapshotView()
	if len(instances) == 0 {
		// Same preconditions bootstrapPoolFromConfig enforces, plus a certs
		// dir: without one the bootstrap reads no file, so its failure is
		// deterministic and a retry could never change the outcome.
		// And only when the last pool build WAS that bootstrap and failed:
		// a registry emptied by an admin delete never activates it.
		return nil, cdrBootstrapRedialArmed && len(live) == 0 &&
			cfg.Endpoint != "" && cfg.ServerFingerprint != "" && cfg.CertsDir != ""
	}
	inPool := make(map[string]struct{}, len(live))
	for _, pc := range live {
		inPool[pc.Name] = struct{}{}
	}
	var missing []CDREnrolledInstance
	for i := range instances {
		if !instances[i].IsEnabled() {
			continue
		}
		if _, ok := inPool[instances[i].Name]; ok {
			continue
		}
		missing = append(missing, instances[i])
	}
	return missing, false
}

// dropInvalidRedialed keeps the dialled members that may still be published
// and reports the rest. A member stays valid while CDR is enabled in the
// active config, ctx is live, and its registry entry still exists, is
// enabled and names the same endpoint, credential files and server pin it
// was dialled with. A bootstrap member stays valid while the registry is
// still empty.
//
// closeDropped says whether THIS pass owns the teardown of what it drops, and
// is exactly "are these clients still unpublished?". Before the pool swap they
// are reachable by nobody, so closing them here is the only thing that would:
// pass true. After the swap they are in the published pool, where closing one
// before it is unpublished hands a live picker a dead connection (see the call
// site): pass false and let cdrPool.replace close them once they are out.
func dropInvalidRedialed(ctx context.Context, dialed []*cdrPooledClient, targets []CDREnrolledInstance, bootstrap bool, closeDropped bool) (kept []*cdrPooledClient, dropped []string) {
	stillOn := ctx.Err() == nil && cdrActiveConfig().Enabled
	byName := make(map[string]*CDREnrolledInstance, len(targets))
	for i := range targets {
		byName[targets[i].Name] = &targets[i]
	}
	for _, pc := range dialed {
		if stillOn && cdrRedialedStillEnrolled(pc.Name, byName[pc.Name], bootstrap) {
			kept = append(kept, pc)
			continue
		}
		dropped = append(dropped, pc.Name)
		if closeDropped && pc.Client != nil {
			_ = pc.Client.Close()
		}
	}
	return kept, dropped
}

func cdrRedialedStillEnrolled(name string, dialedAs *CDREnrolledInstance, bootstrap bool) bool {
	if dialedAs == nil {
		return bootstrap && len(cdrInstances.SnapshotView()) == 0
	}
	cur, ok := cdrInstances.GetCopy(name)
	return ok && cur.IsEnabled() &&
		cur.Endpoint == dialedAs.Endpoint &&
		cur.ServerFingerprint == dialedAs.ServerFingerprint &&
		cur.RotatedFingerprint == dialedAs.RotatedFingerprint &&
		cur.CACertPath == dialedAs.CACertPath &&
		cur.ClientCertPath == dialedAs.ClientCertPath &&
		cur.ClientKeyPath == dialedAs.ClientKeyPath
}
