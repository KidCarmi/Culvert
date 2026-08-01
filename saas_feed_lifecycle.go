package main

// saas_feed_lifecycle.go — F3b-4: the signed-feed runtime lifecycle wiring.
//
// This is the OFFLINE-FIRST startup path (design "Startup ordering"):
//
//	1. construct the trust-kernel/verifier + durable-store dependencies;
//	2. load and classify the effective configuration authority (no network);
//	3. run the F3b-3 record-driven recovery with NO network;
//	4. atomically install the recovered active/LKG/embedded content (recovery does this);
//	5. expose a truthful component status;
//	6. proxy readiness is allowed under the safe baseline (the embedded baseline is
//	   always valid, so the feed never makes readiness internet-dependent);
//	7. only then arm the refresh scheduler — which performs a network refresh ONLY when
//	   the validated effective setting is enabled AND authoritative.
//
// No background fetch begins before recovery + authority resolution complete, and process
// startup/readiness NEVER blocks on the internet/DNS/feed availability: recovery is
// offline and the first network refresh is dispatched asynchronously via the scheduler.
//
// This also RETIRES the legacy raw SaaS syncer from runtime authority: loadURLCategories
// no longer arms globalSaaSFeed (no fetch of the old raw GitHub URL, no dual scheduler).
// The compiled embedded baseline (loaded into catStore independently) preserves safe SaaS
// category behavior until the signed feed is explicitly enabled (post-publication).

import (
	"context"
	"strings"
	"time"
)

// globalSaaSFeedRuntime / globalSaaSFeedScheduler are the process-wide signed-feed engine
// singletons, wired once at startup. Nil until armed (or if arming fails) — every reader
// (status API, /metrics, health, manual refresh) is nil-tolerant.
var (
	globalSaaSFeedRuntime   *saasFeedRuntime
	globalSaaSFeedScheduler *saasFeedScheduler
)

// startSignedFeedLifecycle wires + arms the signed-feed engine for feedDir
// (<dataDir>/saas_feed). Safe to call once at startup; a construction failure logs and
// leaves the feed unarmed (policy keeps serving the compiled catStore baseline).
func startSignedFeedLifecycle(feedDir string, ctx context.Context) {
	if feedDir == "" {
		return
	}
	// 1. Construct the verifier + durable-store dependencies.
	rt, err := newSaaSFeedRuntime(feedDir, globalCategoryOverrides, globalSaaSFeedStatus, time.Now)
	if err != nil {
		logger.Printf("SaaSFeed: signed-feed lifecycle NOT armed (runtime init failed): %s", sanitizeLog(err.Error()))
		return
	}
	globalSaaSFeedRuntime = rt
	// Wire the managed-DP authority mirror store so the CP snapshot-apply path can
	// durably persist authoritative config (the F3a-2 deferred-finding closure).
	globalSaaSFeedAuthorityStore = rt.authority

	// 2. Classify the effective configuration authority (no network).
	res := rt.resolveAuthority()
	rt.status.noteConfig(res)

	// 3+4. Record-driven recovery with NO network; installs active/LKG/embedded atomically.
	recRes, rerr := rt.recover(ctx)
	if rerr != nil {
		logger.Printf("SaaSFeed: recovery error (embedded baseline serving): %s", sanitizeLog(rerr.Error()))
	}

	// 5. Startup-once alert evaluation so an already-stale/critical appliance is visible
	// immediately (not after the first refresh interval).
	evaluateSaaSFeedStartupAlerts(rt.status.Snapshot())

	// 7. Arm the single lifecycle-owned scheduler (parented to the lifecycle context, so
	// it dies with the process — no dedicated shutdown hook needed). It performs a
	// network refresh ONLY when enabled + authoritative; a disabled/waiting node makes
	// zero requests.
	sched := newSaaSFeedScheduler(rt)
	globalSaaSFeedScheduler = sched
	go sched.run(ctx)

	// Dispatch the FIRST refresh asynchronously (never blocks startup) only when the feed
	// is EXPLICITLY enabled AND authoritative. Disabled-by-default / unmanaged nodes never
	// reach this — zero unsolicited requests to the unpublished official host.
	if res.Ready && res.Config.runtimeEnabled() && !res.WaitingForAuthority {
		sched.Wake()
	}

	// authority derives from user-settable config (via resolveAuthority), so inline
	// strings.ReplaceAll at the call site so CodeQL sees the sanitiser (CWE-117); recovery
	// class comes from offline record recovery (not user input) and enabled is a bool.
	logger.Printf("SaaSFeed: signed-feed lifecycle armed (authority=%s enabled=%v recovery=%s)",
		strings.ReplaceAll(res.Authority.String(), "\n", ""), res.Config.runtimeEnabled(), recRes.Class)
}

// wakeSignedFeedScheduler requests an immediate refresh evaluation (a config change:
// disabled→enabled, an authoritative interval/URL change, or a fresh CP snapshot). A
// no-op when the scheduler is unarmed. This is the "explicit immediate wakeup" seam wired
// into the settings PUT and the CP snapshot-apply path.
func wakeSignedFeedScheduler() {
	if s := globalSaaSFeedScheduler; s != nil {
		s.Wake()
	}
}
