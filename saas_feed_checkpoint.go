package main

// saas_feed_checkpoint.go — F3b-3: the resolved compiled product parameters for the
// signed SaaS URL-category feed durability engine.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md (Part B) + the F3b-3 slice
// product-parameter approval. F3b-1 deliberately took the rollback-floor checkpoint as
// an EXPLICIT constructor input with a documented placeholder, deferring the real
// compiled value to this slice (see saas_feed_floor.go
// compiledMinFeedVersionPlaceholder). F3b-3 resolves it.
//
// Approved product parameters (recorded here as the single source of truth):
//
//   - COMPILED_MIN_FEED_VERSION = 0. No public feed version has shipped yet, so the
//     fresh-install rollback floor is 0 and F5's first publication must begin at feed
//     version ≥ 1 (the floor accepts a network candidate only when strictly greater —
//     the declined Codex P2 stays declined: normal network candidates must be > the
//     recovered floor; equal-version handling is limited to OFFLINE recovery of the
//     exact already-durable, digest-bound generation after full re-verification). A
//     future Culvert release may raise this checkpoint ONLY through a separately
//     reviewed release process, once publication/fleet evidence exists — never silently.
//
//   - RETENTION = the newest 5 fully-committed generations, PLUS every explicit GC root
//     (active generation, every valid floor-record generation, a resumable floor-ahead
//     candidate, the recovery-required prior LKG) regardless of age or count. GC never
//     deletes a rooted generation (saas_feed_gc.go).
//
//   - COMPILED_MAX_VALIDITY = urlcatfeed.MaxValidity (30d) — the structural validity
//     ceiling already enforced by the trust kernel + the F3b-2 freshness gate; aliased
//     here for the activation/recovery freshness classification.

import "github.com/KidCarmi/Culvert/internal/urlcatfeed"

const (
	// compiledMinFeedVersion is the baked rollback-floor checkpoint (see the file
	// header for the approval rationale). 0 = no public feed version has shipped.
	compiledMinFeedVersion int64 = 0

	// generationRetentionCount is the number of newest fully-committed generations GC
	// retains beyond the explicit root set (approved product parameter).
	generationRetentionCount = 5
)

// compiledMaxValidity is the 30-day validity ceiling (aliased from the trust kernel so
// the activation/recovery freshness classification and the producer/verifier agree).
const compiledMaxValidity = urlcatfeed.MaxValidity
