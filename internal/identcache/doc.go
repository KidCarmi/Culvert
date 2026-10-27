// Package identcache is the bounded, client-attributed result cache shared by
// every identity backend on Culvert's proxy credential path: the LDAP directory
// bind (auth_ldap.go), the legacy OIDC introspection backend (auth_oidc.go) and
// the IdP-registry introspection provider (auth_oidc_flow.go), all in package
// main. It is a self-contained stdlib-only leaf (ADR-0041): package main owns the
// backends, their keys and TTLs, the cap it passes in, and the process-wide
// eviction total /metrics exports, which it receives through Options.OnEvict.
//
// # Why the eviction policy is a security control (CHAOS-76)
//
// All three caches are populated by UNAUTHENTICATED requests. The proxy
// credential path hands whatever username/password or bearer token the client
// supplied straight to the configured backend, and an AUTHORITATIVE denial is
// cached deliberately — an RFC 7662 endpoint answers an unknown or expired
// token with 200 {"active":false}, and a directory that answers "no such user"
// is an authoritative deny — because not caching those would make every wrong
// credential a fresh round trip. So the key space is derived entirely from
// caller-supplied bytes, and whoever can reach the listener decides what is in
// the map.
//
// All three previously evicted "an arbitrary entry when the cache is full": a
// Go map range that stops at the first key, i.e. whichever entry Go's
// randomised map iteration happened to yield, live or already expired. (Go
// randomises where a range STARTS; it does not promise a uniform draw over
// keys, so the victim is arbitrary rather than uniformly distributed — the
// property that matters is only that it is unrelated to age, ownership or
// liveness.) That is register row AU-3c exactly, which CHAOS-57 closed in the
// LOCAL auth cache (store.go) and which was never ported to these three
// siblings. Two consequences followed, both reachable by an anonymous client:
//
//   - A flood of distinct bogus credentials displaced OTHER clients' cached
//     positives at random. Each insertion past the cap evicts an honest entry
//     with probability (honest entries / cap), so the honest population decays
//     geometrically: one cap-worth of flood removes ~63% of it and three
//     cap-worths remove ~95%. The victim then pays a full directory bind or
//     introspection round trip on EVERY subsequent request, which lands the
//     attacker's amplification on legitimate traffic and on the IdP itself.
//
//   - Worse, the victim is chosen without regard to whether it is still LIVE.
//     Nothing reclaims an expired entry (the lookup path reported a miss and
//     left it in place), so the steady state under a flood is a map full of
//     DEAD attacker verdicts while eviction destroys the few live ones. An
//     expired entry is free to drop — it would have been a miss anyway — so
//     evicting a live entry in preference to one is pure loss.
//
// The sharp end is the interaction with the CHAOS-47/CHAOS-49 unreachable
// cooldown. Displacing an honest client's cached positive while the backend is
// in its cooldown turns a cache HIT into a DENIAL, because the gated path
// denies without a round trip. The cache's stated purpose is to let a cached
// verdict ride out a short backend blip; a flood inverts that for exactly the
// users it exists to serve. Failure stays CLOSED — there is no bypass — but
// the gateway's authentication becomes remotely deniable by a client holding
// no VALID credential — bogus ones are all it needs, since those are what the
// cache records — which is the failure shape internal/authstate's package doc
// was written for.
//
// # The policy
//
// internal/authstate's, the same one CHAOS-57 ported into store.go, so there
// is ONE eviction policy in the tree rather than a fourth variant:
//
//   - Entries are attributed to a CLIENT fairness key. Eviction takes the
//     OLDEST entry of the client holding the MOST live entries, ties broken by
//     oldest entry then by client key (BetterVictim, which store.go's local
//     cache also uses), so the victim never depends on Go's map iteration
//     order.
//     A flooding source evicts ITSELF until it is no longer the largest
//     holder, and a client holding one entry cannot be displaced until every
//     other client is down to one too.
//
//   - An EXPIRED entry is always the better victim and is taken wherever it is
//     found, because dropping it costs nobody anything. The lookup path also
//     reclaims an expired entry in place, so dead verdicts no longer occupy
//     capacity until an eviction happens to land on them.
//
//   - Work per insertion is O(active clients) — bucket FRONTS only, never a
//     scan of the whole map. The O(cache) scan under a process-wide mutex is
//     register row AU-3d, and re-introducing it here would trade one measured
//     defect for another.
//
// Entries carry a PER-ENTRY expiry rather than one store-wide TTL, because a
// positive introspection verdict is clamped to the token's own declared
// lifetime (package main's clampCacheTTLToTokenExpiry) and may therefore be
// shorter-lived than the backend's configured TTL. A bucket front is
// consequently the client's oldest entry by INSERTION, which is not
// necessarily its first to expire; that only means a deeper expired entry
// waits until it reaches the front, and it leaves the fairness property — the
// one an attacker has to beat — untouched.
//
// # What package main supplies
//
// The cap and the eviction sink are construction dependencies (Options), not
// package state: the cap is main's maxAuthCacheSize, shared with the local
// credential cache in store.go, and OnEvict feeds the process-wide
// culvert_identity_cache_evictions_total counter, which has to outlive any one
// cache because the IdP registry compiles a fresh provider (and so a fresh,
// zero cache) whenever an operator edits a profile. The package holds no
// globals, so independent caches, and tests, never share a count.
package identcache
