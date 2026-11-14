// Package realclientip resolves the effective client IP of an admin-UI request
// behind trusted reverse proxies (RISK-019, ADR-0045).
//
// A Resolver owns one trusted-proxy set. ClientIP returns the direct peer
// unless that peer is itself a configured trusted proxy; only then does it
// read X-Forwarded-For and return the rightmost hop that is not a trusted
// proxy. That gate is the whole security argument: a direct attacker cannot
// forge a victim's IP through X-Forwarded-For, because the attacker's own peer
// address is not in the trusted set. An empty set (the zero value) never
// trusts the header.
//
// Package main owns the single application instance, persistence of the set
// in admin settings, and every call site. This package holds no package-level
// state, starts no goroutines and does no I/O or logging.
package realclientip
