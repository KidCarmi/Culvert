package main

// ha_authority.go — leadership and publication authority, as two SEPARATE
// questions (node_lifecycle.go lists the consumers).
//
// THIS FILE IS A STUB. Both functions answer what the code did before they
// existed, so introducing the call sites changes no behaviour. The HA
// authority change (ADR 0064) replaces this file with the real answers: the
// lease or the legacy restart revalidation for leadership, and the
// publication safety gate for publishing. Keep every consumer on these two
// functions; do not re-derive either answer anywhere else.

// haLeadershipHeld reports whether this node holds the authority that
// leadership-dependent operations need: publishing a snapshot, a distributed
// admin mutation, a cluster-CA rotation, serving as the HA leader.
//
// Stub: true. Today none of those paths asks an authority question beyond the
// checks they already make themselves (haServingAllowed, haIssuanceAllowed),
// which stay in place.
func haLeadershipHeld() bool { return true }

// haPublishAuthorized reports whether this node may distribute a
// configuration snapshot to data planes and standbys, with the reason when it
// may not. It is NOT implied by leadership: a node can lead and still be
// refused publication.
//
// Stub: authorized. Today a ready, leader-gated node serves its committed
// snapshot.
func haPublishAuthorized() (ok bool, reason string) { return true, "" }
