package canary

import "time"

// FIRST-CANARY PEER-OBSERVED FRESHNESS (blocker #11).
//
// Every other exact-target fact in this package asks whether Culvert's OWN records are coherent:
// the policy permit, the credential statements, the reviewed binding. None of them asks whether
// those records still describe the peer. They could not: until the governed refresh path existed,
// the catalog only ever held what an operator declared, and `ToolStillCurrent` validated that
// unchanged local record indefinitely. "Exact reviewed fingerprint" and "rug-pull invalidates the
// approval" therefore bound the SEED, not the upstream.
//
// This file is the pure half of the answer. It decides one question:
//
//	is the exact reviewed First-Canary target backed by a RECENT AUTHENTICATED observation
//	of the peer that advertises it?
//
// It reads no state, holds no clock and can permit nothing. The caller supplies one coherent
// capture and one clock sample; the output is a bounded reason the readiness table consumes.
//
// WHAT AN OBSERVATION DOES AND DOES NOT SAY. A peer observation is evidence that an
// authenticated server identity advertised certain tool bytes at a certain time. It is NOT a
// statement about tenancy: the peer has no authority over who owns it, and asking it would let an
// upstream place itself in a tenant. Tenant ownership therefore comes from the registry, and this
// file compares the activation's tenant against THAT — never against anything the observation
// carries. For the same reason PeerObservation deliberately has no tenant field.
//
// FRESHNESS IS NOT AUTHORITY. A fresh observation says only that the peer currently advertises
// this exact tool. It promotes nothing, approves nothing and arms nothing; every other
// prerequisite still has to hold independently.

// FirstCanaryPeerObservationMaxAge is how long an authenticated peer observation may support a
// First Canary activation.
//
// IT IS ITS OWN SECURITY INTERVAL. It is deliberately NOT the live-approval TTL, the tool-trust
// TTL or the Canary window, even where a number coincides: those bound how long a HUMAN DECISION
// stays valid, and this bounds how long a MEASUREMENT of a third party stays believable. The two
// answer different questions and must be able to move independently — shortening the approval TTL
// should not silently tighten peer freshness, and vice versa.
//
// WHY THIRTY MINUTES. The quantity being bounded is the window in which the peer could have
// changed what it advertises without Culvert noticing. The First Canary is an ATTENDED experiment
// — an operator refreshes the observation, reads the observed fingerprint, reviews it, and
// activates — so the bound has to be long enough for that sequence in one sitting and short
// enough that walking away invalidates it. Thirty minutes is the smallest value that comfortably
// admits refresh-review-activate without the evidence expiring mid-review, and it means an
// operator who leaves for half an hour must re-observe before the experiment can arm.
//
// The interaction with the Canary window is deliberate and is the reason the value is not
// tighter. The experiment's window is 15 minutes, so with this bound the peer is at worst
// unobserved for MaxAge + Window = 45 minutes between the last authenticated sighting and the
// last possible execution. Choosing 15 minutes here would halve that exposure but would make an
// ordinary review-then-activate flow expire mid-window once the runtime re-checks freshness
// before each send, failing experiments for a reason unrelated to safety.
const FirstCanaryPeerObservationMaxAge = 30 * time.Minute

// PeerFreshReason is the bounded classification of WHY the exact First-Canary target is not
// backed by a fresh authenticated observation. It is a fixed vocabulary: no identity, endpoint,
// fingerprint, tenant or timestamp ever appears in it, so it is safe on the read-only operator
// surface. The classes are finer than the single readiness row needs because each names a
// different remedy — and because a test that cannot tell "never observed" from "observed too
// long ago" cannot prove the difference is enforced.
type PeerFreshReason string

const (
	// PeerFreshOK — the exact reviewed target is backed by a recent authenticated observation
	// of the peer, under the current pinned identity, from a usable server.
	PeerFreshOK PeerFreshReason = ""
	// PeerFreshUnavailable — the authoritative facts could not be resolved (no coherent
	// inventory capture, no registry or catalog record, an ambiguous scope). Nothing was
	// established, so the fact is unmet. Distinct from a resolved answer that the target is
	// stale.
	PeerFreshUnavailable PeerFreshReason = "peer_observation_facts_unavailable"
	// PeerFreshMissing — the record carries NO observation at all. This is the shipped default:
	// an operator-seeded record has never been backed by a peer, and a restart returns every
	// record to exactly this state.
	PeerFreshMissing PeerFreshReason = "peer_observation_missing"
	// PeerFreshNoIdentity — an observation exists but names no verified identity, so it cannot
	// say WHO was observed. Refused rather than treated as a weaker observation.
	PeerFreshNoIdentity PeerFreshReason = "peer_observation_identity_missing"
	// PeerFreshFuture — the observation is stamped AFTER the evaluation instant. Either the
	// clock moved backwards or the timestamp is not trustworthy; both are ambiguities this
	// resolves toward NOT fresh. Honouring a future stamp would grant freshness for however far
	// ahead it sits.
	PeerFreshFuture PeerFreshReason = "peer_observation_clock_ambiguous"
	// PeerFreshStale — the observation is real and well-formed but older than
	// FirstCanaryPeerObservationMaxAge.
	PeerFreshStale PeerFreshReason = "peer_observation_stale"
	// PeerFreshIdentityNotCurrent — the identity the observation verified is no longer the
	// server's pinned identity, or no longer the one the catalog record's fingerprint carries.
	// The observation may be perfectly recent and is still worthless: it describes a peer this
	// node no longer considers the server.
	PeerFreshIdentityNotCurrent PeerFreshReason = "peer_observation_identity_mismatch"
	// PeerFreshServerUnusable — the registry server is disabled or identity-mismatched now,
	// whatever was observed earlier.
	PeerFreshServerUnusable PeerFreshReason = "peer_observation_server_unusable"
	// PeerFreshTargetMoved — the observation backs a DIFFERENT target than the activation
	// reviewed: a different fingerprint, fingerprint format, server, tool or tenant owner.
	// Freshness belongs to an exact observed target, never to a server: a fresh observation of
	// F2 says nothing whatsoever about an activation reviewed against F1.
	PeerFreshTargetMoved PeerFreshReason = "peer_observation_target_moved"
)

// PeerObservationFacts is the evidence carried on the catalog record, lifted into this package so
// the pure verdict does not import the catalog. Identity is the identity VERIFIED ON THE
// OBSERVATION'S TRANSPORT, never a value read out of the peer's payload.
type PeerObservationFacts struct {
	At       time.Time
	Identity string
}

// PeerFreshnessInput is one coherent capture of everything the verdict needs.
//
// Reviewed and Current are the SAME shape deliberately: Reviewed is what the activation was
// approved to execute, Current is what the authoritative registry+catalog say right now, and the
// binding this file enforces is that the observation backs a target equal to BOTH.
type PeerFreshnessInput struct {
	// Resolved is true only when every field below was actually established from the capture.
	// Every early return in the caller leaves it false, so an unresolved capture is never read
	// as a satisfied fact.
	Resolved bool
	// Now is the caller's single clock sample for this whole readiness evaluation. This package
	// never reads a clock: a pure verdict that sampled time itself could not be tested at a
	// boundary, and two facts in one evaluation could straddle two instants.
	Now time.Time
	// Observed is the evidence on the catalog record backing Current.
	Observed PeerObservationFacts
	// Reviewed is the exact target the activation was reviewed against.
	Reviewed ReviewedTarget
	// Current is the exact target the authoritative capture describes right now.
	Current ReviewedTarget
	// ActivationTenant is the tenant the requested scope names. It is compared against the
	// REGISTRY's owner (carried on Current), never against anything the peer said.
	ActivationTenant string
	// RegistryPinnedIdentity is the server's pinned identity in the live registry snapshot.
	RegistryPinnedIdentity string
	// ServerUsable is the live registry server's usability right now.
	ServerUsable bool
}

// PeerObservationFresh is the pure freshness predicate over one clock sample and one observation.
//
// It is exported and separate from the binding verdict below because it is the property the
// runtime will re-check before a physical send, and there must be exactly ONE definition of
// "fresh" for both — an activation-time bound and a send-time bound that could drift apart would
// be two answers to one question.
//
// Fresh iff ALL hold: the observation exists (non-zero timestamp), it names a verified identity,
// the evaluation instant is not before it, and its age does not exceed the maximum.
//
// THE BOUNDARY IS INCLUSIVE, decided once here: an observation exactly MaxAge old is still fresh,
// and one tick beyond is not. That is the ordinary reading of a maximum age, and pinning it means
// the boundary test asserts a behaviour rather than a coincidence.
func PeerObservationFresh(now time.Time, obs PeerObservationFacts) bool {
	if obs.At.IsZero() || obs.Identity == "" {
		return false
	}
	if now.Before(obs.At) {
		return false
	}
	return now.Sub(obs.At) <= FirstCanaryPeerObservationMaxAge
}

// EvaluatePeerObservedFresh is the pure verdict: is the exact reviewed First-Canary target backed
// by a recent authenticated observation of the peer?
//
// ORDER IS DELIBERATE. The bindings are checked before the clock, so a target that was never the
// reviewed one reports that it moved rather than that it is stale — an operator told "stale"
// would refresh, and refreshing cannot fix a target mismatch.
func EvaluatePeerObservedFresh(in PeerFreshnessInput) PeerFreshReason {
	if !in.Resolved {
		return PeerFreshUnavailable
	}
	// The server must be usable NOW, whatever was true when it was observed. A disabled or
	// identity-mismatched server is not a server this node will execute against.
	if !in.ServerUsable {
		return PeerFreshServerUnusable
	}
	// EXACT TARGET BINDING. Freshness belongs to an exact observed target, never to a server:
	// without this, a fresh observation of F2 would make an activation reviewed against F1 look
	// backed. Tenant is taken from Current — i.e. from the REGISTRY's owner scope — because the
	// peer has no authority over tenancy.
	//
	// THAT CHOICE IS NOT BEHAVIOURALLY OBSERVABLE HERE, and the mutation campaign proved it
	// rather than leaving it assumed: comparing ActivationTenant against Reviewed.Tenant instead
	// is an EQUIVALENT MUTANT, because reaching OK also requires Reviewed.Tenant == Current.Tenant
	// (the very next check), and given that equality the two comparisons agree on every input. No
	// test can distinguish them, so none is written to pretend otherwise.
	//
	// It is still written against Current DELIBERATELY. The equivalence holds only while the
	// Reviewed-vs-Current tenant check sits below; someone removing or reordering that check
	// would silently make the mutant form read tenancy out of the activation's own reviewed set —
	// i.e. out of a value the activation supplies — instead of out of the registry. Reading from
	// the authoritative side means the correct answer does not depend on a second check elsewhere
	// continuing to exist.
	if in.ActivationTenant == "" || in.ActivationTenant != in.Current.Tenant {
		return PeerFreshTargetMoved
	}
	if in.Reviewed.Tenant != in.Current.Tenant ||
		in.Reviewed.ServerID != in.Current.ServerID ||
		in.Reviewed.ToolName != in.Current.ToolName ||
		in.Reviewed.Fingerprint != in.Current.Fingerprint ||
		in.Reviewed.FingerprintFormat != in.Current.FingerprintFormat {
		return PeerFreshTargetMoved
	}
	// IDENTITY MUST BE CURRENT IN BOTH DIRECTIONS. The observation's verified identity has to be
	// the one the catalog record's fingerprint carries AND the one the registry pins now. The
	// two can genuinely disagree in published state (the repin window: Registry.Repin and the
	// re-ingest that follows it are separate publications), and an observation that matches only
	// one of them is not evidence about the server this node would execute against.
	if in.Observed.Identity == "" {
		if in.Observed.At.IsZero() {
			return PeerFreshMissing
		}
		return PeerFreshNoIdentity
	}
	if in.Observed.Identity != in.Current.ServerIdentity ||
		in.Observed.Identity != in.RegistryPinnedIdentity {
		return PeerFreshIdentityNotCurrent
	}
	// FRESHNESS LAST. Everything above is about WHICH target the evidence describes; this is
	// about WHEN it was gathered.
	if in.Observed.At.IsZero() {
		return PeerFreshMissing
	}
	if in.Now.Before(in.Observed.At) {
		return PeerFreshFuture
	}
	if !PeerObservationFresh(in.Now, in.Observed) {
		return PeerFreshStale
	}
	return PeerFreshOK
}
