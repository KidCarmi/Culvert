package hostutil

import (
	"fmt"
	"hash/maphash"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/net/idna"
)

// Security-regression gates for the memoized IDNA slow path (idnamemo.go).
//
// idnamemo_test.go proves the memo is fast, bounded and differentially correct
// over the shapes it RETAINS. The three gates here cover the properties whose
// failure mode is a security one rather than a performance one, and which that
// file does not pin:
//
//  1. The widest LEGITIMATE internationalized destination — the 883-raw /
//     251-canonical shape that proxy_host_bounds.go sized maxRawDestAuthorityBytes
//     to admit — is past maxMemoHostLen, so it takes the un-retained branch. Its
//     answer must be identical there, and the derivation must stay visible: the
//     exclusion is deliberate (it is what makes the footprint ceiling a bound),
//     not an oversight to be "fixed" by raising the constant without re-deriving
//     the ceiling.
//
//  2. A memo must never upgrade a REJECTION to an acceptance. NormalizeHostStrict
//     is the fail-closed gate the request path uses so a host that cannot be
//     canonicalized is refused instead of flowing un-normalized into FQDN,
//     blocklist and category matching (RISK-013). A direct-mapped slot is shared
//     by design, so the crossing that matters is rejected-host-meets-accepted-
//     entry; the existing collision test alternates two ACCEPTED hosts and
//     therefore cannot see it.
//
//  3. The stored key must be a CLONE, never the caller's string. The key arrives
//     as a substring of whatever buffer the caller holds — on the request path,
//     net/http's header buffer — so an entry that kept it would pin that whole
//     backing array per slot and the bounded-footprint property would be a
//     measurement of the test corpus rather than a bound.

// maximalLegitimateIDN returns the longest raw UTF-8 host whose canonical
// A-label form still fits in DNS, measured against the REAL x/net/idna rather
// than asserted from a constant, so an upstream change that alters the expansion
// ratio moves this fixture instead of silently invalidating the reasoning above.
//
// It is the same derivation as package main's chaos66MaxIDN (the control for
// maxRawDestAuthorityBytes); hostutil is below main and cannot import it, and a
// shared fixture is not worth a new export on a leaf seam. 4-byte runes are the
// worst case: Punycode emits at least one byte per encoded code point, so the
// raw:canonical ratio is maximised by the widest UTF-8 encoding.
func maximalLegitimateIDN(t *testing.T) string {
	t.Helper()
	best := ""
	for runes := 1; runes <= 80; runes++ {
		label := strings.Repeat("\U0001D11E", runes) // U+1D11E, 4 UTF-8 bytes
		if a, err := idna.ToASCII(label); err != nil || len(a) > 63 {
			continue // not a valid DNS label
		}
		for labels := 1; labels <= 16; labels++ {
			parts := make([]string, labels)
			for i := range parts {
				parts[i] = label
			}
			host := strings.Join(parts, ".")
			a, err := idna.ToASCII(host)
			if err != nil || len(a) > maxMemoHostLen {
				continue
			}
			if len(host) > len(best) {
				best = host
			}
		}
	}
	if best == "" {
		t.Fatal("could not build a maximal legitimate IDN host")
	}
	return best
}

// TestIDNMemo_MaximalLegitimateIDNIsAnswerTransparent covers the one shape that
// is simultaneously legitimate, resolvable, OVER maxMemoHostLen in raw bytes and
// UNDER it once canonicalized — so it is admitted by both proxy host-bound tiers
// and skipped by the memo. idnamemo_test.go's oversize cases are all oversize in
// their canonical form too (dot-dense ASCII does not shrink, and a 400-rune label
// fails IDNA outright), so none of them exercises this band.
//
// Two things are asserted, and they pull in opposite directions on purpose:
// the answer must not change on the un-retained branch, and the host must not be
// retained. A refactor that moved the length check onto the NORMALIZED form would
// keep the first and break the second, admitting an 883-byte key per slot.
func TestIDNMemo_MaximalLegitimateIDNIsAnswerTransparent(t *testing.T) {
	normMemoResetForTest()
	host := maximalLegitimateIDN(t)
	canonical, err := idna.ToASCII(host)
	if err != nil {
		t.Fatalf("idna.ToASCII(maximal legitimate IDN): %v", err)
	}
	t.Logf("maximal legitimate IDN: raw=%d bytes canonical=%d bytes (memo retention bound %d)",
		len(host), len(canonical), maxMemoHostLen)

	// The derivation control. If this stops holding, the memo now retains the
	// widest legitimate IDN and the footprint ceiling in TestIDNMemo_BoundedFootprint
	// must be re-derived from the new bound rather than left as it is.
	if len(host) <= maxMemoHostLen {
		t.Fatalf("the widest legitimate IDN is %d raw bytes, within the %d-byte retention bound — "+
			"this case no longer exercises the un-retained branch, and the footprint ceiling "+
			"(slots x 2 x %d) no longer bounds what a client can park in the table",
			len(host), maxMemoHostLen, maxMemoHostLen)
	}
	if len(canonical) > maxMemoHostLen {
		t.Fatalf("probe host canonicalizes to %d bytes, past the DNS limit — it would be refused by "+
			"rejectOversizeCanonicalHost and is not the legitimate shape this case is about", len(canonical))
	}

	wantNorm, wantOK := normalizeHostStrictUncached(strings.ToLower(host))
	if !wantOK {
		t.Fatalf("the reference rejected a host idna.ToASCII accepted; the case proves nothing")
	}
	for round := 0; round < 3; round++ {
		gotNorm, gotOK := NormalizeHostStrict(host)
		if gotNorm != wantNorm || gotOK != wantOK {
			t.Fatalf("REGRESSION: round %d returned (%q…, %v), uncached returns (%q…, %v) — "+
				"the un-retained branch must answer identically",
				round, truncForLog(gotNorm), gotOK, truncForLog(wantNorm), wantOK)
		}
	}
	if n := normMemoOccupied(); n != 0 {
		t.Errorf("REGRESSION: %d slots filled by an %d-byte legitimate IDN host — the retention bound "+
			"is measured on the RAW key, which is what the footprint ceiling is derived from",
			n, len(host))
	}
}

// acceptedIDNHost and rejectedIDNHost generate the two slow-path families the
// crossing test needs. Both reach the memo: the first is non-ASCII, the second
// carries an ACE label, so neither is answered by the already-canonical fast
// path. The rejected family is malformed Punycode, which is exactly what the
// fail-closed gate exists to refuse.
func acceptedIDNHost(i int) string { return fmt.Sprintf("bücher%d.example.com", i) }
func rejectedIDNHost(i int) string { return fmt.Sprintf("xn--%d.example.com", i) }

// findCrossVerdictCollision searches for an ACCEPTED and a REJECTED slow-path
// host that land in the same direct-mapped slot under this process's seed. The
// seed is randomized per process, so the pair is found at runtime.
func findCrossVerdictCollision(budget int) (accepted, rejected string, found bool) {
	bySlot := make(map[uint64]string, budget)
	for i := 0; i < budget; i++ {
		h := acceptedIDNHost(i)
		bySlot[maphash.String(normMemoSeed, h)&normMemoMask] = h
	}
	for i := 0; i < budget; i++ {
		h := rejectedIDNHost(i)
		if a, ok := bySlot[maphash.String(normMemoSeed, h)&normMemoMask]; ok {
			return a, h, true
		}
	}
	return "", "", false
}

// TestIDNMemo_RejectionIsNeverUpgradedToAcceptance is the fail-closed gate.
//
// NormalizeHostStrict's contract is that ok=false means REFUSE the request
// (RISK-013): a host the normalizer cannot map to canonical ASCII must not reach
// FQDN/blocklist/category matching un-normalized, because a fail-open in the
// canonicalization step is the asymmetry evasion techniques target. A memo bug
// that answered a rejected host from a neighbouring accepted entry would convert
// that fail-closed gate into a fail-OPEN one, silently, for a host an attacker
// chooses — so the crossing is tested in BOTH directions, with each host finding
// the other resident in their shared slot.
//
// TestIDNMemo_CollisionAnswersBothHosts covers the same mechanism with two
// accepted hosts; it cannot observe the verdict crossing, which is the half with
// a security consequence.
func TestIDNMemo_RejectionIsNeverUpgradedToAcceptance(t *testing.T) {
	normMemoResetForTest()
	accepted, rejected, found := findCrossVerdictCollision(1 << 13)
	if !found {
		t.Skip("no accepted/rejected pair collided within the search budget (seed-dependent)")
	}
	wantNorm, wantOK := normalizeHostStrictUncached(accepted)
	if !wantOK {
		t.Fatalf("probe host %q was expected to normalize; the case proves nothing", accepted)
	}
	if _, ok := normalizeHostStrictUncached(rejected); ok {
		t.Fatalf("probe host %q was expected to be REJECTED; the case proves nothing", rejected)
	}
	if got := maphash.String(normMemoSeed, accepted) & normMemoMask; got != maphash.String(normMemoSeed, rejected)&normMemoMask {
		t.Fatalf("probe hosts do not share a slot; the case proves nothing")
	}

	// Alternate so that each lookup finds the OTHER verdict resident in the slot,
	// then repeat — a direct-mapped slot is overwritten on every miss, so the
	// crossing is retried from both residencies. The ACCEPTED host goes first in
	// each round, which is what makes the security-primary direction (a rejection
	// answered from a resident acceptance) a deterministic probe rather than one
	// that depends on which host happened to occupy the slot.
	for round := 0; round < 4; round++ {
		if norm, ok := NormalizeHostStrict(accepted); norm != wantNorm || !ok {
			t.Fatalf("REGRESSION (round %d): NormalizeHostStrict(%q) = (%q, %v), want (%q, true) — "+
				"a valid host was refused from a colliding rejection entry",
				round, accepted, norm, ok, wantNorm)
		}
		if norm, ok := NormalizeHostStrict(rejected); ok || norm != "" {
			t.Fatalf("REGRESSION (round %d): NormalizeHostStrict(%q) = (%q, %v), want (\"\", false) — "+
				"a host that cannot be canonicalized was ACCEPTED from a colliding entry, turning the "+
				"fail-closed dispatch gate into a fail-open one (RISK-013)",
				round, rejected, norm, ok)
		}
	}

	// And the memoized rejection must stay a rejection when it is the resident
	// entry being HIT rather than recomputed: two consecutive lookups, no
	// intervening eviction.
	for round := 0; round < 2; round++ {
		if norm, ok := NormalizeHostStrict(rejected); ok || norm != "" {
			t.Fatalf("REGRESSION: a memoized rejection was answered as (%q, %v) on hit %d", norm, ok, round)
		}
	}
}

// TestIDNMemo_StoredKeyDoesNotAliasTheCallerBuffer pins the clone in
// normalizeHostStrictMemo, which the bounded-footprint property depends on and
// nothing currently asserts.
//
// The key reaches the memo as a SUBSTRING of whatever the caller passed —
// strings.ToLower returns its input unchanged when there is nothing to lower and
// strings.TrimSuffix returns a substring — and on the request path that input is
// a slice of net/http's header buffer. An entry that kept it would pin the whole
// backing array for the life of the entry: at 1024 slots that is gigabytes held
// alive by hosts whose own length accounting (len(e.host)) reports a few dozen
// bytes each, so TestIDNMemo_BoundedFootprint would still pass while the process
// retained the buffers. The failure is invisible to every byte-counting test,
// which is why it is pinned on the pointer.
func TestIDNMemo_StoredKeyDoesNotAliasTheCallerBuffer(t *testing.T) {
	normMemoResetForTest()
	// A host that is a genuine substring of a large buffer, as r.Host is.
	const padding = 1 << 20
	backing := strings.Repeat("a", padding) + "bücher-alias.example.com"
	host := backing[padding:]
	if unsafe.StringData(host) == unsafe.StringData(backing) {
		t.Fatal("the probe host is not a substring of the padded buffer; the case proves nothing")
	}

	norm, ok := NormalizeHostStrict(host)
	if !ok {
		t.Fatalf("NormalizeHostStrict(%q) rejected a valid IDN host", host)
	}
	e := normMemoSlot(host).Load()
	if e == nil || e.host != host {
		t.Fatalf("the probe host was not retained (entry=%+v); the case proves nothing", e)
	}
	if unsafe.StringData(e.host) == unsafe.StringData(host) {
		t.Fatalf("REGRESSION: the memo stored the caller's string rather than a clone, pinning its "+
			"%d-byte backing array behind a %d-byte key — the bounded-footprint ceiling does not hold",
			len(backing), len(e.host))
	}
	if unsafe.StringData(e.norm) == unsafe.StringData(host) {
		t.Fatalf("REGRESSION: the memoized normalized form aliases the caller's %d-byte buffer",
			len(backing))
	}
	// The returned value must not alias it either: it outlives the call in every
	// caller that keys a store, a log line or a policy decision on it.
	if unsafe.StringData(norm) == unsafe.StringData(host) {
		t.Fatalf("REGRESSION: the returned normalized host aliases the caller's %d-byte buffer",
			len(backing))
	}
}
