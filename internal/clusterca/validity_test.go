package clusterca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Differential oracles: verbatim copies of package main's predicate, clamp and
// classifier as they stood in cluster_ca_validity.go at main 491b963, before
// they moved here (IM-013). Frozen so a later edit to the package cannot
// silently change the bytes an operator, a health probe or a metrics label
// sees, or the window an issued node certificate carries.
var (
	errOracleUnusable    = errors.New("cluster CA unusable")
	errOracleExpired     = errors.New("expired")
	errOracleNotYetValid = errors.New("not yet valid")
)

func oracleUsable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: no cluster CA loaded", errOracleUnusable)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: %w at %s (%s ago)", errOracleUnusable, errOracleExpired,
			cert.NotAfter.UTC().Format(time.RFC3339),
			now.Sub(cert.NotAfter).Round(time.Second))
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: %w until %s (system clock may have rolled back, or the CA was issued by a host whose clock is ahead)",
			errOracleUnusable, errOracleNotYetValid, cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

func oracleClamp(notBefore, notAfter time.Time, ca *x509.Certificate) (leafNotBefore, leafNotAfter time.Time, clampedToIssuer bool) {
	if ca == nil {
		return notBefore, notAfter, false
	}
	clamped := false
	if notBefore.Before(ca.NotBefore) {
		notBefore = ca.NotBefore
		clamped = true
	}
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
		clamped = true
	}
	return notBefore, notAfter, clamped
}

const (
	oracleRemediationClock  = "Correct this Control Plane's system clock (NTP) — the cluster CA is not yet valid. Do NOT rotate the CA; the trust root is fine."
	oracleRemediationRotate = "Rotate or import a cluster CA (Cluster → CA) to restore enrollment."
)

var (
	caStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	caEnd   = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

func testCA() *x509.Certificate { return &x509.Certificate{NotBefore: caStart, NotAfter: caEnd} }

// clockCases are the instants the predicate is judged at, including both exact
// bounds (inclusive), one nanosecond either side, sub-second rounding of the
// "ago" duration, and a non-UTC clock.
func clockCases() map[string]time.Time {
	ist := time.FixedZone("IST", 5*3600+1800)
	return map[string]time.Time{
		"exact NotBefore":          caStart,
		"1ns before NotBefore":     caStart.Add(-time.Nanosecond),
		"far before NotBefore":     caStart.Add(-90 * 24 * time.Hour),
		"inside window":            caStart.Add(5 * 365 * 24 * time.Hour),
		"exact NotAfter":           caEnd,
		"1ns after NotAfter":       caEnd.Add(time.Nanosecond),
		"499ms after NotAfter":     caEnd.Add(499 * time.Millisecond),
		"500ms after NotAfter":     caEnd.Add(500 * time.Millisecond),
		"long after NotAfter":      caEnd.Add(400*24*time.Hour + 3*time.Minute),
		"non-UTC clock, expired":   caEnd.Add(time.Hour).In(ist),
		"non-UTC clock, too early": caStart.Add(-time.Hour).In(ist),
	}
}

func TestUsable_MatchesRootOracle(t *testing.T) {
	certs := map[string]*x509.Certificate{
		"nil":    nil,
		"window": testCA(),
		"non-UTC bounds": {
			NotBefore: caStart.In(time.FixedZone("PST", -8*3600)),
			NotAfter:  caEnd.In(time.FixedZone("PST", -8*3600)),
		},
	}
	for cn, cert := range certs {
		for nn, now := range clockCases() {
			got, want := Usable(cert, now), oracleUsable(cert, now)
			if (got == nil) != (want == nil) {
				t.Fatalf("%s @ %s: got %v, root oracle %v", cn, nn, got, want)
			}
			if got == nil {
				continue
			}
			if got.Error() != want.Error() {
				t.Fatalf("%s @ %s: message drifted\n got  %q\n want %q", cn, nn, got.Error(), want.Error())
			}
			if !errors.Is(got, ErrUnusable) {
				t.Fatalf("%s @ %s: %v does not wrap ErrUnusable", cn, nn, got)
			}
			if errors.Is(want, errOracleExpired) != errors.Is(got, ErrExpired) ||
				errors.Is(want, errOracleNotYetValid) != errors.Is(got, ErrNotYetValid) {
				t.Fatalf("%s @ %s: kind sentinels differ from the root oracle: %v", cn, nn, got)
			}
		}
	}
}

func TestUsable_BoundsAreInclusive(t *testing.T) {
	ca := testCA()
	for _, now := range []time.Time{caStart, caEnd} {
		if err := Usable(ca, now); err != nil {
			t.Fatalf("Usable at the exact bound %s = %v, want nil", now, err)
		}
	}
}

// The cluster CA deliberately applies NO future-skew tolerance (unlike the
// inspection CA's): one nanosecond before NotBefore is already unusable.
func TestUsable_NoFutureSkewTolerance(t *testing.T) {
	err := Usable(testCA(), caStart.Add(-time.Nanosecond))
	if !errors.Is(err, ErrNotYetValid) || errors.Is(err, ErrExpired) {
		t.Fatalf("1ns before NotBefore: %v, want ErrNotYetValid only", err)
	}
}

func TestUnusableKind(t *testing.T) {
	ca := testCA()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"expired", Usable(ca, caEnd.Add(time.Second)), "expired"},
		{"not yet valid", Usable(ca, caStart.Add(-time.Second)), "not_yet_valid"},
		{"no CA", Usable(nil, caStart), "unavailable"},
		{"bare sentinel", ErrUnusable, "unavailable"},
		{"foreign error", errors.New("boom"), "unavailable"},
		{"re-wrapped expiry", fmt.Errorf("sign: %w", Usable(ca, caEnd.Add(time.Hour))), "expired"},
	}
	for _, c := range cases {
		if got := UnusableKind(c.err); got != c.want {
			t.Errorf("%s: UnusableKind = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRemediation_ClockFaultNeverRotates(t *testing.T) {
	if got := Remediation("not_yet_valid"); got != oracleRemediationClock {
		t.Fatalf("not_yet_valid remediation drifted: %q", got)
	}
	if !strings.Contains(Remediation("not_yet_valid"), "Do NOT rotate") {
		t.Fatal("a clock fault must not be answered with a rotation")
	}
	for _, k := range []string{"expired", "unavailable", "", "unknown"} {
		if got := Remediation(k); got != oracleRemediationRotate {
			t.Fatalf("%q remediation drifted: %q", k, got)
		}
	}
}

func TestClampNodeValidity_MatchesRootOracle(t *testing.T) {
	ca := testCA()
	year := 365 * 24 * time.Hour
	windows := map[string][2]time.Time{
		"inside":           {caStart.Add(year), caStart.Add(2 * year)},
		"outlives issuer":  {caEnd.Add(-30 * 24 * time.Hour), caEnd.Add(-30*24*time.Hour + year)},
		"predates issuer":  {caStart.Add(-time.Hour), caStart.Add(year)},
		"both sides":       {caStart.Add(-time.Hour), caEnd.Add(time.Hour)},
		"exact bounds":     {caStart, caEnd},
		"inverted request": {caEnd.Add(time.Hour), caStart.Add(-time.Hour)},
	}
	for _, issuer := range []*x509.Certificate{nil, ca} {
		for name, w := range windows {
			gb, ga, gc := ClampNodeValidity(w[0], w[1], issuer)
			wb, wa, wc := oracleClamp(w[0], w[1], issuer)
			if !gb.Equal(wb) || !ga.Equal(wa) || gc != wc {
				t.Fatalf("%s (issuer nil=%v): got (%v, %v, %v), root oracle (%v, %v, %v)",
					name, issuer == nil, gb, ga, gc, wb, wa, wc)
			}
			if issuer != nil && (gb.Before(issuer.NotBefore) || ga.After(issuer.NotAfter)) {
				t.Fatalf("%s: clamped window [%v, %v] escapes the issuer", name, gb, ga)
			}
		}
	}
}

func TestRenewalWindowIsThirtyDays(t *testing.T) {
	if RenewalWindow != 30*24*time.Hour {
		t.Fatalf("RenewalWindow = %v; it must equal the CA rotation horizon and the DP renewal window", RenewalWindow)
	}
}

// Mutation negative control: the differential test above must fail against a
// plausible regression (adding the inspection CA's 5-minute skew tolerance).
func TestUsable_OracleDetectsSkewToleranceRegression(t *testing.T) {
	tolerant := func(cert *x509.Certificate, now time.Time) error {
		return Usable(cert, now.Add(5*time.Minute))
	}
	now := caStart.Add(-time.Minute)
	if (tolerant(testCA(), now) == nil) == (oracleUsable(testCA(), now) == nil) {
		t.Fatal("the oracle comparison cannot tell a skew-tolerant predicate apart")
	}
}
