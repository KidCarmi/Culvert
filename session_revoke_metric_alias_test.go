package main

// session_revoke_metric_alias_test.go — T-70 deprecation-window gate.
//
// culvert_session_revoke_refused_total (unlabeled) and
// culvert_session_revoke_rejected_total{reason} shipped in v1.0.340. The T-70
// rename moves them to culvert_session_revoke_unverifiable_total and
// culvert_session_revoke_refusals_total{reason}, and keeps the released names
// emitting exactly what they emitted in v1.0.341 until v1.1.0. An existing
// dashboard or alert on a released name must keep reading the same quantity.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// t70Scrape renders /metrics and returns its samples (series → value), its
// TYPE lines (name → type) and its HELP lines (name → text).
func t70Scrape(t *testing.T) (samples, types, helps map[string]string) {
	t.Helper()
	var b strings.Builder
	liveFeedWritePrometheus(&b)
	samples, types, helps = map[string]string{}, map[string]string{}, map[string]string{}
	for _, line := range strings.Split(b.String(), "\n") {
		switch {
		case line == "":
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(strings.TrimPrefix(line, "# TYPE "))
			if _, dup := types[f[0]]; dup {
				t.Errorf("TYPE for %s emitted twice", f[0])
			}
			types[f[0]] = f[1]
		case strings.HasPrefix(line, "# HELP "):
			name, text, _ := strings.Cut(strings.TrimPrefix(line, "# HELP "), " ")
			helps[name] = text
		case strings.HasPrefix(line, "#"):
		default:
			i := strings.LastIndexByte(line, ' ')
			if i < 0 {
				t.Fatalf("malformed sample line %q", line)
			}
			if _, dup := samples[line[:i]]; dup {
				t.Errorf("series %s emitted twice", line[:i])
			}
			samples[line[:i]] = line[i+1:]
		}
	}
	return samples, types, helps
}

// seriesOf returns every sample of one metric name: the bare name for an
// unlabeled sample, or name{...} for a labeled one.
func seriesOf(samples map[string]string, name string) map[string]string {
	out := map[string]string{}
	for k, v := range samples {
		if k == name || strings.HasPrefix(k, name+"{") {
			out[k] = v
		}
	}
	return out
}

func TestT70_SessionRevokeMetricAliases(t *testing.T) {
	chaos73Setup(t)

	// Distinct, non-zero counts per reason, so a series wired to the wrong
	// reason cannot pass by coincidence. Each one comes from its real path.
	logoutWith(t, forgedCookie(t, 0, "t70")) // unsigned ×1
	for range 2 {
		logoutWith(t, "t70-cookie-without-a-mac") // malformed ×2
	}
	for i := range 3 {
		logoutWith(t, genuineCookie(t, fmt.Sprintf("t70-stale-%d", i), -time.Hour, nil)) // expired ×3
	}
	exp := time.Now().Add(time.Hour).Unix()
	far := time.Now().Add(session.MaxSessionLifetime + 2*time.Hour).Unix()
	var remote []session.RevocationEntry
	for i := range 4 { // oversize ×4
		remote = append(remote, session.RevocationEntry{
			Token: fmt.Sprintf("%d", i) + strings.Repeat("x", session.MaxRevocationTokenLen), Expiry: exp,
		})
	}
	for i := range 5 { // far_future ×5
		remote = append(remote, session.RevocationEntry{Token: fmt.Sprintf("t70-far-%d", i), Expiry: far})
	}
	if added := session.Revoked.MergeRevocations(remote); added != 0 {
		t.Fatalf("merged %d untrusted entries; want 0", added)
	}

	want := map[session.RevokeReason]int64{
		session.RevokeUnsigned: 1, session.RevokeMalformed: 2, session.RevokeExpired: 3,
		session.RevokeOversize: 4, session.RevokeCapacity: 0, session.RevokeFarFuture: 5,
	}
	for reason, n := range want {
		if got := session.Refused(reason); got != n {
			t.Fatalf("fixture: session.Refused(%s) = %d; want %d", reason, got, n)
		}
	}
	const wantUnverifiable = "3" // unsigned + malformed; expired is ordinary traffic
	if got := sessionRevocationRefusedTotal(); got != 3 {
		t.Fatalf("fixture: unverifiable logout total = %d; want 3", got)
	}

	samples, types, helps := t70Scrape(t)

	// The released unlabeled counter: same name, NO labels, same quantity.
	// It must never become the labeled per-reason series.
	old := seriesOf(samples, "culvert_session_revoke_refused_total")
	if len(old) != 1 || old["culvert_session_revoke_refused_total"] != wantUnverifiable {
		t.Errorf("released culvert_session_revoke_refused_total = %v; want exactly one unlabeled sample = %s", old, wantUnverifiable)
	}
	canon := seriesOf(samples, "culvert_session_revoke_unverifiable_total")
	if len(canon) != 1 || canon["culvert_session_revoke_unverifiable_total"] != wantUnverifiable {
		t.Errorf("culvert_session_revoke_unverifiable_total = %v; want exactly one unlabeled sample = %s", canon, wantUnverifiable)
	}

	// The released per-reason series and its canonical successor: the same
	// six fixed labels, the same values.
	for _, name := range []string{"culvert_session_revoke_rejected_total", "culvert_session_revoke_refusals_total"} {
		got := seriesOf(samples, name)
		if len(got) != len(want) {
			t.Errorf("%s has %d series %v; want the %d fixed reasons", name, len(got), got, len(want))
		}
		for reason, n := range want {
			key := fmt.Sprintf("%s{reason=%q}", name, string(reason))
			if got[key] != fmt.Sprint(n) {
				t.Errorf("%s = %q; want %d", key, got[key], n)
			}
		}
	}

	for _, name := range []string{
		"culvert_session_revoke_refused_total", "culvert_session_revoke_rejected_total",
		"culvert_session_revoke_unverifiable_total", "culvert_session_revoke_refusals_total",
	} {
		if types[name] != "counter" {
			t.Errorf("TYPE %s = %q; want counter", name, types[name])
		}
	}
	for alias, canonical := range map[string]string{
		"culvert_session_revoke_refused_total":  "culvert_session_revoke_unverifiable_total",
		"culvert_session_revoke_rejected_total": "culvert_session_revoke_refusals_total",
	} {
		if h := helps[alias]; !strings.Contains(h, "DEPRECATED alias of "+canonical) || !strings.Contains(h, "removed in v1.1.0") {
			t.Errorf("HELP %s = %q; must name %s and the v1.1.0 removal", alias, h, canonical)
		}
	}
}

// TestT70_SessionRevokeMetricAliasesAgreeAtZero pins that the aliases are
// always emitted, like their canonical names: a missing series reads as "no
// data", which silences an absent() alert as well as a rate() one.
func TestT70_SessionRevokeMetricAliasesAgreeAtZero(t *testing.T) {
	chaos73Setup(t)
	samples, _, _ := t70Scrape(t)
	for _, key := range []string{
		"culvert_session_revoke_refused_total", "culvert_session_revoke_unverifiable_total",
		`culvert_session_revoke_rejected_total{reason="unsigned"}`, `culvert_session_revoke_refusals_total{reason="unsigned"}`,
		`culvert_session_revoke_rejected_total{reason="far_future"}`, `culvert_session_revoke_refusals_total{reason="far_future"}`,
	} {
		if samples[key] != "0" {
			t.Errorf("%s = %q; want 0 with nothing refused", key, samples[key])
		}
	}
}
