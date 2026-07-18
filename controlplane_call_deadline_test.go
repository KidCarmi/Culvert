package main

// controlplane_call_deadline_test.go — P1 #4: the config-poll deadline must
// scale with the snapshot size so a large config on a thin WAN link does not
// time out and trip spurious failover, while the small RPCs stay tight.

import (
	"testing"
	"time"
)

func TestScaledConfigDeadline(t *testing.T) {
	const mib = int64(1) << 20
	cases := []struct {
		bytes int64
		want  time.Duration
		note  string
	}{
		{0, dpConfigBaseDeadline, "no history → base only"},
		{60 * mib, dpConfigBaseDeadline + 120*time.Second, "60 MiB @ 512 KiB/s ≈ +120s"},
		{4 * mib, dpConfigBaseDeadline + 8*time.Second, "4 MiB ≈ +8s"},
		{1 << 30, dpConfigMaxDeadline, "1 GiB clamps to the ceiling"},
	}
	for _, c := range cases {
		if got := scaledConfigDeadline(c.bytes); got != c.want {
			t.Errorf("scaledConfigDeadline(%d) = %v, want %v — %s", c.bytes, got, c.want, c.note)
		}
	}
}

func TestCallDeadline_SnapshotRPCsScale_OthersTight(t *testing.T) {
	dpLastFullSnapshotBytes.Store(60 << 20) // 60 MiB
	t.Cleanup(func() { dpLastFullSnapshotBytes.Store(0) })

	// Snapshot-carrying RPCs scale up.
	for _, m := range []string{methodGetConfig, methodHASync} {
		if got := callDeadline(m); got <= dpTightCallDeadline {
			t.Errorf("callDeadline(%s) = %v, want a scaled (large) deadline", m, got)
		}
	}
	// Everything else stays tight.
	for _, m := range []string{methodPushMetrics, methodSyncRateLimits, methodEnroll, methodRenewCert} {
		if got := callDeadline(m); got != dpTightCallDeadline {
			t.Errorf("callDeadline(%s) = %v, want the tight %v", m, got, dpTightCallDeadline)
		}
	}
}
