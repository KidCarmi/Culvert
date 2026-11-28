package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/runtimehealth"
	"culvert-maint/internal/server"
)

var (
	rhImg   = "sha256:" + strings.Repeat("1", 64)
	rhOther = "sha256:" + strings.Repeat("2", 64)
	rhCtr   = strings.Repeat("c", 64)
	rhDig   = "sha256:" + strings.Repeat("9", 64)
)

func rhProvider(t *testing.T) (*Provider, *runtimehealth.Store, time.Time) {
	t.Helper()
	st, err := runtimehealth.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p := (&Provider{}).WithRuntimeHealth(st, 5*time.Minute)
	p.now = func() time.Time { return now }
	return p, st, now
}

func TestRuntimeHealth_AbsentWhenOff(t *testing.T) {
	var st server.Status
	(&Provider{}).addRuntimeHealth(&st)
	if st.RuntimeHealth != nil {
		t.Fatalf("runtime_health reported with the observer off: %+v", st.RuntimeHealth)
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), "runtime_health") {
		t.Fatalf("the off payload changed: %s", b)
	}
}

func TestRuntimeHealth_StatesAgainstTheRunningImage(t *testing.T) {
	p, store, now := rhProvider(t)
	if err := store.WriteLatest(runtimehealth.Sample{State: runtimehealth.StateGated, Reason: "gate_passed", ObservedAt: now.Add(-time.Minute), ContainerID: rhCtr, ImageID: rhImg}); err != nil {
		t.Fatal(err)
	}
	for running, want := range map[string]string{rhImg: runtimehealth.StateGated, rhOther: runtimehealth.StateUngated, "": runtimehealth.StateGated} {
		st := server.Status{}
		if running != "" {
			st.RunningImage = &server.RunningImage{ImageID: running}
		}
		p.addRuntimeHealth(&st)
		if st.RuntimeHealth == nil || st.RuntimeHealth.State != want || st.RuntimeHealth.IntervalSeconds != 300 {
			t.Fatalf("running %q: runtime_health = %+v, want %s", running, st.RuntimeHealth, want)
		}
	}
	p.now = func() time.Time { return now.Add(time.Hour) }
	st := server.Status{RunningImage: &server.RunningImage{ImageID: rhImg}}
	p.addRuntimeHealth(&st)
	if st.RuntimeHealth.State != runtimehealth.StateStale {
		t.Fatalf("an hour-old sample at a 5m interval = %s, want stale", st.RuntimeHealth.State)
	}
}

// The status never carries a container id (only content digests and image ids).
func TestRuntimeHealth_NoContainerID(t *testing.T) {
	p, store, now := rhProvider(t)
	_ = store.WriteLatest(runtimehealth.Sample{State: runtimehealth.StateGated, Reason: "gate_passed", ObservedAt: now, ContainerID: rhCtr, ImageID: rhImg})
	_ = store.WriteLastGood(runtimehealth.LastGood{ImageID: rhImg, Ref: "ghcr.io/kidcarmi/culvert@" + rhDig, Digest: rhDig, ContainerID: rhCtr, PassedAt: now, Gate: runtimehealth.GateRuntimeObserver})
	st := server.Status{}
	p.addRuntimeHealth(&st)
	b, _ := json.Marshal(st.RuntimeHealth)
	if strings.Contains(string(b), rhCtr) {
		t.Fatalf("runtime_health carries the container id: %s", b)
	}
	if st.RuntimeHealth.LastGood == nil || st.RuntimeHealth.LastGood.Digest != rhDig {
		t.Fatalf("last_good not reported: %s", b)
	}
}

func TestRuntimeHealth_UnreadableEvidenceIsUnknown(t *testing.T) {
	p, store, _ := rhProvider(t)
	for _, name := range []string{"latest.json", "last_good.json"} {
		if err := os.WriteFile(filepath.Join(store.Dir(), name), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st := server.Status{RunningImage: &server.RunningImage{ImageID: rhImg}}
	p.addRuntimeHealth(&st)
	rh := st.RuntimeHealth
	if rh.State != runtimehealth.StateUnknown || rh.Error == "" || rh.LastGood != nil || rh.LastGoodError == "" {
		t.Fatalf("unreadable evidence reported as %+v", rh)
	}
}
