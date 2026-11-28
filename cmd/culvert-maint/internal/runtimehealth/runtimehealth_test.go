package runtimehealth

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	imgA = "sha256:" + strings.Repeat("a", 64)
	imgB = "sha256:" + strings.Repeat("b", 64)
	ctrA = strings.Repeat("c", 64)
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st
}

func gatedSample(at time.Time) Sample {
	return Sample{State: StateGated, Reason: "gate_passed", ObservedAt: at, ContainerID: ctrA, ImageID: imgA, PinnedTagImageID: imgA, Detail: "200 OK"}
}

func goodRecord(at time.Time) LastGood {
	d := "sha256:" + strings.Repeat("d", 64)
	return LastGood{ImageID: imgA, Ref: "ghcr.io/kidcarmi/culvert@" + d, Digest: d, ContainerID: ctrA, PassedAt: at, Gate: GateRuntimeObserver}
}

func TestStore_AbsentFilesAreNoEvidence(t *testing.T) {
	st := openTemp(t)
	if smp, err := st.ReadLatest(); smp != nil || err != nil {
		t.Fatalf("ReadLatest on an empty store = %v, %v; want nil, nil", smp, err)
	}
	if lg, err := st.ReadLastGood(); lg != nil || err != nil {
		t.Fatalf("ReadLastGood on an empty store = %v, %v; want nil, nil", lg, err)
	}
}

func TestStore_RoundTrip(t *testing.T) {
	st := openTemp(t)
	at := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	if err := st.WriteLatest(gatedSample(at)); err != nil {
		t.Fatalf("WriteLatest: %v", err)
	}
	if err := st.WriteLastGood(goodRecord(at)); err != nil {
		t.Fatalf("WriteLastGood: %v", err)
	}
	smp, err := st.ReadLatest()
	if err != nil || smp == nil || smp.State != StateGated || smp.ImageID != imgA || !smp.ObservedAt.Equal(at) || smp.Schema != SchemaVersion {
		t.Fatalf("ReadLatest = %+v, %v", smp, err)
	}
	lg, err := st.ReadLastGood()
	if err != nil || lg == nil || lg.ImageID != imgA || lg.Gate != GateRuntimeObserver || !lg.PassedAt.Equal(at) {
		t.Fatalf("ReadLastGood = %+v, %v", lg, err)
	}
	// No temp file is left behind.
	ents, _ := os.ReadDir(st.Dir())
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temp file left in the store: %s", e.Name())
		}
	}
}

// The two files are separate: writing any observation never touches the
// last-known-good record.
func TestStore_LatestNeverTouchesLastGood(t *testing.T) {
	st := openTemp(t)
	at := time.Now().UTC()
	if err := st.WriteLastGood(goodRecord(at)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(st.Dir(), lastGoodName))
	for _, smp := range []Sample{
		{State: StateUnhealthy, Reason: "not_ready", ObservedAt: at, ContainerID: ctrA, ImageID: imgB},
		{State: StateUnknown, Reason: "docker_unreadable", ObservedAt: at},
		{State: StateUnhealthy, Reason: "no_proxy_container", ObservedAt: at},
	} {
		if err := st.WriteLatest(smp); err != nil {
			t.Fatalf("WriteLatest(%s): %v", smp.Reason, err)
		}
	}
	after, _ := os.ReadFile(filepath.Join(st.Dir(), lastGoodName))
	if !bytes.Equal(before, after) {
		t.Fatalf("last_good.json changed:\nbefore %s\nafter  %s", before, after)
	}
}

func TestStore_RefusesWhatTheObserverDoesNotWrite(t *testing.T) {
	st := openTemp(t)
	at := time.Now().UTC()
	bad := map[string]Sample{
		"ungated is derived, never written": {State: StateUngated, Reason: "x", ObservedAt: at},
		"stale is derived, never written":   {State: StateStale, Reason: "x", ObservedAt: at},
		"gated without identity":            {State: StateGated, Reason: "gate_passed", ObservedAt: at},
		"no time":                           {State: StateUnknown, Reason: "x"},
		"reason not in the closed shape":    {State: StateUnknown, Reason: "Not Ready!", ObservedAt: at},
		"malformed image id":                {State: StateUnhealthy, Reason: "x", ObservedAt: at, ImageID: "sha256:zz"},
	}
	for name, smp := range bad {
		if err := st.WriteLatest(smp); err == nil {
			t.Errorf("%s: WriteLatest accepted %+v", name, smp)
		}
	}
	good := goodRecord(at)
	badGood := map[string]func(*LastGood){
		"ref without its digest": func(l *LastGood) { l.Ref = "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("e", 64) },
		"unknown gate":           func(l *LastGood) { l.Gate = "upgrade" },
		"no container":           func(l *LastGood) { l.ContainerID = "" },
		"no time":                func(l *LastGood) { l.PassedAt = time.Time{} },
		"malformed image":        func(l *LastGood) { l.ImageID = "a" },
	}
	for name, mut := range badGood {
		lg := good
		mut(&lg)
		if err := st.WriteLastGood(lg); err == nil {
			t.Errorf("%s: WriteLastGood accepted %+v", name, lg)
		}
	}
	if _, err := os.Stat(filepath.Join(st.Dir(), latestName)); !os.IsNotExist(err) {
		t.Fatalf("a refused sample was written: %v", err)
	}
}

func TestStore_ReadRefusesUntrustedFiles(t *testing.T) {
	cases := map[string]string{
		"unknown schema":   `{"schema":2,"state":"gated","reason":"gate_passed","observed_at":"2026-11-27T10:00:00Z","container_id":"` + ctrA + `","image_id":"` + imgA + `"}`,
		"unknown field":    `{"schema":1,"state":"unknown","reason":"x","observed_at":"2026-11-27T10:00:00Z","extra":1}`,
		"derived state":    `{"schema":1,"state":"stale","reason":"x","observed_at":"2026-11-27T10:00:00Z"}`,
		"not json":         `gated`,
		"larger than many": `{"schema":1,"state":"unknown","reason":"x","observed_at":"2026-11-27T10:00:00Z","detail":"` + strings.Repeat("x", maxFileBytes) + `"}`,
	}
	for name, body := range cases {
		st := openTemp(t)
		if err := os.WriteFile(filepath.Join(st.Dir(), latestName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if smp, err := st.ReadLatest(); err == nil {
			t.Errorf("%s: ReadLatest = %+v, want an error", name, smp)
		}
	}
}

func TestClassify(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	stale := 15 * time.Minute
	fresh := gatedSample(now.Add(-time.Minute))
	unhealthy := Sample{State: StateUnhealthy, Reason: "not_ready", ObservedAt: now.Add(-time.Minute), ContainerID: ctrA, ImageID: imgA}
	down := Sample{State: StateUnhealthy, Reason: "no_proxy_container", ObservedAt: now.Add(-time.Minute)}
	old := gatedSample(now.Add(-time.Hour))
	future := gatedSample(now.Add(time.Hour))
	cases := []struct {
		name    string
		smp     *Sample
		running string
		want    string
	}{
		{"no sample, something runs", nil, imgA, StateUngated},
		{"no sample, nothing known to run", nil, "", StateUnknown},
		{"gated, same image", &fresh, imgA, StateGated},
		{"gated, running image unknown", &fresh, "", StateGated},
		{"gated, another image runs now (a late upgrade or a hand retag)", &fresh, imgB, StateUngated},
		{"unhealthy, same image", &unhealthy, imgA, StateUnhealthy},
		{"stack down, nothing runs", &down, "", StateUnhealthy},
		{"stack down, something runs now", &down, imgA, StateUngated},
		{"too old", &old, imgA, StateStale},
		{"dated in the future", &future, imgA, StateStale},
	}
	for _, c := range cases {
		if got, _ := Classify(c.smp, c.running, now, stale); got != c.want {
			t.Errorf("%s: Classify = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestBound(t *testing.T) {
	long := strings.Repeat("é", MaxDetail)
	got := Bound(long)
	if len(got) > MaxDetail || !strings.HasPrefix(long, got) {
		t.Fatalf("Bound cut %d bytes badly", len(got))
	}
	if Bound("a\nb\x00c") != "a b c" {
		t.Fatalf("Bound kept control characters: %q", Bound("a\nb\x00c"))
	}
}
