package main

import "testing"

func TestCheckDataDirWriterPosture(t *testing.T) {
	prev, _ := dataDirWriterPosture.Load().(string)
	t.Cleanup(func() { dataDirWriterPosture.Store(prev) })
	cases := map[string]string{
		"":                       "",
		dataDirPostureOverride:   "datadir_multiple_writers_override",
		dataDirPostureUnverified: "datadir_writer_lock_unverified",
	}
	for state, want := range cases {
		dataDirWriterPosture.Store(state)
		got := checkDataDirWriterPosture()
		if want == "" {
			if len(got) != 0 {
				t.Fatalf("state %q: want no row, got %v", state, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Code != want || got[0].Status != diagWarn || got[0].OperatorAction == "" {
			t.Fatalf("state %q: got %+v, want one warn row %s", state, got, want)
		}
	}
}

func TestCheckDataDirSingleWriterRecordsPosture(t *testing.T) {
	withFreshWriterLockState(t)
	dir := t.TempDir()
	if err := checkDataDirSingleWriter(dir); err != nil {
		t.Fatal(err)
	}
	if s, _ := dataDirWriterPosture.Load().(string); s != "" {
		t.Fatalf("acquired lock must leave posture empty, got %q", s)
	}
}
