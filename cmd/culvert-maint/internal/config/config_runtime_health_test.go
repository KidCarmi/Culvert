package config

import (
	"testing"
	"time"
)

func TestParseRuntimeHealthInterval(t *testing.T) {
	ok := map[string]time.Duration{"": 0, "0s": 0, "0": 0, "1m": time.Minute, "5m": 5 * time.Minute, "24h": 24 * time.Hour}
	for in, want := range ok {
		got, err := parseRuntimeHealthInterval(in)
		if err != nil || got != want {
			t.Errorf("%q = %s, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"30s", "59s", "25h", "-1m", "soon", "1"} {
		if got, err := parseRuntimeHealthInterval(in); err == nil {
			t.Errorf("%q accepted as %s", in, got)
		}
	}
}

func TestLoad_RuntimeHealthIntervalDefaultsOff(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalValid))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RuntimeHealthInterval != 0 {
		t.Fatalf("default runtime_health_interval = %s, want off", cfg.RuntimeHealthInterval)
	}
	cfg, err = Load(writeConfig(t, minimalValid+"\nruntime_health_interval = \"5m\""))
	if err != nil || cfg.RuntimeHealthInterval != 5*time.Minute {
		t.Fatalf("runtime_health_interval = \"5m\" loaded as %v, %v", cfg, err)
	}
	if _, err := Load(writeConfig(t, minimalValid+"\nruntime_health_interval = \"10s\"")); err == nil {
		t.Fatal("a 10s interval was accepted")
	}
}
