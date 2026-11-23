package config

import "testing"

// reconcile_on_startup (AGT-900, owner decision 1): default "off" (today's
// report-only behaviour); "converge" accepted; anything else, including an
// adopt-anything mode this build does not implement, fails Load.
func TestLoad_ReconcileOnStartup(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalValid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ReconcileOnStartup != ReconcileOff {
		t.Errorf("default reconcile_on_startup = %q, want off", cfg.ReconcileOnStartup)
	}
	for val, want := range map[string]ReconcileMode{"off": ReconcileOff, "converge": ReconcileConverge, "": ReconcileOff} {
		cfg, err := Load(writeConfig(t, minimalValid+"\nreconcile_on_startup = \""+val+"\""))
		if err != nil || cfg.ReconcileOnStartup != want {
			t.Errorf("reconcile_on_startup %q: got %+v err=%v, want %q", val, cfg, err, want)
		}
	}
	for _, val := range []string{"converge_adopt", "on", "true", "Converge", " converge", "adopt"} {
		if _, err := Load(writeConfig(t, minimalValid+"\nreconcile_on_startup = \""+val+"\"")); err == nil {
			t.Errorf("reconcile_on_startup %q accepted, want rejection", val)
		}
	}
	if _, err := Load(writeConfig(t, minimalValid+"\nreconcile_on_startup = true")); err == nil {
		t.Error("a boolean reconcile_on_startup was accepted")
	}
}
