package config

import "testing"

func TestLoad_RuntimeRecovery(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalValid))
	if err != nil || cfg.RuntimeRecovery != RecoveryOff {
		t.Fatalf("default runtime_recovery = %q, %v; want off", cfg.RuntimeRecovery, err)
	}
	on := minimalValid + "\nruntime_health_interval = \"1m\"\nruntime_recovery = \"restore_last_gated\""
	if cfg, err = Load(writeConfig(t, on)); err != nil || cfg.RuntimeRecovery != RecoveryRestoreLastGated {
		t.Fatalf("restore_last_gated loaded as %q, %v", cfg.RuntimeRecovery, err)
	}
	if cfg, err = Load(writeConfig(t, minimalValid+"\nruntime_recovery = \"off\"")); err != nil || cfg.RuntimeRecovery != RecoveryOff {
		t.Fatalf("off loaded as %q, %v", cfg.RuntimeRecovery, err)
	}
	for name, body := range map[string]string{
		"without the observer": minimalValid + "\nruntime_recovery = \"restore_last_gated\"",
		"observer off":         minimalValid + "\nruntime_health_interval = \"0s\"\nruntime_recovery = \"restore_last_gated\"",
		"unknown mode":         minimalValid + "\nruntime_health_interval = \"1m\"\nruntime_recovery = \"restore_any\"",
		"wrong case":           minimalValid + "\nruntime_health_interval = \"1m\"\nruntime_recovery = \"Restore_Last_Gated\"",
	} {
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
