package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func swapCfgForRosterDurability(t *testing.T, c *Config) {
	t.Helper()
	prev := cfg
	cfg = c
	t.Cleanup(func() { cfg = prev })
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
}

func TestCheckAdminRosterDurability_WarnsWhenMemoryOnly(t *testing.T) {
	c := &Config{}
	if err := c.SetAuth("admin", "Or1ginalPass!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	swapCfgForRosterDurability(t, c)
	noteRosterNotDurable()

	got := checkAdminRosterDurability()
	if got.Code != "admin_roster_durability" || got.Status != diagWarn {
		t.Fatalf("got %+v, want warn admin_roster_durability", got)
	}
	if !strings.Contains(got.Message, "LOST on restart") || !strings.Contains(got.Message, "1 such change") {
		t.Errorf("message = %q, want loss statement and change count", got.Message)
	}
	if !strings.Contains(got.OperatorAction, "-ui-users-file") {
		t.Errorf("operator_action = %q, want remedy naming -ui-users-file", got.OperatorAction)
	}
}

func TestCheckAdminRosterDurability_OKWhenPersistedOrNoAccounts(t *testing.T) {
	persisted := &Config{}
	if err := persisted.SetAuth("admin", "Or1ginalPass!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	persisted.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	swapCfgForRosterDurability(t, persisted)
	if got := checkAdminRosterDurability(); got.Status != diagOK {
		t.Errorf("persisted roster: status = %q, want ok", got.Status)
	}

	cfg = &Config{} // no credentials, no roster: nothing to lose
	if got := checkAdminRosterDurability(); got.Status != diagOK {
		t.Errorf("no accounts: status = %q, want ok", got.Status)
	}
}
