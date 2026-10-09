package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAdminRosterPersistence(t *testing.T) {
	prev := cfg
	t.Cleanup(func() { cfg = prev })

	cfg = &Config{}
	if got := checkAdminRosterPersistence(); got.Status != diagOK {
		t.Fatalf("no accounts: want ok, got %s", got.Status)
	}

	if err := cfg.SetAuth("admin", "correct-horse-battery-1A!"); err != nil {
		t.Skipf("SetAuth: %v", err)
	}
	resetRosterPersistCountersForTest()
	got := checkAdminRosterPersistence()
	if got.Status != diagWarn || got.OperatorAction == "" || !strings.Contains(got.OperatorAction, "-ui-users-file") {
		t.Fatalf("no roster file: want warn with action, got %+v", got)
	}

	noteRosterNotDurable()
	if got := checkAdminRosterPersistence(); !strings.Contains(got.Message, "1 such change") {
		t.Fatalf("message should count in-memory changes, got %q", got.Message)
	}

	cfg.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	if got := checkAdminRosterPersistence(); got.Status != diagOK {
		t.Fatalf("roster file set: want ok, got %+v", got)
	}
	resetRosterPersistCountersForTest()
}
