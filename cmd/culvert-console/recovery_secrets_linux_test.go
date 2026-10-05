package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRevealClearsTheScreenAndScrollbackAfterEnter(t *testing.T) {
	var out bytes.Buffer
	if err := revealRecoverySecrets([]byte("CULVERT_CA_PASSPHRASE=abc\nCULVERT_LOG_PASSPHRASE=abc\n"), strings.NewReader("\n"), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	at := strings.Index(s, "CULVERT_CA_PASSPHRASE=abc")
	cleared := strings.LastIndex(s, "\x1b[2J\x1b[3J\x1b[H")
	if at < 0 || cleared < at || !strings.HasSuffix(s, "\x1b[2J\x1b[3J\x1b[H") {
		t.Fatalf("the values must be followed by a screen + scrollback clear:\n%q", s)
	}
}

func TestShowRecoverySecretsRefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if err := showRecoverySecrets(strings.NewReader("\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("a non-root caller must be refused")
	}
}
