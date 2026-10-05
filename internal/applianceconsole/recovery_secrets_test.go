package applianceconsole

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const testStackEnv = "CULVERT_SETUP_TOKEN=0123456789abcdef0123456789abcdef\n" +
	"CULVERT_CA_PASSPHRASE=CaPassphraseValue1234567890abcdefghijklmn\n" +
	"CULVERT_LOG_PASSPHRASE=CaPassphraseValue1234567890abcdefghijklmn\n" +
	"OTHER_SECRET=must-never-appear\n"

func TestRecoverySecretsTextShowsOnlyTheAllowlistedPassphrases(t *testing.T) {
	text, err := RecoverySecretsText([]byte(testStackEnv))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CULVERT_CA_PASSPHRASE=CaPassphraseValue1234567890abcdefghijklmn", "CULVERT_LOG_PASSPHRASE=CaPassphraseValue1234567890abcdefghijklmn", "same value"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	for _, never := range []string{"0123456789abcdef0123456789abcdef", "must-never-appear", "CULVERT_SETUP_TOKEN", "OTHER_SECRET"} {
		if strings.Contains(text, never) {
			t.Errorf("reveal leaked %q", never)
		}
	}
}

func TestRecoverySecretGuidanceStatesCustodyHonestly(t *testing.T) {
	g := strings.Join(RecoverySecretGuidance, " ")
	for _, want := range []string{"CULVERT_BACKUP_PASSPHRASE", "not stored on the appliance", "do NOT replace", "A backup archive does NOT contain them"} {
		if !strings.Contains(g, want) {
			t.Errorf("guidance must say %q", want)
		}
	}
}

func TestRecoverySecretsTextReportsAbsenceWithoutGuessing(t *testing.T) {
	if _, err := RecoverySecretsText([]byte("CULVERT_SETUP_TOKEN=x\nCULVERT_CA_PASSPHRASE=\n")); !errors.Is(err, ErrNoRecoverySecrets) {
		t.Fatalf("no passphrase present: %v", err)
	}
	text, err := RecoverySecretsText([]byte("CULVERT_CA_PASSPHRASE=onlyCA\n"))
	if err != nil || !strings.Contains(text, "CULVERT_LOG_PASSPHRASE=(not set in /srv/culvert/.env)") || strings.Contains(text, "same value") {
		t.Fatalf("a missing key must be reported as missing: %v\n%s", err, text)
	}
}

func TestRecoverySecretsActionAsksForThePasswordAgain(t *testing.T) {
	a, calls := actionFixture()
	if err := a.Apply(context.Background(), "8"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"/usr/bin/sudo", "-k", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=recovery-secrets"}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("dispatched %v, want %v", *calls, want)
	}
	v := NewView(false)
	v.screen = "recovery"
	if got := v.Handle("4"); got != "login" {
		t.Fatalf("unauthenticated reveal dispatched %q", got)
	}
}
