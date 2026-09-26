package main

import (
	"os"
	"strings"
	"testing"
)

// TestUIContract_BackupNowDefaultsToEncryption pins D1.5 invariant 6
// ("encrypted backups are the production default") on the GUI trigger: the
// dialog opens with Encrypt checked and the conventional passphrase variable
// prefilled, and submitting an unencrypted backup requires an explicit
// confirmation that names the dev/lab-only posture.
func TestUIContract_BackupNowDefaultsToEncryption(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	fnBody := func(sig string) string {
		i := strings.Index(s, sig)
		if i < 0 {
			t.Fatalf("%s not found", sig)
		}
		body := s[i:]
		end := strings.Index(body, "\n}\n")
		if end < 0 {
			t.Fatalf("%s body is not terminated", sig)
		}
		return body[:end]
	}
	open := fnBody("function backupNowOpen() {")
	for _, want := range []string{
		"getElementById('backup-now-encrypt').checked = true;",
		"getElementById('backup-now-passvar').value = 'CULVERT_BACKUP_PASSPHRASE';",
		"getElementById('backup-now-passlabel').style.display = '';",
	} {
		if !strings.Contains(open, want) {
			t.Errorf("backupNowOpen must default to an encrypted backup: missing %q", want)
		}
	}
	submit := fnBody("async function backupNowSubmit() {")
	if !strings.Contains(submit, "if (!encrypt && !await confirmAction(") || !strings.Contains(submit, "dev/lab only") {
		t.Error("backupNowSubmit must require an explicit dev/lab-only confirmation before an unencrypted backup")
	}
}
