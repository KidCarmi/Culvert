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

// The Backup Now form is a dialog whose open state initializes the encrypted
// defaults. If it carried data-min-role, applySession's role loop would set
// display=” on every admin login and reveal it uninitialized (Encrypt
// unchecked, passphrase empty). It must not carry the attribute, and a
// session change must close it.
func TestUIContract_BackupNowFormIsNotRevealedByRoleFiltering(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	i := strings.Index(s, `<div id="support-backup-trigger"`)
	if i < 0 {
		t.Fatal("support-backup-trigger not found")
	}
	tag := s[i:]
	end := strings.Index(tag, ">")
	if end < 0 {
		t.Fatal("support-backup-trigger opening tag is not terminated")
	}
	tag = tag[:end]
	if strings.Contains(tag, "data-min-role") {
		t.Error("support-backup-trigger must not carry data-min-role: applySession would reveal it before backupNowOpen initializes it")
	}
	j := strings.Index(s, "function applySession(")
	if j < 0 {
		t.Fatal("applySession not found")
	}
	body := s[j:]
	if k := strings.Index(body, "\n}\n"); k >= 0 {
		body = body[:k]
	}
	if !strings.Contains(body, "getElementById('support-backup-trigger')") || !strings.Contains(body, "backupTrigger.style.display = 'none'") {
		t.Error("applySession must close the Backup Now form on every session change")
	}
}

// The agent's operation_timeout defaults to 30 minutes, so a legitimate
// backup can outlive the GUI's 10-minute poll deadline. Giving up must keep
// the operation id, and the Refresh button must resume the status poll, so a
// later failure or cancellation is still reported instead of being lost.
func TestUIContract_BackupNowPollIsResumableAfterDeadline(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	for _, want := range []string{
		"let backupNowPendingOp = null;",
		"function backupNowResumePoll() {",
		"case 'loadBackups':            loadBackups(); backupNowResumePoll(); break;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("index.html must keep an abandoned backup op resumable: missing %q", want)
		}
	}
	i := strings.Index(s, "function backupNowPollStart(")
	if i < 0 {
		t.Fatal("backupNowPollStart not found")
	}
	body := s[i:]
	if k := strings.Index(body, "\n}\n"); k >= 0 {
		body = body[:k]
	}
	if !strings.Contains(body, "backupNowPendingOp = { opId, filename };") {
		t.Error("backupNowPollStart must retain the op id so the poll can be resumed")
	}
	if strings.Count(body, "if (gen !== backupNowPollGen) return;") < 2 {
		t.Error("a superseded poll loop must stop after both the error and the success paths of its request")
	}
	if strings.Count(body, "backupNowPendingOp = null;") < 2 {
		t.Error("backupNowPollStart must drop the retained op id on both terminal branches")
	}
}
