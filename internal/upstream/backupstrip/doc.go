// Package backupstrip sanitizes an admin_settings.json body before it is
// archived (ADR-0043). It removes every sealed upstream credential, marks the
// entry requiresReplacement, and refuses (fail-closed) any body whose shape it
// cannot sanitize with certainty. It holds no mutable state, performs no I/O
// and does no logging. Package main (backup.go, restore.go) owns reading the
// file, the manifest, the audit trail and the user-visible messages; this
// package owns only the byte transformation and the restore dry-run count.
package backupstrip
