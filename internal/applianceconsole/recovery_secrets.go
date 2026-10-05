package applianceconsole

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
)

// RecoverySecretKeys are the ONLY keys of the stack .env that the recovery
// reveal may print: the at-rest passphrases this appliance generated. Any
// other key (the setup token, future secrets) stays unreadable here by
// construction, not by a deny list.
var RecoverySecretKeys = []string{"CULVERT_CA_PASSPHRASE", "CULVERT_LOG_PASSPHRASE"}

// RecoverySecretGuidance is the custody explanation shown with the values,
// and (without them) on the first-boot screen. It never claims that the
// console password or the setup token can replace a passphrase.
var RecoverySecretGuidance = []string{
	"CULVERT_CA_PASSPHRASE decrypts this appliance's inspection CA (ca.bundle);",
	"CULVERT_LOG_PASSPHRASE decrypts its request history. On this appliance both",
	"were generated at installation and are stored only in /srv/culvert/.env.",
	"A backup archive does NOT contain them: to restore onto a new appliance you",
	"need the archive, these passphrases, and CULVERT_BACKUP_PASSPHRASE.",
	"CULVERT_BACKUP_PASSPHRASE (encrypts backup archives) is chosen by you and is",
	"not stored on the appliance, so it cannot be shown here.",
	"The console password and the setup token do NOT replace any of them.",
	"Record them in your organisation's secret store, never in a ticket or chat.",
}

// ErrNoRecoverySecrets means the stack .env names none of the passphrases.
var ErrNoRecoverySecrets = errors.New("no recovery passphrase found in the stack .env")

// RecoverySecretsText renders the custody guidance plus the allowlisted
// passphrases found in env (the stack .env content). Nothing else is read
// from env. A key that is absent or empty is reported as such, never guessed.
func RecoverySecretsText(env []byte) (string, error) {
	found := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(env))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		for _, allowed := range RecoverySecretKeys {
			if key == allowed && value != "" {
				found[key] = value // a later line wins, as when the file is sourced
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if len(found) == 0 {
		return "", ErrNoRecoverySecrets
	}
	var b strings.Builder
	b.WriteString("RECOVERY SECRETS — shown only on this authenticated console\n\n")
	for _, line := range RecoverySecretGuidance {
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")
	for _, key := range RecoverySecretKeys {
		value, ok := found[key]
		if !ok {
			value = "(not set in /srv/culvert/.env)"
		}
		b.WriteString(key + "=" + value + "\n")
	}
	if found[RecoverySecretKeys[0]] != "" && found[RecoverySecretKeys[0]] == found[RecoverySecretKeys[1]] {
		b.WriteString("\n(Both passphrases are the same value on this appliance.)\n")
	}
	return b.String(), nil
}
