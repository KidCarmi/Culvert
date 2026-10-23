package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
)

// stackEnvPath is the root-owned (0600) stack environment install.sh writes.
const stackEnvPath = "/srv/culvert/.env"

// showRecoverySecrets prints the at-rest recovery passphrases to the
// authenticated terminal ONLY (root, reached through `sudo -k`, so the
// operator's password was asked again), then waits and clears the screen and
// its scrollback. The value is never logged, audited or written anywhere
// else; the audit trail records only that recovery_secrets ran.
func showRecoverySecrets(in io.Reader, out io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("recovery secrets require root")
	}
	env, err := os.ReadFile(stackEnvPath)
	if err != nil {
		return fmt.Errorf("read the stack environment: %w", err)
	}
	return revealRecoverySecrets(env, in, out)
}

func revealRecoverySecrets(env []byte, in io.Reader, out io.Writer) error {
	text, err := applianceconsole.RecoverySecretsText(env)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(out, text+"\nPress Enter to clear the screen and return. "); err != nil {
		return err
	}
	_, _ = bufio.NewReader(in).ReadString('\n')
	// Clear the screen AND the scrollback, so the values do not stay on a
	// console someone else may look at later.
	_, err = io.WriteString(out, "\x1b[2J\x1b[3J\x1b[H")
	return err
}
