package main

import (
	"flag"
	"fmt"
	"strings"
)

// argv_guard.go — CHAOS-122. The argv contract of the binary.
//
// Go's flag package stops parsing at the FIRST token that does not begin with
// "-" and leaves that token and EVERY token after it in flag.Args(). main's
// flag.Parse() had no flag.NArg() guard and handleOneShotCommands dispatches on
// FLAGS only, so an argv carrying an unparsed token was not an error: the
// process fell through into normal startup with every flag AFTER that token at
// its zero default, and reported healthy.
//
// CHAOS-121 found that class through one instance of it — the image declares an
// exec-form ENTRYPOINT ["./culvert"] and Docker APPENDS a container command to
// an exec-form entrypoint, so docker-compose.ha.yml's `command: sh -c '…'` made
// the real argv `./culvert sh -c '<script>'` and discarded every flag the file
// declared. That round fixed the artifact and recorded the generic guard as its
// own change, because it needs an audit of every invocation shape rather than a
// one-line flag.NArg() check. This is that guard.
//
// # Why the artifact gate is not enough
//
// TestChaos121_ComposeCommandReachesTheBinaryAsFlags asserts the property
// statically over the compose files it discovers. That is the right gate for
// those files and it does not hold for an orchestrator the repository does not
// ship: a systemd unit, a Kubernetes manifest, a hand-written `docker run`, or
// an operator pasting a documented command line into a `command:` key. The
// binary is the only place the contract can be enforced for all of them.
//
// # What the silent boot actually costs
//
// The partial case is sharper than the total one, because the surface still
// looks configured. Measured on the real binary at this revision with
// `-port 18080 -ui-port 19090 STRAY -policy <file> -audit-log <file>
// -ca-path <file>`:
//
//   - the ports BEFORE the stray token applied, so the proxy and admin UI came
//     up where the operator expected them and /health returned
//     {"status":"ok", …, "ssl_inspection":"ready", "admin_ui":"ready"};
//   - every flag AFTER it was discarded: no policy file, no audit log and no
//     persisted Root CA were created;
//   - the startup default action was "allow" instead of the "deny" the same
//     argv without the stray token produced, which is the documented
//     configured-vs-empty policy rule (docs/agent-context/errata.md): a
//     configured policy file with zero usable rules denies, an absent one
//     allows. So discarding -policy does not merely lose rules, it inverts the
//     posture;
//   - the stray token was never named in any log line, on stdout, or on stderr.
//
// The per-subsystem degradation IS logged ("Policy: in-memory only", "SSLCA:
// Root CA ready in-memory"), which is why this is a legibility failure rather
// than a dark one: those lines are identical to the ones a deliberately
// minimal deployment emits, so they cannot distinguish "the operator did not
// set -policy" from "the orchestrator discarded the operator's -policy".
//
// # The one shape that legitimately carries a positional operand
//
// The audit behind this guard found exactly two positional consumers in the
// shipped surface, and only one of them reaches this point:
//
//   - `culvert bootstrap-resolve …` (bootstrap_resolve.go) is a subcommand
//     dispatched from maybeRunBootstrapResolve BEFORE the global flag set is
//     defined, and it os.Exits. It never reaches flag.Parse, so this guard
//     neither sees nor affects it. (It has the same defect inside its own
//     FlagSet; that is fixed there.)
//   - `culvert --prepare-downgrade … --confirm <word>` reads flag.Args() in
//     runPrepareDowngradeCommand to recover the Tier-3 confirmation word,
//     because --confirm is an IsBoolFlag and therefore does not consume the
//     following token. prepareDowngradeConfirmWord already rejects an
//     unexpected tail itself, so this guard defers to it rather than
//     duplicating a second, weaker check.
//
// Everything else in the tree passes flags only: the Dockerfile CMD, every
// compose `command:` (the `cli` service's ["-h"] included), the maintenance
// agent's compose-run templates (cmd/culvert-maint/internal/runner,
// `--restore <path>` / bare `--confirm`), scripts/install.sh and the operator
// runbooks.
//
// # Deliberate behaviour change
//
// `--restore <archive> --confirm <word>` previously committed the restore and
// silently ignored <word>; it is now refused. That is intentional: an operator
// who typed a word meant it, and committing a restore while discarding part of
// the argv is the failure mode this file exists to remove. The documented
// restore commit form is a bare `--confirm`, which is unaffected, as is the
// maintenance agent, which appends a bare `--confirm`.
//
// The refusal runs BEFORE handleOneShotCommands and therefore before
// checkInterruptedRestore, checkDataDirSingleWriter and anything that writes to
// the persisted-state root: a rejected argv changes nothing on disk.

// errPositionalArgs is the refusal returned for an argv main cannot parse.
// It is a distinct type so tests can assert the refusal rather than a string.
type errPositionalArgs struct {
	args []string
}

func (e *errPositionalArgs) Error() string {
	// argv is operator-supplied and reaches stderr, so it goes through the
	// CWE-117 barrier and is printed with %q (docs/agent-context/conventions.md).
	// Only the first token and the NAMES of the discarded flags are echoed: the
	// tail can carry credential flags (-pass, -metrics-token, …) and stderr is
	// collected by every orchestrator, so their values must not be printed.
	first := sanitizeLog(e.args[0])
	rest := sanitizeLog(redactArgValues(e.args[1:]))
	return fmt.Sprintf("refusing to start: %d unparsed command-line argument(s) beginning with %q (discarded after it, values redacted: %q). "+
		"Go's flag package stops at the first argument that does not begin with \"-\", so EVERY flag after it was "+
		"discarded — which would have started this process with those settings at their defaults (no persisted Root "+
		"CA, no policy file, no audit log) while still reporting healthy. Nothing was started and nothing on disk was "+
		"changed. The usual cause is a container command handed to the image's exec-form ENTRYPOINT [\"./culvert\"], "+
		"which Docker APPENDS rather than replaces: a service that needs a shell must put it in `entrypoint:` and "+
		"`exec ./culvert` from there, so culvert is still PID 1 and still receives SIGTERM. CHAOS-122",
		len(e.args), first, rest)
}

// redactArgValues keeps each flag NAME in an argv tail and replaces every value
// — a token that is not a flag, or the part of `-flag=value` after "=" — with
// <value>. The names alone say which settings were discarded; a value may be a
// password or token.
func redactArgValues(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) < 2 || a[0] != '-' {
			out = append(out, "<value>")
			continue
		}
		if name, _, ok := strings.Cut(a, "="); ok {
			a = name + "=<value>"
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}

// refusePositionalArgs reports an argv that flag.Parse could not fully consume.
//
// prepareDowngrade is *startupState.prepareDowngrade: that one-shot owns its
// positional operand and validates its own tail (prepareDowngradeConfirmWord),
// so it is the single exception. args is flag.Args() — the tokens flag.Parse
// left unconsumed.
func refusePositionalArgs(prepareDowngrade bool, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if prepareDowngrade {
		return nil
	}
	return &errPositionalArgs{args: args}
}

// checkPositionalArgs is the main() seam: it reads the real global flag set.
func checkPositionalArgs(s *startupState) error {
	return refusePositionalArgs(*s.prepareDowngrade, flag.Args())
}
