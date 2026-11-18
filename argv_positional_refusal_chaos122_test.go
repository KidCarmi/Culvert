package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// argv_positional_refusal_chaos122_test.go — CHAOS-122.
//
// Gates over the argv contract described in argv_guard.go: an argv the flag
// package cannot fully consume must be REFUSED, loudly, before anything is
// started or written, rather than booting the gateway with every flag after the
// unparsed token at its default while /health reports ok.
//
// The pre-fix behaviour these gates pin was measured on the real binary, not
// inferred: `-port 18080 -ui-port 19090 STRAY -policy <f> -audit-log <f>
// -ca-path <f>` came up on 18080/19090 with /health ok, created none of the
// three files, logged "Policy: default action: allow" where the same argv
// without STRAY logged "deny", and never named STRAY anywhere.

// ─── Unit: the refusal decision, including its one exception ──────────────────

func TestChaos122_RefusePositionalArgs(t *testing.T) {
	cases := []struct {
		name             string
		prepareDowngrade bool
		args             []string
		wantRefusal      bool
	}{
		{name: "no tail is the normal startup argv", args: nil, wantRefusal: false},
		{name: "empty tail", args: []string{}, wantRefusal: false},
		{
			// CHAOS-121a's exact shape: Docker appends the service command to
			// the image's exec-form ENTRYPOINT ["./culvert"].
			name:        "the shell-command shape that discards every flag",
			args:        []string{"sh", "-c", `ARGS="-port 8080 -ca-path /data/ca.bundle"; exec ./culvert $ARGS`},
			wantRefusal: true,
		},
		{
			// The sharper partial case: the ports applied, the security flags
			// after the stray token did not.
			name:        "a single stray token mid-argv",
			args:        []string{"STRAY", "-policy", "/data/policy.json", "-audit-log", "/data/audit.jsonl"},
			wantRefusal: true,
		},
		{
			// `culvert bootstrapresolve …` (a typo of the real subcommand) used
			// to start a full proxy + admin UI instead of failing.
			name:        "a mistyped subcommand",
			args:        []string{"bootstrapresolve", "--channel", "stable"},
			wantRefusal: true,
		},
		{
			// The ONE shipped shape that owns a positional operand: --confirm
			// is an IsBoolFlag, so the Tier-3 word lands in flag.Args() and
			// prepareDowngradeConfirmWord recovers it.
			name:             "prepare-downgrade keeps its confirmation word",
			prepareDowngrade: true,
			args:             []string{"the-word"},
			wantRefusal:      false,
		},
		{
			// Negative control for the exception: the guard must DEFER to the
			// one-shot's own validator rather than second-guess it, so an
			// over-long tail is not this guard's refusal. prepareDowngradeConfirmWord
			// rejects it (asserted separately below), which is the point: one
			// owner for that tail, not two.
			name:             "prepare-downgrade defers an over-long tail to its own validator",
			prepareDowngrade: true,
			args:             []string{"word", "junk"},
			wantRefusal:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := refusePositionalArgs(tc.prepareDowngrade, tc.args)
			if tc.wantRefusal && err == nil {
				t.Fatalf("argv tail %q must be refused; it would discard every flag after %q", tc.args, tc.args[0])
			}
			if !tc.wantRefusal && err != nil {
				t.Fatalf("argv tail %q must be accepted; got refusal: %v", tc.args, err)
			}
		})
	}
}

// TestChaos122_PrepareDowngradeStillOwnsItsTail is the other half of the
// deferral above: the guard is only correct to stand aside because this
// validator does reject an unexpected tail. If that ever stops being true the
// exception becomes a hole, so it is pinned here rather than assumed.
func TestChaos122_PrepareDowngradeStillOwnsItsTail(t *testing.T) {
	c := &confirmFlag{}
	if err := c.Set("true"); err != nil { // the bare `--confirm` form
		t.Fatalf("set confirm: %v", err)
	}
	if _, err := prepareDowngradeConfirmWord(c, []string{"word", "junk"}); err == nil {
		t.Fatal("prepareDowngradeConfirmWord must reject an over-long tail; the argv guard defers to it")
	}
	word, err := prepareDowngradeConfirmWord(c, []string{"word"})
	if err != nil || word != "word" {
		t.Fatalf("the documented `--confirm <word>` form must still resolve; got %q, %v", word, err)
	}
}

// ─── The refusal has to be actionable, and CWE-117 safe ───────────────────────

func TestChaos122_RefusalMessageNamesTheCauseAndTheTail(t *testing.T) {
	err := refusePositionalArgs(false, []string{"sh", "-c", "exec ./culvert -port 8080"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	// An operator reading only this line must learn: what was rejected, that
	// the rest of the argv was dropped, that nothing happened, and the cause.
	for _, want := range []string{
		`"sh"`,                // the offending token, quoted
		"Nothing was started", // no partial effect
		"ENTRYPOINT",          // the cause an orchestrator hits
		"entrypoint:",         // the remedy
		"CHAOS-122",           // traceable to this round
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message must contain %q so it is actionable without the source; got:\n%s", want, msg)
		}
	}
}

// TestChaos122_RefusalSanitizesTheArgvItEchoes — argv is operator-supplied and
// this message goes to stderr, so it crosses the CWE-117 barrier
// (docs/agent-context/conventions.md: sanitizeLog + %q). A newline in argv must
// not be able to forge a second log line.
func TestChaos122_RefusalSanitizesTheArgvItEchoes(t *testing.T) {
	err := refusePositionalArgs(false, []string{"evil\nFATAL: all clear", "-port", "8080"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("the echoed argv must be newline-sanitized (CWE-117); got:\n%q", err.Error())
	}
	if !strings.Contains(err.Error(), "evil_FATAL") {
		t.Fatalf("expected the newline replaced by sanitizeLog's underscore; got %q", err.Error())
	}
}

// TestChaos122_RefusalRedactsTheDiscardedValues — the discarded tail can carry
// credential flags, and the refusal goes to stderr, which every orchestrator
// collects. The flag NAMES stay (they say what was dropped); no value may.
func TestChaos122_RefusalRedactsTheDiscardedValues(t *testing.T) {
	err := refusePositionalArgs(false, []string{
		"STRAY", "-pass", "review-secret", "-metrics-token=review-token", "--ha-token", "ha-secret",
	})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, secret := range []string{"review-secret", "review-token", "ha-secret"} {
		if strings.Contains(msg, secret) {
			t.Errorf("the refusal echoed the credential value %q to stderr:\n%s", secret, msg)
		}
	}
	for _, want := range []string{`"STRAY"`, "-pass <value>", "-metrics-token=<value>", "--ha-token <value>"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must still name %q so the operator sees what was discarded; got:\n%s", want, msg)
		}
	}
}

// ─── The ordering invariant: refuse BEFORE anything touches the data dir ──────

// TestChaos122_GuardRunsBeforeTheOneShotDispatch pins the position of the call
// in main(). The "nothing on disk was changed" half of the contract is a
// property of WHERE the check sits: handleOneShotCommands, checkInterruptedRestore
// and checkDataDirSingleWriter all reach the persisted-state root, so a reorder
// would keep the refusal and silently lose its no-effect guarantee.
func TestChaos122_GuardRunsBeforeTheOneShotDispatch(t *testing.T) {
	// Anchored to the package source dir, not the CWD: TestTestFileReadsAreCWDIndependent
	// pins that invariant so a concurrent os.Chdir cannot flake this read.
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	s := string(src)
	guard := strings.Index(s, "checkPositionalArgs(s)")
	if guard < 0 {
		t.Fatal("main.go no longer calls checkPositionalArgs: the argv contract is unenforced (CHAOS-122)")
	}
	for _, after := range []string{
		"handleOneShotCommands(s)",
		"checkInterruptedRestore(dataDir)",
		"checkDataDirSingleWriter(dataDir)",
	} {
		if at := strings.Index(s, after); at >= 0 && at < guard {
			t.Errorf("checkPositionalArgs must run BEFORE %s, so a rejected argv changes nothing on disk", after)
		}
	}
}

// ─── bootstrap-resolve: the same defect in its own FlagSet (CHAOS-122b) ───────

// TestChaos122_BootstrapResolveRefusesAPositionalTail. The flag this subcommand
// would silently drop after a stray token is --data-dir, which carries the
// anti-rollback floor scripts/install.sh stages from a surviving proxy-data
// volume — so the dropped flag is precisely the one that stops a mirror-replayed
// old catalog from downgrading the host.
func TestChaos122_BootstrapResolveRefusesAPositionalTail(t *testing.T) {
	var out, errBuf strings.Builder
	code := runBootstrapResolve([]string{"--channel", "stable", "stray", "--data-dir", "/tmp"}, &out, &errBuf)
	if code == 0 {
		t.Fatal("a positional tail must fail closed: --data-dir (the anti-rollback floor) would have been discarded")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must stay empty so the installer's shape gate never sees a partial answer; got %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "unexpected argument") {
		t.Fatalf("expected an unexpected-argument diagnostic naming the cause; got %q", errBuf.String())
	}
	// Negative control: the installer's real argv shape must still be accepted
	// by the guard (it fails later, on the disabled-catalog sentinel, not here).
	var out2, err2 strings.Builder
	_ = runBootstrapResolve([]string{"--channel", "stable", "--print", "image_ref", "--catalog-url", "off"}, &out2, &err2)
	if strings.Contains(err2.String(), "unexpected argument") {
		t.Fatalf("a flags-only argv must pass the guard; got %q", err2.String())
	}
}
