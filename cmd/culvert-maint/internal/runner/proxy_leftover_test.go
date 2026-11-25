package runner

import (
	"context"
	"os/exec"
	"slices"
	"testing"
	"time"
)

func newLeftoverTestRunner(t *testing.T) *Runner {
	t.Helper()
	r, err := New(Options{ComposeProjectDir: t.TempDir(), ComposeFile: "docker-compose.yml", StageTimeout: 5 * time.Second,
		ProxyRepo: "127.0.0.1:5000/culvert", DockerBinary: "/usr/bin/docker"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestProxyCreatedLeftover_OnlyACreatedProxyIsEvidence: true lets the startup
// reconcile start a container, so it is given only for a "created" proxy in
// output understood completely; the states an operator's `docker stop` or a
// running stack leave are not evidence, and unreadable output is an error.
func TestProxyCreatedLeftover_OnlyACreatedProxyIsEvidence(t *testing.T) {
	cases := []struct {
		name     string
		out      string
		fail     bool
		leftover bool
		wantErr  bool
	}{
		{name: "nothing (compose down)", out: "", leftover: false},
		{name: "created proxy (death inside up)", out: `{"Service":"proxy","State":"created","ID":"a","Labels":"com.docker.compose.oneoff=False,com.docker.compose.service=proxy"}`, leftover: true},
		{name: "created proxy beside the exited old one", out: `{"Service":"proxy","State":"exited","ID":"o"}` + "\n" +
			`{"Service":"proxy","State":"created","ID":"n","Labels":"com.docker.compose.oneoff=False,com.docker.compose.service=proxy"}`, leftover: true},
		{name: "array, created proxy", out: `[{"Service":"proxy","State":"Created","ID":"a","Labels":"com.docker.compose.oneoff=False,com.docker.compose.service=proxy"}]`, leftover: true},
		{name: "a failed `compose run` one-off (compose down keeps it)", out: `{"Service":"proxy","State":"created","ID":"r","Name":"x-proxy-run-07ae33c5fc3e","Labels":"com.docker.compose.oneoff=True,com.docker.compose.service=proxy"}`, leftover: false},
		{name: "a one-off beside a real leftover", out: `{"Service":"proxy","State":"created","ID":"r","Labels":"com.docker.compose.oneoff=True"}` + "\n" +
			`{"Service":"proxy","State":"created","ID":"n","Labels":"com.docker.compose.oneoff=False,com.docker.compose.service=proxy"}`, leftover: true},
		{name: "a label value with commas (two config files)", out: `{"Service":"proxy","State":"created","ID":"a","Labels":"com.docker.compose.project.config_files=/a.yml,/b.yml,com.docker.compose.oneoff=False"}`, leftover: true},
		{name: "a created proxy without labels", out: `{"Service":"proxy","State":"created","ID":"a"}`, wantErr: true},
		{name: "oneoff given twice", out: `{"Service":"proxy","State":"created","ID":"a","Labels":"com.docker.compose.oneoff=False,com.docker.compose.oneoff=True"}`, wantErr: true},
		{name: "oneoff with an unknown value", out: `{"Service":"proxy","State":"created","ID":"a","Labels":"com.docker.compose.oneoff=false"}`, wantErr: true},
		{name: "exited proxy only (docker stop)", out: `{"Service":"proxy","State":"exited","ID":"a"}`, leftover: false},
		{name: "running proxy", out: `{"Service":"proxy","State":"running","ID":"a"}`, leftover: false},
		{name: "created container of another service", out: `{"Service":"clamav","State":"created","ID":"b"}`, leftover: false},
		{name: "not ps output", out: "WARNING: something", wantErr: true},
		{name: "a warning line beside a created proxy", out: "time=... level=warning\n" + `{"Service":"proxy","State":"created","ID":"a","Labels":"com.docker.compose.oneoff=False,com.docker.compose.service=proxy"}`, wantErr: true},
		{name: "entry without a service", out: `{"Name":"culvert-proxy-1","State":"created","ID":"a"}`, wantErr: true},
		{name: "command failed (no sudoers rule on an older install)", fail: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newLeftoverTestRunner(t)
			var argv []string
			r.SetExecHooksForTest(func(cmd *exec.Cmd) error {
				argv = cmd.Args
				_, _ = cmd.Stdout.Write([]byte(tc.out))
				return nil
			}, func(*exec.Cmd) error {
				if tc.fail {
					return exec.ErrNotFound
				}
				return nil
			})
			got, err := r.ProxyCreatedLeftover(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil && got != tc.leftover {
				t.Errorf("leftover = %v, want %v", got, tc.leftover)
			}
			if !tc.fail && !slices.Contains(argv, "-a") {
				t.Errorf("the read must list every state (ps -a): argv %q", argv)
			}
		})
	}
}

// TestProxyCreatedLeftover_TruncatedOutputIsNotEvidence: a truncated listing
// is refused, never answered.
func TestProxyCreatedLeftover_TruncatedOutputIsNotEvidence(t *testing.T) {
	r := newLeftoverTestRunner(t)
	r.captureMax = 64
	line := `{"Service":"proxy","State":"created","ID":"a","Labels":"com.docker.compose.oneoff=False,com.docker.compose.service=proxy"}` + "\n"
	r.SetExecHooksForTest(func(cmd *exec.Cmd) error {
		for i := 0; i < 20; i++ {
			_, _ = cmd.Stdout.Write([]byte(line))
		}
		return nil
	}, func(*exec.Cmd) error { return nil })
	if got, err := r.ProxyCreatedLeftover(context.Background()); err == nil {
		t.Fatalf("truncated output was answered (leftover=%v) instead of refused", got)
	}
}

// TestComposeStatusAll_IsReadOnly: the template restore_prior's evidence needs
// is registered as not state-changing, with exactly its one sudoers line.
func TestComposeStatusAll_IsReadOnly(t *testing.T) {
	tmpl := templateByID(TemplateComposeStatusAll)
	if tmpl == nil {
		t.Fatal("compose.status.all not registered")
	}
	if tmpl.StateChanging {
		t.Error("compose.status.all must be read-only")
	}
	want := []string{"/usr/bin/docker compose -f {compose_path} ps -a --format json"}
	if !slices.Equal(tmpl.SudoersLines, want) {
		t.Errorf("SudoersLines = %q, want %q", tmpl.SudoersLines, want)
	}
}

// TestProxyCreatedLeftover_TruncatedOnALineBoundaryIsNotEvidence: output cut
// exactly between two lines decodes cleanly line by line; only the Truncated
// flag says entries are missing (review N2).
func TestProxyCreatedLeftover_TruncatedOnALineBoundaryIsNotEvidence(t *testing.T) {
	r := newLeftoverTestRunner(t)
	line := `{"Service":"clamav","State":"running","ID":"b"}` + "\n"
	r.captureMax = len(line) // exactly one whole line is kept
	r.SetExecHooksForTest(func(cmd *exec.Cmd) error {
		_, _ = cmd.Stdout.Write([]byte(line + line))
		return nil
	}, func(*exec.Cmd) error { return nil })
	if got, err := r.ProxyCreatedLeftover(context.Background()); err == nil {
		t.Fatalf("truncated output was answered (leftover=%v) instead of refused", got)
	}
}
