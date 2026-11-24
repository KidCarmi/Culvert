package runner

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestProxyContainerListed_OnlyUnderstoodOutputIsANo: "not listed" ends a
// safety wait, so it is given only for output understood completely.
func TestProxyContainerListed_OnlyUnderstoodOutputIsANo(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		fail    bool
		listed  bool
		wantErr bool
	}{
		{name: "empty", out: "", listed: false},
		{name: "proxy running", out: `{"Service":"proxy","State":"running","ID":"a"}`, listed: true},
		{name: "proxy restarting", out: `{"Service":"proxy","State":"restarting","ID":"a"}`, listed: true},
		{name: "only another service", out: `{"Service":"clamav","State":"running","ID":"b"}`, listed: false},
		{name: "array, other service", out: `[{"Service":"clamav","State":"running","ID":"b"}]`, listed: false},
		{name: "array, proxy", out: `[{"Service":"proxy","State":"running","ID":"a"}]`, listed: true},
		{name: "not ps output", out: "WARNING: something", wantErr: true},
		{name: "one line does not decode", out: `{"Service":"clamav","ID":"b"}` + "\n" + `{"Service":`, wantErr: true},
		{name: "a warning line beside an entry", out: "time=... level=warning\n" + `{"Service":"clamav","ID":"b"}`, wantErr: true},
		{name: "entry without a service", out: `{"Name":"culvert","State":"running","ID":"a"}`, wantErr: true},
		{name: "command failed", out: "", fail: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(Options{ComposeProjectDir: t.TempDir(), ComposeFile: "docker-compose.yml", StageTimeout: 5 * time.Second,
				ProxyRepo: "127.0.0.1:5000/culvert", DockerBinary: "/usr/bin/docker"})
			if err != nil {
				t.Fatal(err)
			}
			r.SetExecHooksForTest(func(cmd *exec.Cmd) error {
				_, _ = cmd.Stdout.Write([]byte(tc.out))
				return nil
			}, func(*exec.Cmd) error {
				if tc.fail {
					return exec.ErrNotFound
				}
				return nil
			})
			listed, err := r.ProxyContainerListed(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil && listed != tc.listed {
				t.Errorf("listed = %v, want %v", listed, tc.listed)
			}
		})
	}
}

// TestProxyContainerListed_TruncatedOutputIsNotANo: output that hit the capture
// cap may have lost the proxy's line.
func TestProxyContainerListed_TruncatedOutputIsNotANo(t *testing.T) {
	r, err := New(Options{ComposeProjectDir: t.TempDir(), ComposeFile: "docker-compose.yml", StageTimeout: 5 * time.Second,
		ProxyRepo: "127.0.0.1:5000/culvert", DockerBinary: "/usr/bin/docker"})
	if err != nil {
		t.Fatal(err)
	}
	r.captureMax = 64 // white-box: a small cap, so a few lines exceed it
	line := `{"Service":"clamav","State":"running","ID":"b"}` + "\n"
	r.SetExecHooksForTest(func(cmd *exec.Cmd) error {
		for i := 0; i < 20; i++ {
			_, _ = cmd.Stdout.Write([]byte(line))
		}
		return nil
	}, func(*exec.Cmd) error { return nil })
	if listed, err := r.ProxyContainerListed(context.Background()); err == nil {
		t.Fatalf("truncated output was answered (listed=%v) instead of refused", listed)
	}
}
