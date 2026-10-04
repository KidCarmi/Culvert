//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceaccess"
)

// This test mutates only a disposable CI runner, never a deployed appliance.
// Explicit opt-in and absence guards precede account or fixed-path creation.
func TestAccessRealSSHBoundary(t *testing.T) {
	if os.Getenv("CULVERT_ACCESS_SSH_FIXTURE") != "1" {
		t.Skip("requires opted-in disposable Linux runner")
	}
	if os.Geteuid() != 0 {
		t.Fatal("SSH fixture requires root on a disposable runner")
	}
	for _, tool := range []string{"/usr/sbin/sshd", "/usr/bin/ssh", "/usr/bin/ssh-keygen", "/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/bin/pkill"} {
		if _, err := os.Stat(tool); err != nil {
			t.Fatalf("required fixture tool unavailable: %s", tool)
		}
	}
	if _, err := user.Lookup("culvert-operator"); err == nil {
		t.Fatal("refusing existing operator account")
	}
	if _, err := user.LookupGroup("culvert-operator"); err == nil {
		t.Fatal("refusing existing operator group")
	}
	binDir := "/opt/culvert-appliance/bin"
	keyDir := "/etc/ssh/culvert-authorized-keys"
	home := "/home/culvert-operator"
	for _, path := range []string{binDir, keyDir, home} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refusing existing fixture path: %s", path)
		}
	}
	binary := os.Getenv("CULVERT_ACCESS_TEST_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("provide absolute CULVERT_ACCESS_TEST_BINARY from the CI build")
	}
	if got := fixtureCommand(t, binary, "--version"); strings.TrimSpace(got) != applianceaccess.Version {
		t.Fatal("fixture binary is not the built access shell")
	}
	dir := accessRootFixture(t)
	accountMarker := filepath.Base(dir)
	accountAttempted := false
	var accountUID, accountGID string
	var daemon *exec.Cmd
	t.Cleanup(func() {
		if daemon != nil && daemon.Process != nil {
			_ = daemon.Process.Kill()
			_ = daemon.Wait()
		}
		if accountAttempted {
			u, err := user.Lookup("culvert-operator")
			var unknown user.UnknownUserError
			if errors.As(err, &unknown) {
				// useradd can create its private group before creating the user.
				// Without the tagged user, do not guess ownership of that group.
				if _, groupErr := user.LookupGroup("culvert-operator"); groupErr == nil {
					t.Error("partial account setup left a group without a tagged user; refusing group cleanup")
					return
				}
			} else if err != nil || !ownedFixtureAccount(u, accountMarker, home, accountUID, accountGID) {
				t.Error("refusing cleanup of changed operator identity")
				return
			} else {
				accountUID, accountGID = u.Uid, u.Gid
				_, _ = runFixtureCommand(context.Background(), "/usr/bin/pkill", "-KILL", "-u", accountUID)
				if output, err := runFixtureCommand(context.Background(), "/usr/sbin/userdel", "culvert-operator"); err != nil {
					t.Errorf("fixture account cleanup failed: %v; output=%q", err, output)
					return
				}
				if g, err := user.LookupGroup("culvert-operator"); err == nil && g.Gid == accountGID {
					if output, err := runFixtureCommand(context.Background(), "/usr/sbin/groupdel", "culvert-operator"); err != nil {
						t.Errorf("fixture group cleanup failed: %v; output=%q", err, output)
						return
					}
				}
			}
		}
		// These exact paths were absent before this fixture created them.
		for _, path := range []string{binDir, keyDir, home} {
			if filepath.Clean(path) != path || path == "/" {
				t.Error("unsafe cleanup target")
				return
			}
			_ = os.RemoveAll(path)
		}
	})
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyFixtureBinary(t, binary, applianceaccess.Binary)
	stub := "#!/bin/sh\nset -eu\n" +
		"test \"\x24{BASH_ENV-unset}\" = unset\n" +
		"test \"\x24{ENV-unset}\" = unset\n" +
		"test \"\x24{SSH_AUTH_SOCK-unset}\" = unset\n" +
		"test \"\x24{HOME}\" = /\n" +
		"case \"\x241\" in\n--text) echo PUBLIC-STATUS;;\n--json) echo '{\"public\":true}';;\n--report) echo PUBLIC-DIAGNOSTICS;;\n*) exit 91;;\nesac\n" +
		"if IFS= read -r stolen; then exit 92; fi\n"
	if err := os.WriteFile(filepath.Join(binDir, "culvert-console"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	accountAttempted = true
	fixtureCommand(t, "/usr/sbin/useradd", "--user-group", "--create-home", "--comment", accountMarker, "--shell", applianceaccess.Binary, "--password", "!", "culvert-operator")
	u, err := user.Lookup("culvert-operator")
	if err != nil || !ownedFixtureAccount(u, accountMarker, home, "", "") {
		t.Fatal("fixture account identity unexpected")
	}
	accountUID = u.Uid
	accountGID = u.Gid
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(home, ".ssh"), home} {
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(home, "RC-MUST-NOT-RUN")
	for _, name := range []string{".bashrc", ".profile", ".ssh/rc"} {
		path := filepath.Join(home, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh/environment"), []byte("BASH_ENV="+filepath.Join(home, ".bashrc")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(home, ".ssh/environment"), uid, gid); err != nil {
		t.Fatal(err)
	}
	clientKey := filepath.Join(dir, "client")
	otherKey := filepath.Join(dir, "other-client")
	hostKey := filepath.Join(dir, "host")
	for _, key := range []string{clientKey, otherKey, hostKey} {
		fixtureCommand(t, "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	}
	public, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := applianceaccess.CanonicalKeys(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishOperatorKeys(operatorKeys, canonical); err != nil {
		t.Fatal(err)
	}
	// A key planted in the operator's own home must not grant SSH access.
	otherPublic, err := os.ReadFile(otherKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh/authorized_keys"), otherPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(home, ".ssh/authorized_keys"), uid, gid); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	source, err := os.ReadFile("../../appliance/provision/sshd-50-culvert.conf")
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "sshd_config")
	settings := fmt.Sprintf("\nPort %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nLogLevel ERROR\nSubsystem sftp internal-sftp\nAcceptEnv BASH_ENV ENV SSH_AUTH_SOCK PATH PAGER SYSTEMD_PAGER\n", port, hostKey, filepath.Join(dir, "sshd.pid"))
	if err := os.WriteFile(config, append(source, []byte(settings)...), 0o600); err != nil {
		t.Fatal(err)
	}
	// Ubuntu's privilege-separation directory may be absent on an unused runner.
	if _, err := os.Lstat("/run/sshd"); os.IsNotExist(err) {
		if err := os.Mkdir("/run/sshd", 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove("/run/sshd") })
	}
	effective := fixtureCommand(t, "/usr/sbin/sshd", "-T", "-f", config, "-C", "user=culvert-operator,host=localhost,addr=127.0.0.1")
	for _, want := range []string{"usepam yes", "disableforwarding yes", "permituserrc no", "permituserenvironment no", "allowusers culvert-operator", "authorizedkeysfile " + operatorKeys, "forcecommand " + applianceaccess.ForcedCommand} {
		if !strings.Contains("\n"+effective, "\n"+want+"\n") {
			t.Fatalf("effective sshd policy missing %s", want)
		}
	}
	log, err := os.Create(filepath.Join(dir, "sshd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	daemon = exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", config)
	daemon.Stdout, daemon.Stderr = log, log
	if err := daemon.Start(); err != nil {
		t.Fatal("could not start isolated sshd")
	}
	waitSSHFixture(t, port)
	base := []string{"-F", "/dev/null", "-p", strconv.Itoa(port), "-i", clientKey, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5"}
	target := "culvert-operator@127.0.0.1"
	for _, tt := range []struct{ command, want string }{{"status", "PUBLIC-STATUS"}, {"status-json", "{\"public\":true}"}, {"diagnostics", "PUBLIC-DIAGNOSTICS"}, {"help", "read-only"}} {
		for _, pty := range []bool{false, true} {
			args := append([]string{}, base...)
			if pty {
				args = append(args, "-tt")
			} else {
				args = append(args, "-T")
			}
			args = append(args, "-o", "SetEnv=BASH_ENV="+filepath.Join(home, ".bashrc")+" ENV="+filepath.Join(home, ".profile")+" SSH_AUTH_SOCK=/run/docker.sock PATH=/untrusted", target, tt.command)
			out, err := sshFixture(t, args, "")
			if err != nil || !strings.Contains(out, tt.want) {
				t.Fatalf("real SSH command/PTY failed: %s/%t", tt.command, pty)
			}
		}
	}
	out, err := sshFixture(t, append(append([]string{}, base...), "-tt", target), "status\nexit\n")
	if err != nil || !strings.Contains(out, "culvert>") || !strings.Contains(out, "PUBLIC-STATUS") {
		t.Fatal("interactive SSH prompt or stdin isolation failed")
	}
	for _, command := range []string{"status; id", "status && id", "$(id)", "bash", "sudo -n id", "cat /etc/shadow", "curl --unix-socket /run/docker.sock http://localhost/info", "scp -t /tmp/test", "--import-keys", "recover"} {
		out, err := sshFixture(t, append(append([]string{}, base...), target, command), "")
		if err == nil || !strings.Contains(out, "unsupported command") {
			t.Fatalf("SSH bypass not explicitly refused: %s", command)
		}
	}
	if _, err := sshFixture(t, append(append([]string{}, base...), "-s", target, "sftp"), ""); err == nil {
		t.Fatal("SFTP subsystem admitted")
	}
	if _, err := sshFixture(t, append(append([]string{}, base...), "-N", "-o", "ExitOnForwardFailure=yes", "-R", filepath.Join(home, "forward.sock")+":/run/docker.sock", target), ""); err == nil {
		t.Fatal("Unix socket forwarding admitted")
	}
	if _, err := sshFixture(t, append(append([]string{}, base...), "-W", "127.0.0.1:22", target), ""); err == nil {
		t.Fatal("direct TCP forwarding admitted")
	}
	deniedKeyArgs := append([]string{}, base...)
	for i := range deniedKeyArgs {
		if deniedKeyArgs[i] == clientKey {
			deniedKeyArgs[i] = otherKey
		}
	}
	if _, err := sshFixture(t, append(deniedKeyArgs, target, "status"), ""); err == nil {
		t.Fatal("user-owned authorization file bypassed root-owned keys")
	}
	if _, err := sshFixture(t, append(append([]string{}, base...), "culvert@127.0.0.1", "status"), ""); err == nil {
		t.Fatal("local administrative account admitted over SSH")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("user rc/profile hook executed")
	}
}

func fixtureCommand(t *testing.T, binary string, args ...string) string {
	t.Helper()
	output, err := runFixtureCommand(t.Context(), binary, args...)
	if err != nil {
		// Only account tools can expose their output: all input is synthetic and
		// they never handle key material. Other failures still report their cause.
		if fixtureCommandTimeout(binary) == 60*time.Second {
			t.Fatalf("fixture command failed: %s: %v; output=%q", filepath.Base(binary), err, output)
		}
		t.Fatalf("fixture command failed: %s: %v", filepath.Base(binary), err)
	}
	return output
}

func fixtureCommandTimeout(binary string) time.Duration {
	switch binary {
	case "/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/groupdel":
		return 60 * time.Second
	default:
		return 15 * time.Second
	}
}

func runFixtureCommand(parent context.Context, binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, fixtureCommandTimeout(binary))
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) > 4096 {
		output = append(output[:4096], []byte(" [truncated]")...)
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("%w (limit %s; process: %v)", ctx.Err(), fixtureCommandTimeout(binary), err)
	}
	return string(output), err
}

func ownedFixtureAccount(u *user.User, marker, home, uid, gid string) bool {
	return u != nil && u.Username == "culvert-operator" && u.Name == marker &&
		u.HomeDir == home && u.Uid != "" && u.Uid != "0" && u.Gid != "" && u.Gid != "0" &&
		(uid == "" || uid == u.Uid) && (gid == "" || gid == u.Gid)
}

func TestAccessFixtureAccountOwnershipFence(t *testing.T) {
	u := user.User{Username: "culvert-operator", Name: "unique-fixture", HomeDir: "/home/culvert-operator", Uid: "1003", Gid: "1003"}
	if !ownedFixtureAccount(&u, u.Name, u.HomeDir, "", "") || !ownedFixtureAccount(&u, u.Name, u.HomeDir, u.Uid, u.Gid) {
		t.Fatal("fixture must recognize its partially created and captured identity")
	}
	for _, change := range []func(*user.User){
		func(v *user.User) { v.Username = "other" },
		func(v *user.User) { v.Name = "foreign-fixture" },
		func(v *user.User) { v.HomeDir = "/root" },
		func(v *user.User) { v.Uid = "0" },
		func(v *user.User) { v.Gid = "0" },
	} {
		foreign := u
		change(&foreign)
		if ownedFixtureAccount(&foreign, u.Name, u.HomeDir, "", "") {
			t.Fatal("cleanup accepted a foreign or privileged identity")
		}
	}
	if ownedFixtureAccount(&u, u.Name, u.HomeDir, "1004", u.Gid) || ownedFixtureAccount(&u, u.Name, u.HomeDir, u.Uid, "1004") {
		t.Fatal("cleanup accepted a replaced captured identity")
	}
}

func TestAccessFixtureCommandTimeoutsAndDiagnostics(t *testing.T) {
	for _, tool := range []string{"/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/groupdel"} {
		if fixtureCommandTimeout(tool) != 60*time.Second {
			t.Fatal("account tool must have a separate bounded deadline")
		}
	}
	if fixtureCommandTimeout("/usr/bin/ssh-keygen") != 15*time.Second {
		t.Fatal("ordinary fixture tool timeout changed")
	}
	out, err := runFixtureCommand(t.Context(), "/bin/sh", "-c", "printf 'synthetic account failure' >&2; exit 7")
	if err == nil || out != "synthetic account failure" || !strings.Contains(err.Error(), "exit status 7") {
		t.Fatal("fixture discarded actionable process diagnostics")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = runFixtureCommand(ctx, "/bin/sh", "-c", "sleep 20 & wait")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatal("fixture deadline must terminate descendants and report timeout")
	}
}

func copyFixtureBinary(t *testing.T, source, target string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("copy fixture binary failed")
	}
}

func waitSSHFixture(t *testing.T, port int) {
	t.Helper()
	for range 50 {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("isolated sshd did not listen")
}

func sshFixture(t *testing.T, args []string, input string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("SSH request hung instead of completing or being explicitly refused")
	}
	return string(output), err
}
