package main

// install_script_compose_up_fallback_test.go — regression coverage for the
// manual health-check fallback in scripts/install.sh §7 ("Pull and start"),
// used when `docker compose up -d --wait` fails or is unsupported (older
// Compose versions predating v2.17).
//
// The fallback loop is meant to answer one question: "did the stack actually
// come up healthy?" It instead asks a much weaker one — "does ANY line of
// `docker compose ps --format '{{.Health}}'` say healthy?" — with no service
// filter. `docker compose ps` prints one line per service, so on the shipped
// stack (clamav + proxy) the ClamAV sidecar reporting healthy is enough to
// satisfy the check even while the proxy service itself is still "starting"
// (or stuck there, e.g. crash-looping and never settling). The installer then
// prints "Culvert is running!" over a proxy that was never actually confirmed
// healthy — on exactly the older-Compose-version path this fallback exists
// for.
//
// This test extracts the REAL top-level fragment from scripts/install.sh (not
// a hand-copied duplicate — extractShellLines pulls the literal source), runs
// it under docker/sudo/warn/info stubs that simulate ClamAV healthy + proxy
// stuck at "starting" for the whole 90s budget, and asserts COMPOSE_UP_OK
// stays "0" (the installer must not declare success).

import (
	"os/exec"
	"strings"
	"testing"
)

// composeUpFallbackStubs are the shared stubs the extracted fragment runs
// under: `sudo` is a passthrough (the test isn't root and doesn't need to
// be — only the fragment's own logic is under test), `docker compose` is
// faked per-subcommand, and `sleep`/`warn`/`info` are no-ops so the 45-
// iteration/2s-per-iteration loop runs instantly instead of taking up to 90s
// of real wall-clock time.
//
// The fake reports ClamAV healthy and the proxy service PERMANENTLY stuck at
// "starting" — never exited, never healthy — which is exactly what an
// installer must treat as "did not come up" (a crash-looping or wedged proxy
// container, or one that simply needs longer than the 90s budget).
const composeUpFallbackStubs = `
warn() { :; }
info() { :; }
sleep() { :; }
docker() {
  if [[ "$1" == "compose" ]]; then
    shift
    case "$*" in
      "up -d --wait --wait-timeout 330")
        return 1 ;; # simulate --wait unsupported / failed (older Compose)
      "up -d")
        return 0 ;;
      "ps -a --format {{.State}}")
        printf 'running\nrunning\n'; return 0 ;;
      "ps --format {{.Health}}")
        # Pre-fix invocation: no service filter — clamav's own "healthy" line
        # satisfies this even though the proxy service is still starting.
        printf 'healthy\nstarting\n'; return 0 ;;
      "ps proxy --format {{.Health}}")
        # Fixed invocation: scoped to the proxy service, which never reports
        # healthy in this scenario.
        printf 'starting\n'; return 0 ;;
      *)
        echo "unexpected docker invocation: $*" >&2; return 1 ;;
    esac
  fi
  return 1
}
sudo() { "$@"; }
`

// TestInstallScript_ComposeUpFallback_DoesNotDeclareSuccessOnUnhealthyProxy
// reproduces the defect: with ClamAV healthy and the proxy service stuck at
// "starting" for the whole fallback budget, the real script fragment must
// leave COMPOSE_UP_OK=0 so the caller's failure path (dump_compose_diagnostics
// + error()) fires — never print the success banner over a proxy that was
// never confirmed healthy.
func TestInstallScript_ComposeUpFallback_DoesNotDeclareSuccessOnUnhealthyProxy(t *testing.T) {
	fragment := extractShellLines(t, "scripts/install.sh", "COMPOSE_UP_OK=0", `if [[ "$COMPOSE_UP_OK" != "1" ]]; then`)

	script := composeUpFallbackStubs + "\n" + fragment + "\n" + `echo "RESULT=$COMPOSE_UP_OK"` + "\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fragment failed: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "RESULT=0") {
		t.Fatalf("COMPOSE_UP_OK=1 (success declared) while the proxy service itself never reported healthy "+
			"(only ClamAV did) — the fallback health check has no service filter, so any one healthy service "+
			"satisfies it. Real output:\n%s", out)
	}
}

// TestInstallScript_ComposeUpFallback_DeclaresSuccessOnceProxyIsHealthy is the
// control: once the proxy service itself reports healthy, the fallback must
// still declare success (the fix must not overcorrect into always failing).
func TestInstallScript_ComposeUpFallback_DeclaresSuccessOnceProxyIsHealthy(t *testing.T) {
	fragment := extractShellLines(t, "scripts/install.sh", "COMPOSE_UP_OK=0", `if [[ "$COMPOSE_UP_OK" != "1" ]]; then`)

	stubs := strings.Replace(composeUpFallbackStubs,
		`"ps proxy --format {{.Health}}")
        # Fixed invocation: scoped to the proxy service, which never reports
        # healthy in this scenario.
        printf 'starting\n'; return 0 ;;`,
		`"ps proxy --format {{.Health}}")
        printf 'healthy\n'; return 0 ;;`, 1)
	if stubs == composeUpFallbackStubs {
		t.Fatal("test setup error: replacement target not found in composeUpFallbackStubs")
	}

	script := stubs + "\n" + fragment + "\n" + `echo "RESULT=$COMPOSE_UP_OK"` + "\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fragment failed: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "RESULT=1") {
		t.Fatalf("COMPOSE_UP_OK stayed 0 even though the proxy service reported healthy — the fix over-corrected. Real output:\n%s", out)
	}
}
