package main

// docker_compose_entrypoint_argv_chaos121_test.go — CHAOS-121.
//
// Cross-artifact gates over the DEPLOYMENT files the resilience work is
// delivered through. Everything the preceding chaos rounds built — the bounded
// three-phase shutdown envelope with its durability reserve (CHAOS-56), the
// fail-closed startup guards, the HA join-mode checks — reaches a customer only
// if the compose file that starts and stops the container actually hands the
// binary its flags and actually gives it time to stop. Neither was true of
// `docker-compose.ha.yml`, the one shipped compose artifact no CI job has ever
// brought up.
//
// # Gate 1 — the command must REACH the binary as flags
//
// The image declares an exec-form `ENTRYPOINT ["./culvert"]`. Docker APPENDS a
// container's command to an exec-form entrypoint; it does not replace it. So a
// service that writes
//
//	command: >
//	  sh -c '
//	    ARGS="-port 8080 -ca-path /data/ca.bundle …"
//	    exec ./culvert $ARGS
//	  '
//
// does not run a shell at all. The container's real argv is
//
//	./culvert sh -c '<the script>'
//
// and Go's flag package stops parsing at the FIRST token that does not begin
// with "-", so "sh" and everything after it land in flag.Args(). main.go calls
// the package-level flag.Parse() and has no flag.NArg() guard; handleOneShotCommands
// dispatches on FLAGS only, so nothing matches and the process falls straight
// through into normal startup with every flag at its zero default — no
// -ca-path (a fresh Root CA every boot, so every client's installed trust
// anchor breaks), no -policy (the Dockerfile's own comment calls this
// "CRITICAL: without this, rules are lost on restart"), no -audit-log, no
// -cluster-db, no -clamav-addr (AV silently absent), no -cp-grpc-addr (the
// Control Plane listener never opens), no --ha-join/--ha-token (a standby comes
// up as an independent ACTIVE Control Plane — the silent split-brain the HA
// file's own inline comment was written to prevent) and no --enroll (a Data
// Plane never enrolls). The container still passes its /health check, because
// /health is liveness and the process IS alive.
//
// The property this gate asserts is the minimal true one: if the culvert binary
// is argv[0], then argv[1] must begin with "-". That is exactly the condition
// under which flag.Parse sees any flag at all — a leading positional discards
// the whole tail, and flag values (`-port` `8080`) are consumed by their flag
// rather than terminating the scan. A service that genuinely needs a shell must
// move the shell into `entrypoint:` and `exec` the binary from it, so that
// culvert still becomes PID 1 and still receives the SIGTERM the whole shutdown
// envelope depends on.
//
// # Gate 2 — stop_grace_period must cover the shutdown envelope
//
// TestChaos56_EnvelopeFitsTheContainerStopGrace pins the envelope against
// `docker-compose.yml`, by name. It is the right contract and it covered one
// file; `docker-compose.ha.yml` — the CP + standby + DP topology, the nodes
// that hold the cluster store, the audit log and the lease — declared no
// stop_grace_period at all, so Docker's DEFAULT 10s applied against a 51s
// worst case (Total 45s + one shutdownHookGrace per late phase). SIGKILL landed
// inside the EARLY phase, skipping the whole drain (order 100: every in-flight
// client tunnel severed rather than drained) and the ENTIRE durability reserve
// (orders 110-140: syslog, community DB, log store, request log, audit log, log
// closer) — which is the specific harm docker-compose.yml's own comment names,
// and an unclean badger close is what CHAOS-50's boot-path quarantine exists
// for. This gate is the same contract applied to every artifact.
//
// # Gate 3 — a culvert service must wait for ClamAV to be HEALTHY
//
// docker-compose.yml uses the long form with `condition: service_healthy` and
// explains why: "the short-form list (`- clamav`) only waits for the clamav
// container to START, not for its healthcheck to pass". ClamAV's healthcheck
// carries start_period: 300s for the first-boot signature download, and an
// unreachable ClamAV is FAIL-OPEN — diagnostics_clamav_scan.go words it as
// "scanned content is being forwarded WITHOUT an antivirus verdict". The HA
// file used the short form, so every HA/DP boot and node reboot forwarded
// bodies unscanned for minutes.
//
// Each gate is a pure checker over parsed artifacts so the pre-fix shapes can
// be fed to it directly as negative controls (§ the *RejectsThe* tests): a gate
// that cannot be shown to fail against the defect it was written for is not
// evidence.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

// ── Artifact discovery ────────────────────────────────────────────────────────

// composeArtifacts returns every compose file in the repository, discovered
// rather than listed: a new deployment artifact is in scope the moment it is
// added, which is the whole failure mode here (docker-compose.ha.yml was never
// in any gate's scope because every gate named docker-compose.yml).
func composeArtifacts(t *testing.T) []string {
	t.Helper()
	var out []string
	root, err := filepath.Glob("docker-compose*.yml")
	if err != nil {
		t.Fatalf("glob root compose files: %v", err)
	}
	out = append(out, root...)
	if err := filepath.WalkDir("test", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if base := filepath.Base(path); strings.HasPrefix(base, "docker-compose") && strings.HasSuffix(base, ".yml") {
			out = append(out, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk test/ for compose files: %v", err)
	}
	sort.Strings(out)
	if len(out) < 5 {
		t.Fatalf("discovered only %d compose artifacts (%v) — the walk is broken, not the repository", len(out), out)
	}
	return out
}

// ── Dockerfile ENTRYPOINT / CMD ───────────────────────────────────────────────

var dockerExecFormRE = regexp.MustCompile(`(?s)^\s*(ENTRYPOINT|CMD)\s*\[(.*?)\]`)

// dockerfileArgv returns the image's exec-form ENTRYPOINT and CMD token lists.
// Backslash continuations are joined first so a multi-line CMD array parses.
func dockerfileArgv(t *testing.T) (entrypoint, cmd []string) {
	t.Helper()
	raw, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	joined := strings.ReplaceAll(string(raw), "\\\n", " ")
	quoted := regexp.MustCompile(`"([^"]*)"`)
	for _, line := range strings.Split(joined, "\n") {
		m := dockerExecFormRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var toks []string
		for _, q := range quoted.FindAllStringSubmatch(m[2], -1) {
			toks = append(toks, q[1])
		}
		if m[1] == "ENTRYPOINT" {
			entrypoint = toks
		} else {
			cmd = toks
		}
	}
	if len(entrypoint) == 0 {
		t.Fatal("Dockerfile declares no exec-form ENTRYPOINT — this gate's whole premise (command is APPENDED to it) no longer holds; re-derive it before deleting the gate")
	}
	return entrypoint, cmd
}

// ── Compose parsing ───────────────────────────────────────────────────────────

// composeService is one service as the gates need to see it. `raw` is kept so
// a key's PRESENCE can be told from its zero value — `command: []` (clear the
// image CMD) is a different instruction from no `command:` key at all.
type composeService struct {
	file string
	name string
	raw  map[string]any
}

func parseComposeFile(t *testing.T, path string) []composeService {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	names := make([]string, 0, len(doc.Services))
	for n := range doc.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]composeService, 0, len(names))
	for _, n := range names {
		out = append(out, composeService{file: path, name: n, raw: doc.Services[n]})
	}
	return out
}

func (s composeService) id() string { return s.file + ":" + s.name }

// runsCulvert reports whether this service runs the culvert image — built from
// this repository's Dockerfile, or a culvert image tag.
func (s composeService) runsCulvert() bool {
	if _, ok := s.raw["build"]; ok {
		return true
	}
	img, _ := s.raw["image"].(string)
	return strings.Contains(img, "culvert")
}

// supervised reports whether the service is a long-lived container Docker will
// restart — the only shape for which a stop grace means anything. A one-shot
// `cli` service exits on its own and is invoked through `compose run`, which
// replaces its command entirely.
func (s composeService) supervised() bool {
	_, ok := s.raw["restart"]
	return ok
}

// tokens normalizes a command/entrypoint value to an argv list, returning
// present=false only when the key is absent (so the image's own value applies).
// A string value is shell-form, which Compose word-splits; only the leading
// token matters to every gate here, so a whitespace split is sufficient and is
// documented as such rather than pretending to be a shell lexer.
func (s composeService) tokens(key string) (argv []string, present bool) {
	v, ok := s.raw[key]
	if !ok {
		return nil, false
	}
	switch t := v.(type) {
	case string:
		return strings.Fields(t), true
	case []any:
		for _, e := range t {
			argv = append(argv, fmt.Sprint(e))
		}
		return argv, true
	case nil:
		return nil, true
	default:
		return []string{fmt.Sprint(t)}, true
	}
}

// ── Gate 1: the command reaches the binary as flags ──────────────────────────

const culvertBinary = "culvert"

// checkCommandReachesBinary returns one violation string per service whose
// effective argv would discard the flags it declares. Pure, so the pre-fix
// shape can be fed to it as a negative control.
func checkCommandReachesBinary(svcs []composeService, imgEntrypoint, imgCmd []string) []string {
	var viol []string
	for _, s := range svcs {
		if !s.runsCulvert() {
			continue
		}
		entry, ok := s.tokens("entrypoint")
		if !ok {
			entry = imgEntrypoint
		}
		cmd, ok := s.tokens("command")
		if !ok {
			cmd = imgCmd
		}
		if len(entry) == 0 {
			viol = append(viol, fmt.Sprintf("%s: empty effective entrypoint", s.id()))
			continue
		}
		if filepath.Base(entry[0]) == culvertBinary {
			viol = append(viol, checkBinaryEntrypoint(s, entry, cmd)...)
			continue
		}
		viol = append(viol, checkShellEntrypoint(s, entry, cmd)...)
	}
	return viol
}

// checkBinaryEntrypoint covers the ordinary shape: the binary is argv[0], so
// everything after it must be flags.
func checkBinaryEntrypoint(s composeService, entry, cmd []string) []string {
	argv := append(append([]string{}, entry...), cmd...)
	if len(argv) < 2 {
		return nil // no arguments at all: nothing can be silently dropped
	}
	if strings.HasPrefix(argv[1], "-") {
		return nil
	}
	return []string{fmt.Sprintf(
		"%s: the image entrypoint is %q, so `command:` is APPENDED to it — the container argv is %q and Go's flag package stops at the first non-flag token %q, "+
			"silently discarding every flag after it and booting with all defaults (no -ca-path/-policy/-audit-log/-cluster-db/-clamav-addr, no -cp-grpc-addr, no --ha-join/--ha-token, no --enroll) while still passing /health. "+
			"Pass a FLAG LIST, or move the shell into `entrypoint: [\"/bin/sh\", \"-c\"]` and `exec` the binary from it",
		s.id(), strings.Join(entry, " "), strings.Join(argv, " "), argv[1])}
}

// checkShellEntrypoint covers the deliberate shape: a shell entrypoint that
// must hand the process over with `exec`, so culvert is PID 1 and receives the
// SIGTERM the whole shutdown envelope is built on. A shell that merely forks
// the binary keeps PID 1 for itself and swallows the signal.
func checkShellEntrypoint(s composeService, entry, cmd []string) []string {
	script := strings.Join(cmd, " ")
	if strings.Contains(script, "exec ./"+culvertBinary) || strings.Contains(script, "exec ."+string(filepath.Separator)+culvertBinary) {
		return nil
	}
	return []string{fmt.Sprintf(
		"%s: entrypoint %q is a shell, so the script it runs must hand the process over with `exec ./%s` — otherwise the shell stays PID 1 and SIGTERM never reaches the binary, so none of the bounded shutdown sequence runs",
		s.id(), strings.Join(entry, " "), culvertBinary)}
}

func TestChaos121_ComposeCommandReachesTheBinaryAsFlags(t *testing.T) {
	entrypoint, cmd := dockerfileArgv(t)
	var all []composeService
	for _, f := range composeArtifacts(t) {
		all = append(all, parseComposeFile(t, f)...)
	}
	culvertSvcs := 0
	for _, s := range all {
		if s.runsCulvert() {
			culvertSvcs++
		}
	}
	if culvertSvcs < 4 {
		t.Fatalf("only %d culvert services discovered across the compose artifacts — the gate is looking at nothing", culvertSvcs)
	}
	for _, v := range checkCommandReachesBinary(all, entrypoint, cmd) {
		t.Error(v)
	}
}

// TestChaos121_CommandCheckRejectsThePreFixShape is the negative control: the
// exact docker-compose.ha.yml shape that shipped must be reported, and the
// shape that replaced it must not be. Without this, the gate above could be
// asserting nothing.
func TestChaos121_CommandCheckRejectsThePreFixShape(t *testing.T) {
	const script = "ARGS=\"-port 8080 -cluster-db /data/cluster.json\"\nexec ./culvert $ARGS\n"
	imgEntry := []string{"./culvert"}
	imgCmd := []string{"-port", "8080"}

	preFix := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build":   ".",
		"command": "sh -c '" + script + "'",
	}}
	if got := checkCommandReachesBinary([]composeService{preFix}, imgEntry, imgCmd); len(got) == 0 {
		t.Error("the pre-fix shape (shell command, no entrypoint override) was accepted — the gate proves nothing")
	} else if !strings.Contains(got[0], "first non-flag token") {
		t.Errorf("violation does not name the mechanism: %q", got[0])
	}

	fixed := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build":      ".",
		"entrypoint": []any{"/bin/sh", "-c"},
		"command":    []any{script},
	}}
	if got := checkCommandReachesBinary([]composeService{fixed}, imgEntry, imgCmd); len(got) != 0 {
		t.Errorf("the fixed shape was rejected: %v", got)
	}

	// A shell entrypoint that FORKS the binary instead of exec'ing it keeps
	// PID 1 and swallows SIGTERM — a different defect in the same place.
	forked := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build":      ".",
		"entrypoint": []any{"/bin/sh", "-c"},
		"command":    []any{"./culvert -port 8080\n"},
	}}
	if got := checkCommandReachesBinary([]composeService{forked}, imgEntry, imgCmd); len(got) == 0 {
		t.Error("a shell entrypoint that does not exec the binary was accepted — SIGTERM would never reach it")
	}

	// Control: a flag list is the ordinary correct shape and must pass.
	flagList := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"image":   "culvert/proxy:pinned",
		"command": []any{"-port", "8080"},
	}}
	if got := checkCommandReachesBinary([]composeService{flagList}, imgEntry, imgCmd); len(got) != 0 {
		t.Errorf("a plain flag list was rejected: %v", got)
	}
}

// ── Gate 2: stop_grace_period covers the shutdown envelope ───────────────────

// chaos121GraceKnownGaps records, per "<file>:<service>", a supervised culvert
// service that declares no stop_grace_period, with the reason it is acceptable.
// The map IS the mechanism, in the shape CHAOS-113 established for
// scanAlertGUIKnownGaps: REMOVING an entry is the fix, and ADDING one is a
// deliberate statement that this container may be SIGKILLed mid-drain.
//
// Every entry below is a CI fixture, never a shipped deployment. They are
// recorded rather than changed because this round cannot execute them, and
// because the maint-agent fixtures' 10s default is itself worth stating: the
// upgrade path they exercise recreates the container, so they test that restart
// with a grace the production artifact does not use (CHAOS-121 residual risk).
// docker-compose.ci.yml is deliberately absent: it is an overlay fragment with
// no `restart:` key of its own, so it is not a supervised service and inherits
// docker-compose.yml's 60s grace. The gate's own stale-entry check caught an
// earlier draft that listed it.
var chaos121GraceKnownGaps = map[string]string{
	"test/e2e/maint-agent/docker-compose.e2e.yml:proxy":            "CI fixture for the maintenance-agent upgrade flow; see residual risk — it exercises a container recreate at Docker's 10s default rather than the shipped 60s",
	"test/e2e/maint-agent/docker-compose.backup-e2e.yml:proxy":     "CI fixture, same as docker-compose.e2e.yml",
	"test/e2e/catalog-update/docker-compose.catalog-e2e.yml:proxy": "CI fixture whose scenario deliberately SIGKILLs the dispatcher mid-flight (the file's own header says so), so a grace would change what it tests",
}

// checkStopGrace returns one violation per supervised culvert service whose
// declared stop grace does not strictly exceed the worst-case envelope, plus
// one per stale known-gap entry.
func checkStopGrace(svcs []composeService, worst time.Duration) []string {
	var viol []string
	seen := map[string]bool{}
	for _, s := range svcs {
		if !s.runsCulvert() || !s.supervised() {
			continue
		}
		rawGrace, ok := s.raw["stop_grace_period"]
		if !ok {
			if reason, excused := chaos121GraceKnownGaps[s.id()]; excused {
				seen[s.id()] = true
				_ = reason
				continue
			}
			viol = append(viol, fmt.Sprintf(
				"%s: no stop_grace_period, so Docker's DEFAULT 10s applies against a %v worst-case shutdown envelope — the container is SIGKILLed inside the EARLY phase, "+
					"skipping the whole drain (in-flight tunnels severed rather than drained) and the ENTIRE durability reserve (cluster store, request log, a clean badger close, the audit log)",
				s.id(), worst))
			continue
		}
		seen[s.id()] = true
		grace, err := time.ParseDuration(fmt.Sprint(rawGrace))
		if err != nil {
			viol = append(viol, fmt.Sprintf("%s: stop_grace_period %q does not parse as a duration", s.id(), rawGrace))
			continue
		}
		if grace <= worst {
			viol = append(viol, fmt.Sprintf(
				"%s: stop_grace_period %v does not exceed the %v worst-case shutdown envelope — the container will SIGKILL mid-sequence, skipping the durable flushes",
				s.id(), grace, worst))
		}
	}
	for id := range chaos121GraceKnownGaps {
		if !seen[id] {
			viol = append(viol, fmt.Sprintf(
				"chaos121GraceKnownGaps names %q, which is no longer a supervised culvert service without a grace — remove the entry (that removal IS the fix being recorded)", id))
		}
	}
	return viol
}

func TestChaos121_ComposeStopGraceCoversTheShutdownEnvelope(t *testing.T) {
	// The same worst case TestChaos56_EnvelopeFitsTheContainerStopGrace
	// computes, derived from the constants rather than restated.
	worst := defaultShutdownBudget.Total + 2*shutdownHookGrace

	var all []composeService
	for _, f := range composeArtifacts(t) {
		all = append(all, parseComposeFile(t, f)...)
	}
	for _, v := range checkStopGrace(all, worst) {
		t.Error(v)
	}
}

// TestChaos121_StopGraceCheckRejectsTheDockerDefault is the negative control
// for gate 2, including the case the shipped artifact actually had (the key
// absent entirely) and the case a well-meaning edit would produce (a grace
// that is present but too small).
func TestChaos121_StopGraceCheckRejectsTheDockerDefault(t *testing.T) {
	worst := 51 * time.Second

	absent := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build": ".", "restart": "unless-stopped",
	}}
	if got := checkStopGrace([]composeService{absent}, worst); len(got) == 0 {
		t.Error("a supervised culvert service with NO stop_grace_period was accepted — this is exactly the shipped docker-compose.ha.yml shape")
	}

	tooSmall := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build": ".", "restart": "unless-stopped", "stop_grace_period": "30s",
	}}
	if got := checkStopGrace([]composeService{tooSmall}, worst); len(got) == 0 {
		t.Error("a 30s grace was accepted against a 51s envelope")
	}

	enough := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build": ".", "restart": "unless-stopped", "stop_grace_period": "60s",
	}}
	// Filter the stale-entry violations the synthetic input necessarily
	// produces: this control is about the grace comparison, not the map.
	var real []string
	for _, v := range checkStopGrace([]composeService{enough}, worst) {
		if !strings.Contains(v, "chaos121GraceKnownGaps names") {
			real = append(real, v)
		}
	}
	if len(real) != 0 {
		t.Errorf("a 60s grace was rejected against a 51s envelope: %v", real)
	}

	// Control: a one-shot service is not supervised and needs no grace.
	oneShot := composeService{file: "synthetic", name: "cli", raw: map[string]any{
		"image": "culvert/proxy:pinned", "command": []any{"-h"},
	}}
	for _, v := range checkStopGrace([]composeService{oneShot}, worst) {
		if !strings.Contains(v, "chaos121GraceKnownGaps names") {
			t.Errorf("a one-shot cli service was required to declare a grace: %s", v)
		}
	}
}

// ── Gate 3: wait for ClamAV to be HEALTHY, not merely started ────────────────

// checkClamAVDependency returns one violation per culvert service that depends
// on clamav with the short-form list, which waits only for the container to
// START.
func checkClamAVDependency(svcs []composeService) []string {
	var viol []string
	for _, s := range svcs {
		if !s.runsCulvert() {
			continue
		}
		dep, ok := s.raw["depends_on"]
		if !ok {
			continue
		}
		switch d := dep.(type) {
		case []any:
			for _, e := range d {
				if fmt.Sprint(e) == "clamav" {
					viol = append(viol, fmt.Sprintf(
						"%s: short-form `depends_on: [clamav]` waits only for the clamav container to START, not for its healthcheck to pass — "+
							"ClamAV's own healthcheck carries start_period: 300s for the first-boot signature download, and an unreachable ClamAV is FAIL-OPEN "+
							"(bodies forwarded with no antivirus verdict), so every boot and node reboot has an unscanned window. Use `clamav: {condition: service_healthy}`",
						s.id()))
				}
			}
		case map[string]any:
			entry, has := d["clamav"]
			if !has {
				continue
			}
			cond := ""
			if m, ok := entry.(map[string]any); ok {
				cond = fmt.Sprint(m["condition"])
			}
			if cond != "service_healthy" {
				viol = append(viol, fmt.Sprintf("%s: depends_on clamav condition is %q, want \"service_healthy\"", s.id(), cond))
			}
		}
	}
	return viol
}

func TestChaos121_ComposeWaitsForClamAVHealth(t *testing.T) {
	var all []composeService
	for _, f := range composeArtifacts(t) {
		all = append(all, parseComposeFile(t, f)...)
	}
	for _, v := range checkClamAVDependency(all) {
		t.Error(v)
	}
}

// TestChaos121_ClamAVDependencyCheckRejectsTheShortForm is the negative control
// for gate 3.
func TestChaos121_ClamAVDependencyCheckRejectsTheShortForm(t *testing.T) {
	short := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build": ".", "depends_on": []any{"clamav"},
	}}
	if got := checkClamAVDependency([]composeService{short}); len(got) == 0 {
		t.Error("short-form depends_on was accepted — this is the shipped docker-compose.ha.yml shape")
	}

	long := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build": ".", "depends_on": map[string]any{
			"clamav": map[string]any{"condition": "service_healthy"},
		},
	}}
	if got := checkClamAVDependency([]composeService{long}); len(got) != 0 {
		t.Errorf("the long form with service_healthy was rejected: %v", got)
	}

	started := composeService{file: "synthetic", name: "proxy", raw: map[string]any{
		"build": ".", "depends_on": map[string]any{
			"clamav": map[string]any{"condition": "service_started"},
		},
	}}
	if got := checkClamAVDependency([]composeService{started}); len(got) == 0 {
		t.Error("condition: service_started was accepted — it is the long-form spelling of the same defect")
	}
}
