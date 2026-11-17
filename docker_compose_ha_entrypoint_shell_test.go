package main

// docker_compose_ha_entrypoint_shell_test.go — deployment-artifact contract
// for docker-compose.ha.yml.
//
// The HA `proxy` and `dp` services build the repo Dockerfile (`build: .`) and
// carry their whole startup contract in a `command: sh -c '... exec ./culvert
// $$ARGS'` script: the /data persistence flags, the ClamAV/YARA wiring, the
// cluster DB, the HA_JOIN/HA_TOKEN standby join (and its empty-token refusal),
// the DP --enroll URL and the enterprise gRPC TLS flags.
//
// The Dockerfile's final stage declares ENTRYPOINT ["./culvert"], and Compose
// APPENDS `command` to the image ENTRYPOINT unless the service overrides
// `entrypoint:`. Without an override the container runs
// `./culvert sh -c '<script>'`: Go's flag parsing stops at the first non-flag
// ("sh"), the script never executes, and the node boots HEALTHY (the
// healthcheck probes the default :8080) with every flag at its default —
// in-memory roster/CA/policy, no AV, and a standby that never joins Server A.
//
// The effective argv[0] (entrypoint, else the image ENTRYPOINT, followed by
// command) must therefore be the shell itself.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestDockerComposeHA_ShellCommandRunsAsShell(t *testing.T) {
	df, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	stages := regexp.MustCompile(`(?m)^FROM `).Split(string(df), -1)
	m := regexp.MustCompile(`(?m)^ENTRYPOINT\s+\[(.*)\]\s*$`).FindStringSubmatch(stages[len(stages)-1])
	if m == nil {
		t.Fatal("final Dockerfile stage has no exec-form ENTRYPOINT; update this contract")
	}
	var imageEntrypoint []string
	if err := yaml.Unmarshal([]byte("["+m[1]+"]"), &imageEntrypoint); err != nil {
		t.Fatalf("parse Dockerfile ENTRYPOINT %q: %v", m[1], err)
	}

	raw, err := os.ReadFile("docker-compose.ha.yml")
	if err != nil {
		t.Fatalf("read docker-compose.ha.yml: %v", err)
	}
	var doc struct {
		Services map[string]struct {
			Build      any       `yaml:"build"`
			Entrypoint *[]string `yaml:"entrypoint"`
			Command    string    `yaml:"command"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse docker-compose.ha.yml: %v", err)
	}

	for _, name := range []string{"proxy", "dp"} {
		svc, ok := doc.Services[name]
		if !ok {
			t.Fatalf("docker-compose.ha.yml has no %q service", name)
		}
		if svc.Build == nil {
			t.Fatalf("service %q no longer builds the repo Dockerfile; update this contract", name)
		}
		cmd := strings.Fields(svc.Command)
		if len(cmd) < 2 || cmd[0] != "sh" || cmd[1] != "-c" {
			t.Fatalf("service %q command is no longer `sh -c ...`; update this contract", name)
		}
		entry := imageEntrypoint
		if svc.Entrypoint != nil {
			entry = *svc.Entrypoint
		}
		argv := append(append([]string{}, entry...), cmd[:2]...)
		if argv[0] != "sh" && argv[0] != "/bin/sh" {
			t.Errorf("service %q runs as %q: the image ENTRYPOINT is prepended to the `sh -c` command, "+
				"so the startup script never runs and every flag in it is ignored; set `entrypoint: []`",
				name, argv)
		}
	}
}
