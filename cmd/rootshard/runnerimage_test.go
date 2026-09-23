package main

import "testing"

// The shard records the hosted runner image it ran on, from the runner's own
// environment, and records nothing when that environment is absent.
func TestRunnerImage_FromHostedRunnerEnvironment(t *testing.T) {
	env := map[string]string{"ImageOS": "ubuntu24", "ImageVersion": " 20260915.1 "}
	if img, ver := runnerImage(func(k string) string { return env[k] }); img != "ubuntu24" || ver != "20260915.1" {
		t.Errorf("image %q version %q", img, ver)
	}
	if img, ver := runnerImage(func(string) string { return "" }); img != "" || ver != "" {
		t.Errorf("off a hosted runner the image must be empty, not guessed: %q %q", img, ver)
	}
}
