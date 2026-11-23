package server

import (
	"regexp"
	"testing"

	"culvert-maint/internal/config"
	"culvert-maint/internal/runner"
)

func evidenceServer() *Server {
	return &Server{opts: Options{Cfg: &config.Config{
		ImageAllowlist: regexp.MustCompile(`^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`)}}}
}

func capture(id string, refs ...string) *runner.RunningProxyImage {
	return &runner.RunningProxyImage{RunningImageID: id, RepoDigests: refs}
}

// The evidence rule, case by case (owner decision 2).
func TestRunningEvidence_VerifiedOnlyByACaptureAfterTheLastUp(t *testing.T) {
	s := evidenceServer()
	reg := repo + "@sha256:" + digNew
	local := "culvert/proxy@sha256:" + digOld // containerd store: synthetic local reference
	cases := []struct {
		name     string
		steps    func(e *runningEvidence)
		want     finalRunning
		negative string // what a guessing implementation would report instead
	}{
		{"nothing captured", func(*runningEvidence) {}, finalRunning{state: finalRunningUnverified}, "the target digest"},
		{"captured, then up ran", func(e *runningEvidence) { e.noteCapture(capture("sha256:"+cfgOld, reg)); e.noteUp() },
			finalRunning{state: finalRunningUnverified}, "the pre-up image"},
		{"up, then captured", func(e *runningEvidence) { e.noteUp(); e.noteCapture(capture("sha256:"+cfgNew, reg)) },
			finalRunning{state: finalRunningVerified, digest: "sha256:" + digNew, imageID: "sha256:" + cfgNew}, ""},
		{"registry ref after a local one", func(e *runningEvidence) { e.noteCapture(capture("sha256:"+cfgNew, local, reg)) },
			finalRunning{state: finalRunningVerified, digest: "sha256:" + digNew, imageID: "sha256:" + cfgNew}, "the local digest"},
		{"only a local reference: no registry digest", func(e *runningEvidence) { e.noteCapture(capture("sha256:"+digOld, local)) },
			finalRunning{state: finalRunningVerified, digest: "", imageID: "sha256:" + digOld}, "the local digest as a registry digest"},
		{"non-allow-listed repository", func(e *runningEvidence) {
			e.noteCapture(capture("sha256:"+cfgNew, "evil.example/culvert@sha256:"+digNew))
		},
			finalRunning{state: finalRunningVerified, imageID: "sha256:" + cfgNew}, "a digest from another repository"},
		{"latest capture wins", func(e *runningEvidence) {
			e.noteCapture(capture("sha256:"+cfgOld, repo+"@sha256:"+digOld))
			e.noteUp()
			e.noteCapture(capture("sha256:"+cfgNew, reg))
		}, finalRunning{state: finalRunningVerified, digest: "sha256:" + digNew, imageID: "sha256:" + cfgNew}, ""},
	}
	for _, c := range cases {
		var e runningEvidence
		c.steps(&e)
		if got := s.finalRunningFrom(&e); got != c.want {
			t.Errorf("%s: got %+v, want %+v (a guessing implementation would report %s)", c.name, got, c.want, c.negative)
		}
	}
	// nil evidence (the standalone rollback handler's) ignores every call and is unverified.
	var nilEv *runningEvidence
	nilEv.noteUp()
	nilEv.noteCapture(capture("sha256:"+cfgNew, reg))
	if got := s.finalRunningFrom(nilEv); got.state != finalRunningUnverified {
		t.Errorf("nil evidence must be unverified, got %+v", got)
	}
}

// End to end through the real apply flow: whatever the scenario, a "verified" result names
// exactly the image the fake Docker world runs, and an unverified one names nothing.
func TestApply_FinalRunning_NeverReportsAGuessAsVerified(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(rig *applyRig)
		body      map[string]interface{}
		wantState string
		wantRun   string // digest the world runs at the end (asserted, so the case is what it claims)
	}{
		{"upgrade succeeds", func(*applyRig) {}, nil, finalRunningVerified, digNew},
		{"health fails, rollback succeeds", func(rig *applyRig) { rig.unhealthyDigests = map[string]bool{digNew: true} },
			nil, finalRunningVerified, digOld},
		// The rollback's own health gate fails, so rollback_verify never runs: today's code
		// inferred the prior digest here; the bounded final capture now establishes it.
		{"rollback restarted but its health fails", func(rig *applyRig) {
			rig.unhealthyDigests = map[string]bool{digNew: true, digOld: true}
		}, nil, finalRunningVerified, digOld},
		{"up fails before recreating, rollback disabled", func(rig *applyRig) {
			rig.dockerModel = true
			rig.failFn = failUpgradeUpBeforeRecreate(rig)
		}, map[string]interface{}{"rollback_on_failure": false}, finalRunningVerified, digOld},
		{"up fails after recreating, container down", func(rig *applyRig) {
			rig.dockerModel = true
			rig.failFn = failUpgradeUpAfterRecreate(rig)
		}, map[string]interface{}{"rollback_on_failure": false}, finalRunningUnverified, digNew},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rig := startApplyRig(t)
			defer rig.stop()
			c.setup(rig)
			body := map[string]interface{}{"image_ref": repo + "@sha256:" + digNew}
			for k, v := range c.body {
				body[k] = v
			}
			op, _ := rig.acceptAndWait(t, body)
			res := resultMap(t, op)
			if got := rig.currentRunning(); got != c.wantRun {
				t.Fatalf("scenario setup: the world runs %s, want %s", short(got), short(c.wantRun))
			}
			state, digest, id := res["final_running_state"], res["final_running_digest"], res["final_running_image_id"]
			if state != c.wantState {
				t.Fatalf("final_running_state = %v, want %v (digest=%v image_id=%v)", state, c.wantState, digest, id)
			}
			switch state {
			case finalRunningVerified:
				if digest != "sha256:"+rig.currentRunning() || id == "" {
					t.Errorf("verified result must name the running image: digest=%v image_id=%v, running %s",
						digest, id, short(rig.currentRunning()))
				}
			default:
				if digest != "" || id != "" {
					t.Errorf("unverified result must not name an image: digest=%v image_id=%v", digest, id)
				}
			}
		})
	}
}
