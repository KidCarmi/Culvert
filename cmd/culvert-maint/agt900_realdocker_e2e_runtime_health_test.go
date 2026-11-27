//go:build agt900_e2e

// Real-Docker rows for the runtime health observer (ADR-0062 slice 5,
// contract AGT-007). The observer runs at its smallest interval (1m); every
// row also proves it changed nothing: the shim's call log holds no mutating
// docker command, and the journal and audit log are untouched.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const e2eHealthEvery = "1m"

// e2eHealthView is the runtime_health part of GET /v1/status.
type e2eHealthView struct {
	RuntimeHealth *struct {
		State      string     `json:"state"`
		Reason     string     `json:"reason"`
		ObservedAt *time.Time `json:"observed_at"`
		ImageID    string     `json:"image_id"`
		Error      string     `json:"error"`
		LastGood   *struct {
			ImageID string `json:"image_id"`
			Ref     string `json:"ref"`
			Digest  string `json:"digest"`
		} `json:"last_good"`
		LastGoodError string `json:"last_good_error"`
	} `json:"runtime_health"`
}

func (v e2eHealthView) String() string {
	h := v.RuntimeHealth
	if h == nil {
		return "absent"
	}
	lg := "none"
	if h.LastGood != nil {
		lg = e2eNormID(h.LastGood.ImageID)
	}
	return fmt.Sprintf("%s/%s image=%s last_good=%s", h.State, h.Reason, e2eNormID(h.ImageID), lg)
}

// health reads runtime_health.
func (p *agentProc) health() e2eHealthView {
	var v e2eHealthView
	_, _ = p.get("/v1/status", &v)
	return v
}

// waitHealth polls runtime_health until ok holds or d passes; it returns the
// last view and every distinct observed_at seen on the way.
func (p *agentProc) waitHealth(d time.Duration, ok func(e2eHealthView) bool) (e2eHealthView, []time.Time) {
	var seen []time.Time
	deadline := time.Now().Add(d)
	for {
		v := p.health()
		if h := v.RuntimeHealth; h != nil && h.ObservedAt != nil && (len(seen) == 0 || !seen[len(seen)-1].Equal(*h.ObservedAt)) {
			seen = append(seen, *h.ObservedAt)
		}
		if ok(v) || time.Now().After(deadline) {
			return v, seen
		}
		time.Sleep(2 * time.Second)
	}
}

func healthIs(state, reason, imageID string) func(e2eHealthView) bool {
	return func(v e2eHealthView) bool {
		h := v.RuntimeHealth
		return h != nil && h.State == state && (reason == "" || h.Reason == reason) && (imageID == "" || e2eNormID(h.ImageID) == imageID)
	}
}

// lastGoodFile is last_good.json as the agent wrote it ("" when absent).
func (r *e2eRig) lastGoodFile() string {
	b, err := os.ReadFile(filepath.Join(r.state, "health", "last_good.json")) // #nosec G304 -- harness-owned state dir
	if err != nil {
		return ""
	}
	return string(b)
}

// untouched is what the observer must never write: journal records and audit
// entries.
func (r *e2eRig) untouched() string {
	ents, _ := os.ReadDir(filepath.Join(r.state, "reconcile"))
	n := 0
	for _, en := range ents {
		if strings.HasSuffix(en.Name(), ".json") {
			n++
		}
	}
	a, _ := os.ReadFile(filepath.Join(r.state, "audit.jsonl")) // #nosec G304 -- harness-owned state dir
	return fmt.Sprintf("records=%d audit_lines=%d", n, strings.Count(string(a), "\n"))
}

// observeRig starts an "off"-mode agent with the observer on.
func (e *e2eEnv) observeRig(t *testing.T, name string, res *e2eResult) (*e2eRig, *agentProc) {
	r := newE2ERig(t, e, name)
	r.res = res
	r.cfgExtra = fmt.Sprintf("runtime_health_interval = %q\n", e2eHealthEvery)
	p := r.start("off", "2m")
	return r, p
}

// The first tick is one interval after start; the settle window of a first
// start (75s) skips it, so the first sample can take two intervals.
const e2eFirstSample = 200 * time.Second
const e2eNextSample = 100 * time.Second

func (r *e2eRig) noMutation(res *e2eResult, p *agentProc, base string) {
	res.eq("no mutating docker command", "[]", "["+strings.Join(r.mutating(p), ",")+"]")
	res.eq("no journal record or audit entry", base, r.untouched())
}

// obs_gated_unhealthy_stopped: the running prior is gated and becomes
// last_good; a failing /ready and then a stopped proxy are each reported
// unhealthy and leave last_good byte for byte.
func (e *e2eEnv) caseObserveGatedThenBad(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "gated prior + last_good=prior; then unhealthy/not_ready; then unhealthy/no_proxy_container; last_good unchanged, Docker unchanged"}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r, p := e.observeRig(t, name, res)
	defer r.killProc(p)
	base := r.untouched()
	prior := e.snap().Image
	v, _ := p.waitHealth(e2eFirstSample, healthIs("gated", "gate_passed", prior))
	res.eq("first sample", "gated/gate_passed image="+shortID(prior)+" last_good="+shortID(prior), shortView(v))
	if lg := v.RuntimeHealth; lg != nil && lg.LastGood != nil {
		res.eq("last_good ref", e.ref("prior"), lg.LastGood.Ref)
	}
	good := r.lastGoodFile()
	res.check("last_good.json written", good != "", "present", fmt.Sprint(good != ""))

	if err := os.WriteFile(e.ctlFile("fail_ready_prior"), []byte("1\n"), 0o644); err != nil { // #nosec G306 -- read by the fake proxy as another uid
		res.err = err.Error()
		return
	}
	v, _ = p.waitHealth(e2eNextSample, healthIs("unhealthy", "not_ready", prior))
	res.eq("after /ready fails", "unhealthy/not_ready", stateOf(v))
	res.check("last_good unchanged after a failed gate", r.lastGoodFile() == good, "unchanged", "changed")
	_ = os.Remove(e.ctlFile("fail_ready_prior"))

	s := e.snap()
	if _, err := e.docker("stop", s.ContainerID); err != nil {
		res.err = err.Error()
		return
	}
	v, _ = p.waitHealth(e2eNextSample, healthIs("unhealthy", "", ""))
	res.check("after docker stop", stateOf(v) == "unhealthy/no_proxy_container" || stateOf(v) == "unhealthy/container_not_running",
		"unhealthy/no_proxy_container or container_not_running", stateOf(v))
	res.check("last_good unchanged after the proxy stopped", r.lastGoodFile() == good, "unchanged", "changed")
	res.observed = v.String()
	r.noMutation(res, p, base)
}

// obs_hand_retag: an operator moves the tag and recreates by hand. Status says
// ungated at once (the sample is of another image); the next sample gates the
// new image and last_good follows it.
func (e *e2eEnv) caseObserveHandRetag(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "gated prior; after a hand retag+up to good: ungated at once, then gated good and last_good=good; the agent ran no mutating command"}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r, p := e.observeRig(t, name, res)
	defer r.killProc(p)
	base := r.untouched()
	prior := e.snap().Image
	v, _ := p.waitHealth(e2eFirstSample, healthIs("gated", "gate_passed", prior))
	res.eq("first sample", "gated/gate_passed", stateOf(v))

	if _, err := e.docker("pull", "-q", e.ref("good")); err != nil {
		res.err = err.Error()
		return
	}
	if _, err := e.docker("tag", e.ref("good"), e2ePinned); err != nil {
		res.err = err.Error()
		return
	}
	if _, err := e.docker(e.composeArgs("up", "-d")...); err != nil {
		res.err = err.Error()
		return
	}
	if err := e.waitReady(90 * time.Second); err != nil {
		res.err = err.Error()
		return
	}
	goodID := e.snap().Image
	v = p.health()
	res.eq("right after the hand recreate", "ungated/running_image_not_observed", stateOf(v))
	v, _ = p.waitHealth(e2eNextSample, healthIs("gated", "gate_passed", goodID))
	res.eq("next sample", "gated/gate_passed image="+shortID(goodID), stateOf(v)+" image="+shortID(e2eNormID(v.imageID())))
	if h := v.RuntimeHealth; h != nil && h.LastGood != nil {
		res.eq("last_good follows the newly gated image", e.ref("good"), h.LastGood.Ref)
	} else {
		res.check("last_good present", false, "good", "none")
	}
	res.observed = v.String()
	r.noMutation(res, p, base)
}

// obs_upgrade: an upgrade runs while the observer is on. No sample is kept
// while the upgrade holds the lock; afterwards the new image is gated.
func (e *e2eEnv) caseObserveAcrossUpgrade(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "upgrade succeeds; no sample observed inside it; afterwards gated good, last_good=good"}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r, p := e.observeRig(t, name, res)
	defer r.killProc(p)
	v, _ := p.waitHealth(e2eFirstSample, healthIs("gated", "gate_passed", ""))
	res.eq("before the upgrade", "gated/gate_passed", stateOf(v))
	from := time.Now()
	opID, err := r.apply(p, "good")
	if err != nil {
		res.err = err.Error()
		return
	}
	var inside []time.Time
	done := make(chan opView, 1)
	go func() { done <- p.waitOp(opID, 10*time.Minute) }()
	var op opView
	for waiting := true; waiting; {
		select {
		case op = <-done:
			waiting = false
		case <-time.After(2 * time.Second):
			if h := p.health().RuntimeHealth; h != nil && h.ObservedAt != nil && h.ObservedAt.After(from.Add(2*time.Second)) {
				inside = append(inside, *h.ObservedAt)
			}
		}
	}
	to := time.Now()
	res.eq("upgrade", "succeeded", op.State)
	kept := 0
	for _, at := range inside {
		if at.Before(to.Add(-2 * time.Second)) {
			kept++
		}
	}
	res.eq("samples kept while the upgrade held the lock", "0", fmt.Sprint(kept))
	goodID := e.snap().Image
	v, _ = p.waitHealth(e2eNextSample+30*time.Second, healthIs("gated", "gate_passed", goodID))
	res.eq("after the upgrade", "gated/gate_passed", stateOf(v))
	if h := v.RuntimeHealth; h != nil && h.LastGood != nil {
		res.eq("last_good", e.ref("good"), h.LastGood.Ref)
	}
	res.observed = fmt.Sprintf("op %s; %s", op.State, v)
}

// obs_off: without the key nothing is sampled, nothing is written and status
// is unchanged.
func (e *e2eEnv) caseObserveOff(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "no runtime_health in status, no health directory, no docker call beyond status reads"}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	p := r.start("off", "2m")
	defer r.killProc(p)
	time.Sleep(75 * time.Second)
	raw := map[string]json.RawMessage{}
	_, _ = p.get("/v1/status", &raw)
	_, has := raw["runtime_health"]
	_, statErr := os.Stat(filepath.Join(r.state, "health"))
	res.check("no runtime_health in status", !has, "absent", fmt.Sprint(has))
	res.check("no health directory", os.IsNotExist(statErr), "absent", fmt.Sprint(statErr))
	res.eq("no mutating docker command", "[]", "["+strings.Join(r.mutating(p), ",")+"]")
	res.observed = fmt.Sprintf("runtime_health present=%v health dir err=%v", has, statErr)
}

func (v e2eHealthView) imageID() string {
	if v.RuntimeHealth == nil {
		return ""
	}
	return v.RuntimeHealth.ImageID
}

func shortID(id string) string { return short(e2eNormID(id)) }

func stateOf(v e2eHealthView) string {
	if v.RuntimeHealth == nil {
		return "absent"
	}
	return v.RuntimeHealth.State + "/" + v.RuntimeHealth.Reason
}

func shortView(v e2eHealthView) string {
	h := v.RuntimeHealth
	if h == nil {
		return "absent"
	}
	lg := "none"
	if h.LastGood != nil {
		lg = shortID(h.LastGood.ImageID)
	}
	return fmt.Sprintf("%s/%s image=%s last_good=%s", h.State, h.Reason, shortID(h.ImageID), lg)
}

// e2eRuntimeHealthCases are the slice 5 rows, registered after the recovery
// rows.
func e2eRuntimeHealthCases(t *testing.T, e *e2eEnv) []e2eNamedCase {
	return []e2eNamedCase{
		{"obs_gated_unhealthy_stopped", func() { e.caseObserveGatedThenBad(t, "obs_gated_unhealthy_stopped") }},
		{"obs_hand_retag", func() { e.caseObserveHandRetag(t, "obs_hand_retag") }},
		{"obs_upgrade", func() { e.caseObserveAcrossUpgrade(t, "obs_upgrade") }},
		{"obs_off", func() { e.caseObserveOff(t, "obs_off") }},
	}
}
