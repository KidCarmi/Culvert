//go:build lifecycle_conformance

package lifecyclemodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ───────────────────────── converge (V2) decision: full bounded input space

// The bounded V2 domains, in odometer order (the last one varies fastest). The local ids
// follow the references (a record's reference resolves to its own image or not at all);
// the real decision's exhaustive test (reconcile_decision_v2_test.go) also covers foreign
// local ids, unreadable Docker, stopped containers and the other record kinds.
var (
	domV2Attempts = []int{0, 1, 2}
	domV2Refs     = [][3]bool{ // RefValid, TargetRefPresent, PriorRefPresent
		{true, true, true}, {true, true, false}, {true, false, true}, {true, false, false},
		{false, true, true}, {false, true, false}, {false, false, true}, {false, false, false}}
	domV2Armed   = []bool{false, true}
	domV2TID     = []string{"", "T", "P"}
	domV2PID     = []string{"", "P", "T"}
	domV2Running = []string{"", "P", "T", "X"}
	domV2Tag     = []string{"", "P", "T", "X"}
	domV2Probe   = []string{probeNotRun, probeReady, probeNotReady}
	// Slice 6: the record kind and, for runtime.recover, the compatibility verdict, as one
	// domain: a verdict means nothing for an upgrade record, so it is not crossed with it.
	domV2KindCompat = [][2]string{{"", ""}, {KindRuntimeRecover, compatModelOK},
		{KindRuntimeRecover, compatModelUnknown}, {KindRuntimeRecover, compatModelIncompatible}}
)

// ReconcileV2Vectors is the V2 decision table over the bounded space: Expected holds one
// byte per input, 'A' + the index of its verdict ("action/reason") in Verdicts.
type ReconcileV2Vectors struct {
	Order    string            `json:"order"`
	Verdicts []string          `json:"verdicts"`
	Domains  []ReconcileDomain `json:"domains"`
	Expected string            `json:"expected"`
}

func reconcileV2Domains() []ReconcileDomain {
	return []ReconcileDomain{
		{"phase", anySlice(domPhase)}, {"attempts", anySlice(domV2Attempts)}, {"ref_valid_target_prior", anySlice(domV2Refs)},
		{"armed", anySlice(domV2Armed)}, {"target_id", anySlice(domV2TID)}, {"prior_id", anySlice(domV2PID)},
		{"running_id", anySlice(domV2Running)}, {"tag_id", anySlice(domV2Tag)}, {"probe", anySlice(domV2Probe)},
		{"kind_compat", anySlice(domV2KindCompat)},
	}
}

// ReconcileV2InputAt returns the input at the given per-domain indices (len 10).
func ReconcileV2InputAt(idx []int) ReconcileV2Inputs {
	refs := domV2Refs[idx[2]]
	in := ReconcileV2Inputs{Phase: domPhase[idx[0]], Attempts: domV2Attempts[idx[1]],
		RefValid: refs[0], TargetRefPresent: refs[1], PriorRefPresent: refs[2], Armed: domV2Armed[idx[3]],
		TargetID: domV2TID[idx[4]], PriorID: domV2PID[idx[5]], RunningID: domV2Running[idx[6]],
		TagID: domV2Tag[idx[7]], Probe: domV2Probe[idx[8]]}
	in.Kind, in.Compat = domV2KindCompat[idx[9]][0], domV2KindCompat[idx[9]][1]
	if in.TargetRefPresent {
		in.TargetLocal = imgT
	}
	if in.PriorRefPresent {
		in.PriorLocal = imgP
	}
	return in
}

// Advance moves idx to the next input in odometer order and reports false after the last.
func (rv *ReconcileV2Vectors) Advance(idx []int) bool {
	for d := len(idx) - 1; d >= 0; d-- {
		idx[d]++
		if idx[d] < len(rv.Domains[d].Values) {
			return true
		}
		idx[d] = 0
	}
	return false
}

// verdictCodes are the per-input codes, in order: code i is verdictCodes[i].
const verdictCodes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Verdict returns the model's "action/reason" for the n-th input.
func (rv *ReconcileV2Vectors) Verdict(n int) string {
	return rv.Verdicts[strings.IndexByte(verdictCodes, rv.Expected[n])]
}

// GenReconcileV2Vectors evaluates ReconcileV2Spec on every input of the bounded space.
func GenReconcileV2Vectors() *ReconcileV2Vectors {
	rv := &ReconcileV2Vectors{Order: "odometer over domains, last domain varies fastest", Domains: reconcileV2Domains()}
	code := map[string]byte{}
	total := 1
	for _, d := range rv.Domains {
		total *= len(d.Values)
	}
	out := make([]byte, 0, total)
	idx := make([]int, len(rv.Domains))
	for more := true; more; more = rv.Advance(idx) {
		v := verdictOf(ReconcileV2Spec(ReconcileV2InputAt(idx)))
		c, ok := code[v]
		if !ok {
			c = verdictCodes[len(rv.Verdicts)] // more verdicts than codes panics: never a silent alias
			code[v] = c
			rv.Verdicts = append(rv.Verdicts, v)
		}
		out = append(out, c)
	}
	rv.Expected = string(out)
	return rv
}

func reconcileV2Fingerprint(rv *ReconcileV2Vectors) ReconcileFingerprint {
	raw, err := json.Marshal(rv)
	if err != nil {
		panic(err) // plain data: cannot fail
	}
	sum := sha256.Sum256(raw)
	counts := map[string]int{}
	for n := range rv.Expected {
		counts[rv.Verdict(n)]++
	}
	return ReconcileFingerprint{Inputs: len(rv.Expected), SHA256: hex.EncodeToString(sum[:]), VerdictCounts: counts}
}
