package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// GET/PUT /api/authpolicy/killswitch — the Auth Exempt break-glass control
// (surfaces authpolicy.go's pre-existing runtime toggle so an admin can
// engage/release it and see its state without a restart or a simulate call).

func TestKillSwitchAPI_ViewerCanRead(t *testing.T) {
	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
	w := httptest.NewRecorder()
	apiAuthPolicyKillSwitch(w, roleReq(RoleViewer, "GET", "/api/authpolicy/killswitch", nil))
	if w.Code != 200 {
		t.Fatalf("GET status = %d, want 200", w.Code)
	}
	var got struct {
		EnvDisabled     bool `json:"envDisabled"`
		RuntimeDisabled bool `json:"runtimeDisabled"`
		Engaged         bool `json:"engaged"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.RuntimeDisabled || got.Engaged {
		t.Errorf("fresh state should be disengaged: %+v", got)
	}
}

func TestKillSwitchAPI_ViewerCannotWrite(t *testing.T) {
	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
	w := httptest.NewRecorder()
	apiAuthPolicyKillSwitch(w, roleReq(RoleViewer, "PUT", "/api/authpolicy/killswitch", map[string]any{"disabled": true}))
	if w.Code != 403 {
		t.Fatalf("viewer PUT status = %d, want 403", w.Code)
	}
	if authExemptDisabledRuntimeState() {
		t.Error("a rejected write must not engage the runtime toggle")
	}
}

func TestKillSwitchAPI_OperatorCannotWrite(t *testing.T) {
	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
	w := httptest.NewRecorder()
	apiAuthPolicyKillSwitch(w, roleReq(RoleOperator, "PUT", "/api/authpolicy/killswitch", map[string]any{"disabled": true}))
	if w.Code != 403 {
		t.Fatalf("operator PUT status = %d, want 403 (auth waivers stay admin-only)", w.Code)
	}
}

func TestKillSwitchAPI_AdminCanEngageAndRelease(t *testing.T) {
	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	w := httptest.NewRecorder()
	apiAuthPolicyKillSwitch(w, roleReq(RoleAdmin, "PUT", "/api/authpolicy/killswitch", map[string]any{"disabled": true}))
	if w.Code != 200 {
		t.Fatalf("admin engage status = %d, want 200", w.Code)
	}
	if !authExemptDisabledRuntimeState() {
		t.Fatal("runtime toggle must be engaged after PUT disabled=true")
	}
	if !authExemptKillSwitchEngaged() {
		t.Fatal("combined kill switch must report engaged")
	}

	w2 := httptest.NewRecorder()
	apiAuthPolicyKillSwitch(w2, roleReq(RoleAdmin, "PUT", "/api/authpolicy/killswitch", map[string]any{"disabled": false}))
	if w2.Code != 200 {
		t.Fatalf("admin release status = %d, want 200", w2.Code)
	}
	if authExemptDisabledRuntimeState() {
		t.Fatal("runtime toggle must be released after PUT disabled=false")
	}
}

// GET /api/authpolicy must surface the same combined status so an admin sees
// it on the list view without a second request.
func TestAuthPolicyList_IncludesKillSwitchStatus(t *testing.T) {
	withFreshPolicyStore(t)
	setAuthExemptDisabled(true)
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleViewer, "GET", "/api/authpolicy", nil))
	if w.Code != 200 {
		t.Fatalf("GET /api/authpolicy status = %d, want 200", w.Code)
	}
	var got struct {
		KillSwitch struct {
			RuntimeDisabled bool `json:"runtimeDisabled"`
			Engaged         bool `json:"engaged"`
		} `json:"killSwitch"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.KillSwitch.RuntimeDisabled || !got.KillSwitch.Engaged {
		t.Errorf("list view must reflect the engaged runtime kill switch: %+v", got.KillSwitch)
	}
}
