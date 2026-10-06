package main

import "testing"

func TestCheckReleaseVerifyPosture(t *testing.T) {
	prev := currentReleaseManager()
	t.Cleanup(func() { setReleaseManager(prev) })

	setReleaseManager(nil)
	if c := checkReleaseVerifyPosture(); c.Code != "release_catalog_verify" || c.Status != diagOK {
		t.Fatalf("no manager: want ok, got %+v", c)
	}
	cases := []struct {
		mode VerifyMode
		want string
		act  bool
	}{
		{VerifyEnforce, diagOK, false},
		{VerifyPermissive, diagWarn, true},
		{VerifyDisabled, diagWarn, true},
	}
	for _, tc := range cases {
		rm := newReleaseManager(nil, nil)
		rm.verifyMode = tc.mode
		setReleaseManager(rm)
		c := checkReleaseVerifyPosture()
		if c.Status != tc.want || (c.OperatorAction != "") != tc.act {
			t.Errorf("mode %s: got %+v", tc.mode, c)
		}
	}
}

func TestOperatorContract_IncludesReleaseVerifyRow(t *testing.T) {
	prev := currentReleaseManager()
	t.Cleanup(func() { setReleaseManager(prev) })
	rm := newReleaseManager(nil, nil)
	rm.verifyMode = VerifyDisabled
	setReleaseManager(rm)
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "release_catalog_verify" {
			if c.Status != diagWarn {
				t.Fatalf("want warn, got %+v", c)
			}
			return
		}
	}
	t.Fatal("release_catalog_verify row missing from operator contract")
}
