package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// SEC-SECPARTIAL-1 — a partial POST /api/security must not disable the
// per-IP rate limiter.
//
// `RateLimitRPM` was a plain `int` guarded by `if body.RateLimitRPM >= 0`.
// An absent JSON field decodes to 0 and `0 >= 0` is always true, so every body
// that omitted rateLimitRPM called rl.Configure(0, …) = DISABLED — and
// adminSettingsSave + saveConfigVersion then made it durable. The endpoint's
// own published contract declares the body a "Partial update — supply only the
// fields to change" (api/openapi SecurityUpdate, rateLimitRPM optional), and
// three of the shipped admin UI's buttons send exactly such bodies:
// secAddIP {ipAdd}, secRemoveIP {ipRemove}, saveSecurity {ipFilterMode}.

// secPartialEnv puts the limiter in a known enabled state and restores it.
func secPartialEnv(t *testing.T, rpm int) {
	t.Helper()
	prevLimit, prevOn := rl.Limit(), rl.Enabled()
	t.Cleanup(func() {
		if prevOn {
			rl.Configure(prevLimit, time.Minute)
		} else {
			rl.Configure(0, time.Minute)
		}
	})
	rl.Configure(rpm, time.Minute)
	if !rl.Enabled() || rl.Limit() != rpm {
		t.Fatalf("precondition: enabled=%v limit=%d, want enabled at %d", rl.Enabled(), rl.Limit(), rpm)
	}
}

func postSecurity(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	apiSecurity(rec, adminCtx(jsonReq(http.MethodPost, "/api/security", body)))
	return rec
}

// TestSECSECPARTIAL1_PartialUpdateLeavesTheRateLimiterAlone is the DEFECT GATE.
// Pre-fix every row left rl.Enabled()==false and rl.Limit()==0.
func TestSECSECPARTIAL1_PartialUpdateLeavesTheRateLimiterAlone(t *testing.T) {
	const rpm = 600
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"ipAdd (secAddIP button)", map[string]any{"ipAdd": "203.0.113.77"}},
		{"ipRemove (secRemoveIP button)", map[string]any{"ipRemove": "203.0.113.77"}},
		{"ipFilterMode (saveSecurity button)", map[string]any{"ipFilterMode": "block"}},
		{"ipFilterMode empty (saveSecurity with no radio selected)", map[string]any{"ipFilterMode": ""}},
		{"rateLimitExemptAdd", map[string]any{"rateLimitExemptAdd": "198.51.100.0/24"}},
		{"rateLimitExemptDel", map[string]any{"rateLimitExemptDel": "198.51.100.0/24"}},
		{"empty object", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secPartialEnv(t, rpm)
			prevMode := ipf.Mode()
			t.Cleanup(func() {
				ipf.Remove("203.0.113.77")
				rl.RemoveExemption("198.51.100.0/24")
				ipf.SetMode(prevMode)
			})

			rec := postSecurity(t, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if !rl.Enabled() || rl.Limit() != rpm {
				t.Errorf("DEFECT: a partial update disabled the rate limiter — enabled=%v limit=%d, want enabled at %d",
					rl.Enabled(), rl.Limit(), rpm)
			}
		})
	}
}

// TestSECSECPARTIAL1_ExplicitValuesStillApply is the not-vacuous control: the
// fix must not make rateLimitRPM unsettable. An explicit 0 must still disable
// (that is what the panel's "Disable rate limiting" button sends).
func TestSECSECPARTIAL1_ExplicitValuesStillApply(t *testing.T) {
	t.Run("explicit zero disables", func(t *testing.T) {
		secPartialEnv(t, 600)
		if rec := postSecurity(t, map[string]any{"rateLimitRPM": 0}); rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
		}
		if rl.Enabled() || rl.Limit() != 0 {
			t.Errorf("explicit 0 did not disable: enabled=%v limit=%d", rl.Enabled(), rl.Limit())
		}
	})

	t.Run("explicit value enables and sets the limit", func(t *testing.T) {
		secPartialEnv(t, 600)
		if rec := postSecurity(t, map[string]any{"rateLimitRPM": 120}); rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
		}
		if !rl.Enabled() || rl.Limit() != 120 {
			t.Errorf("explicit 120 not applied: enabled=%v limit=%d", rl.Enabled(), rl.Limit())
		}
	})

	// Boundary: the smallest enabling value must still enable.
	t.Run("explicit one enables", func(t *testing.T) {
		secPartialEnv(t, 600)
		if rec := postSecurity(t, map[string]any{"rateLimitRPM": 1}); rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
		}
		if !rl.Enabled() || rl.Limit() != 1 {
			t.Errorf("explicit 1 not applied: enabled=%v limit=%d", rl.Enabled(), rl.Limit())
		}
	})
}

// TestSECSECPARTIAL1_NegativeLimitIsRefusedAndChangesNothing pins the boundary
// the old `>= 0` guard handled by SILENTLY IGNORING it: a negative value now
// refuses the whole request, and refuses it before any field is applied, so a
// rejected body cannot leave the configuration half-updated.
func TestSECSECPARTIAL1_NegativeLimitIsRefusedAndChangesNothing(t *testing.T) {
	for _, rpm := range []int{-1, -600} {
		secPartialEnv(t, 600)
		prevMode := ipf.Mode()
		t.Cleanup(func() { ipf.SetMode(prevMode); ipf.Remove("203.0.113.78") })

		rec := postSecurity(t, map[string]any{
			"rateLimitRPM": rpm,
			// Sent alongside so the all-or-nothing property is observable: if
			// the refusal came after these were applied, the mode would move.
			"ipFilterMode": "block",
			"ipAdd":        "203.0.113.78",
		})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("rateLimitRPM=%d: status = %d, want 400", rpm, rec.Code)
		}
		if !rl.Enabled() || rl.Limit() != 600 {
			t.Errorf("rateLimitRPM=%d: limiter changed on a refused request: enabled=%v limit=%d", rpm, rl.Enabled(), rl.Limit())
		}
		if ipf.Mode() != prevMode {
			t.Errorf("rateLimitRPM=%d: a refused request still applied ipFilterMode (%q -> %q)", rpm, prevMode, ipf.Mode())
		}
	}
}

// TestSECSECPARTIAL1_MalformedRateLimitStillRejected keeps the existing
// wrong-type contract (apicontract_request_slice3i_test.go pins the 400) intact
// across the int -> *int change.
func TestSECSECPARTIAL1_MalformedRateLimitStillRejected(t *testing.T) {
	secPartialEnv(t, 600)
	for _, bad := range []any{"lots", []int{1}, map[string]any{"n": 1}, true} {
		rec := postSecurity(t, map[string]any{"rateLimitRPM": bad})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("rateLimitRPM=%#v: status = %d, want 400", bad, rec.Code)
		}
		if !rl.Enabled() || rl.Limit() != 600 {
			t.Errorf("rateLimitRPM=%#v: limiter changed on a malformed request: enabled=%v limit=%d", bad, rl.Enabled(), rl.Limit())
		}
	}
}

// TestSECSECPARTIAL1_ExplicitNullIsTreatedAsAbsent pins JSON null, the one
// shape a pointer field introduces that an int field could not express.
func TestSECSECPARTIAL1_ExplicitNullIsTreatedAsAbsent(t *testing.T) {
	secPartialEnv(t, 600)
	if rec := postSecurity(t, map[string]any{"rateLimitRPM": nil}); rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if !rl.Enabled() || rl.Limit() != 600 {
		t.Errorf("explicit null changed the limiter: enabled=%v limit=%d, want enabled at 600", rl.Enabled(), rl.Limit())
	}
}
