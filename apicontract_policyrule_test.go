package main

// Slice 3.1 — the PolicyRule schema is fully enumerated (35 fields,
// additionalProperties:false). These assert the create/update request bodies
// validate a realistic rule and reject unknown fields / wrong types — coverage
// the previous open GenericWriteInput could not provide.

import "testing"

func TestConformance_PolicyRule_Request(t *testing.T) {
	spec := loadContract(t)
	good := `{
		"priority": 10, "name": "allow-eng", "sourceGroup": "engineering",
		"destFQDN": "*.github.com", "sslAction": "Inspect", "action": "Allow",
		"destCountry": ["US","GB"], "enabled": true, "fileFiltering": false,
		"schedule": {"days":["Mon","Tue"],"timeStart":"09:00","timeEnd":"17:00","timezone":"UTC"}
	}`
	for _, method := range []string{"POST", "PUT"} {
		if err := spec.ValidateJSONRequest(method, "/api/policy", []byte(good)); err != nil {
			t.Fatalf("%s valid PolicyRule rejected: %v", method, err)
		}
	}
	// unknown field rejected (additionalProperties:false)
	if err := spec.ValidateJSONRequest("POST", "/api/policy", []byte(`{"name":"x","bogusField":1}`)); err == nil {
		t.Fatal("PolicyRule schema accepted an unknown field")
	}
	// wrong type rejected
	if err := spec.ValidateJSONRequest("POST", "/api/policy", []byte(`{"priority":"high"}`)); err == nil {
		t.Fatal("PolicyRule schema accepted a string priority")
	}
	// nested schedule wrong type rejected
	if err := spec.ValidateJSONRequest("POST", "/api/policy", []byte(`{"schedule":{"days":"Mon"}}`)); err == nil {
		t.Fatal("PolicyRule schema accepted a non-array schedule.days")
	}
}

func TestConformance_DecryptionProfile_Request(t *testing.T) {
	spec := loadContract(t)
	good := `{"name":"strict","inspectHttp2":true,"minTlsVersion":"1.2","stallTimeoutSecs":30}`
	if err := spec.ValidateJSONRequest("POST", "/api/decryption-profiles", []byte(good)); err != nil {
		t.Fatalf("valid DecryptionProfile rejected: %v", err)
	}
	if err := spec.ValidateJSONRequest("POST", "/api/decryption-profiles", []byte(`{"name":"x","unknown":1}`)); err == nil {
		t.Fatal("DecryptionProfile accepted unknown field")
	}
	if err := spec.ValidateJSONRequest("PUT", "/api/decryption-profiles", []byte(`{"stallTimeoutSecs":"soon"}`)); err == nil {
		t.Fatal("DecryptionProfile accepted string stallTimeoutSecs")
	}
}

func TestConformance_AuthPolicyRule_Request(t *testing.T) {
	spec := loadContract(t)
	good := `{"priority":5,"name":"require-auth","ruleType":"auth","action":"Allow"}`
	if err := spec.ValidateJSONRequest("POST", "/api/authpolicy", []byte(good)); err != nil {
		t.Fatalf("valid auth rule rejected: %v", err)
	}
	if err := spec.ValidateJSONRequest("POST", "/api/authpolicy", []byte(`{"nope":1}`)); err == nil {
		t.Fatal("auth policy accepted unknown field")
	}
}

func TestConformance_MoreStructs_Request(t *testing.T) {
	spec := loadContract(t)
	cases := []struct{ method, path, good, bad string }{
		{"POST", "/api/urlcat", `{"name":"social","hosts":["fb.com"],"builtIn":false}`, `{"name":"x","extra":1}`},
		{"POST", "/api/fileblock/profiles", `{"name":"exe","extensions":["exe","dll"]}`, `{"extensions":"exe"}`},
		{"POST", "/api/rewrite", `{"host":"x.com","req_set":{"X-A":"1"},"resp_remove":["Server"]}`, `{"id":"one"}`},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if err := spec.ValidateJSONRequest(c.method, c.path, []byte(c.good)); err != nil {
				t.Fatalf("valid body rejected: %v", err)
			}
			if err := spec.ValidateJSONRequest(c.method, c.path, []byte(c.bad)); err == nil {
				t.Fatalf("accepted invalid body %s", c.bad)
			}
		})
	}
}
