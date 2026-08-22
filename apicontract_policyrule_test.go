package main

// Slice 3.1 — the PolicyRule schema is fully enumerated (35 fields,
// additionalProperties:false). These assert the create/update request bodies
// validate a realistic rule and reject unknown fields / wrong types — coverage
// the previous open GenericWriteInput could not provide.

import (
	"strings"
	"testing"
)

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

func TestConformance_SmallStructs_Request(t *testing.T) {
	spec := loadContract(t)
	cases := []struct{ method, path, good, bad string }{
		{"POST", "/api/blocklist", `{"hosts":["a.com","b.com"]}`, `{"host":5}`},
		{"POST", "/api/dpi", `{"pattern":"evil"}`, `{"pattern":1}`},
		{"POST", "/api/alerts/webhooks", `{"name":"slack","url":"https://h","events":["threat_detected"],"enabled":true}`, `{"name":"x"}`},
		{"PUT", "/api/settings/unauth-mode", `{"defaultAuthOutcome":"Default"}`, `{"defaultAuthOutcome":"Nope"}`},
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

func TestConformance_NicheStructs_Request(t *testing.T) {
	spec := loadContract(t)
	cases := []struct{ method, path, good, bad string }{
		{"POST", "/api/pac/pools", `{"name":"p1","endpoints":[{"host":"x"}]}`, `{"endpoints":"x"}`},
		{"POST", "/api/pac/profiles", `{"name":"pr1","enabled":true,"poolId":"p1"}`, `{"name":"x","bogus":1}`},
		// "ldap" joined the type enum (ADR-0027), so the invalid-enum probe
		// uses a type that stays outside the contract.
		{"POST", "/api/idp", `{"name":"okta","type":"oidc","emailDomains":["c.com"],"enabled":true}`, `{"name":"x","type":"kerberos"}`},
		{"PUT", "/api/policy/draft", `{"require_commit":true}`, `{"require_commit":"yes"}`},
		{"POST", "/api/config/versions", `{"version":3,"dry_run":true}`, `{"version":"three"}`},
		{"POST", "/api/idp/discover", `{"issuer":"https://idp"}`, `{"foo":"bar"}`},
		{"POST", "/api/cluster/revoke", `{"node_id":"n1","reason":"rotate"}`, `{"node_id":5}`},
		{"POST", "/api/security-scan/yara/rules", `{"name":"r1","source":"rule x {}"}`, `{"source":"x"}`},
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

func TestConformance_FinalStructs_Request(t *testing.T) {
	spec := loadContract(t)
	if err := spec.ValidateJSONRequest("POST", "/api/cluster/bandwidth", []byte(`{"name":"eng","max_bytes_per_sec":1000000,"priority":5}`)); err != nil {
		t.Fatalf("valid bandwidth policy rejected: %v", err)
	}
	if err := spec.ValidateJSONRequest("POST", "/api/cluster/bandwidth", []byte(`{"max_bytes_per_sec":"lots"}`)); err == nil {
		t.Fatal("bandwidth accepted string max_bytes_per_sec")
	}
	if err := spec.ValidateJSONRequest("POST", "/api/releases/dispatch", []byte(`{"agent":"a1","channel":"stable","pre_backup":true}`)); err != nil {
		t.Fatalf("valid dispatch rejected: %v", err)
	}
	if err := spec.ValidateJSONRequest("POST", "/api/releases/dispatch", []byte(`{"agent":"a1","bogus":1}`)); err == nil {
		t.Fatal("dispatch accepted unknown field")
	}
}

// TestOpenAPI_Gate9_NoResponseTypeCollision guards the contract against schema
// component names that collide with the response wrapper types oapi-codegen
// generates per operation (<OperationId>Response) — a collision breaks generated
// client compilation (caught live: LoginResponse vs the login op).
func TestOpenAPI_Gate9_NoResponseTypeCollision(t *testing.T) {
	spec := loadContract(t)
	schemas := map[string]bool{}
	if spec.Doc.Components != nil {
		for name := range spec.Doc.Components.Schemas {
			schemas[name] = true
		}
	}
	for _, op := range spec.Ops {
		id := op.Op.OperationID
		if id == "" {
			continue
		}
		gen := strings.ToUpper(id[:1]) + id[1:] + "Response"
		if schemas[gen] {
			t.Errorf("schema %q collides with the generated response type for operationId %q — rename the schema (breaks client generation)", gen, id)
		}
	}
}
