package mcpacceptance

// QUAL-6.1 — authoritative-mode environment consumption. This file closes the four
// recorded QUAL-6 harness gaps so that in authoritative mode the acceptance harness
// tests the OPERATOR-SELECTED qualification environment rather than silently
// substituting internal fixtures:
//
//  1. operator-selected qualification policy (consumed verbatim; preflight-gated);
//  2. operator-selected bind host (the listener actually binds it; loopback proven
//     absent when the host is non-loopback);
//  3. operator-owned telemetry data/KEK/archive (consumed exactly; preserved on
//     cleanup; reused across the real restart);
//  4. operator-accessible Admin + metrics supervision (reachable + auth-enforced at
//     the advertised endpoint; a safe descriptor exposes where to look).
//
// The load-bearing invariant: for every operator-specified field that affects the
// acceptance claim, the value RECORDED equals the value CONSUMED by the spawned
// artifact, and it is PROVEN at runtime — never recorded-but-ignored.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// preflightAuthoritative binds the operator policy digest into the config hash and
// validates the operator policy can satisfy the required acceptance scenarios,
// BEFORE any process starts. Any failure aborts the run (no traffic, no fallback to
// a fixture).
func (h *Harness) preflightAuthoritative() error {
	op := h.fixture.operator
	if op == nil {
		return fmt.Errorf("acceptance: authoritative preflight requires an operator environment")
	}
	raw, err := os.ReadFile(filepath.Clean(op.policyFile)) // #nosec G304 -- operator-supplied policy path, statted regular+bounded
	if err != nil {
		return fmt.Errorf("acceptance: read operator policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	h.summary.OperatorPolicyDigest = digest

	rev, err := validatePolicyScenarioRequirements(raw)
	if err != nil {
		return err
	}
	h.operatorPolicyRevision = rev

	// Fold the policy CONTENT digest into the acceptance config hash so the hash
	// describes the environment that actually ran (path alone is machine-unstable and
	// blind to a content change under the same path).
	cfgHash, err := h.spec.effectiveConfigHash(digest)
	if err != nil {
		return err
	}
	h.summary.AcceptanceConfigHash = cfgHash
	return nil
}

// policyDoc is the bounded shape of the qualification policy the preflight inspects.
type policyDoc struct {
	SchemaVersion  int    `json:"schema_version"`
	Capability     string `json:"capability"`
	PolicyRevision uint64 `json:"policy_revision"`
	DefaultAction  string `json:"default_action"`
	Rules          []struct {
		ID         string `json:"id"`
		Action     string `json:"action"`
		Conditions []struct {
			Field string `json:"field"`
			Op    string `json:"op"`
			Value string `json:"value"`
		} `json:"conditions"`
	} `json:"rules"`
}

// validatePolicyScenarioRequirements statically verifies the operator policy can
// support the harness scenario contract WITHOUT mutating it. The harness needs, at
// minimum, a Zero-Trust default-deny posture and a same-tenant tools/list ALLOW-class
// path (so the discovery-ALLOW, tenant-matrix same-tenant, and quarantine-beats-ALLOW
// cases are meaningful). If the operator policy cannot provide them, it fails
// preflight with POLICY_SCENARIO_REQUIREMENT_UNSATISFIED rather than patching the
// policy behind the operator's back. It returns the declared policy_revision.
func validatePolicyScenarioRequirements(raw []byte) (uint64, error) {
	var doc policyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("POLICY_SCENARIO_REQUIREMENT_UNSATISFIED: operator policy is not valid JSON: %w", err)
	}
	if doc.SchemaVersion < 1 {
		return 0, fmt.Errorf("POLICY_SCENARIO_REQUIREMENT_UNSATISFIED: policy schema_version missing")
	}
	if doc.Capability != "gateway" {
		return 0, fmt.Errorf("POLICY_SCENARIO_REQUIREMENT_UNSATISFIED: policy capability must be gateway")
	}
	if doc.PolicyRevision < 1 {
		return 0, fmt.Errorf("POLICY_SCENARIO_REQUIREMENT_UNSATISFIED: policy_revision must be >= 1")
	}
	if !strings.EqualFold(doc.DefaultAction, "DENY") {
		return 0, fmt.Errorf("POLICY_SCENARIO_REQUIREMENT_UNSATISFIED: default_action must be DENY (Zero Trust)")
	}
	if !policyHasDiscoveryAllow(doc) {
		return 0, fmt.Errorf("POLICY_SCENARIO_REQUIREMENT_UNSATISFIED: no ALLOW rule for operation.method==tools/list (discovery ALLOW-class case)")
	}
	return doc.PolicyRevision, nil
}

// policyHasDiscoveryAllow reports whether the policy carries an ALLOW rule that
// matches tools/list on operation.method (an exact match). This is the minimum the
// discovery-ALLOW and same-tenant matrix cases require.
func policyHasDiscoveryAllow(doc policyDoc) bool {
	for i := range doc.Rules {
		r := doc.Rules[i]
		if !strings.EqualFold(r.Action, "ALLOW") {
			continue
		}
		for _, c := range r.Conditions {
			if c.Field == "operation.method" && strings.EqualFold(c.Op, "exact") && c.Value == "tools/list" {
				return true
			}
		}
	}
	return false
}

// buildSupervisionDescriptor assembles the safe live-supervision descriptor from the
// primary's ports and the operator credential references, prints it to stdout (so an
// operator can supervise DURING the run), and stashes it on the summary. It contains
// only URLs, a username, credential FILE PATHS, and the run id — never a password,
// token, or key.
func (h *Harness) buildSupervisionDescriptor() {
	op := h.fixture.operator
	if op == nil {
		return
	}
	host := h.fixture.bindHost
	info := &SupervisionInfo{
		RunID:                h.summary.RunID,
		GatewayURL:           fmt.Sprintf("https://%s/mcp/gateway", net.JoinHostPort(host, itoa(h.procA.pc.mcpPort))),
		AdminURL:             fmt.Sprintf("http://%s", net.JoinHostPort(host, itoa(h.procA.pc.uiPort))),
		MetricsURL:           fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, itoa(h.procA.pc.proxyPort))),
		AdminUser:            op.adminUser,
		AdminCredentialRef:   op.adminPassRef,
		MetricsCredentialRef: op.metricsRef,
	}
	h.summary.Supervision = info
	// Safe stdout descriptor: no secret material. The operator already holds the
	// credentials referenced by path; the harness never re-emits them.
	fmt.Printf("supervision run=%s gateway=%s admin=%s metrics=%s admin_user=%s admin_credential_ref=%s metrics_credential_ref=%s\n",
		info.RunID, info.GatewayURL, info.AdminURL, info.MetricsURL, info.AdminUser, info.AdminCredentialRef, info.MetricsCredentialRef)
}

// runAuthoritativeEnv emits the QUAL-6.1 effective-environment criteria proving each
// operator control was actually consumed at runtime, and writes the supervision
// descriptor into the evidence bundle.
func (h *Harness) runAuthoritativeEnv(ctx context.Context) {
	h.runEnvPolicy(ctx)
	h.runEnvBindHost(ctx)
	h.runEnvTelemetryOwnership()
	h.runSupervisionReachable(ctx)
	h.writeSupervisionEvidence()
}

// runEnvPolicy proves the operator policy (not a fixture) is the policy the runtime
// evaluated: the primary's config references the operator file verbatim, the digest
// is recorded, and the runtime policy revision equals the operator file's declared
// revision.
func (h *Harness) runEnvPolicy(ctx context.Context) {
	h.runCriterion("environment.policy_operator_selected", "operator policy is the policy evaluated", "environment", true,
		"primary reads the operator policy file; runtime revision == operator revision", func() (st Status, obs, rsn string, evi []string) {
			if h.procA.pc.policyOwner != ownerOperator || h.procA.pc.policyPath != h.fixture.operator.policyFile {
				return fail("primary not bound to operator policy file", "policy_not_operator")
			}
			if h.summary.OperatorPolicyDigest == "" {
				return fail("operator policy digest missing", "digest_absent")
			}
			hv, res := h.procA.health(ctx, h.uiClient)
			if res.status != 200 {
				return fail(fmt.Sprintf("health status %d", res.status), "health_unreachable")
			}
			if hv.Gateway.PolicyRevision != h.operatorPolicyRevision {
				return fail(fmt.Sprintf("runtime rev=%d operator rev=%d", hv.Gateway.PolicyRevision, h.operatorPolicyRevision), "revision_mismatch")
			}
			return pass(fmt.Sprintf("operator policy digest=%s runtime rev=%d", short(h.summary.OperatorPolicyDigest), hv.Gateway.PolicyRevision))
		})
}

// runEnvBindHost proves the Gateway listener bound the operator-selected host: a TLS
// connection to that host reaches the auth layer, and (when the host is non-loopback)
// loopback is NOT serving — so there was no silent fallback to 127.0.0.1.
func (h *Harness) runEnvBindHost(ctx context.Context) {
	h.runCriterion("environment.bind_host_effective", "listener bound the operator bind host", "environment", true,
		"TLS reaches the selected host; loopback absent when non-loopback", func() (st Status, obs, rsn string, evi []string) {
			sid, init := initSession(ctx, h.mcpBearer, h.procA.pc.mcpPort, h.fixture.serverA, h.tokenA)
			if sid == "" || init.status != 200 {
				return fail(fmt.Sprintf("init on bind host status=%d tlsErr=%v", init.status, init.tlsError), "bind_host_unreachable")
			}
			if !isLoopbackHost(h.fixture.bindHost) {
				// The listener bound a specific non-loopback interface; loopback must refuse.
				dialer := net.Dialer{Timeout: h.spec.Run.request()}
				conn, derr := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", itoa(h.procA.pc.mcpPort)))
				if derr == nil {
					_ = conn.Close()
					return fail("loopback accepted a connection (unexpected fallback)", "loopback_fallback")
				}
			}
			h.summary.EffectiveBindHost = h.fixture.bindHost
			return pass("bound " + h.fixture.bindHost)
		})
}

// runEnvTelemetryOwnership proves the primary consumed the operator telemetry custody
// boundary exactly (operator-owned paths, outside the harness work root) and that the
// operator KEK exists on disk (the binary loaded or created it at the operator path;
// the harness never generated or read it).
func (h *Harness) runEnvTelemetryOwnership() {
	h.runCriterion("environment.telemetry_operator_owned", "telemetry is operator-owned and consumed", "environment", true,
		"primary telemetry data/KEK/archive are the operator paths (outside work root)", func() (st Status, obs, rsn string, evi []string) {
			pc := h.procA.pc
			op := h.fixture.operator
			if pc.telemetryOwner != ownerOperator {
				return fail("telemetry not operator-owned", "not_operator_owned")
			}
			if pc.dataDir != op.telDataDir || pc.kekFile != op.telKEKFile || pc.archiveDir != op.telArchive || pc.nodeID != op.telNodeID {
				return fail("telemetry paths diverged from operator env", "telemetry_substituted")
			}
			for _, p := range []string{pc.dataDir, pc.kekFile, pc.archiveDir} {
				if underDir(p, h.workDir) {
					return fail("operator telemetry path is under the harness work root", "telemetry_in_workroot")
				}
			}
			if _, err := os.Stat(pc.kekFile); err != nil {
				return fail("operator KEK not present after start", "kek_absent")
			}
			h.summary.TelemetrySummary.Ownership = string(ownerOperator)
			h.summary.TelemetrySummary.NodeID = pc.nodeID
			return pass("operator-owned node=" + pc.nodeID)
		})
}

// runSupervisionReachable proves the operator-accessible Admin and metrics endpoints
// are reachable at the advertised address AND enforce their auth (correct credentials
// succeed; wrong/absent credentials are rejected). No secret is written to evidence.
func (h *Harness) runSupervisionReachable(ctx context.Context) {
	host := h.fixture.bindHost
	op := h.fixture.operator

	h.runCriterion("supervision.admin_reachable", "operator Admin endpoint reachable + authenticated", "supervision", true,
		"GET /api/mcp/health at the advertised admin URL: operator creds 200, wrong creds 401", func() (st Status, obs, rsn string, evi []string) {
			ok := httpGetHostStatus(ctx, h.uiClient, "http", host, h.procA.pc.uiPort, "/api/mcp/health", op.adminUser, op.adminPass, "")
			if ok != 200 {
				return fail(fmt.Sprintf("operator creds status=%d", ok), "admin_unreachable")
			}
			bad := httpGetHostStatus(ctx, h.uiClient, "http", host, h.procA.pc.uiPort, "/api/mcp/health", op.adminUser, "wrong-password-xxxxxxxx", "")
			if bad != 401 {
				return fail(fmt.Sprintf("wrong creds status=%d (expected 401)", bad), "admin_auth_not_enforced")
			}
			if h.summary.Supervision != nil {
				h.summary.Supervision.AdminReachable = true
			}
			return pass("admin reachable + auth enforced")
		})

	h.runCriterion("supervision.metrics_reachable", "operator metrics endpoint reachable + protected", "supervision", true,
		"GET /metrics at the advertised metrics URL: operator token 200 with MCP series, no token 401", func() (st Status, obs, rsn string, evi []string) {
			body, ok := httpGetHostBody(ctx, h.metricsClient, "http", host, h.procA.pc.proxyPort, "/metrics", "", "", op.metricsToken)
			if ok != 200 || !strings.Contains(string(body), "culvert_mcp_") {
				return fail(fmt.Sprintf("token status=%d mcp_series=%v", ok, strings.Contains(string(body), "culvert_mcp_")), "metrics_unreachable")
			}
			if bad := scanHighCardinality(body); bad != "" {
				return fail("banned label: "+bad, "high_cardinality_label")
			}
			noTok := httpGetHostStatus(ctx, h.metricsClient, "http", host, h.procA.pc.proxyPort, "/metrics", "", "", "")
			if noTok == 200 {
				return fail("metrics served without a token", "metrics_auth_not_enforced")
			}
			if h.summary.Supervision != nil {
				h.summary.Supervision.MetricsReachable = true
			}
			return pass("metrics reachable + protected")
		})
}

// writeSupervisionEvidence writes the safe supervision descriptor into the evidence
// bundle. It contains only URLs, a username, credential file references, and the run
// id — never a secret value.
func (h *Harness) writeSupervisionEvidence() {
	if h.summary.Supervision == nil || h.evidenceDir == "" {
		return
	}
	b, err := canonicalJSON(h.summary.Supervision)
	if err != nil {
		return
	}
	_ = writeFile(h.evidenceDir, "supervision.json", b)
}

// isLoopbackHost reports whether host is a loopback address (or "localhost").
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// underDir reports whether path is inside dir (used to prove operator telemetry is
// NOT under the harness work root). Both are cleaned; a prefix match on a path
// boundary is required (so "/a/bc" is not "under" "/a/b").
func underDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	p := filepath.Clean(path)
	d := filepath.Clean(dir)
	if p == d {
		return true
	}
	return strings.HasPrefix(p, d+string(os.PathSeparator))
}

// httpGetHostStatus issues a GET to scheme://host:port/path with optional basic auth
// (user/pass) or bearer token, returning only the status code. It dials the given
// host directly (the admin/metrics listeners bind all interfaces, so the advertised
// address is reachable).
func httpGetHostStatus(ctx context.Context, cli *http.Client, scheme, host string, port int, path, user, pass, bearer string) int {
	_, st := httpGetHostBody(ctx, cli, scheme, host, port, path, user, pass, bearer)
	return st
}

// httpGetHostBody is httpGetHostStatus that also returns the (bounded) body.
func httpGetHostBody(ctx context.Context, cli *http.Client, scheme, host string, port int, path, user, pass, bearer string) (body []byte, status int) {
	url := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, itoa(port)), path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a read-only handle
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode
}
