package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/bootstrap"
)

func apiClusterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	result := map[string]any{
		"role":                   clusterRole.role,
		"nodeID":                 clusterRole.nodeID,
		"grpcAddr":               clusterRole.grpcAddr,
		"uptime":                 time.Since(startTime).Round(time.Second).String(),
		"enrollEnabled":          globalClusterCA.Ready(),
		"caFingerprint":          globalClusterCA.CACertFingerprint(),
		"ha":                     globalHA.Status(),
		"grpcCompressionEnabled": clusterGRPCCompression,
	}
	if clusterRole.role == "control-plane" {
		result["nodes"] = NodeMetricsList()
		result["enrolledNodes"] = globalClusterStore.ListNodes()
		result["activeTokens"] = countActiveTokens()
	}
	jsonOK(w, result)
}

func countActiveTokens() int {
	count := 0
	for _, t := range globalClusterStore.ListTokens() {
		if !t.Used && time.Now().Before(t.ExpiresAt) {
			count++
		}
	}
	return count
}

// apiClusterMode enables Control Plane mode at runtime from the admin GUI.
//
// Intentionally OUT of the config-version rollback surface — cluster
// role/lifecycle state (CP/DP mode flip persisted to cluster.json);
// rollback of a role flip is semantically meaningless once the control
// plane has activated. Do NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-topology / lifecycle).
func apiClusterMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}

	var req struct {
		GRPCAddr string `json:"grpc_addr"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
		CAFile   string `json:"ca_file"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.GRPCAddr == "" {
		http.Error(w, "grpc_addr is required (e.g. \":50051\")", http.StatusBadRequest)
		return
	}
	// Validate gRPC address format.
	if _, _, err := net.SplitHostPort(req.GRPCAddr); err != nil {
		http.Error(w, fmt.Sprintf("grpc_addr must be a valid host:port (e.g. \":50051\"): %v", err), http.StatusBadRequest)
		return
	}
	// Reject path traversal in file paths (CWE-22). Only allow simple file names.
	for _, p := range []string{req.CertFile, req.KeyFile, req.CAFile} {
		if p == "" {
			continue
		}
		if strings.Contains(p, "..") || strings.Contains(p, "/") || strings.Contains(p, "\\") {
			http.Error(w, "invalid certificate path", http.StatusBadRequest)
			return
		}
	}

	if err := enableControlPlane(req.GRPCAddr, req.CertFile, req.KeyFile, req.CAFile, clusterDBPathGlobal); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: "cluster.enable-cp",
		Object: req.GRPCAddr,
		Detail: "Control Plane enabled via GUI",
	})
	jsonOK(w, map[string]any{"ok": true, "role": "control-plane", "grpcAddr": req.GRPCAddr})
}

// apiClusterTokens handles enrollment token CRUD.
func apiClusterTokens(w http.ResponseWriter, r *http.Request) { //nolint:cyclop // split into sub-handlers
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		tokens := globalClusterStore.ListTokens()
		jsonOK(w, map[string]any{"tokens": tokens})

	case http.MethodPost:
		apiClusterTokenCreate(w, r)

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		tokenHash := r.URL.Query().Get("hash")
		if tokenHash == "" {
			http.Error(w, "hash parameter required", http.StatusBadRequest)
			return
		}
		if !globalClusterStore.DeleteToken(tokenHash) {
			http.Error(w, "token not found", http.StatusNotFound)
			return
		}
		if err := globalClusterStore.Save(); err != nil {
			logger.Printf("ClusterDB save error: %v", err)
			http.Error(w, "failed to persist token deletion", http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiClusterTokenCreate mints a one-shot node-enrollment token.
//
// Intentionally OUT of the config-version rollback surface — tokens
// are membership/enrollment artifacts; rolling back could resurrect a
// token an operator already consumed (or invalidate one in flight).
// Do NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-topology / trust).
func apiClusterTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if clusterRole.role != "control-plane" {
		http.Error(w, "enrollment only available on Control Plane", http.StatusBadRequest)
		return
	}
	if !globalClusterCA.Ready() {
		http.Error(w, "cluster CA not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		NodePrefix string `json:"node_prefix"`
		AllowCIDR  string `json:"allow_cidr"`
		TTLHours   int    `json:"ttl_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate node_prefix: alphanumeric + _- only, max 255 chars.
	if req.NodePrefix != "" {
		if len(req.NodePrefix) > 255 {
			http.Error(w, "node_prefix must be <= 255 characters", http.StatusBadRequest)
			return
		}
		for _, c := range req.NodePrefix {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				http.Error(w, "node_prefix must contain only alphanumeric characters, underscores, and dashes", http.StatusBadRequest)
				return
			}
		}
	}

	// Cap TTL at 8760 hours (1 year).
	const maxTTLHours = 8760
	ttl := 24 * time.Hour
	if req.TTLHours > 0 {
		if req.TTLHours > maxTTLHours {
			http.Error(w, fmt.Sprintf("ttl_hours must be <= %d (1 year)", maxTTLHours), http.StatusBadRequest)
			return
		}
		ttl = time.Duration(req.TTLHours) * time.Hour
	}

	admin := sessionAdmin(r)
	plaintext, err := globalClusterStore.GenerateToken(req.NodePrefix, req.AllowCIDR, admin, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Build enrollment URL.
	cpAddr := clusterRole.grpcAddr
	caFP := globalClusterCA.CACertFingerprint()
	enrollURL := fmt.Sprintf("culvert://enroll/%s/%s?ca-fp=sha256:%s", cpAddr, plaintext, caFP)

	// Build bootstrap command (curl | bash).
	cpBase := bootstrap.BaseURL(r, trustForwardedHeaders)
	bootstrapCmd := fmt.Sprintf("curl -fsSL -k %s/api/cluster/bootstrap/%s | sudo bash", cpBase, plaintext)
	enrollCmd := fmt.Sprintf("./culvert -enroll %q", enrollURL)

	auditEvent(r, "enrollment.token_created", sanitizeLog(req.NodePrefix),
		fmt.Sprintf("cidr=%s ttl=%dh", sanitizeLog(req.AllowCIDR), int(ttl.Hours())))

	jsonOK(w, map[string]any{
		"token":         plaintext,
		"enroll_url":    enrollURL,
		"enroll_cmd":    enrollCmd,
		"bootstrap_cmd": bootstrapCmd,
		"expires_at":    time.Now().Add(ttl).Format(time.RFC3339),
	})
}

// apiClusterNodes returns enrolled nodes with their status.
func apiClusterNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	nodes := globalClusterStore.ListNodes()
	jsonOK(w, map[string]any{"nodes": nodes})
}

// apiClusterRevoke revokes an enrolled node.
//
// Intentionally OUT of the config-version rollback surface —
// un-revoking a banned node via rollback is a security regression by
// definition. Do NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-sec).
func apiClusterRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	if len(req.Reason) > 1000 {
		http.Error(w, "reason must be <= 1000 characters", http.StatusBadRequest)
		return
	}

	admin := sessionAdmin(r)
	if err := globalClusterStore.RevokeNode(req.NodeID, admin, req.Reason); err != nil {
		// RevokeNode calls Save() internally. Distinguish persistence errors
		// (500) from logical errors like "not found" or "already revoked" (400).
		if strings.Contains(err.Error(), "persist") {
			http.Error(w, "failed to persist node revocation", http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	auditEvent(r, "enrollment.node_revoked", sanitizeLog(req.NodeID),
		fmt.Sprintf("reason=%s", sanitizeLog(req.Reason)))

	logger.Printf("Enrollment: node %q revoked by %s (reason: %s)", sanitizeLog(req.NodeID), sanitizeLog(admin), sanitizeLog(req.Reason))
	jsonOK(w, map[string]any{"ok": true})
}

// apiClusterCA returns cluster CA info (GET) or imports a custom CA (POST).
//
// Intentionally OUT of the config-version rollback surface — cluster
// CA material is a forward-only trust artifact, and a rollback would
// flip the CAFingerprint (controlplane.go:1550-1560) and trigger
// fleet-wide DP cert renewal against a reverted CA. Plus the cluster
// CA private key must never enter plaintext config-version snapshot
// files. Do NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-sec) and §3.2 (HA blast radius).
func apiClusterCA(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, globalClusterCA.Info())
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Cert == "" || body.Key == "" {
			http.Error(w, "cert and key are required", http.StatusBadRequest)
			return
		}
		// Pre-validate PEM format and cert:key match before importing.
		cert, err := parseAndValidateCACert([]byte(body.Cert))
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid certificate: %v", err), http.StatusBadRequest)
			return
		}
		ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			http.Error(w, "certificate must use an ECDSA key", http.StatusBadRequest)
			return
		}
		if _, err := parseAndValidateCAKey([]byte(body.Key), ecPub); err != nil {
			http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
			return
		}
		if err := globalClusterCA.ImportCA([]byte(body.Cert), []byte(body.Key)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "cluster.ca", "imported", "Custom cluster CA imported")
		jsonOK(w, globalClusterCA.Info())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiClusterRateLimits returns distributed rate limiting status.
// Shows whether gossip is active, how many nodes are syncing, and hot IP count.
func apiClusterRateLimits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	nodes, hotIPs := globalRLAggregator.Stats()
	jsonOK(w, map[string]any{
		"enabled":        clusterRateLimitEnabled.Load(),
		"syncing_nodes":  nodes,
		"hot_ips":        hotIPs,
		"remote_ips":     clusterCounts.Count(),
		"rate_limit_rpm": rl.Limit(),
		"threshold_pct":  hotThresholdPct,
	})
}

// apiClusterAudit returns the centralized audit log from all Data Plane nodes.
func apiClusterAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	entries := globalClusterAudit.Recent(200)
	jsonOK(w, map[string]any{"entries": entries, "total": globalClusterAudit.Count()})
}

// apiClusterRevocations returns distributed session revocation sync status.
func apiClusterRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{
		"local_revoked": sessionRevoked.Count(),
		"cluster_mode":  audit.DPMode() || clusterRole.role == "control-plane",
	})
}

// GET /api/cluster/rotation — CA rotation progress.
func apiClusterRotation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rot := globalClusterStore.CARotationStatus()
	if rot == nil {
		jsonOK(w, map[string]any{"active": false})
		return
	}

	// Build list of pending nodes.
	pending := []string{}
	for _, n := range globalClusterStore.ListNodes() {
		if n.Status == "revoked" {
			continue
		}
		if _, ok := rot.RenewedNodes[n.NodeID]; !ok {
			pending = append(pending, n.NodeID)
		}
	}

	jsonOK(w, map[string]any{
		"active":          true,
		"started_at":      rot.StartedAt,
		"new_fingerprint": rot.NewFingerprint,
		"old_fingerprint": rot.OldFingerprint,
		"old_expires":     rot.OldExpires,
		"total_nodes":     rot.TotalNodes,
		"renewed_count":   len(rot.RenewedNodes),
		"renewed_nodes":   rot.RenewedNodes,
		"pending_nodes":   pending,
		"complete":        len(rot.RenewedNodes) >= rot.TotalNodes,
	})
}

// POST /api/cluster/labels — set labels on a node.
//
// Intentionally OUT of the config-version rollback surface — node
// labels are operational topology, not versioned policy. Do NOT add
// saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (C-topology).
func apiClusterLabels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		NodeID string            `json:"node_id"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}
	// Validate label keys/values.
	for k, v := range req.Labels {
		if len(k) > 63 || len(v) > 255 {
			http.Error(w, "label key max 63 chars, value max 255 chars", http.StatusBadRequest)
			return
		}
	}
	if err := globalClusterStore.SetNodeLabels(req.NodeID, req.Labels); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	auditEvent(r, "cluster.labels", sanitizeLog(req.NodeID), fmt.Sprintf("labels updated (%d keys)", len(req.Labels)))
	jsonOK(w, map[string]any{"ok": true})
}

// POST /api/cluster/drain — toggle node drain/maintenance mode.
//
// Intentionally OUT of the config-version rollback surface — drain is
// operational topology; rolling back a drain decision once traffic has
// already been shifted is semantically wrong. Do NOT add
// saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (C-topology).
func apiClusterDrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		NodeID   string `json:"node_id"`
		Draining bool   `json:"draining"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}
	if err := globalClusterStore.SetNodeDraining(req.NodeID, req.Draining); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := "cluster.drain"
	detail := "node set to draining (maintenance mode)"
	if !req.Draining {
		action = "cluster.undrain"
		detail = "node returned to active service"
	}
	auditEvent(r, action, sanitizeLog(req.NodeID), detail)
	jsonOK(w, map[string]any{"ok": true})
}

// GET /api/cluster/metrics — aggregated cluster-wide metrics.
func apiClusterMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	nodeMetricsMu.RLock()
	var totalReqs, totalBlocked, totalAuthFail int64
	nodes := make([]map[string]any, 0, len(nodeMetrics))
	for nid, m := range nodeMetrics {
		totalReqs += m.Total
		totalBlocked += m.Blocked
		totalAuthFail += m.AuthFail
		nodes = append(nodes, map[string]any{
			"node_id":   nid,
			"total":     m.Total,
			"blocked":   m.Blocked,
			"auth_fail": m.AuthFail,
			"uptime":    m.Uptime,
		})
	}
	nodeMetricsMu.RUnlock()

	jsonOK(w, map[string]any{
		"cluster_total":     totalReqs,
		"cluster_blocked":   totalBlocked,
		"cluster_auth_fail": totalAuthFail,
		"node_count":        len(nodes),
		"nodes":             nodes,
	})
}

// resolveOTLPHeaders builds the OTLP auth headers map from the name+value
// fields. If both are empty, preserves the existing headers (admin changed
// endpoint but didn't re-enter the auth token).

// registerClusterRoutes wires the upstream-proxy chaining endpoints and
// the multi-node cluster admin endpoints. /healthz is intentionally
// public and lives under registerObservabilityRoutes, not here. All
// routes are gated by uiAuthMiddleware (except /healthz handled
// elsewhere); per-handler RBAC is the handler's responsibility.
func registerClusterRoutes(mux *http.ServeMux) {
	// ── Upstream proxy chaining ──────────────────────────────────────────
	mux.HandleFunc("/api/upstream", apiUpstream)                     // GET view / POST credential-free v1 bulk adapter
	mux.HandleFunc("/api/upstream/settings", apiUpstreamSettings)    // GET view (legacy alias)
	mux.HandleFunc("/api/upstream/health", apiUpstreamHealth)        // POST force health check
	mux.HandleFunc("/api/upstream/entries", apiUpstreamEntries)      // POST create managed entry (2F-C)
	mux.HandleFunc("/api/upstream/entries/", apiUpstreamEntryRouter) // PUT/DELETE {id}, POST {id}/credential (2F-C)

	// ── Cluster / multi-node ─────────────────────────────────────────────
	mux.HandleFunc("/api/cluster/status", apiClusterStatus)                       // GET this node + connected nodes
	mux.HandleFunc("/api/cluster/mode", apiClusterMode)                           // POST enable control-plane mode
	mux.HandleFunc("/api/cluster/tokens", apiClusterTokens)                       // GET list / POST create / DELETE remove
	mux.HandleFunc("/api/cluster/nodes", apiClusterNodes)                         // GET enrolled nodes
	mux.HandleFunc("/api/cluster/revoke", apiClusterRevoke)                       // POST revoke a node
	mux.HandleFunc("/api/cluster/labels", apiClusterLabels)                       // POST set node labels
	mux.HandleFunc("/api/cluster/node-groups", apiNodeGroups)                     // GET list / POST create / DELETE remove
	mux.HandleFunc("/api/cluster/node-groups/membership", apiNodeGroupMembership) // GET group membership (F9)
	mux.HandleFunc("/api/cluster/drain", apiClusterDrain)                         // POST toggle node drain mode
	mux.HandleFunc("/api/cluster/metrics", apiClusterMetrics)                     // GET aggregated cluster metrics
	mux.HandleFunc("/api/cluster/convergence", apiClusterConvergence)             // GET config-sync fleet convergence (T3 P1)
	mux.HandleFunc("/api/cluster/ca", apiClusterCA)                               // GET info / POST import cluster CA
	mux.HandleFunc("/api/cluster/rate-limits", apiClusterRateLimits)              // GET distributed RL status
	mux.HandleFunc("/api/cluster/audit", apiClusterAudit)                         // GET centralized audit log
	mux.HandleFunc("/api/cluster/revocations", apiClusterRevocations)             // GET revocation sync status
	mux.HandleFunc("/api/cluster/rotation", apiClusterRotation)                   // GET CA rotation progress
	mux.HandleFunc("/api/cluster/ha", apiClusterHA)                               // GET HA status
	mux.HandleFunc("/api/cluster/ha/promote", apiClusterHAPromote)                // POST manual standby→leader promotion
	mux.HandleFunc("/api/cluster/bandwidth", apiBandwidthPolicies)                // GET/POST/DELETE bandwidth QoS policies
	mux.HandleFunc("/api/cluster/bootstrap/", apiBootstrapRouter)                 // GET bootstrap script/compose (token-authed)
}
