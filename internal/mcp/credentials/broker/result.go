package broker

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// SafeResult is the ONLY value the broker returns to a caller about a
// materialization. It is safe to record: it contains no plaintext, no encrypted
// envelope bytes, no token, key, password, private key, Authorization header, or
// provider secret path — only sanitized operational metadata.
type SafeResult struct {
	PlanID       string
	ProfileID    profile.ID
	ProviderID   profile.ProviderID
	Version      profile.CredentialVersion
	Server       registry.ServerID
	ToolRefHash  string // sha-256 hash of the tool ref (never the raw name), empty if none
	Operation    profile.OperationClass
	Risk         profile.RiskClass
	CacheHit     bool
	Materialized bool
	Rotation     string // rotation state label
	Revoked      bool
	IssuedAt     time.Time
	Expiry       time.Time
	Reason       mcperr.Reason // stable reason code (ReasonNone on success)
}

// toolRefHash returns a one-way hash of a tool binding for safe correlation, or ""
// when no tool is bound. The raw tool name is never surfaced.
func toolRefHash(tb *profile.ToolBinding) string {
	if tb == nil {
		return ""
	}
	return jose.SHA256B64URL([]byte(string(tb.Server) + "\x00" + tb.Name))
}
