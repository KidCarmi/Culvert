package runtime

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// Deps are the shared IMMUTABLE libraries the listeners read. They are read-only
// from the listeners' perspective (snapshots / pure validators); the listeners never
// mutate them and never share mutable per-capability state through them. The replay
// cache is per-capability partitioned internally, so one instance is safe for both.
type Deps struct {
	Registry     *registry.Registry
	Catalog      *catalog.Catalog
	Keys         authn.KeyResolver
	Introspector authn.Introspector
	Replay       *senderconstraint.ReplayCache
	// Sink receives sanitized observe records. A nil sink drops records (still
	// bounded). Sink failure NEVER permits a denied request or a decision-point
	// operation, and must not block shutdown.
	Sink Sink
	// Clock is injected for deterministic tests; nil ⇒ time.Now.
	Clock func() time.Time
}

func (d Deps) now() time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now()
}

// authDeps builds the PR-3 authn.Deps from the shared libraries.
func (d Deps) authDeps() authn.Deps {
	return authn.Deps{
		Keys:         d.Keys,
		Introspector: d.Introspector,
		Registry:     d.Registry,
		Catalog:      d.Catalog,
		Replay:       d.Replay,
	}
}
