package identity

import "github.com/KidCarmi/Culvert/internal/mcp/protocol"

// Link is one stable, typed link in the delegation chain. It carries a typed
// reference, never a display name.
type Link struct {
	Kind PrincipalKind
	ID   string
}

// Chain returns the explicit causal delegation chain of a resolved context, in
// order:
//
//	subject (Human|Workload) → Agent → Client → Culvert capability → Server → Tool → Resource
//
// Management stops at the Culvert capability and never carries a Server/Tool link
// (Resolve rejects a Management context that does). Optional links (Agent, and
// the Gateway Server/Tool/Resource) are simply absent when not present — they are
// NEVER synthesized from display names or untrusted parameters.
func (c *ResolvedContext) Chain() []Link {
	subjectLink := c.subject.ref().asLink()
	links := []Link{subjectLink, {Kind: KindClient, ID: c.client.ClientID}}
	// Insert the agent link (if any) between subject and client.
	if c.agent != nil {
		links = []Link{subjectLink, {Kind: KindAgent, ID: c.agent.AgentID}, {Kind: KindClient, ID: c.client.ClientID}}
	}
	// The Culvert capability link.
	links = append(links, Link{Kind: KindResource, ID: capabilityResourceID(c.capability, c.canonicalResource)})
	if c.server != nil {
		links = append(links, Link{Kind: KindServer, ID: string(*c.server)})
	}
	if c.tool != nil {
		links = append(links, Link{Kind: KindTool, ID: string(c.tool.Server) + "/" + c.tool.Name})
	}
	if c.resource != nil {
		links = append(links, Link{Kind: KindResource, ID: c.resource.Type + ":" + c.resource.ID})
	}
	return links
}

func (r PrincipalRef) asLink() Link { return Link(r) }

// capabilityResourceID labels the Culvert capability link with the canonical
// resource so the chain records WHICH Culvert surface authority stops at.
func capabilityResourceID(capability protocol.Capability, canonical string) string {
	if canonical != "" {
		return canonical
	}
	if capability == protocol.Management {
		return "culvert:management"
	}
	return "culvert:gateway"
}
