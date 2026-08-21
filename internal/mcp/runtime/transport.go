package runtime

import "github.com/KidCarmi/Culvert/internal/mcp/protocol"

// transportPhase is the coarse transport decision for an inbound HTTP method.
type transportPhase uint8

const (
	// phaseTerminal — the request terminates at the transport layer with a fixed
	// HTTP status and ZERO retained streams; the request pipeline is never run.
	phaseTerminal transportPhase = iota
	// phasePipeline — a POST that proceeds into the full request pipeline.
	phasePipeline
)

// transportResult is the transport-layer decision. When phase is phaseTerminal,
// Status is the terminal HTTP status and RetainStream is ALWAYS false — the
// no-stream invariant ("N rejected clients ⇒ zero retained streams") begins here.
type transportResult struct {
	phase        transportPhase
	status       int
	retainStream bool // always false; a field so the invariant is visible/testable
	reason       string
}

// decideTransportMethod maps an HTTP method to its transport decision under the
// frozen 2025 Streamable HTTP baseline. There is deliberately NO legacy
// endpoint-event SSE, NO held stream, and NO automatic fallback:
//
//   - POST proceeds into the full request pipeline.
//   - GET is a terminal 405 with zero streams. PR-5 is observe-only and has no
//     server-initiated messaging, so no GET ever opens a text/event-stream —
//     stronger than "GET without a negotiated session is 405", it holds for every
//     GET (a security-rejected client's follow-on GET terminates at 405 too).
//   - DELETE is a terminal 405.
//   - Every other method is a terminal 405 with no session mutation and no stream.
//
// The only non-4xx transport outcome — the 200 initialize counter-offer — lives
// INSIDE the pipeline (a POST carrying an initialize whose version is
// unsupported), never at method dispatch.
func decideTransportMethod(method string) transportResult {
	switch method {
	case "POST":
		return transportResult{phase: phasePipeline}
	case "GET":
		d := protocol.DecideTransport(protocol.CondGetWithoutNegotiatedContext)
		return transportResult{phase: phaseTerminal, status: d.Status, retainStream: d.RetainStream, reason: d.Reason}
	case "DELETE":
		d := protocol.DecideTransport(protocol.CondDeleteUnsupported)
		return transportResult{phase: phaseTerminal, status: d.Status, retainStream: d.RetainStream, reason: d.Reason}
	default:
		// Any unsupported method: deterministic terminal 405, no session mutation,
		// no stream.
		return transportResult{phase: phaseTerminal, status: 405, retainStream: false, reason: "http_method_rejected"}
	}
}
