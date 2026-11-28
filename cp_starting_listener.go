package main

// cp_starting_listener.go — the control plane's EARLY listener.
//
// The start-up sequence activates the cluster role (first publish, listener
// bind, HA resume) only after every configuration store has loaded. Without
// this file the control-plane port would therefore be CLOSED for the whole
// store-loading phase, and a peer cannot tell a closed port on a restarting
// node from a dead one: a standby counts it toward failover.
//
// So a control plane binds its gRPC address in phase 1, right after its
// identity and cluster CA are established, with a server that can say exactly
// one thing: CULVERT_NODE_STARTING (node_lifecycle.go), for every
// ConfigService method.
//
// It is a SEPARATE, minimal server, by design:
//
//   - It registers no real handler. There is no code path from it to a store,
//     to a publish, to enrolment or to leadership — it cannot serve a snapshot
//     or mutate anything, whatever arrives.
//   - It advertises nothing: no role claim, no CP address publish, no HA
//     status. ADR-0005's commit-before-advertise order is untouched.
//   - The CHAOS-71 activation (bind supervisor, role claim on an observed
//     bind, address ownership, onActivated) is not modified at all. The early
//     listener is STOPPED immediately before that activation binds the real
//     server on the same address.
//
// The hand-over is stop-then-bind, so for a moment nothing is listening. A
// peer that connects in that moment sees one connection error and retries; it
// can never see a served configuration before the node is ready, because the
// real server's handlers sit behind the same lifecycle gate (gatedUnary →
// nodeServingRefusal) until markNodeReady. If the real bind then fails, the
// node behaves exactly as it did before this file existed: the resilient boot
// path keeps retrying in the background and reports it (cp_grpc_health.go).

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"time"

	"google.golang.org/grpc"
)

// cpStartingListener is one bound early listener.
type cpStartingListener struct {
	srv  *grpc.Server
	addr string
	done chan struct{}
}

// cpStartingMethods is every ConfigService method, from the same table that
// classifies them for HA serving (cpRPCPolicies — pinned complete by
// TestChaos71_Wall_EveryCPRPCHasAnHAServingPolicy), so a new RPC is answered
// "starting" here without anyone remembering to add it.
func cpStartingMethods() []string {
	out := make([]string, 0, len(cpRPCPolicies))
	for m := range cpRPCPolicies {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// registerStartingConfigService registers ConfigService on srv with every
// method answering the starting status. No controlPlaneServer exists here.
func registerStartingConfigService(srv *grpc.Server) {
	methods := cpStartingMethods()
	descs := make([]grpc.MethodDesc, 0, len(methods))
	for _, m := range methods {
		descs = append(descs, grpc.MethodDesc{MethodName: m, Handler: cpStartingHandler(m)})
	}
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: configServiceName,
		HandlerType: (*controlPlaneServer)(nil),
		Methods:     descs,
		Streams:     []grpc.StreamDesc{},
	}, nil)
}

func cpStartingHandler(method string) func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
	return func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var discard json.RawMessage
		_ = dec(&discard) //nolint:errcheck // the request is not read; the answer does not depend on it
		return nil, cpStartingStatus(method)
	}
}

// startCPStartingListener binds cfg.addr with the starting server. It returns
// nil — logged, never fatal — when the listener cannot be built (TLS material
// that does not load, a port that is taken): the activation that follows owns
// reporting and retrying the real bind, exactly as before.
func startCPStartingListener(cfg cpListenerConfig) *cpStartingListener {
	serverOpt, mode, err := cpServerOptionMode(cfg.certFile, cfg.keyFile, cfg.caFile)
	if err != nil {
		logger.Printf("Startup: control-plane early listener not started (%q) — the port stays closed until the node is ready; the activation will report the listener",
			sanitizeLog(err.Error()))
		return nil
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", cfg.addr)
	if err != nil {
		logger.Printf("Startup: control-plane early listener could not bind %q (%q) — the port stays closed until the node is ready; the activation will retry the bind",
			sanitizeLog(cfg.addr), sanitizeLog(err.Error()))
		return nil
	}
	srv := newControlPlaneGRPCServer(serverOpt)
	registerStartingConfigService(srv)
	l := &cpStartingListener{srv: srv, addr: cfg.addr, done: make(chan struct{})}
	go func() {
		defer close(l.done)
		_ = srv.Serve(ln) //nolint:errcheck // ends on stopEarlyListener(); a serve error only closes the early listener
	}()
	logger.Printf("Startup: control-plane listener bound in STARTING state on %s (%s, %s after process start) — every request is answered %s until the node is ready",
		sanitizeLog(cfg.addr), mode, nodeStartupElapsed().Round(time.Millisecond), cpStartingStatusMarker)
	return l
}

// stopEarlyListener closes the early listener and waits for its serve loop to end, so the
// address is free for the activation's bind. Safe on nil and idempotent. It
// does not drain: every answer this server gives is an immediate refusal.
func (l *cpStartingListener) stopEarlyListener() {
	if l == nil || l.srv == nil {
		return
	}
	l.srv.Stop()
	<-l.done
	l.srv = nil
	logger.Printf("Startup: control-plane early listener on %s stopped — handing the address to the activation", sanitizeLog(l.addr))
}
