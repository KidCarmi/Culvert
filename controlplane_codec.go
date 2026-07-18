package main

// controlplane_codec.go — the wire codec for the hand-rolled ConfigService.
//
// The CP↔DP service passes json.RawMessage as both request and response (JSON
// over gRPC, no protoc — see controlplane.go). gRPC's DEFAULT codec is protobuf,
// which rejects json.RawMessage ("proto: failed to marshal, message is
// json.RawMessage, want proto.Message"), so without a codec the real gRPC path
// fails at (un)marshal time for every RPC. No test ever caught this because the
// cluster tests drive the RPCs through the callForTest mock. This file supplies
// a raw byte-passthrough CodecV2 registered under a private content-subtype and
// forced onto every cluster call, so the JSON bytes travel verbatim.

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/mem"
)

// clusterCodecName is the gRPC content-subtype for the ConfigService codec.
// Private to this build; the client forces it (grpc.ForceCodecV2) and the
// server resolves it from the global registry by this name — so both peers use
// the raw codec without touching the default proto codec that other libraries
// may rely on.
const clusterCodecName = "culvertjsonraw"

func init() { encoding.RegisterCodecV2(rawCodec{}) }

// rawCodec is a CodecV2 that treats json.RawMessage as opaque bytes: no
// re-encoding, no schema. Marshal accepts the value/pointer forms gRPC hands it
// (request value on the client, handler-returned value on the server); Unmarshal
// fills a *json.RawMessage with an owned copy of the wire bytes.
type rawCodec struct{}

func (rawCodec) Name() string { return clusterCodecName }

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	var b []byte
	switch m := v.(type) {
	case json.RawMessage:
		b = m
	case *json.RawMessage:
		b = *m
	case []byte:
		b = m
	default:
		return nil, fmt.Errorf("rawCodec: cannot marshal %T (want json.RawMessage)", v)
	}
	// SliceBuffer has no pool, so gRPC's free is a no-op — handing it the
	// caller's slice is safe (gRPC never mutates it before sending).
	return mem.BufferSlice{mem.SliceBuffer(b)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	m, ok := v.(*json.RawMessage)
	if !ok {
		return fmt.Errorf("rawCodec: cannot unmarshal into %T (want *json.RawMessage)", v)
	}
	// Materialize copies into a fresh slice we own — safe to retain after gRPC
	// frees the wire buffers on return.
	*m = data.Materialize()
	return nil
}

// clusterClientCallOptions returns the default call options for every CP↔DP
// gRPC call: the raw codec (mandatory — the default proto codec cannot carry
// json.RawMessage), the raised frame budget on both directions, and the opt-in
// gzip compressor. Shared by the DP client's connect() and the bufconn
// round-trip tests so the tested option set is exactly the production one.
func clusterClientCallOptions() []grpc.CallOption {
	opts := []grpc.CallOption{
		grpc.ForceCodecV2(rawCodec{}),
		// Asymmetric: the client RECEIVES the big snapshot (GetConfig / HASync
		// responses) but only SENDS tiny requests, so recv gets the full frame
		// and send is pinned to the tight inbound bound (mirror of the server).
		grpc.MaxCallRecvMsgSize(maxClusterGRPCMsgSize),
		grpc.MaxCallSendMsgSize(maxClusterInboundMsgSize),
	}
	// gzip is OPT-IN and default-off (clusterGRPCCompression). See connect()
	// and CULVERT_CLUSTER_GRPC_COMPRESSION for the CP-first migration rationale.
	if clusterGRPCCompression {
		opts = append(opts, grpc.UseCompressor(gzip.Name))
	}
	return opts
}
