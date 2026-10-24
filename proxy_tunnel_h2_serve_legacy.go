//go:build !(go1.27 && !http2legacy)

package main

import "net/http"

// h2InspectServeBaseConfig returns the ServeConnOpts.BaseConfig for an inspected-H2
// tunnel served on the shared h2InspectShared. This file is the original
// x/net/http2 implementation (http2/server.go), which x/net compiles under exactly
// this constraint — `!(go1.27 && !http2legacy)` — so the two selections can never
// disagree within one build.
//
// In the original implementation every ServeConn'd conn registers into the
// ConfigureServer'd shutdown state regardless of BaseConfig, but the header-list
// cap is read ONLY from BaseConfig: a nil one is replaced by a zero http.Server,
// silently dropping MaxHeaderBytes to the library default. So base must be passed
// here. See proxy_tunnel_h2_serve_wrap.go for the other implementation;
// TestH2InspectServe_* pin both the GOAWAY and the caps.
func h2InspectServeBaseConfig(base *http.Server) *http.Server { return base }
