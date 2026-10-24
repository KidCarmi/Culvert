//go:build go1.27 && !http2legacy

package main

import "net/http"

// h2InspectServeBaseConfig returns the ServeConnOpts.BaseConfig for an inspected-H2
// tunnel served on the shared h2InspectShared. This file is the x/net/http2
// "wrapping" implementation (http2/server_wrap.go), which x/net compiles under
// exactly this constraint — `go1.27 && !http2legacy` — so the two selections can
// never disagree within one build.
//
// In the wrapping implementation, ServeConn with a non-nil BaseConfig serves the
// conn through a ONE-OFF COPY of that http.Server, which base.Shutdown never
// reaches: no GOAWAY on process shutdown. With a nil BaseConfig on a
// ConfigureServer'd server it serves through the serve func bound to base itself,
// so base.Shutdown's RegisterOnShutdown trigger GOAWAYs the conn, and base's live
// MaxHeaderBytes still caps the header list (the h2 caps come from srv either way).
// TestH2InspectServe_* pin both the GOAWAY and the caps.
func h2InspectServeBaseConfig(*http.Server) *http.Server { return nil }
