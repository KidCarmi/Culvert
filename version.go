package main

// version is the build-time version string, linker-injected via
// -X main.version=v1.2.3 and read across the binary (e.g. bootstrap.Image,
// /healthz, diagnostics). It previously lived in the now-removed update.go.
// Defaults to "dev" for local/untagged builds.
var version = "dev"
