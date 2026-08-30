package main

// version is the build-time version string, linker-injected via
// -X main.version=v1.2.3 and read across the binary (e.g. bootstrap.Image,
// /healthz, diagnostics). It previously lived in the now-removed update.go.
// Defaults to "dev" for local/untagged builds.
var version = "dev"

// buildCommit is the immutable commit digest of the build, linker-injected via
// -X main.buildCommit=<short-sha> alongside version. It exists so a build's
// runtime identity (currentRuntimeIdentity → canary.RuntimeIdentity) is UNIQUE
// per commit: `git describe --tags --abbrev=0` stamps only the latest tag, so
// two different commits released under the same tag would otherwise share one
// version and let a later binary reuse an earlier build's Shadow Exit
// attestation / rollback rehearsal / canary runtime state. Empty for local
// (`go build`) builds, whose version is "dev" (already not attestable).
var buildCommit = ""
