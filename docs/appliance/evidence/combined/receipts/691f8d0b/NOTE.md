# Receipt 691f8d0b — read with its sub-module companion

This run is kept unedited. Commands 21 and 22 (govulncheck in `cmd/culvert-maint`
and `pkg/releaseproof`) exited 3 with Go standard-library advisories "Found in
go1.26". Those two modules carry their own `go.mod` with no `toolchain` line, so
on this host they ran under the host default go1.26.0. CI never does that:
`.github/actions/setup-go-cache` installs the root `toolchain` (go1.27.3) and sets
`GOTOOLCHAIN=local` for every step, and the Dockerfile `maintbuilder` stage is
`golang:1.27.3-alpine`. Command 11 (agent vet + race tests) ran under go1.26.0
for the same reason.

`../691f8d0b-submodules-go1.27.3/` reruns every sub-module command on the SAME
commit and tree under `GOTOOLCHAIN=go1.27.3`, as CI does: all 9 exit 0
(govulncheck: no reachable vulnerabilities; one in a required module, not
called). No code was changed between the two runs.
