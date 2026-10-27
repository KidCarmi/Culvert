//go:build tools

// Package gosectool pins the gosec build that the CI security gates install.
//
// It exists for one reason: gosec v2.29.0 (the gate's pinned rules) is built
// against golang.org/x/tools v0.49.0, which cannot read Go 1.27 export data
// ("export data version 5 is greater than maximum supported version"), so on
// the go1.27 toolchain every package fails to load. v2.30.0 moved to a newer
// x/tools but regressed package loading ("no metadata for <pkg>") on every
// toolchain. This module keeps the v2.29.0 rules and only raises x/tools, the
// loader, to a release that reads the current export format.
//
// Install from the repository root with:
//
//	GOTOOLCHAIN="$(sed -n 's/^toolchain //p' go.mod)" \
//	  go install -C tools/gosec github.com/securego/gosec/v2/cmd/gosec
//
// THE GOTOOLCHAIN PREFIX IS NOT OPTIONAL LOCALLY, and it reads the root pin
// rather than naming one: this module carries no `toolchain` line on purpose
// (toolchain_consistency_test.go: the version lives in exactly ONE place), so
// `go install -C tools/gosec` alone builds gosec with whatever compiler the
// developer has. CI does not need the prefix because setup-go installs the
// pinned compiler and exports GOTOOLCHAIN=local, and no workflow may set
// GOTOOLCHAIN itself — do not "fix" a workflow by adding one.
//
// The failure mode this prevents is a SILENT ALL-CLEAR, not a build error. A
// gosec built by go1.26 against a go1.27 tree cannot read the newer export
// data, so go/types rejects it inside the scanner: the run prints "Golang
// errors in file ... could not import math/rand/v2" against two unrelated
// files, reports `Issues: 0`, and exits non-zero for the load error. Measured
// on 2026-10-25: that shape hid FOUR HIGH G704 findings that the same gosec
// built on go1.27.3 reported immediately. A scanner that cannot type-check the
// tree has not cleared it — read the Golang-errors block before the Issues
// count, and never take a zero with load errors above it as a pass.
//
// Remove this module and return the workflows to `go install …@<version>`
// once a gosec release both loads Go 1.27 packages and scans the root module
// without load errors.
package gosectool

import _ "github.com/securego/gosec/v2/cmd/gosec"
