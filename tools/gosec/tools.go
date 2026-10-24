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
//	go install -C tools/gosec github.com/securego/gosec/v2/cmd/gosec
//
// Remove this module and return the workflows to `go install …@<version>`
// once a gosec release both loads Go 1.27 packages and scans the root module
// without load errors.
package gosectool

import _ "github.com/securego/gosec/v2/cmd/gosec"
