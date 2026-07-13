// Package migrations embeds the SQL schema so services and tests apply the exact
// same migration without filesystem path assumptions.
package migrations

import _ "embed"

//go:embed 0001_init.sql
var Schema string
