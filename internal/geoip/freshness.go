package geoip

// freshness.go — CHAOS-127. Reading the build timestamp of a .mmdb file on
// disk WITHOUT publishing it as the live reader.
//
// BuildTime() (geoip.go) answers "how old is the database this process is
// SERVING", which is the right question for detection purposes and the one
// every surface in the product asks. It cannot answer the second question an
// operator has the moment they act on a staleness warning: "did the file I
// just replaced actually get picked up?"
//
// It never does. InitGeoDB is startup-only and TryDeferredLoad (deferred.go)
// "is deliberately NOT a reload" — it publishes only while no reader is
// loaded, so on a node with a working database it is a no-op by construction.
// GEO-1/CHAOS-64 records why a true reload is not a rider: the POINTER swap is
// atomic but Close() munmaps the backing buffer, so an in-flight lookup
// holding the old reader reads unmapped memory — a SIGSEGV/SIGBUS that
// recover() cannot catch and that leaves no log line.
//
// So the remedy is a restart, and the thing that was missing is any way for
// the product to SAY SO on evidence. FileBuildTime supplies the evidence: the
// build timestamp of the file as it exists on disk right now, which a caller
// compares against BuildTime() to distinguish "the operator has not updated
// the file yet" from "the operator updated the file and this process is still
// serving the old one until it restarts".
//
// Why the embedded build epoch and not the file's mtime: mtime answers "was
// this path written to", which is the wrong question in both directions. A
// `cp -p` or a restore from an archive preserves mtime and would report no
// change across a real data update, and a `touch` reports a change across
// none. The epoch is a property of the DATA, which is what is being compared.

import (
	"fmt"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// FileBuildTime returns the MaxMind build timestamp embedded in the .mmdb file
// at path, without installing it as this process's live reader.
//
// It never mutates package state and never publishes the reader it opens — it
// closes it before returning, and nothing outside this call can hold it, which
// is the same safety argument publishIfUnloaded makes for the reader it opens
// and declines to install. See the file comment above for why this exists and
// why the embedded epoch is the right measure.
//
// It performs file I/O (an mmap and a metadata parse), so callers must keep it
// off the request and scrape paths.
func FileBuildTime(path string) (time.Time, error) {
	if path == "" {
		return time.Time{}, fmt.Errorf("geoip: no database path configured")
	}
	r, err := geoip2.Open(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	built := readerBuildTime(r)
	// The timestamp is already read and valid; a close failure on a reader
	// nothing else can reach is not a reason to discard it.
	_ = r.Close() //nolint:errcheck // see above: the value is already extracted and the reader is unreachable
	return built, nil
}
