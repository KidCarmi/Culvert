package main

// Data-epoch wiring (ADR-0062 slice 6a, contract UPG-003; internal/dataepoch).
//
// Two entry points:
//
//   - checkDataEpochAtBoot, once per proxy start, before any store loads:
//     raises <dataDir>/.data-epoch to this build's epoch and never lowers it.
//     At epoch 1 (every build so far) it writes nothing. Data written by a
//     newer build is logged loudly and the boot carries on, as it always has:
//     refusing such a boot is a separate decision this change does not make.
//     A raise that cannot be written is FATAL, because the build would
//     otherwise migrate data while the marker still names the older epoch,
//     and a later recovery could put back an image that cannot read it.
//   - `culvert --print-data-epoch`, a read-only one-shot the maintenance
//     agent runs through the profile-gated `cli` service: prints the data
//     directory's epoch and this build's range as one JSON object.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/KidCarmi/Culvert/internal/dataepoch"
)

// checkDataEpochAtBoot raises the data epoch marker to this build's epoch.
func checkDataEpochAtBoot() {
	out, cur, err := dataepoch.RaiseTo(dataDir, dataepoch.Current)
	switch {
	case err != nil && cur.Epoch != 0 && cur.Epoch < dataepoch.Current:
		fmt.Fprintf(os.Stderr, "FATAL: the data epoch marker could not be raised to %d: %v\n", dataepoch.Current, err)
		os.Exit(1)
	case err != nil:
		// The marker could not be read. This build is at the implicit epoch
		// and writes nothing; anything that asks for the data epoch is told
		// the marker is unreadable, and recovery treats that as unknown.
		logger.Printf("WARN: data epoch: %q", sanitizeLog(err.Error()))
	case out == dataepoch.Newer:
		logger.Printf("WARN: data epoch: this data directory was written by a newer build (epoch %d); this build reads epochs %d to %d",
			cur.Epoch, dataepoch.OldestReadable, dataepoch.Current)
	case out == dataepoch.Raised:
		logger.Printf("data epoch: raised to %d", cur.Epoch)
	}
}

// runPrintDataEpoch is the --print-data-epoch one-shot.
func runPrintDataEpoch(w io.Writer) error {
	r, err := dataepoch.ReportFor(dataDir)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(r)
}
