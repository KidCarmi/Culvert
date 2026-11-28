// Data-epoch reads for runtime recovery (ADR-0062 slice 6a, contract UPG-003).
//
// Two read-only facts decide whether an earlier proxy image may be put back on
// the running data:
//
//   - ReadDataEpoch: the data directory's epoch, as `culvert
//     --print-data-epoch` reports it from inside the profile-gated `cli`
//     service (the only container that mounts the data volume on demand). The
//     image the `cli` service runs is whatever culvert/proxy:pinned is now; an
//     image built before slice 6a has no such flag and the read fails.
//   - ImageDataEpochRange: the epochs an image reads, from its labels, through
//     the existing `docker image inspect` template.
//
// Neither changes anything in Docker beyond the short-lived `cli` container.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Image label keys (internal/dataepoch in the main module).
const (
	DataEpochLabelMin = "io.culvert.data-epoch.min"
	DataEpochLabelMax = "io.culvert.data-epoch.max"
)

// DataEpoch is the data directory's epoch as the proxy image reported it.
type DataEpoch struct {
	Epoch         int
	MarkerPresent bool
	// BuildMin and BuildMax are the range of the image that read it.
	BuildMin, BuildMax int
}

type dataEpochReport struct {
	Schema        int   `json:"schema"`
	Epoch         int   `json:"epoch"`
	MarkerPresent *bool `json:"marker_present"`
	BuildMin      int   `json:"build_min"`
	BuildMax      int   `json:"build_max"`
}

// ReadDataEpoch runs the data-epoch one-shot. Any failure, including an image
// that predates the flag, is an error: the epoch is then unknown.
func (r *Runner) ReadDataEpoch(ctx context.Context) (*DataEpoch, error) {
	tmpl := templateByID(TemplateComposeCLIDataEpoch)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeCLIDataEpoch not registered")
	}
	res, err := r.runWithEnv(ctx, r.buildArgv(tmpl), map[string]string{EnvCulvertBackupPassphrase: ""})
	if err != nil {
		return nil, fmt.Errorf("data epoch: %w", err)
	}
	return parseDataEpoch(res.Stdout)
}

// parseDataEpoch takes the single JSON object line the one-shot prints. Any
// other line on stdout, an unknown field or a missing one is an error.
func parseDataEpoch(stdout []byte) (*DataEpoch, error) {
	var line []byte
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	for sc.Scan() {
		l := bytes.TrimSpace(sc.Bytes())
		if len(l) == 0 {
			continue
		}
		if line != nil {
			return nil, errors.New("data epoch: more than one line of output")
		}
		line = append([]byte(nil), l...)
	}
	if line == nil {
		return nil, errors.New("data epoch: no output")
	}
	var rep dataEpochReport
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("data epoch: %w", err)
	}
	switch {
	case rep.Schema != 1:
		return nil, fmt.Errorf("data epoch: report schema %d", rep.Schema)
	case rep.Epoch < 1 || rep.MarkerPresent == nil:
		return nil, errors.New("data epoch: incomplete report")
	case rep.BuildMin < 1 || rep.BuildMin > rep.BuildMax:
		return nil, fmt.Errorf("data epoch: build range %d..%d", rep.BuildMin, rep.BuildMax)
	}
	return &DataEpoch{Epoch: rep.Epoch, MarkerPresent: *rep.MarkerPresent, BuildMin: rep.BuildMin, BuildMax: rep.BuildMax}, nil
}

// EpochRange is the range of data epochs an image declares it reads.
// Labelled is false when the image carries neither label.
type EpochRange struct {
	Labelled bool
	Min, Max int
}

// ImageDataEpochRange reads an image's data-epoch labels. An image with
// neither label is Labelled=false (no error); one label without the other, a
// value that is not a positive integer, or min > max is an error.
func (r *Runner) ImageDataEpochRange(ctx context.Context, imageRef string) (EpochRange, error) {
	res, err := r.ComposeImageInspect(ctx, imageRef)
	if err != nil {
		return EpochRange{}, fmt.Errorf("image data epochs: %w", err)
	}
	return parseEpochLabels(res.Stdout)
}

func parseEpochLabels(stdout []byte) (EpochRange, error) {
	var recs []struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(stdout, &recs); err != nil {
		return EpochRange{}, fmt.Errorf("image data epochs: %w", err)
	}
	if len(recs) != 1 {
		return EpochRange{}, fmt.Errorf("image data epochs: %d inspect records", len(recs))
	}
	lb := recs[0].Config.Labels
	minS, hasMin := lb[DataEpochLabelMin]
	maxS, hasMax := lb[DataEpochLabelMax]
	switch {
	case !hasMin && !hasMax:
		return EpochRange{}, nil
	case hasMin != hasMax:
		return EpochRange{}, errors.New("image data epochs: only one of the two labels is set")
	}
	lo, err1 := positiveInt(minS)
	hi, err2 := positiveInt(maxS)
	if err1 != nil || err2 != nil || lo > hi {
		return EpochRange{}, fmt.Errorf("image data epochs: malformed labels %q..%q", minS, maxS)
	}
	return EpochRange{Labelled: true, Min: lo, Max: hi}, nil
}

func positiveInt(s string) (int, error) {
	if s == "" || strings.TrimSpace(s) != s || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "0") {
		return 0, errors.New("not a canonical positive integer")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, errors.New("not a positive integer")
	}
	return n, nil
}
