package server

import (
	"errors"
	"testing"

	"culvert-maint/internal/runner"
)

// Only a positive proof is compatible; every unknown stays unknown and never
// restores.
func TestDataCompat(t *testing.T) {
	r12 := runner.EpochRange{Labelled: true, Min: 1, Max: 2}
	at := func(n int) *runner.DataEpoch { return &runner.DataEpoch{Epoch: n, BuildMin: 1, BuildMax: n} }
	boom := errors.New("read failed")
	cases := []struct {
		name    string
		rng     runner.EpochRange
		rngErr  error
		data    *runner.DataEpoch
		dataErr error
		want    compatVerdict
	}{
		{"within, at min", r12, nil, at(1), nil, compatOK},
		{"within, at max", r12, nil, at(2), nil, compatOK},
		{"data newer than the image reads", r12, nil, at(3), nil, compatIncompatible},
		{"data older than the image reads", runner.EpochRange{Labelled: true, Min: 2, Max: 3}, nil, at(1), nil, compatIncompatible},
		{"unlabelled image", runner.EpochRange{}, nil, at(1), nil, compatUnknown},
		{"labels unreadable", runner.EpochRange{}, boom, at(1), nil, compatUnknown},
		{"data epoch unreadable", r12, nil, nil, boom, compatUnknown},
		{"data epoch missing", r12, nil, nil, nil, compatUnknown},
		{"malformed range passed in", runner.EpochRange{Labelled: true, Min: 3, Max: 1}, nil, at(1), nil, compatUnknown},
		{"data epoch zero passed in", r12, nil, &runner.DataEpoch{}, nil, compatUnknown},
	}
	for _, c := range cases {
		if got, reason := dataCompat(c.rng, c.rngErr, c.data, c.dataErr); got != c.want || reason == "" {
			t.Errorf("%s: dataCompat = %v (%q), want %v", c.name, got, reason, c.want)
		}
	}
}
