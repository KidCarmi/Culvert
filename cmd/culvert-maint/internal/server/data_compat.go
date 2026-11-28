// Image and data compatibility (ADR-0062 slice 6a; owner decision 5: image
// and data compatibility before restoring an earlier image).
//
// dataCompat is the single rule every plan that puts an earlier image back on
// running data must pass. It is three-valued on purpose: anything that is not
// a positive proof is "unknown", and unknown never restores.
package server

import "culvert-maint/internal/runner"

// compatVerdict is the outcome of dataCompat.
type compatVerdict int

const (
	compatUnknown compatVerdict = iota
	compatOK
	compatIncompatible
)

func (v compatVerdict) String() string {
	switch v {
	case compatOK:
		return "compatible"
	case compatIncompatible:
		return "incompatible"
	}
	return "unknown"
}

// Reasons dataCompat gives for a verdict other than compatible.
const (
	compatReasonDataUnreadable   = "data_epoch_unreadable"
	compatReasonLabelsUnreadable = "image_labels_unreadable"
	compatReasonImageUnlabelled  = "image_declares_no_data_epochs"
	compatReasonOutsideRange     = "data_epoch_outside_image_range"
	compatReasonCompatibleWithin = "data_epoch_within_image_range"
)

// dataCompat decides whether the image with range rng may run on the data
// whose epoch is data. dataErr and rngErr are the errors of the two reads.
func dataCompat(rng runner.EpochRange, rngErr error, data *runner.DataEpoch, dataErr error) (verdict compatVerdict, reason string) {
	switch {
	case dataErr != nil || data == nil || data.Epoch < 1:
		return compatUnknown, compatReasonDataUnreadable
	case rngErr != nil:
		return compatUnknown, compatReasonLabelsUnreadable
	case !rng.Labelled:
		return compatUnknown, compatReasonImageUnlabelled
	case rng.Min < 1 || rng.Min > rng.Max:
		return compatUnknown, compatReasonLabelsUnreadable
	case data.Epoch < rng.Min || data.Epoch > rng.Max:
		return compatIncompatible, compatReasonOutsideRange
	}
	return compatOK, compatReasonCompatibleWithin
}
