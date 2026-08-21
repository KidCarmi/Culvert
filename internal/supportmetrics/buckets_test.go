package supportmetrics

import (
	"math"
	"testing"
)

func TestBucketLadder_ValidateNilIsValid(t *testing.T) {
	var b *BucketLadder
	if err := b.Validate(); err != nil {
		t.Fatalf("nil ladder must validate (no bucket definition): %v", err)
	}
}

func TestBucketLadder_ValidateRejectsEmptyLabels(t *testing.T) {
	b := &BucketLadder{}
	if err := b.Validate(); err == nil {
		t.Fatal("ladder with no labels must fail validation")
	}
}

func TestBucketLadder_ValidateRejectsMismatchedThresholdCount(t *testing.T) {
	b := &BucketLadder{Labels: []string{"a", "b", "c"}, Thresholds: []float64{1}}
	if err := b.Validate(); err == nil {
		t.Fatal("ladder with len(labels)-1 != len(thresholds) must fail validation")
	}
}

func TestBucketLadder_ValidateRejectsEmptyLabel(t *testing.T) {
	b := &BucketLadder{Labels: []string{"a", ""}, Thresholds: []float64{1}}
	if err := b.Validate(); err == nil {
		t.Fatal("ladder with an empty label must fail validation")
	}
}

func TestBucketLadder_ValidateRejectsDuplicateLabel(t *testing.T) {
	b := &BucketLadder{Labels: []string{"a", "a"}, Thresholds: []float64{1}}
	if err := b.Validate(); err == nil {
		t.Fatal("ladder with a duplicate label must fail validation")
	}
}

func TestBucketLadder_ValidateRejectsNonAscendingThresholds(t *testing.T) {
	cases := [][]float64{
		{10, 5},   // descending
		{5, 5},    // equal (not strictly ascending)
		{5, 5, 6}, // duplicate in the middle
	}
	for _, thresholds := range cases {
		b := &BucketLadder{Labels: make([]string, len(thresholds)+1), Thresholds: thresholds}
		for i := range b.Labels {
			b.Labels[i] = "l" + string(rune('a'+i))
		}
		if err := b.Validate(); err == nil {
			t.Errorf("thresholds %v must fail validation (not strictly ascending)", thresholds)
		}
	}
}

func TestBucketLadder_ValidateRejectsNonFiniteThreshold(t *testing.T) {
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		b := &BucketLadder{Labels: []string{"a", "b"}, Thresholds: []float64{bad}}
		if err := b.Validate(); err == nil {
			t.Errorf("non-finite threshold %v must fail validation", bad)
		}
	}
}

func TestBucketLadder_ValidateAcceptsWellFormed(t *testing.T) {
	if err := CAExpiryBucketLadder.Validate(); err != nil {
		t.Fatalf("CAExpiryBucketLadder must validate: %v", err)
	}
	if err := UptimeBucketLadder.Validate(); err != nil {
		t.Fatalf("UptimeBucketLadder must validate: %v", err)
	}
}
