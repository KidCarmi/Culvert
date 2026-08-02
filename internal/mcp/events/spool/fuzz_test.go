package spool

import "testing"

// FuzzDecodeRecord feeds arbitrary bytes into the untrusted segment-record decoder.
// The invariant is total: no input may panic, and a malformed frame is rejected —
// a spool recovering from a corrupted or attacker-influenced segment must never
// crash.
func FuzzDecodeRecord(f *testing.F) {
	f.Add([]byte("MCPR"))
	f.Add(make([]byte, recFixedPrefixLen))
	f.Add(append([]byte("MCPR\x01\x01"), make([]byte, 200)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := decodeRecordAt(data)
		if err != nil {
			return
		}
		// A decoded frame's declared total must be within the buffer.
		if fr.total > len(data) || fr.total < recFixedPrefixLen {
			t.Fatalf("decoded frame total out of range: %d (buf %d)", fr.total, len(data))
		}
	})
}

// FuzzDecodeSegHeader fuzzes the segment-header decoder.
func FuzzDecodeSegHeader(f *testing.F) {
	f.Add(make([]byte, segHeaderLen))
	f.Add(encodeSegHeader(segHeader{partition: 1, capability: 1, segID: 1, firstSeq: 1}))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeSegHeader(data) // must not panic
	})
}

// FuzzDecodeCheckpoint fuzzes the checkpoint decoder; a corrupt checkpoint must be
// rejected, never panic.
func FuzzDecodeCheckpoint(f *testing.F) {
	ck := checkpoint{Version: checkpointVersion, Partition: 1, NextSeq: 1, NextSegID: 1}
	body, _ := ck.encode()
	f.Add(body)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeCheckpoint(data) // must not panic
	})
}
