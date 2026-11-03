package logstore

import (
	"encoding/json"
)

// batchencode.go — the flush-path serializer for the request-log history store.
//
// WHY THIS EXISTS. writeLoop batches up to flushBatchSize entries and writes
// them to Badger in one WriteBatch. The encode step used to be one
// json.Marshal per entry, and json.Marshal returns a FRESHLY HEAP-ALLOCATED
// slice every call. Because the store takes one entry per proxied request,
// that made the encode step scale its garbage with request rate: measured on a
// 256-entry batch of realistic entries (BenchmarkFlushEncode*), 768 allocations
// and 271 KB of garbage per batch — about 3 allocations and ~1.06 KB per
// request, all of it dead the moment Badger copied it.
//
// batchEncoder keeps ONE buffer and ONE json.Encoder for the lifetime of the
// write loop and appends every record in the batch into that single buffer,
// handing Badger a subslice per entry. Same batch, same bytes, no per-entry
// allocation: 768 → 0 allocations and 271 KB → <1 KB per batch, with the
// encode step itself ~35% faster (it no longer copies each record out of
// json's internal scratch space into a new slice).
//
// This is the shape internal/reqlog/persist.go already uses for the JSONL
// sink (a retained Encoder over a reused bufio.Writer); the history store is
// its sibling sink on the same Entry and simply had not been given it.
//
// THREE INVARIANTS MAKE THE BUFFER REUSE SAFE. Each is load-bearing:
//
//  1. SUBSLICES ARE TAKEN ONLY AFTER ENCODING FINISHES. append may move the
//     backing array, which would silently invalidate any subslice handed out
//     earlier. So add() records OFFSETS and recs()/at() resolve them to slices
//     once the buffer is final. Never interleave add() with at().
//
//  2. THE BUFFER IS RESET ONLY AFTER WriteBatch.Flush HAS RETURNED. Badger
//     does not retain the value slice past the write: skl.Arena.putVal copies
//     the bytes into the memtable arena, and WriteBatch.Flush waits for every
//     pending write via throttle.Finish before returning. Resetting earlier
//     would hand Badger bytes that a later entry overwrites. See writeLoop.
//
//  3. THE STORED BYTES EXCLUDE Encode's TRAILING NEWLINE. json.Encoder.Encode
//     writes exactly json.Marshal's compact output plus one '\n' (and applies
//     the same default HTML escaping), so dropping that one byte makes the
//     value byte-identical to what json.Marshal produced. The history store's
//     values are standalone blobs, not a line-delimited stream, so the newline
//     must not be stored. TestFlushEncodeByteIdentity pins this against
//     json.Marshal — including HTML-escapable runes, invalid UTF-8, U+2028/9,
//     the nested dec block and the zero Entry — so a change in encoding/json
//     fails the build rather than silently rewriting persisted records.
//
// A failed Encode truncates the record back out of the buffer and is reported
// to the caller, preserving writeLoop's original behaviour of SKIPPING an
// unmarshallable entry (and not consuming a sequence number for it) rather
// than aborting the batch or storing a partial value. Entry is all scalars,
// strings, a string slice and one struct pointer, so encoding/json cannot
// actually fail on it today and that arm is unreachable (which is why add is
// not at 100% statement coverage). It is kept because the json.Marshal form it
// replaces had the same guard: the branch is insurance against a future field
// type, not dead weight.

// encoderBufReclaim bounds the buffer the write loop keeps between flushes.
// Steady state is ~256 KB (flushBatchSize entries of ~1 KB), which is worth
// retaining; a pathological outsized entry is not worth pinning for the life
// of the process, so a buffer that grew past this is released after the flush
// and the next batch starts from a fresh one.
const encoderBufReclaim = 1 << 20 // 1 MiB

// encodedRec locates one finished record inside batchEncoder.buf and remembers
// which batch entry produced it, because writeLoop needs that entry's TS to
// build the key and only successfully encoded entries get one.
type encodedRec struct {
	entry      int // index into the batch passed to the write loop
	start, end int // bounds in batchEncoder.buf
}

// batchEncoder serializes a whole batch into one reused buffer. Not safe for
// concurrent use: it is owned by the single writeLoop goroutine.
type batchEncoder struct {
	buf  []byte
	enc  *json.Encoder
	recs []encodedRec
}

// bufAppender is the Encoder's sink. It is stored inside the Encoder at
// construction, so encoding allocates no writer per call. It holds the
// *batchEncoder (not a *[]byte) so the grown slice is published back.
type bufAppender struct{ be *batchEncoder }

func (w bufAppender) Write(p []byte) (int, error) {
	w.be.buf = append(w.be.buf, p...)
	return len(p), nil
}

func newBatchEncoder() *batchEncoder {
	be := &batchEncoder{}
	be.enc = json.NewEncoder(bufAppender{be})
	return be
}

// reset clears the previous batch's records, keeping the buffer's capacity so
// the steady-state batch encodes without growing it. Call only once the
// previous batch's values can no longer be read — see invariant 2.
func (be *batchEncoder) reset() {
	if cap(be.buf) > encoderBufReclaim {
		be.buf = nil // release an outsized buffer rather than pin it
	} else {
		be.buf = be.buf[:0]
	}
	be.recs = be.recs[:0]
}

// add encodes one entry, appending its record to the shared buffer. idx is the
// entry's index in the caller's batch. It reports whether the entry was
// encoded; a false leaves the buffer exactly as it was found.
func (be *batchEncoder) add(idx int, e *Entry) bool {
	start := len(be.buf)
	if err := be.enc.Encode(e); err != nil {
		be.buf = be.buf[:start] // drop any partial write
		return false
	}
	// Invariant 3: strip Encode's single trailing newline. Guarded rather than
	// assumed so a stdlib change cannot silently truncate a record's last byte.
	if n := len(be.buf); n > start && be.buf[n-1] == '\n' {
		be.buf = be.buf[:n-1]
	}
	be.recs = append(be.recs, encodedRec{entry: idx, start: start, end: len(be.buf)})
	return true
}

// at returns record i's bytes. Valid only once the batch is fully encoded
// (invariant 1) and only until the next reset (invariant 2).
func (be *batchEncoder) at(i int) []byte {
	r := be.recs[i]
	return be.buf[r.start:r.end]
}
