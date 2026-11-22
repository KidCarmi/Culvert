// Package uploadqueue is the persistent, node-local queue of support bundles
// an operator has consented to upload, and the state machine each entry moves
// through (IM-029, ADR-0062; M6 Secure Upload, PR-3).
//
// A Queue owns: the entry record and its JSON form, one file per bundle in a
// directory its owner names, the five states, the idempotent enqueue and
// re-arm rule, the two capacity checks, terminal-record pruning, the
// classification of one attempt's result, and the retry ladder.
//
// A Queue does not own: where the data directory is, which ids are bundle
// ids, how a file is made durable, how a remote error text is scrubbed, or
// the four bounds. Those are Options. It does not decide whether upload is
// enabled, does not seal or transfer a bundle, starts no goroutine and writes
// no audit record: the consent gate, the worker and the transfer are main's,
// and the transfer client is the parent package's.
//
// Every Queue is independent. The package has no package-level state beyond
// its error values, and no init.
package uploadqueue
