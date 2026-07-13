// Package journal implements Carrack VFS V2 complete-object transfer recovery.
//
// A journal pins one replayable source or one immutable driver object, records
// the exact transfer layout, and publishes immutable progress receipts only
// after payload bytes are durable and verified. Journal state uses append-only
// optimistic revisions; concurrent or stale executors lose a revision CAS and
// can only repeat idempotent driver operations.
//
// Upload parts and download blocks are transfer details. Successful upload
// completion still publishes exactly one complete provider object, and a
// successful download atomically exposes exactly one complete local file.
package journal
