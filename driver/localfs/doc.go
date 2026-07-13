// Package localfs implements the Carrack VFS V2 complete-object contract on a
// rooted local filesystem.
//
// Every published StorageKey names one complete regular file. Resumable upload
// parts live only below the reserved .carrack directory and are assembled into
// one complete file before publication. They are never inventory objects and
// never become independently addressable VFS data.
//
// Local filesystems natively support complete reads, exact ranges, atomic
// no-replace publication, deletion, and inventory. This driver emulates durable
// arbitrary-order multipart upload with local staging files. SHA-256 is checked
// while bytes are persisted and again while staged parts are assembled, so no
// post-publication readback is required. It does not support server-side copy;
// callers must stream the complete object through Carrack when copy is required.
package localfs
