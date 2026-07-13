// Package merkle defines the canonical Carrack VFS V2 file and directory
// integrity roots shared by Go clients and the Rust control plane.
//
// Every digest is SHA-256 over an ASCII domain string terminated by NUL,
// followed by fixed-width unsigned big-endian integers and fixed-size binary
// identifiers or digests. Variable names are prefixed by a uint32 byte length.
// The format never hashes JSON, native integer layouts, provider metadata, or
// locale-dependent text.
//
// File leaves commit to block ordinal, exact byte length, and payload. Internal
// nodes commit to their first leaf, leaf count, and both child digests. The
// canonical tree recursively places the largest power-of-two prefix on the
// left. The file root additionally commits to verification block size, exact
// file size, leaf count, and tree digest.
//
// Directory names must already be Unicode NFC and are sorted by their UTF-8
// bytes. File entries commit to stable file ID, immutable version ID, length,
// file root, and portable metadata root. Directory entries commit to stable
// child directory ID and child data root. ACL and placement policy roots remain
// separate from this content tree.
package merkle
