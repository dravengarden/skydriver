// Package driver defines the Skydriver VFS V2 complete-object storage contract.
//
// A driver stores one immutable Skydriver file version as one complete provider
// object. Multipart parts, verification blocks, encryption frames, and byte
// ranges are transfer details and never independently addressable VFS data.
//
// The package separates mandatory complete-object semantics from optional
// acceleration interfaces. Callers use one high-level API and assess declared
// capabilities before I/O; they do not branch on concrete provider kinds.
package driver
