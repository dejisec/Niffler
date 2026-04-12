//! NFSv4 client implementation via libnfs.
//!
//! Always compiled in — requires system libnfs (linked via pkg-config in build.rs).
//! Uses manual FFI declarations against the libnfs C library.

mod connector;
mod ffi;
mod ops;

pub use connector::Nfs4Connector;
