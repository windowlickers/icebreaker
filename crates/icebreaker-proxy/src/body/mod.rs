//! Body handling utilities for response scanning.

mod decompressing;
mod overlap_buffer;
mod scanning;

pub use decompressing::{DecompressError, DecompressingBody};
pub use overlap_buffer::{OverlapBuffer, StreamScanner, DEFAULT_OVERLAP_SIZE};
pub use scanning::{ScanningBody, SecretScannerConfig};
