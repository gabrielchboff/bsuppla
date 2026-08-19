//! Scanning domain: detect, filter, and report.
//!
//! - `scanner.rs` walks the reconstructed filesystem and runs all
//!   detectors on each file.
//! - `allowlist.rs` / `baseline.rs` filter findings against known-safe
//!   state.
//! - `report.rs` formats the result.

pub mod allowlist;
pub mod baseline;
pub mod report;
pub mod scanner;

pub use scanner::scan_filesystem;
