//! bsuppla — statically analyze Docker images without executing them.
//!
//! Layout: three flat domain folders plus support modules at the root.
//!
//! ```text
//! src/
//! ├── main.rs        bin entry point
//! ├── lib.rs         this module map
//! ├── core.rs        Severity, Finding, FileContext, Detector,
//! │                  DetectorRegistry, PathRule — shared domain model
//! ├── error.rs       typed error enum
//! ├── config.rs      Config (CLI + env)
//! ├── pipeline.rs    stage orchestration
//! ├── ingest/        Docker image -> local filesystem (docker, image,
//! │                  manifest, layers, extract)
//! ├── scan/          analysis (scanner walker, allowlist, baseline, report)
//! └── detectors/     signals — the extension surface
//! ```

pub mod config;
pub mod core;
pub mod detectors;
pub mod error;
pub mod ingest;
pub mod pipeline;
pub mod scan;
