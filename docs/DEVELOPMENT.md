# Development Guide

How the project is organized and how to extend it.

## Layout: support modules + three flat domain folders

Nothing nests deeper than one folder. `detectors/` is the extension surface
and lives at the top level — you should never have to dig to find where
signals live.

```
bsuppla/src/
├── main.rs          Bin entry point (10 lines)
├── lib.rs           Module map (this crate's public API)
│
├── core.rs          Shared domain model + extension API (one file):
│                    Severity, Finding, FileContext, Detector trait,
│                    DetectorRegistry, PathRule — no deps on the rest
├── error.rs         Typed error enum (thiserror)
├── config.rs        Config: CLI args + BSUPPLA_* env vars
├── pipeline.rs      Stage orchestration (composition root)
│
├── ingest/          Input: Docker image -> local filesystem
│   ├── mod.rs
│   ├── docker.rs        docker pull / docker save
│   ├── image.rs         read manifest.json from the image tar
│   ├── manifest.rs      parse the manifest
│   ├── layers.rs        verify layer files exist
│   └── extract.rs       apply layer tars onto an output dir
│
├── scan/            Analysis
│   ├── mod.rs
│   ├── scanner.rs       walk the filesystem, run the detector registry
│   ├── allowlist.rs     suppress known-safe findings
│   ├── baseline.rs      baseline load, diff, export
│   └── report.rs        text report + suspicion level
│
└── detectors/       Signals — the extension surface
    ├── mod.rs           default_registry(): the ONE assembly point
    ├── permissions.rs
    ├── elf.rs
    ├── credentials.rs
    ├── package_managers.rs
    └── risky.rs
```

## Dependencies

```
main → config, pipeline
pipeline → ingest, scan (+ config, error)
scan → detectors, core (+ allowlist/baseline/report internally)
ingest → core, error
detectors → core
core → (nothing)
```

Only `pipeline` composes domains; every other module depends on `core`
types and nothing more. `bsuppla::core` is the public, stable API surface:
any consumer can build a custom registry by composing detectors — no
modification of the crate needed (open-closed at the API level).

## Execution flow

```
Config::from_args (config.rs)
  → pipeline::run (pipeline.rs)
      → ingest::pull / ingest::save            (skippable: BSUPPLA_SKIP_DOCKER)
      → ingest::read_manifest_from_image
      → ingest::parse_manifest
      → ingest::locate_layers
      → ingest::build_filesystem
      → scan::scan_filesystem                  (skippable: BSUPPLA_SKIP_SCAN)
          (one DetectorRegistry built once for the whole walk)
          → detectors::default_registry
          → scan::allowlist / scan::baseline filtering
          → scan::report::report_findings
```

## How to add a new detector

**Everything happens in `detectors/` — one new file, one new line.**

### 1. Simple path/name signal (No struct, no trait impl)

Create `src/detectors/docker_socket.rs`... or simpler: the signal is so
small it can go straight into `default_registry()`:

```rust
// src/detectors/mod.rs — inside default_registry():
registry.register(Box::new(PathRule::new(
    "docker_socket_present",                    // kind (used in allowlist/baseline files)
    Severity::High,                             // Critical | High | Medium | Low
    "docker socket exposed",                    // printed detail
    |ctx| ctx.normalized_path() == "/var/run/docker.sock", // predicate
)));
```

`PathRule::new(kind, severity, detail, predicate)` — that's it, one line.
Note that `PathRule` and `Severity` must be in scope (they are already
imported in `detectors/mod.rs`).

### 2. Signal that reads file contents

Create `src/detectors/<name>.rs`:

```rust
use crate::core::{Detector, FileContext, Finding, Severity};

pub struct MyDetector;

impl Detector for MyDetector {
    fn name(&self) -> &'static str { "my_signal" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        if !ctx.normalized_path().ends_with("/etc/thing") {
            return None;
        }
        let bytes = std::fs::read(ctx.path).ok()?;
        // ...analyze bytes...
        Some(Finding::new(
            "my_signal",
            ctx.relative_path.clone(),
            "why it's suspicious".to_string(),
            self.severity(),
        ))
    }
}
```

Then in `detectors/mod.rs`:

```rust
pub mod my_detector;                                  // 1. declare the module
registry.register(Box::new(my_detector::MyDetector)); // 2. one registration line
```

Done. Add unit tests in the same file.

### 3. Multiple related rules

Give them factory functions in one category file (like
`credentials::authorized_keys_rule()`), register each factory with one
line. Tests live next to the factories.

### FileContext fields

`path` (real path — use to read bytes), `relative_path` (path inside the
image), `normalized_path()` (relative path with leading `/`), `mode`,
`is_executable`, `is_world_writable`, `is_world_readable`, `is_suid`,
`is_sgid`, `file_name_str()`.

## How to add a pipeline stage

1. Put the stage in `ingest/` or `scan/` (or a new folder if it's a new
   domain — folders stay flat, one level max).
2. Declare the module in the folder's `mod.rs`.
3. Call it from `pipeline.rs` at the right spot.
4. Wire options in `config.rs` (env var or CLI flag).

## Conventions

- Findings are `core::Finding` everywhere; allowlist/baseline/report only
  depend on that type, never on specific detectors.
- New errors: add a variant to `error.rs`; `#[from]` auto-converts
  standard error types.
- Sibling modules inside a folder use `super::`; `pipeline.rs` is the only
  place that composes across folders.
- Run `cargo test` (unit + doctest + `tests/cli.rs` end-to-end),
  `cargo clippy`, and `cargo fmt` before committing.