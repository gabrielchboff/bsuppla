//! Filesystem walking + scan orchestration.
//!
//! Walks the reconstructed image filesystem and runs every registered
//! detector on each file, then hands the findings to the reporter.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::{allowlist, baseline, report};
use crate::core::{DetectorRegistry, FileContext, Finding};
use crate::detectors;
use crate::error::Result;

pub fn scan_filesystem(
    root: &str,
    allowlist_path: Option<&str>,
    baseline_path: Option<&str>,
    baseline_out_path: Option<&str>,
) -> Result<()> {
    println!("\n[+] Scanning filesystem for potential supply-chain issues...\n");
    let root_path = Path::new(root);
    let allowlist = allowlist::load_allowlist(allowlist_path);
    let baseline = baseline::load_baseline(baseline_path).unwrap_or_default();

    // A detector is a pure function of the file context; the registry is
    // built once and shared across the whole walk.
    let registry = detectors::default_registry();

    let findings = walk_dir(root_path, root_path, &registry)?;
    report::report_findings(&findings, &allowlist, &baseline, baseline_out_path)?;
    Ok(())
}

fn walk_dir(root: &Path, path: &Path, registry: &DetectorRegistry) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(findings),
    };

    let ftype = meta.file_type();
    if ftype.is_symlink() {
        return Ok(findings);
    }

    if meta.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return Ok(findings),
        };

        for entry in entries.flatten() {
            findings.extend(walk_dir(root, &entry.path(), registry)?);
        }
        return Ok(findings);
    }

    if !meta.is_file() {
        return Ok(findings);
    }

    let rel_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();

    let mode = meta.permissions().mode();
    let is_exec = (mode & 0o111) != 0;
    let is_world_writable = (mode & 0o002) != 0;
    let is_world_readable = (mode & 0o004) != 0;
    let is_suid = (mode & 0o4000) != 0;
    let is_sgid = (mode & 0o2000) != 0;

    let ctx = FileContext {
        path: &path.to_path_buf(),
        relative_path: &rel_path,
        mode,
        is_executable: is_exec,
        is_world_writable,
        is_world_readable,
        is_suid,
        is_sgid,
    };

    for finding in registry.detect(&ctx) {
        findings.push(finding);
    }

    Ok(findings)
}
