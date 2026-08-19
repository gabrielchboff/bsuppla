//! Baseline handling: load a known-good findings file, diff, and export.

use std::collections::HashSet;
use std::fs;

use crate::core::Finding;
use crate::error::Result;

/// Load baseline entries (`<kind>: <path>` lines) as a set of finding keys.
pub fn load_baseline(path: Option<&str>) -> Option<HashSet<String>> {
    let path = path?;
    let content = fs::read_to_string(path).ok()?;
    let mut set = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        set.insert(line.to_string());
    }
    Some(set)
}

/// Split findings into (new, known) based on the baseline.
pub fn diff_with_baseline<'a>(
    findings: &'a [&Finding],
    baseline: &HashSet<String>,
) -> (Vec<&'a Finding>, Vec<&'a Finding>) {
    if baseline.is_empty() {
        return (findings.to_vec(), Vec::new());
    }
    let mut new_findings = Vec::new();
    let mut known = Vec::new();
    for f in findings {
        if baseline.contains(&f.key()) {
            known.push(*f);
        } else {
            new_findings.push(*f);
        }
    }
    (new_findings, known)
}

/// Baseline entries that were not observed in the current scan.
pub fn missing_from_scan(findings: &[&Finding], baseline: &HashSet<String>) -> Vec<String> {
    if baseline.is_empty() {
        return Vec::new();
    }
    let present: HashSet<String> = findings.iter().map(|f| f.key()).collect();
    baseline
        .iter()
        .filter(|k| !present.contains(*k))
        .cloned()
        .collect()
}

/// Write the current findings to a baseline file for future scans.
pub fn write_baseline(path: &str, findings: &[&Finding]) -> Result<()> {
    let mut lines: Vec<String> = findings.iter().map(|f| f.key()).collect();
    lines.sort();
    let content = lines.join("\n");
    fs::write(path, content)?;
    Ok(())
}
