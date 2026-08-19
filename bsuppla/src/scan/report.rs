//! One-line report output: findings list, baseline status, suspicion level.
//!
//! JSON/other report formats can be added here without touching the scanner.

use std::collections::HashSet;

use super::allowlist::{self, AllowEntry};
use super::baseline;
use crate::core::Finding;
use crate::error::Result;

pub fn report_findings(
    findings: &[Finding],
    allowlist: &[AllowEntry],
    baseline: &HashSet<String>,
    baseline_out_path: Option<&str>,
) -> Result<()> {
    let filtered: Vec<&Finding> = findings
        .iter()
        .filter(|f| !allowlist::is_allowlisted(f, allowlist))
        .collect();

    let baseline_filtered = allowlist::filter_baseline(baseline, allowlist);
    let (new_findings, known_findings) =
        baseline::diff_with_baseline(&filtered, &baseline_filtered);
    let missing_baseline = baseline::missing_from_scan(&filtered, &baseline_filtered);

    if let Some(path) = baseline_out_path {
        baseline::write_baseline(path, &filtered)?;
        println!("[+] Baseline written: {path}");
    }

    if new_findings.is_empty() && baseline_filtered.is_empty() {
        println!("[+] No high-signal findings detected.");
        println!("[+] Suspicion level: low");
        return Ok(());
    }

    if !new_findings.is_empty() {
        println!("[+] Findings:");
        for f in &new_findings {
            println!(" - {}: {} ({})", f.kind, f.path.display(), f.detail);
        }
    } else if !baseline_filtered.is_empty() {
        println!("[+] No new findings (all matched baseline).");
    }

    if !baseline_filtered.is_empty() {
        println!("[+] Baseline matched: {}", known_findings.len());
        if !missing_baseline.is_empty() {
            println!("[+] Baseline missing:");
            for key in &missing_baseline {
                println!(" - {key}");
            }
        }
    }

    let level = suspicion_level(&new_findings);
    println!("[+] Suspicion level: {level}");
    Ok(())
}

fn suspicion_level(findings: &[&Finding]) -> &'static str {
    let mut score = 0u32;
    for f in findings {
        score += f.severity.score();
    }
    if score >= 10 {
        "high"
    } else if score >= 4 {
        "medium"
    } else {
        "low"
    }
}

#[cfg(test)]
mod tests {
    use super::suspicion_level;
    use crate::core::{Finding, Severity};
    use std::path::PathBuf;

    fn finding(severity: Severity) -> Finding {
        Finding::new("test", PathBuf::from("/test"), "d".to_string(), severity)
    }

    #[test]
    fn level_is_low_for_small_scores() {
        let f = finding(Severity::Low);
        assert_eq!(suspicion_level(&[&f]), "low");
    }

    #[test]
    fn level_is_medium_at_threshold() {
        let f = finding(Severity::Medium);
        let g = finding(Severity::Low);
        // 3 + 2 = 5 (>= 4)
        assert_eq!(suspicion_level(&[&f, &g]), "medium");
    }

    #[test]
    fn level_is_high_for_large_scores() {
        let f = finding(Severity::High);
        let g = finding(Severity::High);
        let h = finding(Severity::Medium);
        assert_eq!(suspicion_level(&[&f, &g, &h]), "high");
    }
}
