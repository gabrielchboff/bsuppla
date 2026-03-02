use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::detector::{FileContext, Finding};
use crate::detectors;
use crate::error::Result;

#[derive(Debug, Clone)]
struct AllowEntry {
    kind: Option<String>,
    pattern: String,
}

#[derive(Debug, Default)]
struct ScanConfig<'a> {
    allowlist_path: Option<&'a str>,
    baseline_path: Option<&'a str>,
    baseline_out_path: Option<&'a str>,
}

pub fn scan_filesystem(
    root: &str,
    allowlist_path: Option<&str>,
    baseline_path: Option<&str>,
    baseline_out_path: Option<&str>,
) -> Result<()> {
    println!("\n[+] Scanning filesystem for potential supply-chain issues...\n");
    let root_path = Path::new(root);
    let cfg = ScanConfig {
        allowlist_path,
        baseline_path,
        baseline_out_path,
    };
    let allowlist = load_allowlist(cfg.allowlist_path);
    let baseline = load_baseline(cfg.baseline_path).unwrap_or_default();
    let findings = walk_dir(root_path, root_path)?;
    report_findings(&findings, &allowlist, &baseline, cfg.baseline_out_path)?;
    Ok(())
}

fn walk_dir(root: &Path, path: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let registry = detectors::default_registry();

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
            findings.extend(walk_dir(root, &entry.path())?);
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

fn report_findings(
    findings: &[Finding],
    allowlist: &[AllowEntry],
    baseline: &HashSet<String>,
    baseline_out_path: Option<&str>,
) -> Result<()> {
    let filtered: Vec<&Finding> = findings
        .iter()
        .filter(|f| !is_allowlisted_with_kind(f, allowlist))
        .collect();

    let baseline_filtered = filter_baseline(baseline, allowlist);
    let (new_findings, known_findings) = diff_with_baseline(filtered.as_slice(), &baseline_filtered);
    let missing_baseline = missing_from_scan(&filtered, &baseline_filtered);

    if let Some(path) = baseline_out_path {
        write_baseline(path, &filtered)?;
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
            println!(
                " - {}: {} ({})",
                f.kind,
                f.path.display(),
                f.detail
            );
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

fn write_baseline(path: &str, findings: &[&Finding]) -> Result<()> {
    let mut lines: Vec<String> = findings.iter().map(|f| f.key()).collect();
    lines.sort();
    let content = lines.join("\n");
    fs::write(path, content)?;
    Ok(())
}

fn load_baseline(path: Option<&str>) -> Option<HashSet<String>> {
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

fn load_allowlist(path: Option<&str>) -> Vec<AllowEntry> {
    let mut entries = default_allowlist();
    let Some(path) = path else {
        return entries;
    };
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return entries,
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((kind, pat)) = parse_allowlist_line(line) {
            entries.push(AllowEntry {
                kind: Some(kind),
                pattern: normalize_allowlist_line(&pat),
            });
        } else {
            entries.push(AllowEntry {
                kind: None,
                pattern: normalize_allowlist_line(line),
            });
        }
    }
    entries
}

fn normalize_allowlist_line(line: &str) -> String {
    if line.starts_with('/') {
        line.to_string()
    } else {
        format!("/{line}")
    }
}

fn parse_allowlist_line(line: &str) -> Option<(String, String)> {
    let (kind, rest) = line.split_once(": ")?;
    if kind.is_empty() || rest.is_empty() {
        return None;
    }
    Some((kind.to_string(), rest.to_string()))
}

fn default_allowlist() -> Vec<AllowEntry> {
    vec![
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/bin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/sbin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/usr/bin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/usr/sbin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/lib/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/usr/lib/*".to_string(),
        },
    ]
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut i = 0usize;
    let mut j = 0usize;
    let mut star_i: Option<usize> = None;
    let mut star_j: Option<usize> = None;

    while j < t.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star_i = Some(i);
            star_j = Some(j);
            i += 1;
        } else if let (Some(si), Some(sj)) = (star_i, star_j) {
            i = si + 1;
            j = sj + 1;
            star_j = Some(j);
        } else {
            return false;
        }
    }

    while i < p.len() && p[i] == b'*' {
        i += 1;
    }
    i == p.len()
}

fn is_allowlisted_with_kind(finding: &Finding, allowlist: &[AllowEntry]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    let norm = normalized(&finding.path);
    allowlist.iter().any(|a| {
        if let Some(k) = &a.kind
            && k != &finding.kind
        {
            return false;
        }
        wildcard_match(&a.pattern, &norm)
    })
}

fn filter_baseline(baseline: &HashSet<String>, allowlist: &[AllowEntry]) -> HashSet<String> {
    if allowlist.is_empty() {
        return baseline.clone();
    }
    baseline
        .iter()
        .filter(|k| !baseline_path_allowlisted(k, allowlist))
        .cloned()
        .collect()
}

fn baseline_path_allowlisted(entry: &str, allowlist: &[AllowEntry]) -> bool {
    let mut parts = entry.splitn(2, ": ");
    let kind = parts.next().unwrap_or("");
    let path = match parts.next() {
        Some(p) => p,
        None => return false,
    };
    let norm = normalize_allowlist_line(path);
    allowlist.iter().any(|a| {
        if let Some(k) = &a.kind
            && k != kind
        {
            return false;
        }
        wildcard_match(&a.pattern, &norm)
    })
}

fn diff_with_baseline<'a>(
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

fn missing_from_scan(findings: &[&Finding], baseline: &HashSet<String>) -> Vec<String> {
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

fn normalized(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.starts_with('/') {
        s.to_string()
    } else {
        format!("/{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        baseline_path_allowlisted, wildcard_match, AllowEntry,
    };

    #[test]
    fn baseline_allowlist_match() {
        let allowlist = vec![AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/bin/*".to_string(),
        }];
        let entry = "elf_suspicious: /bin/busybox";
        assert!(baseline_path_allowlisted(entry, &allowlist));
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("/usr/lib/*", "/usr/lib/libssl.so.3"));
        assert!(wildcard_match("*/bin/*", "/usr/bin/curl"));
        assert!(!wildcard_match("/usr/lib/*", "/usr/bin/curl"));
    }
}
